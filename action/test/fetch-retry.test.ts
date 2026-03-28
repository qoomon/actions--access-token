import {jest, describe, it, expect, beforeEach, afterEach} from '@jest/globals';
import {HttpClientError} from '@actions/http-client';

// mock @actions/core to suppress log output
jest.unstable_mockModule('@actions/core', () => ({
  info: jest.fn(),
}));

const {fetchWithRetry} = await import('../src/fetch-retry.js');

describe('fetchWithRetry', () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('should return result on successful first attempt', async () => {
    const fn = jest.fn<() => Promise<string>>().mockResolvedValue('success');

    const result = await fetchWithRetry(fn);

    expect(result).toBe('success');
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('should retry on 429 status code and eventually succeed', async () => {
    const fn = jest.fn<() => Promise<string>>()
        .mockRejectedValueOnce(new HttpClientError('Too Many Requests', 429))
        .mockResolvedValue('success');

    const promise = fetchWithRetry(fn, {baseDelay: 100});
    await jest.advanceTimersByTimeAsync(100); // 100 * 2^0

    const result = await promise;
    expect(result).toBe('success');
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('should retry on 503 status code and eventually succeed', async () => {
    const fn = jest.fn<() => Promise<string>>()
        .mockRejectedValueOnce(new HttpClientError('Service Unavailable', 503))
        .mockResolvedValue('success');

    const promise = fetchWithRetry(fn, {baseDelay: 100});
    await jest.advanceTimersByTimeAsync(100); // 100 * 2^0

    const result = await promise;
    expect(result).toBe('success');
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('should use exponential backoff delays', async () => {
    const fn = jest.fn<() => Promise<string>>()
        .mockRejectedValueOnce(new HttpClientError('Too Many Requests', 429))
        .mockRejectedValueOnce(new HttpClientError('Too Many Requests', 429))
        .mockRejectedValueOnce(new HttpClientError('Too Many Requests', 429))
        .mockResolvedValue('success');

    const promise = fetchWithRetry(fn, {baseDelay: 100, maxRetries: 3});

    // Attempt 0 fails, wait 100ms (100 * 2^0)
    await jest.advanceTimersByTimeAsync(100);
    expect(fn).toHaveBeenCalledTimes(2);

    // Attempt 1 fails, wait 200ms (100 * 2^1)
    await jest.advanceTimersByTimeAsync(200);
    expect(fn).toHaveBeenCalledTimes(3);

    // Attempt 2 fails, wait 400ms (100 * 2^2)
    await jest.advanceTimersByTimeAsync(400);
    expect(fn).toHaveBeenCalledTimes(4);

    const result = await promise;
    expect(result).toBe('success');
  });

  it('should throw after max retries exceeded', async () => {
    const error = new HttpClientError('Too Many Requests', 429);
    const fn = jest.fn<() => Promise<string>>().mockRejectedValue(error);

    const promise = fetchWithRetry(fn, {baseDelay: 100, maxRetries: 2});

    // Attach a no-op catch to prevent unhandled rejection while timers advance
    promise.catch(() => { /* expected */ });

    // Attempt 0 fails, wait 100ms (100 * 2^0)
    await jest.advanceTimersByTimeAsync(100);
    // Attempt 1 fails, wait 200ms (100 * 2^1)
    await jest.advanceTimersByTimeAsync(200);

    await expect(promise).rejects.toThrow(error);
    expect(fn).toHaveBeenCalledTimes(3); // initial + 2 retries
  });

  it('should not retry on non-retryable status codes', async () => {
    const error = new HttpClientError('Not Found', 404);
    const fn = jest.fn<() => Promise<string>>().mockRejectedValue(error);

    await expect(fetchWithRetry(fn, {baseDelay: 100})).rejects.toThrow(error);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('should not retry on non-HttpClientError errors', async () => {
    const error = new Error('Network error');
    const fn = jest.fn<() => Promise<string>>().mockRejectedValue(error);

    await expect(fetchWithRetry(fn, {baseDelay: 100})).rejects.toThrow(error);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('should respect custom retryableStatusCodes', async () => {
    const fn = jest.fn<() => Promise<string>>()
        .mockRejectedValueOnce(new HttpClientError('Bad Gateway', 502))
        .mockResolvedValue('success');

    const promise = fetchWithRetry(fn, {baseDelay: 100, retryableStatusCodes: [502]});
    await jest.advanceTimersByTimeAsync(100);

    const result = await promise;
    expect(result).toBe('success');
    expect(fn).toHaveBeenCalledTimes(2);
  });
});
