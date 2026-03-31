import {jest, describe, it, expect, beforeEach, afterEach} from '@jest/globals';

const {retry} = await import('../src/retry.js');

describe('retry', () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('should return result on successful first attempt', async () => {
    const fn = jest.fn<() => Promise<string>>().mockResolvedValue('success');

    const result = await retry(fn);

    expect(result).toBe('success');
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('should retry on retryable error and eventually succeed', async () => {
    const fn = jest.fn<() => Promise<string>>()
        .mockRejectedValueOnce(new Error('transient'))
        .mockResolvedValue('success');

    const promise = retry(fn, {baseDelay: 100});
    await jest.advanceTimersByTimeAsync(100); // 100 * 2^0

    const result = await promise;
    expect(result).toBe('success');
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('should use exponential backoff delays', async () => {
    const fn = jest.fn<() => Promise<string>>()
        .mockRejectedValueOnce(new Error('fail'))
        .mockRejectedValueOnce(new Error('fail'))
        .mockRejectedValueOnce(new Error('fail'))
        .mockResolvedValue('success');

    const promise = retry(fn, {baseDelay: 100, maxRetries: 3});

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
    const error = new Error('persistent');
    const fn = jest.fn<() => Promise<string>>().mockRejectedValue(error);

    const promise = retry(fn, {baseDelay: 100, maxRetries: 2});

    // Attach a no-op catch to prevent unhandled rejection while timers advance
    promise.catch(() => { /* expected */ });

    // Attempt 0 fails, wait 100ms (100 * 2^0)
    await jest.advanceTimersByTimeAsync(100);
    // Attempt 1 fails, wait 200ms (100 * 2^1)
    await jest.advanceTimersByTimeAsync(200);

    await expect(promise).rejects.toThrow(error);
    expect(fn).toHaveBeenCalledTimes(3); // initial + 2 retries
  });

  it('should not retry when retryable predicate returns false', async () => {
    const error = new Error('non-retryable');
    const fn = jest.fn<() => Promise<string>>().mockRejectedValue(error);

    await expect(retry(fn, {
      baseDelay: 100,
      retryable: () => false,
    })).rejects.toThrow(error);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('should only retry errors matching the retryable predicate', async () => {
    const retryableError = new Error('retryable');
    const nonRetryableError = new Error('non-retryable');
    const fn = jest.fn<() => Promise<string>>()
        .mockRejectedValueOnce(retryableError)
        .mockRejectedValueOnce(nonRetryableError);

    const promise = retry(fn, {
      baseDelay: 100,
      retryable: (error) => error instanceof Error && error.message === 'retryable',
    });

    // Attach a no-op catch to prevent unhandled rejection while timers advance
    promise.catch(() => { /* expected */ });

    // First error is retryable, wait for backoff
    await jest.advanceTimersByTimeAsync(100);

    // Second error is non-retryable, should throw immediately
    await expect(promise).rejects.toThrow(nonRetryableError);
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('should throw on negative maxRetries', async () => {
    const fn = jest.fn<() => Promise<string>>();
    await expect(retry(fn, {maxRetries: -1})).rejects.toThrow('maxRetries must be a non-negative integer');
    expect(fn).not.toHaveBeenCalled();
  });

  it('should throw on non-integer maxRetries', async () => {
    const fn = jest.fn<() => Promise<string>>();
    await expect(retry(fn, {maxRetries: 1.5})).rejects.toThrow('maxRetries must be a non-negative integer');
    expect(fn).not.toHaveBeenCalled();
  });

  it('should throw on NaN maxRetries', async () => {
    const fn = jest.fn<() => Promise<string>>();
    await expect(retry(fn, {maxRetries: NaN})).rejects.toThrow('maxRetries must be a non-negative integer');
    expect(fn).not.toHaveBeenCalled();
  });

  it('should throw on negative baseDelay', async () => {
    const fn = jest.fn<() => Promise<string>>();
    await expect(retry(fn, {baseDelay: -100})).rejects.toThrow('baseDelay must be a non-negative finite number');
    expect(fn).not.toHaveBeenCalled();
  });

  it('should throw on Infinity baseDelay', async () => {
    const fn = jest.fn<() => Promise<string>>();
    await expect(retry(fn, {baseDelay: Infinity})).rejects.toThrow('baseDelay must be a non-negative finite number');
    expect(fn).not.toHaveBeenCalled();
  });

  it('should throw on NaN baseDelay', async () => {
    const fn = jest.fn<() => Promise<string>>();
    await expect(retry(fn, {baseDelay: NaN})).rejects.toThrow('baseDelay must be a non-negative finite number');
    expect(fn).not.toHaveBeenCalled();
  });

  it('should retry all errors by default when no retryable predicate is given', async () => {
    const fn = jest.fn<() => Promise<string>>()
        .mockRejectedValueOnce(new Error('any error'))
        .mockResolvedValue('success');

    const promise = retry(fn, {baseDelay: 100});
    await jest.advanceTimersByTimeAsync(100);

    const result = await promise;
    expect(result).toBe('success');
    expect(fn).toHaveBeenCalledTimes(2);
  });
});
