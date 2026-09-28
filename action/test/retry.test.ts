import assert from 'node:assert/strict';
import {afterEach, beforeEach, describe, it, mock} from 'node:test';

const {retry} = await import('../src/retry.js');

describe('retry', () => {
  beforeEach(() => {
    mock.timers.enable();
  });

  afterEach(() => {
    mock.timers.reset();
    mock.restoreAll();
  });

  it('should return result on successful first attempt', async () => {
    const fn = mock.fn<() => Promise<string>>(async () => 'success');

    const result = await retry(fn);

    assert.equal(result, 'success');
    assert.equal(fn.mock.callCount(), 1);
  });

  it('should retry on retryable error and eventually succeed', async () => {
    const transientError = new Error('transient');
    const fn = mock.fn<() => Promise<string>>(async () => 'success');
    fn.mock.mockImplementationOnce(async () => {
      throw transientError;
    }, 0);

    const promise = retry(fn, {baseDelay: 100});
    await advanceTimersBy(100); // 100 * 2^0

    const result = await promise;
    assert.equal(result, 'success');
    assert.equal(fn.mock.callCount(), 2);
  });

  it('should use exponential backoff delays', async () => {
    const fn = mock.fn<() => Promise<string>>(async () => 'success');
    fn.mock.mockImplementationOnce(async () => {
      throw new Error('fail');
    }, 0);
    fn.mock.mockImplementationOnce(async () => {
      throw new Error('fail');
    }, 1);
    fn.mock.mockImplementationOnce(async () => {
      throw new Error('fail');
    }, 2);

    const promise = retry(fn, {baseDelay: 100, maxRetries: 3});

    // Attempt 0 fails, wait 100ms (100 * 2^0)
    await advanceTimersBy(100);
    assert.equal(fn.mock.callCount(), 2);

    // Attempt 1 fails, wait 200ms (100 * 2^1)
    await advanceTimersBy(200);
    assert.equal(fn.mock.callCount(), 3);

    // Attempt 2 fails, wait 400ms (100 * 2^2)
    await advanceTimersBy(400);
    assert.equal(fn.mock.callCount(), 4);

    const result = await promise;
    assert.equal(result, 'success');
  });

  it('should throw after max retries exceeded', async () => {
    const error = new Error('persistent');
    const fn = mock.fn<() => Promise<string>>(async () => {
      throw error;
    });

    const promise = retry(fn, {baseDelay: 100, maxRetries: 2});

    // Attach a no-op catch to prevent unhandled rejection while timers advance
    promise.catch(() => { /* expected */ });

    // Attempt 0 fails, wait 100ms (100 * 2^0)
    await advanceTimersBy(100);
    // Attempt 1 fails, wait 200ms (100 * 2^1)
    await advanceTimersBy(200);

    await assert.rejects(promise, (caught: unknown) => {
      assert.equal(caught, error);
      return true;
    });
    assert.equal(fn.mock.callCount(), 3); // initial + 2 retries
  });

  it('should not retry when retryable predicate returns false', async () => {
    const error = new Error('non-retryable');
    const fn = mock.fn<() => Promise<string>>(async () => {
      throw error;
    });

    await assert.rejects(retry(fn, {
      baseDelay: 100,
      retryable: () => false,
    }), (caught: unknown) => {
      assert.equal(caught, error);
      return true;
    });
    assert.equal(fn.mock.callCount(), 1);
  });

  it('should only retry errors matching the retryable predicate', async () => {
    const retryableError = new Error('retryable');
    const nonRetryableError = new Error('non-retryable');
    const fn = mock.fn<() => Promise<string>>(async () => 'success');
    fn.mock.mockImplementationOnce(async () => {
      throw retryableError;
    }, 0);
    fn.mock.mockImplementationOnce(async () => {
      throw nonRetryableError;
    }, 1);

    const promise = retry(fn, {
      baseDelay: 100,
      retryable: (error) => error instanceof Error && error.message === 'retryable',
    });

    // Attach a no-op catch to prevent unhandled rejection while timers advance
    promise.catch(() => { /* expected */ });

    // First error is retryable, wait for backoff
    await advanceTimersBy(100);

    // Second error is non-retryable, should throw immediately
    await assert.rejects(promise, (caught: unknown) => {
      assert.equal(caught, nonRetryableError);
      return true;
    });
    assert.equal(fn.mock.callCount(), 2);
  });

  it('should throw on negative maxRetries', async () => {
    const fn = mock.fn<() => Promise<string>>();
    await assert.rejects(retry(fn, {maxRetries: -1}), /maxRetries must be a non-negative integer/);
    assert.equal(fn.mock.callCount(), 0);
  });

  it('should throw on non-integer maxRetries', async () => {
    const fn = mock.fn<() => Promise<string>>();
    await assert.rejects(retry(fn, {maxRetries: 1.5}), /maxRetries must be a non-negative integer/);
    assert.equal(fn.mock.callCount(), 0);
  });

  it('should throw on NaN maxRetries', async () => {
    const fn = mock.fn<() => Promise<string>>();
    await assert.rejects(retry(fn, {maxRetries: NaN}), /maxRetries must be a non-negative integer/);
    assert.equal(fn.mock.callCount(), 0);
  });

  it('should throw on negative baseDelay', async () => {
    const fn = mock.fn<() => Promise<string>>();
    await assert.rejects(retry(fn, {baseDelay: -100}), /baseDelay must be a non-negative finite number/);
    assert.equal(fn.mock.callCount(), 0);
  });

  it('should throw on Infinity baseDelay', async () => {
    const fn = mock.fn<() => Promise<string>>();
    await assert.rejects(retry(fn, {baseDelay: Infinity}), /baseDelay must be a non-negative finite number/);
    assert.equal(fn.mock.callCount(), 0);
  });

  it('should throw on NaN baseDelay', async () => {
    const fn = mock.fn<() => Promise<string>>();
    await assert.rejects(retry(fn, {baseDelay: NaN}), /baseDelay must be a non-negative finite number/);
    assert.equal(fn.mock.callCount(), 0);
  });

  it('should call onRetry callback before each retry', async () => {
    const firstError = new Error('fail-1');
    const secondError = new Error('fail-2');
    const fn = mock.fn<() => Promise<string>>(async () => 'success');
    fn.mock.mockImplementationOnce(async () => {
      throw firstError;
    }, 0);
    fn.mock.mockImplementationOnce(async () => {
      throw secondError;
    }, 1);
    const onRetry = mock.fn<(error: unknown, attempt: number, delay: number) => void>();

    const promise = retry(fn, {baseDelay: 100, maxRetries: 3, onRetry});
    await advanceTimersBy(100); // 100 * 2^0
    await advanceTimersBy(200); // 100 * 2^1

    const result = await promise;
    assert.equal(result, 'success');
    assert.equal(onRetry.mock.callCount(), 2);
    assert.deepEqual(onRetry.mock.calls[0]?.arguments, [firstError, 1, 100]);
    assert.deepEqual(onRetry.mock.calls[1]?.arguments, [secondError, 2, 200]);
  });

  it('should retry all errors by default when no retryable predicate is given', async () => {
    const fn = mock.fn<() => Promise<string>>(async () => 'success');
    fn.mock.mockImplementationOnce(async () => {
      throw new Error('any error');
    }, 0);

    const promise = retry(fn, {baseDelay: 100});
    await advanceTimersBy(100);

    const result = await promise;
    assert.equal(result, 'success');
    assert.equal(fn.mock.callCount(), 2);
  });
});

async function advanceTimersBy(milliseconds: number): Promise<void> {
  await Promise.resolve();
  mock.timers.tick(milliseconds);
  await Promise.resolve();
}
