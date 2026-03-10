import {describe, expect, it, jest} from '@jest/globals';
import {retry} from '../../src/common/common-utils.js';

describe('retry', () => {

  describe('when fn succeeds on the first attempt', () => {
    it('should return result without retrying', async () => {
      // --- Given ---
      const fn = jest.fn<() => Promise<string>>().mockResolvedValue('success');

      // --- When ---
      const result = await retry(fn, {retries: 3, delay: 0});

      // --- Then ---
      expect(result).toBe('success');
      expect(fn).toHaveBeenCalledTimes(1);
    });
  });

  describe('when fn fails once then succeeds', () => {
    it('should return result after one retry', async () => {
      // --- Given ---
      const error = new Error('transient error');
      const fn = jest.fn<() => Promise<string>>()
          .mockRejectedValueOnce(error)
          .mockResolvedValue('success');

      // --- When ---
      const result = await retry(fn, {retries: 3, delay: 0});

      // --- Then ---
      expect(result).toBe('success');
      expect(fn).toHaveBeenCalledTimes(2);
    });
  });

  describe('when fn always fails', () => {
    it('should throw the actual error (not "Illegal state") after exhausting all retries', async () => {
      // --- Given ---
      const error = new Error('persistent error');
      const fn = jest.fn<() => Promise<string>>().mockRejectedValue(error);

      // --- When ---
      const call = retry(fn, {retries: 3, delay: 0});

      // --- Then ---
      await expect(call).rejects.toThrow('persistent error');
      expect(fn).toHaveBeenCalledTimes(3);
    });

    it('should NOT throw "Illegal state" error', async () => {
      // --- Given ---
      const fn = jest.fn<() => Promise<string>>().mockRejectedValue(new Error('real error'));

      // --- When ---
      const call = retry(fn, {retries: 3, delay: 0});

      // --- Then ---
      await expect(call).rejects.not.toThrow('Illegal state');
    });
  });

  describe('when onError callback is defined', () => {
    it('should stop retrying when onError returns false', async () => {
      // --- Given ---
      const error = new Error('error');
      const fn = jest.fn<() => Promise<string>>().mockRejectedValue(error);
      const onError = jest.fn<(err: unknown) => boolean>().mockReturnValue(false);

      // --- When ---
      const call = retry(fn, {retries: 3, delay: 0, onError});

      // --- Then ---
      await expect(call).rejects.toThrow('error');
      expect(fn).toHaveBeenCalledTimes(1);
      expect(onError).toHaveBeenCalledTimes(1);
    });

    it('should continue retrying when onError returns true', async () => {
      // --- Given ---
      const error = new Error('error');
      const fn = jest.fn<() => Promise<string>>().mockRejectedValue(error);
      const onError = jest.fn<(err: unknown) => boolean>().mockReturnValue(true);

      // --- When ---
      const call = retry(fn, {retries: 3, delay: 0, onError});

      // --- Then ---
      await expect(call).rejects.toThrow('error');
      expect(fn).toHaveBeenCalledTimes(3);
    });

    it('should stop retrying when async onError returns false', async () => {
      // --- Given ---
      const error = new Error('error');
      const fn = jest.fn<() => Promise<string>>().mockRejectedValue(error);
      const onError = jest.fn<(err: unknown) => Promise<boolean>>().mockResolvedValue(false);

      // --- When ---
      const call = retry(fn, {retries: 3, delay: 0, onError});

      // --- Then ---
      await expect(call).rejects.toThrow('error');
      expect(fn).toHaveBeenCalledTimes(1);
    });
  });

  describe('when onRetry callback is defined', () => {
    it('should return result when onRetry returns false', async () => {
      // --- Given ---
      const fn = jest.fn<() => Promise<string>>().mockResolvedValue('success');
      const onRetry = jest.fn<(result: string) => boolean>().mockReturnValue(false);

      // --- When ---
      const result = await retry(fn, {retries: 3, delay: 0, onRetry});

      // --- Then ---
      expect(result).toBe('success');
      expect(fn).toHaveBeenCalledTimes(1);
    });

    it('should keep retrying when onRetry returns true until retries exhausted', async () => {
      // --- Given ---
      const fn = jest.fn<() => Promise<string>>().mockResolvedValue('not-ready');
      const onRetry = jest.fn<(result: string) => boolean>().mockReturnValue(true);

      // --- When ---
      const call = retry(fn, {retries: 3, delay: 0, onRetry});

      // --- Then ---
      await expect(call).rejects.toThrow('Illegal state');
      expect(fn).toHaveBeenCalledTimes(3);
    });

    it('should return result when async onRetry returns false', async () => {
      // --- Given ---
      const fn = jest.fn<() => Promise<string>>().mockResolvedValue('success');
      const onRetry = jest.fn<(result: string) => Promise<boolean>>().mockResolvedValue(false);

      // --- When ---
      const result = await retry(fn, {retries: 3, delay: 0, onRetry});

      // --- Then ---
      expect(result).toBe('success');
      expect(fn).toHaveBeenCalledTimes(1);
    });

    it('should keep retrying when async onRetry returns true', async () => {
      // --- Given ---
      const fn = jest.fn<() => Promise<string>>()
          .mockResolvedValueOnce('not-ready')
          .mockResolvedValue('ready');
      const onRetry = jest.fn<(result: string) => Promise<boolean>>()
          .mockImplementation(async (result) => result === 'not-ready');

      // --- When ---
      const result = await retry(fn, {retries: 3, delay: 0, onRetry});

      // --- Then ---
      expect(result).toBe('ready');
      expect(fn).toHaveBeenCalledTimes(2);
    });
  });
});
