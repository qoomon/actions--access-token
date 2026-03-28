import {HttpClientError} from '@actions/http-client';
import * as core from '@actions/core';

/**
 * Retry an async function with exponential backoff on retryable HTTP status codes.
 * @param fn - async function to retry
 * @param options - retry options
 * @return result of the async function
 */
export async function fetchWithRetry<T>(
    fn: () => Promise<T>,
    options?: {
      maxRetries?: number,
      baseDelay?: number,
      retryableStatusCodes?: number[],
    },
): Promise<T> {
  const maxRetries = options?.maxRetries ?? 3;
  const baseDelay = options?.baseDelay ?? 1000;
  const retryableStatusCodes = options?.retryableStatusCodes ?? [429, 503];

  for (let attempt = 0; ; attempt++) {
    try {
      return await fn();
    } catch (error) {
      const isRetryable = error instanceof HttpClientError
          && retryableStatusCodes.includes(error.statusCode);
      if (attempt < maxRetries && isRetryable) {
        const delay = baseDelay * Math.pow(2, attempt);
        core.info(`Request failed with status ${(error as HttpClientError).statusCode},` +
            ` retrying in ${delay}ms (attempt ${attempt + 1}/${maxRetries})...`);
        await new Promise((resolve) => setTimeout(resolve, delay));
        continue;
      }
      throw error;
    }
  }
}
