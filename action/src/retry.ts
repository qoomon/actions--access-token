/**
 * Retry an async function with exponential backoff.
 * @param fn - async function to retry
 * @param options - retry options
 * @return result of the async function
 */
export async function retry<T>(
    fn: () => Promise<T>,
    options?: {
      maxRetries?: number,
      baseDelay?: number,
      retryable?: (error: unknown) => boolean,
    },
): Promise<T> {
  const maxRetries = options?.maxRetries ?? 3;
  const baseDelay = options?.baseDelay ?? 1000;
  const retryable = options?.retryable ?? (() => true);

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      if (attempt < maxRetries && retryable(error)) {
        const delay = baseDelay * Math.pow(2, attempt);
        await new Promise((resolve) => setTimeout(resolve, delay));
        continue;
      }
      throw error;
    }
  }
  throw new Error('retry: unreachable');
}
