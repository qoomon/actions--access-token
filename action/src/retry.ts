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

  if (!Number.isInteger(maxRetries) || maxRetries < 0) {
    throw new Error(`maxRetries must be a non-negative integer, got ${maxRetries}`);
  }
  if (!Number.isFinite(baseDelay) || baseDelay < 0) {
    throw new Error(`baseDelay must be a non-negative finite number, got ${baseDelay}`);
  }

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
