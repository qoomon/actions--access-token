import {createMiddleware} from 'hono/factory';
import {HTTPException} from 'hono/http-exception';
import {Status} from './http-utils.js';

interface TimeoutOptions {
  timeout: number; // timeout in milliseconds
  message?: string;
}

/**
 * Request timeout middleware
 * @param options - timeout configuration
 * @return middleware
 */
export function requestTimeout(options: TimeoutOptions) {
  const {timeout, message = 'Request timeout'} = options;

  return createMiddleware(async (context, next) => {
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => {
        reject(new HTTPException(Status.REQUEST_TIMEOUT, {message}));
      }, timeout);
    });

    try {
      await Promise.race([next(), timeoutPromise]);
    } catch (error) {
      // If it's our timeout error, let it bubble up
      if (error instanceof HTTPException && error.status === Status.REQUEST_TIMEOUT) {
        throw error;
      }
      // For other errors, still check if we've timed out
      throw error;
    }
  });
}