import {createMiddleware} from 'hono/factory';
import {HTTPException} from 'hono/http-exception';
import {Status} from './http-utils.js';

interface RateLimitStore {
  get(key: string): Promise<number | null>;
  set(key: string, value: number, ttl: number): Promise<void>;
  increment(key: string, ttl: number): Promise<number>;
}

interface RateLimitOptions {
  windowMs: number;
  max: number;
  message?: string;
  keyGenerator?: (context: any) => string;
  skip?: (context: any) => boolean;
}

/**
 * Simple in-memory rate limiter
 * For production use, consider Redis-based store
 */
class MemoryStore implements RateLimitStore {
  private store = new Map<string, { count: number; expires: number }>();

  async get(key: string): Promise<number | null> {
    const entry = this.store.get(key);
    if (!entry || entry.expires < Date.now()) {
      this.store.delete(key);
      return null;
    }
    return entry.count;
  }

  async set(key: string, value: number, ttl: number): Promise<void> {
    this.store.set(key, { count: value, expires: Date.now() + ttl });
  }

  async increment(key: string, ttl: number): Promise<number> {
    const current = await this.get(key);
    const newCount = (current || 0) + 1;
    await this.set(key, newCount, ttl);
    return newCount;
  }
}

/**
 * Rate limiting middleware
 * @param options - rate limiting configuration
 * @return middleware
 */
export function rateLimiter(options: RateLimitOptions) {
  const {
    windowMs,
    max,
    message = 'Too many requests, please try again later.',
    keyGenerator = (context) => context.req.header('x-forwarded-for') || 
                               context.req.header('x-real-ip') || 
                               'unknown',
    skip = () => false,
  } = options;

  const store = new MemoryStore();

  return createMiddleware(async (context, next) => {
    if (skip(context)) {
      return next();
    }

    const key = keyGenerator(context);
    const current = await store.increment(key, windowMs);

    // Add rate limit headers
    context.header('X-RateLimit-Limit', max.toString());
    context.header('X-RateLimit-Remaining', Math.max(0, max - current).toString());
    context.header('X-RateLimit-Reset', new Date(Date.now() + windowMs).toISOString());

    if (current > max) {
      throw new HTTPException(Status.TOO_MANY_REQUESTS, {
        message,
      });
    }

    return next();
  });
}