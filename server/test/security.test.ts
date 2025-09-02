import {describe, expect, it} from '@jest/globals';
import {rateLimiter} from '../src/common/rate-limiter.js';
import {SecurityLogger} from '../src/common/security-logger.js';
import {requestTimeout} from '../src/common/timeout.js';
import {sanitizeErrorMessage, containsSensitiveInfo, redactSensitiveInfo} from '../src/common/security-utils.js';
import {Hono} from 'hono';
import {testClient} from 'hono/testing';
import {logger} from '../src/logger.js';

describe('Security Enhancements', () => {
  describe('Rate Limiting Middleware', () => {
    it('should create rate limiter with proper configuration', () => {
      const limiter = rateLimiter({
        windowMs: 15 * 60 * 1000,
        max: 100,
        message: 'Too many requests',
      });

      expect(limiter).toBeDefined();
      expect(typeof limiter).toBe('function');
    });

    it('should add rate limit headers to responses', async () => {
      const app = new Hono();
      app.use(rateLimiter({
        windowMs: 60000,
        max: 10,
      }));
      app.get('/', (c) => c.json({ message: 'ok' }));

      const client = testClient(app);
      const response = await client['/'].$get();

      expect(response.headers.get('X-RateLimit-Limit')).toBe('10');
      expect(response.headers.get('X-RateLimit-Remaining')).toBeDefined();
      expect(response.headers.get('X-RateLimit-Reset')).toBeDefined();
    });
  });

  describe('Security Logger', () => {
    it('should create security logger instance', () => {
      const securityLogger = new SecurityLogger(logger);
      expect(securityLogger).toBeDefined();
    });

    it('should log authentication events', () => {
      const securityLogger = new SecurityLogger(logger);
      
      // These methods should not throw
      expect(() => {
        securityLogger.logAuthSuccess({
          requestId: 'test-123',
          subject: 'repo:test/test:ref:refs/heads/main',
        });
      }).not.toThrow();

      expect(() => {
        securityLogger.logAuthFailure({
          requestId: 'test-123',
          reason: 'Invalid token',
        });
      }).not.toThrow();
    });
  });

  describe('Request Timeout Middleware', () => {
    it('should create timeout middleware', () => {
      const timeout = requestTimeout({ timeout: 30000 });
      expect(timeout).toBeDefined();
      expect(typeof timeout).toBe('function');
    });
  });

  describe('Security Utils', () => {
    describe('sanitizeErrorMessage', () => {
      it('should return original message for owner', () => {
        const message = 'Repository test/repo not found';
        const result = sanitizeErrorMessage(message, true);
        expect(result).toBe(message);
      });

      it('should return generic message for non-owner', () => {
        const message = 'Repository test/repo not found';
        const result = sanitizeErrorMessage(message, false);
        expect(result).toBe('Access denied');
      });
    });

    describe('containsSensitiveInfo', () => {
      it('should detect GitHub repository URLs', () => {
        expect(containsSensitiveInfo('github.com/user/repo')).toBe(true);
        expect(containsSensitiveInfo('Check out https://github.com/test/project')).toBe(true);
      });

      it('should detect SHA hashes', () => {
        expect(containsSensitiveInfo('abc123def456789012345678901234567890abcd')).toBe(true);
        expect(containsSensitiveInfo('1234567890abcdef1234567890abcdef12345678901234567890abcdef1234567890abcdef')).toBe(true);
      });

      it('should detect bearer tokens', () => {
        expect(containsSensitiveInfo('Bearer abc123.def456.ghi789')).toBe(true);
        expect(containsSensitiveInfo('Authorization: Bearer token123')).toBe(true);
      });

      it('should not flag normal text', () => {
        expect(containsSensitiveInfo('This is a normal error message')).toBe(false);
        expect(containsSensitiveInfo('Permission denied')).toBe(false);
      });
    });

    describe('redactSensitiveInfo', () => {
      it('should redact GitHub URLs', () => {
        const text = 'Repository github.com/user/repo not found';
        const result = redactSensitiveInfo(text);
        expect(result).toBe('Repository github.com/[REDACTED]/[REDACTED] not found');
      });

      it('should redact SHA hashes', () => {
        const text = 'Commit abc123def456789012345678901234567890abcd failed';
        const result = redactSensitiveInfo(text);
        expect(result).toBe('Commit [REDACTED-SHA1] failed');
      });

      it('should redact bearer tokens', () => {
        const text = 'Authorization: Bearer abc123.def456.ghi789';
        const result = redactSensitiveInfo(text);
        expect(result).toBe('Authorization: Bearer [REDACTED]');
      });
    });
  });
});