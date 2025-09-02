import {Logger} from 'pino';

/**
 * Security event types for monitoring and alerting
 */
export enum SecurityEventType {
  AUTHENTICATION_SUCCESS = 'auth_success',
  AUTHENTICATION_FAILURE = 'auth_failure',
  AUTHORIZATION_FAILURE = 'authz_failure',
  RATE_LIMIT_EXCEEDED = 'rate_limit_exceeded',
  INVALID_TOKEN = 'invalid_token',
  POLICY_VIOLATION = 'policy_violation',
  SUSPICIOUS_ACTIVITY = 'suspicious_activity',
}

/**
 * Security event data structure
 */
export interface SecurityEvent {
  event: SecurityEventType;
  timestamp: Date;
  requestId?: string;
  clientIp?: string;
  userAgent?: string;
  subject?: string;
  repository?: string;
  owner?: string;
  permissions?: Record<string, string>;
  reason?: string;
  metadata?: Record<string, any>;
}

/**
 * Enhanced security logger for audit trail and monitoring
 */
export class SecurityLogger {
  private logger: Logger;

  constructor(baseLogger: Logger) {
    this.logger = baseLogger.child({ component: 'security' });
  }

  /**
   * Log authentication success
   */
  logAuthSuccess(event: Partial<SecurityEvent>): void {
    this.logger.info({
      ...event,
      event: SecurityEventType.AUTHENTICATION_SUCCESS,
      timestamp: new Date(),
    }, 'Authentication successful');
  }

  /**
   * Log authentication failure
   */
  logAuthFailure(event: Partial<SecurityEvent>): void {
    this.logger.warn({
      ...event,
      event: SecurityEventType.AUTHENTICATION_FAILURE,
      timestamp: new Date(),
    }, 'Authentication failed');
  }

  /**
   * Log authorization failure
   */
  logAuthzFailure(event: Partial<SecurityEvent>): void {
    this.logger.warn({
      ...event,
      event: SecurityEventType.AUTHORIZATION_FAILURE,
      timestamp: new Date(),
    }, 'Authorization failed');
  }

  /**
   * Log rate limit exceeded
   */
  logRateLimitExceeded(event: Partial<SecurityEvent>): void {
    this.logger.warn({
      ...event,
      event: SecurityEventType.RATE_LIMIT_EXCEEDED,
      timestamp: new Date(),
    }, 'Rate limit exceeded');
  }

  /**
   * Log invalid token usage
   */
  logInvalidToken(event: Partial<SecurityEvent>): void {
    this.logger.warn({
      ...event,
      event: SecurityEventType.INVALID_TOKEN,
      timestamp: new Date(),
    }, 'Invalid token detected');
  }

  /**
   * Log policy violation
   */
  logPolicyViolation(event: Partial<SecurityEvent>): void {
    this.logger.warn({
      ...event,
      event: SecurityEventType.POLICY_VIOLATION,
      timestamp: new Date(),
    }, 'Policy violation detected');
  }

  /**
   * Log suspicious activity
   */
  logSuspiciousActivity(event: Partial<SecurityEvent>): void {
    this.logger.error({
      ...event,
      event: SecurityEventType.SUSPICIOUS_ACTIVITY,
      timestamp: new Date(),
    }, 'Suspicious activity detected');
  }

  /**
   * Generic security event logger
   */
  logSecurityEvent(event: SecurityEvent): void {
    const logLevel = this.getLogLevel(event.event);
    this.logger[logLevel]({
      ...event,
      timestamp: new Date(),
    }, `Security event: ${event.event}`);
  }

  private getLogLevel(eventType: SecurityEventType): 'info' | 'warn' | 'error' {
    switch (eventType) {
      case SecurityEventType.AUTHENTICATION_SUCCESS:
        return 'info';
      case SecurityEventType.AUTHENTICATION_FAILURE:
      case SecurityEventType.AUTHORIZATION_FAILURE:
      case SecurityEventType.RATE_LIMIT_EXCEEDED:
      case SecurityEventType.INVALID_TOKEN:
      case SecurityEventType.POLICY_VIOLATION:
        return 'warn';
      case SecurityEventType.SUSPICIOUS_ACTIVITY:
        return 'error';
      default:
        return 'warn';
    }
  }
}