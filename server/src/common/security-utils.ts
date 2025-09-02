/**
 * Security utilities for information disclosure prevention
 */

/**
 * Sanitizes error messages to prevent information disclosure
 * @param error - The original error message
 * @param isOwner - Whether the caller owns the resource
 * @param fallbackMessage - Fallback message for non-owners
 * @return sanitized error message
 */
export function sanitizeErrorMessage(
  error: string,
  isOwner: boolean,
  fallbackMessage: string = 'Access denied'
): string {
  if (isOwner) {
    return error;
  }
  return fallbackMessage;
}

/**
 * Sanitizes repository references in error messages
 * @param message - Error message that may contain repository names
 * @param isOwner - Whether the caller owns the repository
 * @return sanitized message
 */
export function sanitizeRepositoryReference(
  message: string,
  isOwner: boolean
): string {
  if (isOwner) {
    return message;
  }
  
  // Replace repository patterns with generic reference
  return message
    .replace(/repository '?[^'\s]+'?/gi, 'repository')
    .replace(/repo '?[^'\s]+'?/gi, 'repository')
    .replace(/owner '?[^'\s]+'?/gi, 'owner');
}

/**
 * Checks if a string contains sensitive information that should be redacted
 * @param text - Text to check
 * @return true if text contains sensitive information
 */
export function containsSensitiveInfo(text: string): boolean {
  const sensitivePatterns = [
    /github\.com\/[^\/]+\/[^\/\s]+/i, // GitHub repository URLs
    /[a-f0-9]{40}/i, // SHA-1 hashes (Git commits)
    /[a-f0-9]{64}/i, // SHA-256 hashes
    /Bearer\s+[a-zA-Z0-9._-]+/i, // Bearer tokens
    /token[^a-zA-Z0-9][a-zA-Z0-9._-]{8,}/i, // Token-like strings
  ];
  
  return sensitivePatterns.some(pattern => pattern.test(text));
}

/**
 * Redacts sensitive information from text
 * @param text - Text to redact
 * @return redacted text
 */
export function redactSensitiveInfo(text: string): string {
  return text
    .replace(/github\.com\/[^\/]+\/[^\/\s]+/gi, 'github.com/[REDACTED]/[REDACTED]')
    .replace(/[a-f0-9]{40}/gi, '[REDACTED-SHA1]')
    .replace(/[a-f0-9]{64}/gi, '[REDACTED-SHA256]')
    .replace(/Bearer\s+[a-zA-Z0-9._-]+/gi, 'Bearer [REDACTED]')
    .replace(/token[^a-zA-Z0-9]([a-zA-Z0-9._-]{8,})/gi, 'token=[REDACTED]');
}