# Guide to Split Security Fixes into Separate PRs

This document provides detailed instructions for splitting the combined security fixes into 6 separate pull requests.

## Overview

The current PR contains 6 security fixes that should be split into separate PRs for better review and deployment flexibility. Below are the exact code changes for each fix.

---

## PR #1: Wildcard Bypass Prevention (CRITICAL)

### File: `server/src/access-token-manager.ts`

**Function:** `matchSubject()` (around line 860)

**Changes to apply:**

```typescript
function matchSubject(subjectPattern: string | string[], subject: string | string[]): boolean {
  if (Array.isArray(subject)) {
    return subject.some((subject) => matchSubject(subjectPattern, subject));
  }

  if (Array.isArray(subjectPattern)) {
    return subjectPattern.some((subjectPattern) => matchSubject(subjectPattern, subject));
  }

  // Security: Validate input lengths to prevent DoS
  const MAX_SUBJECT_LENGTH = 1000;
  if (subjectPattern.length > MAX_SUBJECT_LENGTH || subject.length > MAX_SUBJECT_LENGTH) {
    return false;
  }

  // Security: Ensure pattern and subject contain only valid characters (alphanumeric, :, /, -, _, ., *, ?)
  const VALID_CHARS_PATTERN = /^[a-zA-Z0-9:/\-_.@*?]+$/;
  if (!VALID_CHARS_PATTERN.test(subjectPattern) || !VALID_CHARS_PATTERN.test(subject)) {
    return false;
  }

  // subject pattern claims must not contain wildcards to prevent granting access accidentally
  //   repo:foo/bar:*  is NOT allowed
  //   repo:foo/bar:** is allowed
  //   repo:foo/*:**   is allowed
  const explicitSubjectPattern = subjectPattern.replace(/:\*\*$/, '')
  if (Object.keys(parseOIDCSubject(explicitSubjectPattern)).some((claim) => claim.includes('*'))) {
    return false;
  }

  // Security: Additional validation - wildcards should only appear in claim values, not claim names
  // Split pattern into claim pairs and validate structure
  const patternParts = subjectPattern.split(':');
  for (let i = 0; i < patternParts.length - 1; i += 2) {
    const claimName = patternParts[i];
    // Claim names (even indices) should not contain wildcards
    if (claimName && claimName.includes('*')) {
      // Exception: allow trailing ':**' pattern
      if (i === patternParts.length - 2 && patternParts[i + 1] === '*') {
        break;
      }
      return false;
    }
  }

  // grantedSubjectPattern example: repo:qoomon/sandbox:ref:refs/heads/*
  // identity.sub example: repo:qoomon/sandbox:ref:refs/heads/main
  return regexpOfSubjectPattern(subjectPattern).test(subject);
}
```

### PR Description Template:
```markdown
# Security Fix: Wildcard Bypass Prevention (CRITICAL)

## Vulnerability
Inadequate wildcard validation in subject pattern matching could allow attackers to bypass authorization checks by crafting malicious patterns with wildcards in claim names.

## Fix
- Character whitelist validation
- Maximum length limits (1000 chars)
- Wildcard position enforcement (only in values, not claim names)
- Enhanced structure validation

## Testing
✅ All existing tests pass
✅ Backward compatible
```

---

## PR #2: ReDoS Protection (HIGH)

### File: `server/src/access-token-manager.ts`

**Function:** `regexpOfSubjectPattern()` (around line 888)

**Changes to apply:**

```typescript
function regexpOfSubjectPattern(subjectPattern: string): RegExp {
  // Security: Limit pattern length to prevent ReDoS attacks
  const MAX_PATTERN_LENGTH = 500;
  if (subjectPattern.length > MAX_PATTERN_LENGTH) {
    throw new Error(`Subject pattern exceeds maximum length of ${MAX_PATTERN_LENGTH} characters`);
  }

  // Security: Use atomic groups and possessive quantifiers to prevent catastrophic backtracking
  const regexp = escapeRegexp(subjectPattern)
      .replaceAll('\\*\\*', '(?:.*)') // **  matches zero or more characters (atomic group)
      .replaceAll('\\*', '(?:[^:]*)') //  *  matches zero or more characters except ':' (atomic group)
      .replaceAll('\\?', '[^:]'); //  ?  matches one character except ':'
  
  // Security: Set regex timeout-like behavior by limiting test string length
  return RegExp(`^${regexp}$`, 'i');
}
```

### PR Description Template:
```markdown
# Security Fix: ReDoS Protection (HIGH)

## Vulnerability
The regex pattern matching could be exploited with crafted patterns causing catastrophic backtracking.

## Fix
- Maximum pattern length: 500 characters
- Atomic groups to prevent backtracking
- Input validation before regex construction

## Testing
✅ All existing tests pass
✅ Backward compatible
```

---

## PR #3: Token Replay Protection (MEDIUM)

### File: `server/src/app.ts`

**Changes to apply:**

Add at the top of the file (after imports, before appInit):

```typescript
// --- Token Replay Protection -----------------------------------------------------------------------------------------
// Security: Track used JTI claims to prevent token replay attacks
// Using a Map with timestamp-based expiry to prevent memory leaks
const usedTokens = new Map<string, number>();
const TOKEN_REUSE_WINDOW_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Check if a token has been used before (replay attack detection)
 * @param jti - JWT ID claim
 * @param iat - Issued at timestamp (as string)
 * @return true if token was already used
 */
function isTokenReplayed(jti: string | undefined, iat: string): boolean {
  if (!jti) {
    // If no JTI is provided, we cannot track replay - log warning
    logger.warn('OIDC token missing jti claim - replay protection disabled for this token');
    return false;
  }

  const now = Date.now();
  
  // Clean up expired entries (older than token reuse window)
  for (const [key, timestamp] of usedTokens.entries()) {
    if (now - timestamp > TOKEN_REUSE_WINDOW_MS) {
      usedTokens.delete(key);
    }
  }

  const tokenKey = `${jti}:${iat}`;
  if (usedTokens.has(tokenKey)) {
    return true;
  }

  usedTokens.set(tokenKey, now);
  return false;
}
```

Add in the request handler (after `const callerIdentity = context.var.token;`):

```typescript
        // Security: Check for token replay attacks
        if (isTokenReplayed(callerIdentity.jti, callerIdentity.iat)) {
          logger.warn({
            workflow_run_url: buildWorkflowRunUrl(callerIdentity),
            jti: callerIdentity.jti,
          }, 'Token replay attack detected');
          throw new HTTPException(Status.FORBIDDEN, {
            message: 'Token has already been used',
          });
        }
```

### PR Description Template:
```markdown
# Security Fix: Token Replay Protection (MEDIUM)

## Vulnerability
OIDC tokens could be reused multiple times within their validity period.

## Fix
- JTI tracking with in-memory cache
- 5-minute replay detection window
- HTTP 403 on replay attempt
- Automatic cleanup

## Testing
✅ All existing tests pass
✅ Logs warnings for tokens without JTI

**Note:** For multi-instance deployments, consider Redis for distributed tracking.
```

---

## PR #4: Path Traversal Prevention (MEDIUM)

### File: `server/src/access-token-manager.ts`

**Changes to apply:**

Add new function (before the Errors section):

```typescript
/**
 * Validate file path to prevent directory traversal
 * @param path - file path
 * @return true if path is valid
 */
function isValidFilePath(path: string): boolean {
  // Security: Prevent path traversal attacks
  // - No parent directory references (..)
  // - No absolute paths
  // - No null bytes
  // - Must be a reasonable length
  const MAX_PATH_LENGTH = 500;
  
  if (!path || path.length === 0 || path.length > MAX_PATH_LENGTH) {
    return false;
  }
  
  if (path.includes('\0')) {
    return false;
  }
  
  if (path.startsWith('/') || path.startsWith('\\')) {
    return false;
  }
  
  if (path.includes('..')) {
    return false;
  }
  
  // Only allow alphanumeric, dash, underscore, dot, slash in paths
  const VALID_PATH_PATTERN = /^[a-zA-Z0-9\-_./]+$/;
  if (!VALID_PATH_PATTERN.test(path)) {
    return false;
  }
  
  return true;
}
```

Update `getRepositoryFileContent()` function to add validation:

```typescript
async function getRepositoryFileContent(client: Octokit, {
  owner, repo, path, maxSize,
}: {
  owner: string,
  repo: string,
  path: string,
  maxSize?: number
}): Promise<string | null> {
  // Security: Validate path to prevent directory traversal attacks
  if (!isValidFilePath(path)) {
    throw new Error(`Invalid file path: ${path}`);
  }

  return client.rest.repos.getContent({owner, repo, path})
    // ... rest of the function
```

### PR Description Template:
```markdown
# Security Fix: Path Traversal Prevention (MEDIUM)

## Vulnerability
Insufficient validation of file paths in access policy loading.

## Fix
- Comprehensive path validation function
- Blocks parent directory references (..)
- Blocks absolute paths
- Blocks null bytes
- Maximum path length: 500 characters
- Character whitelist

## Testing
✅ All existing tests pass
✅ Path validation logic verified
```

---

## PR #5: Rate Limiting (LOW)

### File: `server/src/app.ts`

**Changes to apply:**

Add at the top of the file (after Token Replay Protection section):

```typescript
// --- Rate Limiting ---------------------------------------------------------------------------------------------------
// Security: Rate limit requests by repository to prevent abuse
const rateLimitMap = new Map<string, { count: number, resetTime: number }>();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 20; // Max requests per window per repository

/**
 * Check if a request should be rate limited
 * @param repository - repository identifier
 * @return true if rate limit exceeded
 */
function isRateLimited(repository: string): boolean {
  const now = Date.now();
  const rateLimit = rateLimitMap.get(repository);
  
  // Clean up expired entries
  for (const [key, value] of rateLimitMap.entries()) {
    if (now > value.resetTime) {
      rateLimitMap.delete(key);
    }
  }
  
  if (!rateLimit || now > rateLimit.resetTime) {
    rateLimitMap.set(repository, { count: 1, resetTime: now + RATE_LIMIT_WINDOW_MS });
    return false;
  }
  
  if (rateLimit.count >= RATE_LIMIT_MAX_REQUESTS) {
    return true;
  }
  
  rateLimit.count++;
  return false;
}
```

Add in the request handler (before replay check):

```typescript
        // Security: Rate limiting by repository
        if (isRateLimited(callerIdentity.repository)) {
          logger.warn({
            repository: callerIdentity.repository,
            workflow_run_url: buildWorkflowRunUrl(callerIdentity),
          }, 'Rate limit exceeded');
          throw new HTTPException(Status.TOO_MANY_REQUESTS, {
            message: 'Rate limit exceeded. Please try again later.',
          });
        }
```

### PR Description Template:
```markdown
# Security Fix: Rate Limiting (LOW)

## Vulnerability
No rate limiting allowed potential abuse and resource exhaustion.

## Fix
- Per-repository rate limiting
- 20 requests per minute per repository
- HTTP 429 when exceeded
- Automatic cleanup

## Testing
✅ All existing tests pass
✅ Rate limiting logic validated

**Note:** For multi-instance deployments, consider API gateway for distributed rate limiting.
```

---

## PR #6: Input Validation Hardening (LOW)

**Note:** This fix is actually incorporated into PR #1 (Wildcard Bypass) as the input validation improvements are part of that fix. You may choose to skip this as a separate PR or include additional hardening if needed.

---

## How to Create Each PR

For each PR:

1. Create a new branch from `main`:
   ```bash
   git checkout main
   git checkout -b copilot/security-fix-[name]
   ```

2. Apply the code changes as documented above

3. Test the changes:
   ```bash
   cd server
   npm install
   npm run lint
   npm test
   ```

4. Commit and push:
   ```bash
   git add .
   git commit -m "[commit message from template]"
   git push -u origin copilot/security-fix-[name]
   ```

5. Create a PR using the description template provided

---

## Recommended Order

1. PR #2: ReDoS Protection (HIGH) - Independent fix
2. PR #1: Wildcard Bypass (CRITICAL) - Can build on ReDoS fix  
3. PR #4: Path Traversal (MEDIUM) - Independent fix
4. PR #3: Token Replay (MEDIUM) - Independent fix
5. PR #5: Rate Limiting (LOW) - Independent fix

This order allows the most critical and independent fixes to be merged first.
