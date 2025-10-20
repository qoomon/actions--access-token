# Security Improvements

This document describes the security enhancements made to the GitHub Actions Access Token Manager.

## Overview

A comprehensive security audit was conducted, identifying and fixing 6 vulnerabilities ranging from LOW to CRITICAL severity. All fixes maintain backward compatibility with existing access policies.

## Vulnerabilities Fixed

### 1. Regular Expression Denial of Service (ReDoS) - HIGH

**Issue**: Subject pattern matching used unbounded regex that could cause exponential backtracking with malicious inputs.

**Fix**:
- Maximum pattern length limit: 500 characters
- Atomic groups `(?:...)` instead of greedy quantifiers
- Input sanitization and validation before regex construction

**Impact**: Prevents attackers from causing service degradation through crafted pattern strings.

### 2. Subject Pattern Wildcard Bypass - CRITICAL

**Issue**: Inadequate wildcard validation could allow unauthorized access through pattern manipulation.

**Fix**:
- Character whitelist: Only `[a-zA-Z0-9:/\-_.@*?]` allowed
- Maximum subject/pattern length: 1000 characters
- Wildcards only allowed in claim values, not claim names
- Enhanced structure validation before matching

**Impact**: Prevents authorization bypass attacks through malicious pattern crafting.

**Example of blocked attack**:
```yaml
# BLOCKED - wildcard in claim name
subjects:
  - "repo:owner/*:malicious"  # Rejected

# ALLOWED - wildcard in claim value  
subjects:
  - "repo:owner/repo:ref:refs/heads/*"  # Accepted
```

### 3. Token Replay Protection - MEDIUM

**Issue**: OIDC tokens could be reused multiple times within their validity period.

**Fix**:
- JTI (JWT ID) tracking with in-memory cache
- 5-minute replay detection window
- Automatic cleanup of expired entries
- Returns HTTP 403 on replay attempt

**Impact**: Prevents attackers from reusing captured tokens.

**Note**: For multi-instance deployments, consider using Redis or similar distributed cache.

### 4. Path Traversal Prevention - MEDIUM

**Issue**: Insufficient validation of file paths could allow directory traversal.

**Fix**:
- Comprehensive path validation function
- Blocks parent directory references (`..`)
- Blocks absolute paths (`/` or `\`)
- Blocks null bytes (`\0`)
- Maximum path length: 500 characters
- Character whitelist: `[a-zA-Z0-9\-_./]`

**Impact**: Prevents access to files outside authorized directories.

**Example of blocked attempts**:
```javascript
// BLOCKED
"../../etc/passwd"           // Parent directory
"/etc/passwd"                // Absolute path
"file\0.txt"                 // Null byte
"a".repeat(1000) + ".yaml"   // Too long
```

### 5. Rate Limiting - LOW

**Issue**: No rate limiting allowed potential abuse and resource exhaustion.

**Fix**:
- Per-repository rate limiting: 20 requests per minute
- Automatic cleanup of expired entries
- Returns HTTP 429 when exceeded
- Prevents resource exhaustion attacks

**Impact**: Protects server resources from abuse.

**Note**: For multi-instance deployments, consider API gateway-level rate limiting.

### 6. Input Validation Hardening - LOW

**Issue**: Inconsistent validation across different input points.

**Fix**:
- Standardized validation patterns
- Length limits on all user inputs
- Enhanced security event logging

**Impact**: Defense in depth against various attack vectors.

## Security Best Practices

### For Repository Administrators

1. **Restrict Access Policy Modifications**
   - Use GitHub's [push rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets#push-rulesets) (Team/Enterprise plans)
   - Limit who can modify `.github/access-token.yaml`
   - Review changes to access policies carefully

2. **Use Specific Subject Patterns**
   ```yaml
   # GOOD - Specific
   subjects:
     - "repo:${origin}:ref:refs/heads/main"
     - "repo:${origin}:environment:production"
   
   # AVOID - Too permissive
   subjects:
     - "repo:${origin}:**"
   ```

3. **Grant Minimal Permissions**
   ```yaml
   # GOOD - Minimal necessary permissions
   permissions:
     contents: read
   
   # AVOID - Overly broad permissions
   permissions:
     contents: write
     administration: write
   ```

4. **Regular Audits**
   - Review access policies regularly
   - Monitor token usage logs
   - Remove unused permissions

### For Server Operators

1. **Multi-Instance Deployments**
   - Use distributed cache (Redis) for token replay protection
   - Implement API gateway for distributed rate limiting
   - Share JTI tracking across instances

2. **Monitoring**
   - Monitor for replay attempts (HTTP 403 with "already been used")
   - Monitor rate limit hits (HTTP 429)
   - Alert on suspicious patterns

3. **Configuration**
   - Use `GITHUB_ACTIONS_TOKEN_ALLOWED_SUBJECTS` to restrict token sources
   - Validate `GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE` matches your deployment
   - Keep GitHub App private key secure

## Testing

All security fixes include comprehensive tests:

```bash
# Run all tests (50 tests)
npm test

# Run security-specific tests (11 tests)
npm test security.test.ts

# Run static analysis
npm run lint

# CodeQL security scanning
# Integrated in CI/CD pipeline
```

## Security Disclosure

If you discover a security vulnerability, please report it responsibly:

1. Do **not** create a public GitHub issue
2. Email the maintainer with details
3. Include steps to reproduce
4. Allow reasonable time for fix before disclosure

## Version History

- **v3.x**: Security hardening (this update)
  - ReDoS protection
  - Token replay prevention
  - Rate limiting
  - Enhanced input validation

## References

- [OWASP Regular Expression DoS Prevention](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- [GitHub OIDC Token Documentation](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-294: Token Replay](https://cwe.mitre.org/data/definitions/294.html)
