# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **[CRITICAL]** Fixed subject pattern wildcard bypass vulnerability that could allow unauthorized access
- **[HIGH]** Fixed Regular Expression Denial of Service (ReDoS) vulnerability in pattern matching
- **[MEDIUM]** Added token replay protection using JTI tracking (5-minute window)
- **[MEDIUM]** Added path traversal prevention in access policy file loading
- **[LOW]** Implemented rate limiting (20 requests per minute per repository)
- **[LOW]** Enhanced input validation across all user-controlled inputs

### Added
- Token replay detection with JTI claim tracking
- Per-repository rate limiting to prevent abuse
- Comprehensive security test suite (11 new tests)
- Security documentation in SECURITY.md
- Input length and complexity validation
- Character whitelisting for patterns and paths

### Changed
- Improved regex pattern matching to use atomic groups preventing catastrophic backtracking
- Enhanced subject pattern validation with stricter wildcard rules
- Standardized validation logic across the codebase
- Better security logging for suspicious activities

### Technical Details
- Maximum pattern length: 500 characters
- Maximum subject length: 1000 characters
- Maximum file path length: 500 characters
- Rate limit: 20 requests per minute per repository
- Token replay window: 5 minutes
- Character whitelist for patterns: `[a-zA-Z0-9:/\-_.@*?]`
- Character whitelist for paths: `[a-zA-Z0-9\-_./]`

### Testing
- All 50 tests passing (39 existing + 11 new security tests)
- CodeQL analysis: 0 alerts
- Linting: No errors
- Backward compatibility: Maintained

### Notes
- No breaking changes - all fixes are backward compatible
- For multi-instance deployments, consider Redis for token replay protection
- For distributed deployments, consider API gateway for rate limiting

## [3.0.0] - Previous Release

### Added
- Initial public release of GitHub Actions Access Token Manager
- OIDC-based authentication
- Repository and owner-level access policies
- GitHub App integration
- Wildcard subject pattern matching

[Unreleased]: https://github.com/qoomon/actions--access-token/compare/v3.0.0...HEAD
