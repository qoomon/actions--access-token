# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 3.x     | :white_check_mark: |
| 2.x     | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

We take the security of the GitHub Actions Access Token Manager seriously. If you discover a security vulnerability, please follow these steps:

### How to Report

1. **DO NOT** create a public GitHub issue for security vulnerabilities
2. Email security details to the maintainers privately
3. Include the following information:
   - Description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact assessment
   - Suggested fix (if available)

### What to Expect

- **Acknowledgment**: Within 24 hours
- **Initial Assessment**: Within 72 hours  
- **Regular Updates**: Every 7 days until resolved
- **Resolution Timeline**: 30-90 days depending on complexity

### Security Vulnerability Types

We are particularly interested in vulnerabilities related to:

#### High Priority
- Authentication bypass
- Authorization escalation  
- Token leakage or exposure
- Code injection attacks
- Information disclosure
- Denial of Service attacks

#### Medium Priority
- Rate limiting bypass
- Policy enforcement bypass
- Container escape vulnerabilities
- Dependency vulnerabilities

#### Lower Priority
- General security hardening suggestions
- Documentation improvements
- Configuration recommendations

## Security Best Practices

### For Users

1. **Policy Configuration**
   - Follow the principle of least privilege
   - Regularly review and audit access policies
   - Use specific subject patterns rather than wildcards
   - Enable repository protection rules for policy files

2. **Deployment Security**
   - Use secure secret management systems
   - Deploy with proper network security
   - Enable comprehensive logging and monitoring
   - Keep dependencies updated

3. **Access Control**
   - Limit write access to `.github/access-token.yaml` files
   - Use GitHub's branch protection and rulesets
   - Monitor access policy changes
   - Implement approval workflows for policy modifications

### For Contributors

1. **Code Security**
   - Follow secure coding practices
   - Validate all inputs thoroughly
   - Use parameterized queries and safe APIs
   - Implement proper error handling

2. **Dependency Management**
   - Keep dependencies updated
   - Review dependency security advisories
   - Use `npm audit` and `dependabot`
   - Pin dependency versions

3. **Testing**
   - Include security tests in test suites
   - Test authentication and authorization flows
   - Verify input validation effectiveness
   - Test rate limiting and error handling

## Security Disclosure Timeline

### Responsible Disclosure Process

1. **Day 0**: Vulnerability reported privately
2. **Day 1**: Acknowledgment sent to reporter
3. **Day 3**: Initial assessment and triage
4. **Day 7**: Investigation begins
5. **Day 30**: Target for initial fix (if feasible)
6. **Day 90**: Maximum time for public disclosure

### Public Disclosure

After a security issue is resolved:
1. Security advisory published on GitHub
2. Release notes include security fix details
3. CVE assigned if applicable
4. Credit given to security researcher (if desired)

## Security Contacts

For security-related questions or concerns:
- Create a private security advisory on GitHub
- Follow the vulnerability reporting process above

## Security Architecture

This project implements multiple layers of security:

### Authentication Layer
- GitHub Actions OIDC token validation
- JWT signature verification with JWKS
- Subject claim pattern matching

### Authorization Layer  
- Multi-level policy enforcement (owner + repository)
- Permission scope validation
- Principle of least privilege

### Infrastructure Security
- Rate limiting and request throttling
- Request timeouts and size limits
- Comprehensive security logging
- Container security hardening

### Monitoring & Detection
- Security event logging
- Audit trail maintenance
- Anomaly detection capabilities
- Incident response procedures

## Known Security Considerations

### By Design Limitations

1. **Repository Existence Disclosure**
   - Error messages may leak repository existence to unauthorized users
   - Mitigated by using generic error messages for non-owners

2. **Rate Limiting Scope**
   - Current rate limiting is IP-based
   - Consider implementing subject-based rate limiting for additional protection

3. **Policy File Security**
   - Policy files are stored in repositories
   - Users must implement proper access controls

### Mitigation Strategies

- Regular security assessments and penetration testing
- Comprehensive logging and monitoring
- Principle of least privilege enforcement
- Defense in depth security architecture

## Security Updates

### Automatic Updates
- Dependabot configured for dependency updates
- Security patches prioritized and expedited
- Automated testing for security regressions

### Manual Review Required
- Major version updates
- New dependency additions
- Security-sensitive code changes
- Policy enforcement modifications

## Compliance

This project aims to comply with:
- OWASP Secure Coding Practices
- GitHub Security Best Practices
- Container Security Standards
- API Security Guidelines

## Security Training

Contributors should be familiar with:
- Secure coding practices
- OWASP Top 10 vulnerabilities
- GitHub security features
- Container security principles
- Incident response procedures

---

Last Updated: September 2024
Next Review: March 2025