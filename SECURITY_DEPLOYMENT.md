# Security Configuration Guide
## GitHub Actions Access Token Manager

This document provides security configuration recommendations for deploying the GitHub Actions Access Token Manager in production environments.

## Environment Variables Security

### Required Variables
```bash
# GitHub App Configuration
GITHUB_APP_ID="123456"                          # GitHub App ID
GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA..."     # GitHub App Private Key (PEM format)

# OIDC Token Verification
GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE="https://your-server.com"
GITHUB_ACTIONS_TOKEN_ALLOWED_SUBJECTS="repo:org/*:*,repo:trusted-org/*:*"

# Optional Security Configuration
LOG_LEVEL="info"                                # Use 'warn' or 'error' in production
PORT="3000"                                     # Server port
REQUEST_ID_HEADER="X-Request-ID"               # Custom request ID header
```

### Secret Management Best Practices

1. **Use Secret Management Services**
   ```bash
   # AWS Secrets Manager
   aws secretsmanager get-secret-value --secret-id github-app-private-key
   
   # Azure Key Vault
   az keyvault secret show --vault-name MyKeyVault --name github-app-key
   
   # Google Secret Manager
   gcloud secrets versions access latest --secret="github-app-private-key"
   ```

2. **Kubernetes Secrets**
   ```yaml
   apiVersion: v1
   kind: Secret
   metadata:
     name: github-app-secrets
   type: Opaque
   data:
     app-id: <base64-encoded-app-id>
     private-key: <base64-encoded-private-key>
   ```

3. **Docker Secrets**
   ```bash
   # Create secrets
   echo "your-private-key" | docker secret create github_app_private_key -
   
   # Use in Docker Compose
   docker service create \
     --secret github_app_private_key \
     --env GITHUB_APP_PRIVATE_KEY_FILE=/run/secrets/github_app_private_key \
     your-image
   ```

## Rate Limiting Configuration

The server includes built-in rate limiting with the following defaults:
- **Window**: 15 minutes
- **Max Requests**: 100 per client
- **Key**: Client IP address

### Custom Rate Limiting
```typescript
// Modify rate limiting in production
app.use('/access_tokens', rateLimiter({
  windowMs: 5 * 60 * 1000,  // 5 minutes (more restrictive)
  max: 50,                   // 50 requests per window
  message: 'Rate limit exceeded. Please try again later.',
  keyGenerator: (context) => {
    // Use custom key generation (e.g., based on OIDC subject)
    return context.req.header('authorization') || 'unknown';
  }
}));
```

### External Rate Limiting
For production deployments, consider using external rate limiting:

1. **Nginx Rate Limiting**
   ```nginx
   http {
     limit_req_zone $binary_remote_addr zone=api:10m rate=1r/s;
     
     server {
       location /access_tokens {
         limit_req zone=api burst=5 nodelay;
         proxy_pass http://backend;
       }
     }
   }
   ```

2. **Cloudflare Rate Limiting**
   ```javascript
   // Cloudflare Workers
   const RATE_LIMIT = 100; // requests per minute
   const rateLimiter = new Map();
   ```

## Network Security

### TLS Configuration
```nginx
server {
  listen 443 ssl http2;
  ssl_certificate /path/to/cert.pem;
  ssl_certificate_key /path/to/key.pem;
  
  # Security headers
  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header X-Frame-Options "DENY" always;
  add_header X-XSS-Protection "1; mode=block" always;
  
  location / {
    proxy_pass http://localhost:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
```

### Firewall Rules
```bash
# Allow only necessary ports
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # HTTP (redirect to HTTPS)
ufw allow 443/tcp   # HTTPS
ufw default deny incoming
ufw default allow outgoing
```

## Container Security

### Production Dockerfile Hardening
```dockerfile
# Use specific version tags
FROM gcr.io/distroless/nodejs20-debian12:latest@sha256:specific-hash

# Create non-root user
USER 1000:1000

# Set security options
LABEL security.non-root=true
LABEL security.readonly-rootfs=true

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1
```

### Docker Compose Security
```yaml
version: '3.8'
services:
  app:
    image: github-access-token-server:latest
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
    user: "1000:1000"
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
```

### Kubernetes Security
```yaml
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: app
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
```

## Monitoring and Alerting

### Security Event Monitoring
```typescript
// Custom security monitoring
const securityLogger = new SecurityLogger(logger);

// Monitor for suspicious patterns
const suspiciousActivityPatterns = [
  /multiple.*failed.*attempts/i,
  /rate.*limit.*exceeded/i,
  /unauthorized.*access/i,
];

// Alert on security events
securityLogger.on('security-event', (event) => {
  if (event.event === SecurityEventType.SUSPICIOUS_ACTIVITY) {
    // Send alert to monitoring system
    alertingService.send({
      severity: 'HIGH',
      message: `Suspicious activity detected: ${event.reason}`,
      metadata: event.metadata,
    });
  }
});
```

### Metrics Collection
```yaml
# Prometheus configuration
- job_name: 'github-access-token'
  static_configs:
    - targets: ['localhost:3000']
  metrics_path: '/metrics'
  scrape_interval: 30s
```

### Log Aggregation
```yaml
# ELK Stack configuration
input {
  file {
    path => "/var/log/github-access-token/*.log"
    type => "github-access-token"
  }
}

filter {
  if [type] == "github-access-token" {
    json {
      source => "message"
    }
    
    if [component] == "security" {
      mutate {
        add_tag => ["security-event"]
      }
    }
  }
}
```

## Access Policy Security

### Policy File Protection
```yaml
# Repository ruleset configuration
name: "Protect Access Token Policies"
enforcement: active
target: push
bypass_actors:
  - actor_type: RepositoryRole
    actor_id: admin
rules:
  - type: file_path_restriction
    parameters:
      restricted_file_paths:
        - ".github/access-token.yaml"
        - ".github/access-token.yml"
```

### Policy Validation
```yaml
# GitHub Actions workflow for policy validation
name: Validate Access Policies
on:
  pull_request:
    paths:
      - '.github/access-token.yaml'
      - '.github/access-token.yml'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Validate policy syntax
        run: |
          if [ -f .github/access-token.yaml ]; then
            yamllint .github/access-token.yaml
          fi
```

## Compliance and Auditing

### Audit Log Format
```json
{
  "timestamp": "2024-09-02T12:00:00Z",
  "event": "auth_success",
  "subject": "repo:org/repo:ref:refs/heads/main",
  "repository": "org/repo",
  "permissions": {"contents": "read"},
  "client_ip": "192.168.1.100",
  "user_agent": "actions/runner",
  "request_id": "req-123456"
}
```

### Compliance Checklist
- [ ] All access is logged and auditable
- [ ] Sensitive data is properly redacted in logs
- [ ] Rate limiting prevents abuse
- [ ] Authentication failures are monitored
- [ ] Policy changes are tracked
- [ ] Container security best practices followed
- [ ] Network security implemented
- [ ] Secrets properly managed
- [ ] Incident response plan in place

## Incident Response

### Security Incident Playbook
1. **Detection**: Monitor security logs for anomalies
2. **Assessment**: Determine impact and scope
3. **Containment**: Disable compromised tokens/apps
4. **Eradication**: Remove threats and vulnerabilities
5. **Recovery**: Restore normal operations
6. **Lessons Learned**: Update security measures

### Emergency Procedures
```bash
# Disable GitHub App (emergency)
curl -X PATCH \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.v3+json" \
  https://api.github.com/app/installations/$INSTALLATION_ID \
  -d '{"suspended_by":"security-incident"}'

# Revoke all tokens (if supported by implementation)
curl -X POST https://your-server.com/admin/revoke-all-tokens \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

## Deployment Checklist

### Pre-deployment
- [ ] Security scan completed
- [ ] Vulnerability assessment performed
- [ ] Secrets properly configured
- [ ] Rate limiting configured
- [ ] Monitoring setup
- [ ] Backup procedures in place

### Post-deployment
- [ ] Health checks passing
- [ ] Security monitoring active
- [ ] Log aggregation working
- [ ] Rate limiting functional
- [ ] Authentication working
- [ ] Incident response tested

---

This security configuration guide should be regularly updated as new threats emerge and security best practices evolve.