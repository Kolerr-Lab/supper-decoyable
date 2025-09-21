# Security Policy

## Supported Versions

We actively support the following versions with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in DECOYABLE, please report it to us as follows:

### Contact Information

- **Email**: `security@decoyable.dev`
- **PGP Key**: [Download our PGP public key](https://decoyable.dev/pgp-key.asc)
- **Response Time**: We will acknowledge your report within 48 hours and provide a more detailed response within 7 days indicating our next steps.

### What to Include

Please include the following information in your report:

- A clear description of the vulnerability
- Steps to reproduce the issue
- Potential impact and severity
- Any suggested fixes or mitigations

### Our Process

1. **Acknowledgment**: We'll acknowledge receipt of your report within 48 hours
2. **Investigation**: We'll investigate the issue and determine its validity and severity
3. **Updates**: We'll provide regular updates on our progress (at least weekly)
4. **Fix**: We'll develop and test a fix for the vulnerability
5. **Disclosure**: We'll coordinate disclosure with you based on your preferences

### Guidelines

- Please do not publicly disclose the vulnerability until we've had a chance to fix it
- We follow responsible disclosure practices
- We credit researchers for valid security findings
- We do not offer monetary rewards at this time

## Security Best Practices

When using DECOYABLE, follow these security best practices:

### Deployment

- Run DECOYABLE in a containerized environment
- Use Docker secrets for sensitive configuration
- Enable HTTPS/TLS for API endpoints
- Regularly update dependencies and base images

### Configuration

- Use strong, randomly generated secrets
- Limit network exposure of services
- Implement proper access controls
- Enable audit logging

### Monitoring

- Monitor for unusual scanning patterns
- Set up alerts for security events
- Regularly review access logs
- Keep security tools updated

## Security Features

DECOYABLE includes several built-in security features:

- **Input Validation**: All inputs are validated using Pydantic models
- **HTTPS Support**: Built-in SSL/TLS certificate support
- **Docker Secrets**: Secure credential management
- **Network Segmentation**: Isolated network configurations
- **Security Scanning**: Integrated vulnerability detection
- **Audit Logging**: Comprehensive logging of all operations

## Known Security Considerations

- DECOYABLE requires privileged access to scan systems effectively
- Containerized deployments should use read-only filesystems where possible
- Network scanning capabilities may trigger security monitoring systems
- Results may contain sensitive information that should be handled appropriately

## Contact

For security-related questions or concerns:

- Email: `security@decoyable.dev`
- General inquiries: `support@decoyable.dev`
