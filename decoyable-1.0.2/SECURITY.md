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

- **Email**: `ricky@kolerr.com`
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

- Email: `ricky@kolerr.com`
- General inquiries: `lab.kolerr@kolerr.com`

## RBAC and API Authentication

### API Authentication Tokens

Administrative actions in DECOYABLE require proper authentication:

```bash
# Set environment variable for API authentication
export API_AUTH_TOKEN="your-secure-token-here"

# Or in .env file
API_AUTH_TOKEN=your-secure-token-here
```

### Role-Based Access Control (RBAC)

DECOYABLE implements the following access levels:

- **Read-Only**: View status, logs, and patterns (no authentication required for basic monitoring)
- **Operator**: Run scans and view detailed analysis (API_AUTH_TOKEN required)
- **Administrator**: Execute defense actions like IP blocking, decoy management (API_AUTH_TOKEN + ADMIN_ROLE required)

### Setting Up Authentication

1. **Generate a secure token**:
   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

2. **Configure in environment**:
   ```bash
   export API_AUTH_TOKEN="generated-token-here"
   export ADMIN_ROLE="enabled"  # For admin operations
   ```

3. **Test authentication**:
   ```bash
   curl -H "Authorization: Bearer $API_AUTH_TOKEN" http://localhost:8000/admin/status
   ```

## Encrypted Vulnerability Reporting

### PGP Key Setup

For sensitive vulnerability reports, we support PGP-encrypted communications:

#### Downloading Our Public Key

```bash
# Download from our website
curl -O https://decoyable.dev/pgp-key.asc

# Verify fingerprint (contact us to confirm)
gpg --show-keys pgp-key.asc
```

#### Encrypting Your Report

```bash
# Import our public key
gpg --import pgp-key.asc

# Encrypt your message
echo "Your vulnerability details here" | gpg --encrypt --armor -r "ricky@kolerr.com" > encrypted_report.asc

# Send the encrypted file via email
# The file encrypted_report.asc can be safely sent through any channel
```

#### Verifying Our Responses

We'll sign our responses with our private key. To verify:

```bash
# Import our public key if not already done
gpg --import pgp-key.asc

# Verify signed message
gpg --verify signed_response.asc
```

## Admin Guidance for Active Defense Commands

### Safety Precautions

**⚠️ CRITICAL**: Active defense commands can modify system firewall rules and network configurations. Always test in isolated environments first.

#### Pre-Execution Checklist

- [ ] **Environment Check**: Are you in a test/isolated environment?
- [ ] **Backup**: Have you backed up current iptables rules?
- [ ] **Monitoring**: Is logging enabled and monitored?
- [ ] **Rollback Plan**: Do you know how to unblock IPs if needed?
- [ ] **Authorization**: Do you have explicit permission to modify network rules?

#### Backup Current Rules

```bash
# Save current iptables rules
sudo iptables-save > iptables-backup-$(date +%Y%m%d-%H%M%S).rules

# Save current ipset sets (if using)
sudo ipset save > ipset-backup-$(date +%Y%m%d-%H%M%S).rules
```

### Command Execution Guidelines

#### IP Blocking Operations

```bash
# Check current blocks before adding new ones
decoyable defense status

# Block a single IP (temporary - lasts until restart)
decoyable defense block-ip 192.168.1.100

# Block with custom timeout (in seconds)
decoyable defense block-ip 192.168.1.100 --timeout 3600

# Verify the block
sudo iptables -L -n | grep 192.168.1.100

# Emergency unblock (if needed)
sudo iptables -D INPUT -s 192.168.1.100 -j DROP
```

#### Decoy Management

```bash
# List current decoys
decoyable defense list-decoys

# Add a new decoy endpoint
decoyable defense add-decoy /api/v1/admin

# Remove a decoy (if supported)
decoyable defense remove-decoy /api/v1/admin

# Test decoy response
curl http://localhost:8080/api/v1/admin
```

#### Monitoring and Maintenance

```bash
# Continuous monitoring (run in background)
watch -n 30 'decoyable defense status'

# Export logs for analysis
decoyable defense logs --format json --days 7 > defense_logs.json

# Check LLM provider status
decoyable defense llm-status

# Re-analyze a specific capture
decoyable defense analyze capture-123
```

### Emergency Procedures

#### If You Accidentally Block Yourself

```bash
# From another machine with access:
ssh user@unblocked-server
sudo iptables -D INPUT -s YOUR_IP -j DROP

# Or if you have console access:
# Edit iptables rules directly or reboot to clear
```

#### System Recovery

```bash
# Restore iptables rules from backup
sudo iptables-restore < iptables-backup-20231201-120000.rules

# Clear all DECOYABLE blocks (CAUTION: removes all blocks)
sudo iptables -F DECOYABLE_BLOCKS 2>/dev/null || true
sudo ipset destroy decoyable_blocked_ips 2>/dev/null || true
```

### Best Practices for Production

1. **Gradual Rollout**: Start with monitoring-only mode, then enable blocking
2. **Alert Integration**: Connect to your SIEM/SOC for human oversight
3. **Regular Audits**: Review blocked IPs and decoy effectiveness weekly
4. **Update Management**: Keep DECOYABLE updated for latest defense patterns
5. **Documentation**: Maintain records of all defense actions and their rationale

### Troubleshooting Common Issues

#### Command Fails with Authentication Error

```bash
# Check if API_AUTH_TOKEN is set
echo $API_AUTH_TOKEN

# Verify token format (should be URL-safe)
python -c "import base64; print('Valid' if len('$API_AUTH_TOKEN') >= 32 else 'Too short')"
```

#### IP Blocking Not Working

```bash
# Check if iptables service is running
sudo systemctl status iptables

# Verify DECOYABLE has necessary permissions
sudo -u decoyable-user decoyable defense block-ip 192.168.1.100

# Check kernel modules
lsmod | grep ip_tables
```

#### Decoy Services Not Responding

```bash
# Check Docker container status
docker-compose ps

# View decoy service logs
docker-compose logs decoy_http

# Test decoy endpoint directly
curl -v http://localhost:8080/decoy/test
```

---

**Remember**: Active defense is powerful but requires careful operation. When in doubt, consult with your security team or run in monitoring-only mode first.
