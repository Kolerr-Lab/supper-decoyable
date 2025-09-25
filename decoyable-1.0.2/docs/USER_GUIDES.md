# DECOYABLE User Guides: End-to-End Examples

> **Real-world scenarios showing how to use DECOYABLE from setup to operation**

This guide provides **practical, end-to-end examples** of how different users can leverage DECOYABLE in cybersecurity operations. Each example includes complete workflows, commands, and expected outcomes.

---

## Table of Contents

- [Quick Start Overview](#quick-start-overview)
- [Example 1: Developer Onboarding & Code Security](#example-1-developer-onboarding--code-security)
- [Example 2: Security Team Daily Monitoring](#example-2-security-team-daily-monitoring)
- [Example 3: Incident Response Team](#example-3-incident-response-team)
- [Example 4: Enterprise Production Deployment](#example-4-enterprise-production-deployment)
- [Example 5: CI/CD Pipeline Integration](#example-5-cicd-pipeline-integration)
- [Common Patterns & Best Practices](#common-patterns--best-practices)
- [Troubleshooting](#troubleshooting)

---

## Quick Start Overview

### Prerequisites

- Python 3.8+
- Docker & Docker Compose (for full deployments)
- OpenAI API key (optional, falls back to pattern matching)

### Quick Setup Commands

**Unix/Linux/macOS:**

```bash
git clone https://github.com/Kolerr-Lab/supper-decoyable.git
cd supper-decoyable
./run_full_check.sh  # Complete dev environment setup
```

**Windows PowerShell:**

```powershell
git clone https://github.com/Kolerr-Lab/supper-decoyable.git
cd supper-decoyable
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest -q
```

---

## Example 1: Developer Onboarding & Code Security

### Scenario: Developer Onboarding

New developer joining the team wants to secure their codebase before deployment.

### End-to-End Workflow

#### 1. Initial Setup (5 minutes)

```bash
# Clone and setup environment
git clone https://github.com/Kolerr-Lab/supper-decoyable.git
cd supper-decoyable

# Quick development environment setup
./run_full_check.sh
# → Creates venv, installs deps, runs tests, starts dev server
```

#### 2. Scan Local Codebase (2 minutes)

```bash
# Run comprehensive security scan
python main.py scan all --path /path/to/my-app --output scan-results.json

# Check results
cat scan-results.json | jq '.summary'
# Output: {"secrets_found": 0, "vulnerabilities": 2, "sast_issues": 5}
```

#### 3. Fix Issues & Re-scan (10 minutes)

```bash
# Fix identified issues (e.g., remove hardcoded secrets, update vulnerable deps)
# Then re-scan to verify
python main.py scan all --path /path/to/my-app

# Success: All scans pass
```

#### 4. API Integration (Optional)

```bash
# Start DECOYABLE API for CI/CD integration
docker-compose up -d

# Test API endpoint
curl -X POST "http://localhost:8000/scan/secrets" \
  -H "Content-Type: application/json" \
  -d '{"path": "/path/to/my-app"}'
```

### Outcome

Developer has secure, scan-verified code ready for deployment.

---

## Example 2: Security Team Daily Monitoring

### Scenario: Security Team Monitoring

SOC analyst monitoring infrastructure for threats using DECOYABLE's active defense.

### End-to-End Workflow

#### 1. Morning Setup & Status Check (5 minutes)

```bash
# Connect to production DECOYABLE instance
ssh security@decoyable-prod

# Check system health
decoyable defense status
# Output: Honeypots active, LLM providers healthy, 0 blocked IPs

# Review overnight activity
decoyable defense logs --hours 12 --format table
```

#### 2. Monitor Real-time Activity (Throughout Day)

```bash
# Set up continuous monitoring dashboard
watch -n 60 'decoyable defense status && echo "--- Recent Attacks ---" && decoyable defense logs --limit 5'

# Check LLM analysis health
decoyable defense llm-status
# Output: OpenAI: ✅ (45ms avg), Anthropic: ✅ (52ms avg), Google: ✅ (38ms avg)
```

#### 3. Respond to Alerts (As Needed)

```bash
# When alert triggers, investigate
decoyable defense logs --limit 1 --format json | jq '.'

# If high-confidence attack, block IP
decoyable defense block-ip 192.168.1.100 --reason "Brute force SSH attack"

# Verify block
decoyable defense status | grep "blocked_ips"
```

#### 4. End-of-Day Reporting (5 minutes)

```bash
# Generate daily security report
decoyable defense logs --days 1 --format json > daily_report_$(date +%Y%m%d).json

# Send to management
curl -X POST https://soc-dashboard.company.com/api/reports \
  -H "Authorization: Bearer $SOC_API_KEY" \
  -F "file=@daily_report_$(date +%Y%m%d).json"
```

### Outcome

Continuous threat monitoring with automated response and daily reporting.

---

## Example 3: Incident Response Team

### Scenario: Incident Response

Security incident detected - unknown actor probing infrastructure.

### End-to-End Workflow

#### 1. Initial Assessment (2 minutes)

```bash
# Check recent attack patterns
decoyable defense logs --minutes 30 --format table

# Analyze attack characteristics
decoyable defense patterns | grep "attack_type"
# Output: brute_force: 45, sql_injection: 12, xss: 8
```

#### 2. Deep Investigation (5 minutes)

```bash
# Get detailed attack data
decoyable defense logs --ip 10.0.0.50 --format json > investigation_data.json

# Re-run LLM analysis on suspicious captures
for capture_id in $(jq -r '.[].id' investigation_data.json | head -3); do
  decoyable defense analyze "$capture_id"
done
```

#### 3. Containment Actions (3 minutes)

```bash
# Block attacking IP with evidence
decoyable defense block-ip 10.0.0.50 --reason "Coordinated attack pattern detected"

# Add temporary decoy to monitor for similar behavior
decoyable defense add-decoy /api/v2/admin --ttl 3600

# Notify SOC team
curl -X POST https://pagerduty.com/api/v2/incidents \
  -H "Authorization: Token token=$PAGERDUTY_TOKEN" \
  -d '{"incident": {"type": "incident", "title": "Active attack containment initiated"}}'
```

#### 4. Post-Incident Analysis (10 minutes)

```bash
# Export full incident data
decoyable defense logs --ip 10.0.0.50 --days 7 > incident_report.json

# Update threat intelligence
curl -X POST https://threatintel.company.com/api/indicators \
  -H "Authorization: Bearer $THREATINTEL_TOKEN" \
  -d @incident_report.json

# Review and improve detection rules
decoyable defense patterns > current_patterns.txt
# Analyze patterns and update rules as needed
```

### Outcome

Rapid incident containment with comprehensive documentation and intelligence sharing.

---

## Example 4: Enterprise Production Deployment

### Scenario: Enterprise Deployment

DevOps team deploying DECOYABLE across enterprise infrastructure.

### End-to-End Workflow

#### 1. Infrastructure Planning (15 minutes)

```bash
# Design deployment architecture
# - DECOYABLE API: Kubernetes service
# - Honeypots: Isolated network segment
# - Database: Managed PostgreSQL
# - Monitoring: Existing ELK stack integration

# Create deployment configuration
cat > production-config.env << EOF
API_AUTH_TOKEN=$(openssl rand -hex 32)
ADMIN_ROLE=enabled
SECURITY_TEAM_ENDPOINT=https://soc.company.com/api/alerts
DATABASE_URL=postgresql://decoyable:password@db.company.com/decoyable
REDIS_URL=redis://redis.company.com:6379
EOF
```

#### 2. Containerized Deployment (10 minutes)

```bash
# Build production images
docker build -t company/decoyable:latest -f docker/Dockerfile.prod .
docker build -t company/decoyable-honeypot:latest -f docker/honeypot.Dockerfile .

# Deploy to Kubernetes
kubectl apply -f k8s/decoyable-deployment.yaml
kubectl apply -f k8s/decoyable-honeypot.yaml
kubectl apply -f k8s/decoyable-network-policy.yaml

# Verify deployment
kubectl get pods -l app=decoyable
kubectl logs -l app=decoyable --tail=20
```

#### 3. Integration Setup (10 minutes)

```bash
# Configure SIEM integration
curl -X POST "https://splunk.company.com/api/services/collector" \
  -H "Authorization: Splunk $SPLUNK_TOKEN" \
  -d '{"event": "DECOYABLE integration active", "source": "decoyable"}'

# Setup alerting webhooks
decoyable defense configure-webhook \
  --url https://slack.company.com/api/webhooks \
  --events "high_confidence_block,llm_failure"

# Test integrations
curl -X POST "http://decoyable.company.com/test-integration"
```

#### 4. Operational Handover (5 minutes)

```bash
# Create runbooks for security team
cat > runbook.md << EOF
# DECOYABLE Operations Runbook

## Daily Checks
- decoyable defense status
- decoyable defense logs --hours 24

## Emergency Response
- decoyable defense block-ip <ip> --reason "Emergency block"
- decoyable defense unban-ip <ip> --reason "False positive"

## Maintenance
- Weekly: Review blocked IPs for cleanup
- Monthly: Update LLM provider configurations
EOF

# Hand over to security operations team
```

### Outcome

Enterprise-grade deployment with full monitoring, alerting, and operational procedures.

---

## Example 5: CI/CD Pipeline Integration

### Scenario: CI/CD Integration

Development team integrating DECOYABLE security scans into automated pipelines.

### End-to-End Workflow

#### 1. Pipeline Configuration (10 minutes)

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup DECOYABLE
        run: |
          pip install decoyable

      - name: Run Security Scans
        run: |
          decoyable scan secrets --path . --output secrets.json
          decoyable scan deps --path . --output deps.json
          decoyable scan sast --path . --output sast.json

      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: security-scan-results
          path: |
            secrets.json
            deps.json
            sast.json
```

#### 2. Quality Gate Implementation (5 minutes)

```yaml
# Add quality gate
      - name: Security Quality Gate
        run: |
          # Fail pipeline if critical issues found
          if jq '.summary.critical > 0' secrets.json; then
            echo "🚨 Critical secrets found! Failing pipeline."
            exit 1
          fi

          if jq '.summary.high > 5' deps.json; then
            echo "🚨 Too many high-severity vulnerabilities! Failing pipeline."
            exit 1
          fi
```

#### 3. Results Integration (5 minutes)

```yaml
      - name: Comment PR with Results
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const secrets = JSON.parse(fs.readFileSync('secrets.json', 'utf8'));
            const deps = JSON.parse(fs.readFileSync('deps.json', 'utf8'));

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## 🔒 Security Scan Results

            **Secrets Found**: ${secrets.summary.total}
            **Dependencies Issues**: ${deps.summary.total}

            [View full results](${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }})`
            });
```

#### 4. Dashboard Integration (Optional)

```bash
# Send results to security dashboard
curl -X POST "https://security-dashboard.company.com/api/scan-results" \
  -H "Authorization: Bearer $DASHBOARD_TOKEN" \
  -d @secrets.json \
  -d @deps.json \
  -d @sast.json
```

### Outcome

Automated security scanning integrated into development workflow with quality gates and reporting.

---

## Common Patterns & Best Practices

### Setup Pattern

```bash
# Always start with environment check
./run_full_check.sh  # Development
# or
docker-compose up -d  # Production
```

### Monitoring Pattern

```bash
# Regular health checks
decoyable defense status
decoyable defense llm-status

# Log review
decoyable defense logs --hours 24
```

### Response Pattern

```bash
# Investigation
decoyable defense logs --ip <suspicious_ip> --format json

# Containment
decoyable defense block-ip <ip> --reason "Description"

# Analysis
decoyable defense analyze <capture_id>
```

### Reporting Pattern

```bash
# Export data
decoyable defense logs --days 7 --format json > weekly_report.json

# Send to integrations
curl -X POST $WEBHOOK_URL -d @weekly_report.json
```

### Key Takeaways

1. **Start Simple**: Use `run_full_check.sh` for development, Docker for production
2. **Monitor Continuously**: Regular status checks prevent issues
3. **Automate Where Possible**: Integrate into CI/CD for consistent security
4. **Plan for Scale**: Design integrations early (SIEM, dashboards, alerting)
5. **Document Procedures**: Create runbooks for your team's specific needs
6. **Test Safely**: Always test new configurations in staging environments first

---

## Troubleshooting

### Common Issues

#### API Authentication Errors

```bash
# Check if API_AUTH_TOKEN is set
echo $API_AUTH_TOKEN

# Verify token format
python -c "import base64; print('Valid' if len('$API_AUTH_TOKEN') >= 32 else 'Too short')"
```

#### Docker Deployment Issues

```bash
# Check container status
docker-compose ps

# View logs
docker-compose logs -f api

# Restart services
docker-compose restart
```

#### LLM Provider Failures

```bash
# Check provider status
decoyable defense llm-status

# Test specific provider
curl -X POST "http://localhost:8000/analysis/test-provider" \
  -H "Content-Type: application/json" \
  -d '{"provider": "openai"}'
```

#### High False Positive Rate

```bash
# Review recent blocks
decoyable defense logs --blocked-only --days 7

# Adjust confidence thresholds (requires admin access)
decoyable defense configure-thresholds --brute_force 0.8 --sql_injection 0.9
```

### Getting Help

- **Documentation**: Check `README.md`, `SECURITY.md`, and this guide
- **Logs**: Use `decoyable defense logs` for troubleshooting
- **Community**: Open issues on GitHub for bugs or feature requests
- **Security Issues**: Use encrypted reporting as described in `SECURITY.md`

---

## Next Steps

1. **Try the Examples**: Start with Example 1 for a quick win
2. **Customize**: Adapt the examples to your specific environment
3. **Integrate**: Connect DECOYABLE to your existing security tools
4. **Scale**: Move from development to production deployments
5. **Contribute**: Share your use cases and improvements with the community

**DECOYABLE adapts to your workflow - from individual developer security checks to enterprise-scale active defense operations!** 🛡️🤖

---

*This guide is maintained alongside DECOYABLE. Check for updates and additional examples as the platform evolves.*
