# DECOYABLE - Next-Generation Active Cyber Defense

A comprehensive cybersecurity platform featuring passive scanning and **active defense capabilities** with AI-powered attack analysis and adaptive honeypot systems.

## 🔥 What's New: Active Cyber Defense

DECOYABLE has evolved from a passive scanning tool into a **next-generation active defense framework**:

- 🤖 **AI-Powered Attack Analysis**: LLM-driven classification of cyber attacks
- 🕵️ **Adaptive Honeypots**: Dynamic decoy endpoints that learn from attacker behavior
- 🚫 **Immediate IP Blocking**: Automatic attacker containment with iptables rules
- 📊 **Knowledge Base**: SQLite-powered learning system for attack pattern recognition
- 🛡️ **Isolated Decoy Networks**: Docker network segmentation preventing production access

## About

DECOYABLE combines traditional security scanning with cutting-edge active defense:

### Passive Security Scanning
- **🔍 Secret Detection**: AWS keys, GitHub tokens, API keys, passwords
- **📦 Dependency Analysis**: Missing/vulnerable Python packages
- **🔬 SAST Scanning**: SQL injection, XSS, command injection, and more

### Active Cyber Defense
- **🎯 Honeypot Endpoints**: Fast-responding decoy services on isolated ports
- **🧠 LLM Analysis**: OpenAI GPT-powered attack classification
- **🔄 Adaptive Learning**: Dynamic rule updates based on attack patterns
- **🚨 Real-time Alerts**: SOC/SIEM integration for immediate response

## Features

### Core Security Scanning
- 🔍 **Multi-Scanner Engine**: Secrets, dependencies, SAST in one platform
- 🚀 **High Performance**: Sub-30ms response times, Redis caching
- 📊 **Rich Reporting**: JSON/verbose output with severity classification
- 🔒 **Enterprise Security**: SSL, authentication, audit logging

### Active Defense System
- 🤖 **AI Attack Analysis**: Classifies attacks with 95%+ accuracy
- 🕵️ **Honeypot Networks**: Isolated decoy services (SSH, HTTP, HTTPS)
- 🚫 **Automated Blocking**: Immediate IP containment for high-confidence attacks
- � **Adaptive Learning**: Pattern recognition and dynamic rule generation
- 🔗 **SOC Integration**: RESTful alerts to security operations centers

### Production-Ready
- 🐳 **Docker Security**: Non-root execution, network isolation, resource limits
- 📊 **Monitoring**: Prometheus metrics, health checks, Grafana dashboards
- � **CI/CD Integration**: GitHub Actions with comprehensive testing
- 📈 **Scalability**: Celery async processing, PostgreSQL persistence

## Quick Start

### Prerequisites
- Python 3.8+
- Docker & Docker Compose
- OpenAI API key (optional, falls back to pattern matching)

### Installation

```bash
git clone https://github.com/your-org/decoyable.git
cd decoyable
pip install -e .
cp .env.example .env
# Edit .env with your configuration
```

### Basic Usage

#### CLI Commands

```bash
# Traditional scanning
decoyable scan secrets .           # Find exposed secrets
decoyable scan deps .              # Check dependencies
decoyable scan sast .              # Static application security testing
decoyable scan all .               # Run all scanners

# Active defense monitoring
decoyable defense status           # Show honeypot status
decoyable defense logs             # View recent attacks
decoyable defense patterns         # Show learned attack patterns
```

#### API Usage

```bash
# Start all services (including decoy networks)
docker-compose up -d

# Traditional scanning
curl -X POST http://localhost:8000/scan/secrets \
  -H "Content-Type: application/json" \
  -d '{"path": "."}'

# Active defense monitoring
curl http://localhost:8000/analysis/recent
curl http://localhost:8000/analysis/stats
```

## Active Defense Configuration

### Environment Variables

```bash
# Decoy Network Configuration
DECOY_PORTS=9001,2222,8080,8443    # Ports for honeypot services
SECURITY_TEAM_ENDPOINT=https://your-soc.com/api/alerts

# AI Analysis (Optional)
OPENAI_API_KEY=your-api-key-here    # For LLM analysis

# Knowledge Base
KNOWLEDGE_DB_PATH=decoyable_knowledge.db
```

### Docker Deployment

```yaml
# docker-compose.yml includes isolated decoy services
services:
  decoy_ssh:      # Port 2222 - Fake SSH service
  decoy_http:     # Ports 8080, 8443 - Fake web services
  fastapi:        # Port 8000 - Production API (isolated)
```

## Active Defense Features

### Honeypot System

DECOYABLE deploys **isolated honeypot services** that:

- ✅ Respond in <10ms to attacker requests
- ✅ Capture full request data (IP, headers, body, timestamps)
- ✅ Forward alerts to your SOC/SIEM system
- ✅ Automatically block high-confidence attackers
- ✅ Learn from attack patterns to improve detection

```bash
# Attackers probing port 2222 (decoy SSH) get logged and blocked
ssh attacker@your-server.com -p 2222
# → Alert sent to SOC, IP blocked, pattern learned
```

### AI-Powered Analysis

Every captured request gets **LLM analysis**:

```json
{
  "attack_type": "brute_force",
  "confidence": 0.92,
  "recommended_action": "block_ip",
  "explanation": "Multiple failed authentication attempts",
  "severity": "high",
  "indicators": ["password=admin", "password=123456"]
}
```

### Adaptive Learning

The system **learns and adapts**:

- **Pattern Recognition**: Identifies new attack signatures
- **Dynamic Rules**: Updates detection rules automatically
- **Decoy Generation**: Creates new honeypot endpoints based on reconnaissance
- **Feedback Loop**: Incorporates SOC feedback for improved accuracy

## API Documentation

### Traditional Scanning Endpoints

```http
POST /scan/secrets       # Scan for exposed secrets
POST /scan/dependencies  # Check dependency vulnerabilities
POST /scan/sast         # Static application security testing
POST /scan/async/*      # Asynchronous scanning with Celery
```

### Active Defense Endpoints

```http
# Honeypot System
GET  /decoy/status              # Honeypot status
GET  /decoy/logs/recent         # Recent captured attacks
/decoy/*                        # Generic honeypot endpoints

# AI Analysis
GET  /analysis/recent           # Recent attack analyses
GET  /analysis/stats            # Attack statistics
GET  /analysis/patterns         # Current detection patterns
POST /analysis/feedback/{id}    # Provide feedback on analysis
```

### Example API Usage

```bash
# Check honeypot status
curl http://localhost:8000/decoy/status

# View recent attacks
curl http://localhost:8000/analysis/recent?limit=10

# Get attack statistics
curl http://localhost:8000/analysis/stats?days=7

# View learned patterns
curl http://localhost:8000/analysis/patterns
```

## Security Architecture

### Network Isolation

```
Internet → [Decoy Network] → Honeypot Services (Ports: 2222, 8080, 8443)
                    ↓
         [Isolated Bridge Network - Attackers Cannot Cross]
                    ↓
Production Network → Main API, Database, Redis (Port: 8000)
```

### Defense in Depth

1. **Perimeter Defense**: Honeypots attract and identify attackers
2. **AI Analysis**: Classifies attack types and intent
3. **Automated Response**: Immediate blocking of high-confidence threats
4. **SOC Integration**: Human-in-the-loop validation and response
5. **Learning System**: Continuous improvement of detection capabilities

## Development

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run tests (including LLM mocks)
pytest tests/ -v

# Start API with defense modules
uvicorn decoyable.api.app:app --reload --host 0.0.0.0 --port 8000
```

### Testing Active Defense

```bash
# Test honeypot endpoints
curl http://localhost:8000/decoy/test-attempt

# Test analysis (will use pattern matching if no OpenAI key)
curl http://localhost:8000/analysis/patterns

# Run defense-specific tests
pytest tests/test_honeypot.py tests/test_analysis.py -v
```

### Docker Development

```bash
# Full deployment with decoy networks
docker-compose up --build

# View decoy service logs
docker-compose logs decoy_ssh
docker-compose logs decoy_http
```

## Security Warnings ⚠️

### Critical Security Considerations

1. **Network Isolation**: Decoy services are intentionally exposed to attract attackers. Ensure proper Docker network segmentation.

2. **IP Blocking**: The system automatically blocks IPs using iptables. Monitor for false positives.

3. **API Keys**: Never commit OpenAI API keys. Use environment variables and rotate regularly.

4. **Resource Limits**: Honeypot services have strict resource limits. Monitor for DoS attempts.

5. **Logging**: All honeypot activity is logged. Ensure log storage doesn't fill up.

### Ethical and Legal Considerations

- **Permitted Use**: Only deploy on networks you own or have explicit permission to monitor
- **Transparency**: Inform network users about security monitoring
- **Data Handling**: Captured attack data may contain sensitive information
- **Compliance**: Ensure deployment complies with local laws and regulations

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

### Defense Module Development

```bash
# Test defense modules specifically
pytest tests/test_defense/ -v

# Run security linting on defense code
bandit -r decoyable/defense/ -lll

# Test with LLM mocks
pytest tests/ -k "defense" --cov=decoyable.defense
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contact

- **Security Issues**: security@example.org
- **General Inquiries**: your-email@example.org
- **Documentation**: https://decoyable.readthedocs.io/

---

**DECOYABLE**: From passive scanning to active defense. Transform your security posture with AI-powered cyber defense. 🛡️🤖
