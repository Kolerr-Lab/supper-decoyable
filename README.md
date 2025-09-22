# DECOYABLE - Next-Generation Active Cyber Defense
- 📊 **Scalability**: Celery async processing, PostgreSQL persistence

## IDE Integration

### VS Code Extension

DECOYABLE now includes a **comprehensive VS Code extension** that brings security scanning and AI-powered fixes directly into your development environment:

#### 🚀 Key Features
- **Real-time Security Scanning**: Auto-scan files on save/open with live feedback
- **AI-Powered Fixes**: Intelligent remediation using DECOYABLE's multi-provider LLM router
- **Multi-Modal Analysis**: Secrets, dependencies, SAST, and code quality scanning
- **Native IDE Integration**: Commands, tree views, diagnostics, and code actions
- **Enterprise-Ready**: Professional UI with comprehensive settings and safety features

#### 📦 Installation
```bash
# Install from packaged extension (recommended)
code --install-extension vscode-extension/decoyable-security-1.0.0.vsix

# Or install from source for development
code vscode-extension/
```

#### 🛠️ Usage
- **Scan Current File**: `Ctrl+Shift+S`
- **Scan Workspace**: `DECOYABLE: Scan Workspace` command
- **Fix All Issues**: `Ctrl+Shift+F`
- **View Results**: Security Issues panel in Explorer

#### ⚙️ Configuration
Access settings through `Preferences: Open Settings (UI)`:
```json
{
  "decoyable.pythonPath": "python",
  "decoyable.scanOnSave": true,
  "decoyable.scanOnOpen": false,
  "decoyable.autoFix": false,
  "decoyable.showNotifications": true
}
```

**Learn more**: See `vscode-extension/INSTALLATION.md` for comprehensive setup and usage instructions.

## Quick Start comprehensive cybersecurity platform featuring passive scanning and **active defense capabilities** with AI-powered attack analysis and adaptive honeypot systems.

## 🔥 What's New: Active Cyber Defense

DECOYABLE has evolved from a passive scanning tool into a **next-generation active defense framework**:

- 🤖 **AI-Powered Attack Analysis**: Multi-provider LLM classification with smart failover
- 🕵️ **Adaptive Honeypots**: Dynamic decoy endpoints that learn from attacker behavior
- 🔒 **Zero-Trust Architecture**: Containerized security with comprehensive CI/CD pipeline
- 🚫 **Immediate IP Blocking**: Automatic attacker containment with iptables rules
- 📊 **Knowledge Base**: SQLite-powered learning system for attack pattern recognition
- 🛡️ **Isolated Decoy Networks**: Docker network segmentation preventing production access
- 🛠️ **VS Code Extension**: Real-time security scanning and AI-powered fixes directly in your IDE

## About

DECOYABLE combines traditional security scanning with cutting-edge active defense:

### Passive Security Scanning
- **🔍 Secret Detection**: AWS keys, GitHub tokens, API keys, passwords
- **📦 Dependency Analysis**: Missing/vulnerable Python packages
- **🔬 SAST Scanning**: SQL injection, XSS, command injection, and more

### Active Cyber Defense
- **🎯 Honeypot Endpoints**: Fast-responding decoy services on isolated ports
- **🧠 Multi-Provider LLM Analysis**: OpenAI GPT, Anthropic Claude, Google Gemini with automatic failover
- **🔄 Smart Routing Engine**: Priority-based routing with health checks and circuit breakers
- **📈 Performance Monitoring**: Real-time metrics and provider status tracking
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
- 🚀 **Kafka Streaming**: Optional high-volume event processing with horizontal scaling
- 🔧 **CI/CD Integration**: GitHub Actions with comprehensive testing
- 📈 **Scalability**: Celery async processing, PostgreSQL persistence

## Quick Start

### Option 1: VS Code Extension (Recommended for Development)

For the best development experience, use the **DECOYABLE VS Code Extension**:

1. **Install the extension**:
   ```bash
   code --install-extension vscode-extension/decoyable-security-1.0.0.vsix
   ```

2. **Open your project** in VS Code - security scanning happens automatically!

3. **Manual scanning**: `Ctrl+Shift+S` (current file) or `DECOYABLE: Scan Workspace`

4. **Fix issues**: `Ctrl+Shift+F` for AI-powered remediation

**See `vscode-extension/INSTALLATION.md` for detailed setup instructions.**

### Option 2: CLI Installation

For traditional CLI usage or server deployment:

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
OPENAI_API_KEY=your-api-key-here    # For LLM analysis (primary)
ANTHROPIC_API_KEY=your-api-key-here   # For LLM analysis (secondary)
GOOGLE_API_KEY=your-api-key-here      # For LLM analysis (tertiary)

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

### Multi-Provider LLM Routing

**Smart failover and load balancing** across multiple LLM providers:

- **🔄 Automatic Failover**: Switches providers when one fails or hits rate limits
- **⚡ Performance Optimization**: Routes to fastest available provider
- **🛡️ Circuit Breaker**: Temporarily disables unhealthy providers
- **📊 Real-time Monitoring**: Provider health and performance metrics
- **🔧 Configurable Priority**: Set primary, secondary, and tertiary providers

**Supported Providers:**
- **OpenAI GPT** (Primary - gpt-3.5-turbo, gpt-4)
- **Anthropic Claude** (Secondary - claude-3-haiku, claude-3-sonnet)
- **Google Gemini** (Tertiary - gemini-pro, gemini-pro-vision)

**API Endpoint for Monitoring:**
```bash
curl http://localhost:8000/analysis/llm-status
```

### Adaptive Learning

The system **learns and adapts**:

- **Pattern Recognition**: Identifies new attack signatures
- **Dynamic Rules**: Updates detection rules automatically
- **Decoy Generation**: Creates new honeypot endpoints based on reconnaissance
- **Feedback Loop**: Incorporates SOC feedback for improved accuracy

### Kafka Streaming (Optional)

For **high-volume deployments**, DECOYABLE supports **Kafka-based event streaming**:

- **🔄 Asynchronous Processing**: Attack events published to Kafka topics for scalable processing
- **📈 Horizontal Scaling**: Consumer groups can scale independently for analysis, alerts, and persistence
- **🛡️ Back-Pressure Handling**: Critical blocking actions remain synchronous (<50ms latency)
- **🔌 Plug-in Architecture**: Kafka is optional - system runs without it by default
- **📊 Event-Driven Architecture**: Decouple event capture from processing for better resilience

#### Enable Kafka Streaming

```bash
# Set environment variables
export KAFKA_ENABLED=true
export KAFKA_BOOTSTRAP_SERVERS=localhost:9092
export KAFKA_ATTACK_TOPIC=decoyable.attacks

# Start with Kafka profile
docker-compose --profile kafka up
```

#### Architecture

```text
Attack Request → Honeypot Capture → Kafka Producer → Topics
                                                       ↓
Consumer Groups → Analysis → SOC Alerts → Database → Adaptive Defense
```

**Benefits:**
- Handle "thousand cuts" style attacks without blocking the main application
- Scale analysis, alerting, and persistence independently
- Replay failed events from Kafka topics
- Integrate with existing Kafka-based security pipelines

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

- **Security Issues**: ricky@kolerr.com
- **General Inquiries**: lab.kolerr@kolerr.com
- **Documentation**: lab.kolerr@kolerr.com

---

**DECOYABLE**: From passive scanning to active defense. Transform your security posture with AI-powered cyber defense. 🛡️🤖

## Commands (Quick Reference)

Use these to run DECOYABLE locally or perform admin actions. For production, prefer Docker/compose flow.

### Local (Unix)

```bash
# Full quick-check helper (creates venv if missing, runs lint/tests, quick scans, and starts dev server)
./run_full_check.sh
```

### Windows PowerShell helper

```powershell
# Activate virtualenv
.\.venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt

# Run tests
pytest -q

# Run quick scans
python main.py scan secrets --path .
python main.py scan deps --path .

# Start dev server
uvicorn decoyable.api.app:app --reload --host 0.0.0.0 --port 8000
```

### Admin & Active Defense (see SECURITY.md for RBAC and operational guidance)

- `decoyable defense status` — show honeypot status
- `decoyable defense logs` — view recent attacks
- `decoyable defense patterns` — show learned detection patterns
- Admin-only (requires `API_AUTH_TOKEN` or similar): `decoyable defense block-ip <ip>`
