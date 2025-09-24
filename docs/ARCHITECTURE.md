# Architecture Documentation

## Overview

DECOYABLE is a modular, AI-powered cybersecurity scanning platform designed for enterprise security teams and developers. This document outlines the system architecture, component relationships, and design decisions.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    DECOYABLE PLATFORM                           │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │   FastAPI   │  │  Analysis   │  │  Honeypot   │            │
│  │   REST API  │  │   Engine    │  │   System    │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │   LLM       │  │   Cache     │  │  Database   │            │
│  │ Integration │  │   Layer     │  │   Layer     │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │   Docker    │  │   CI/CD     │  │   External  │            │
│  │ Container   │  │  Pipeline   │  │  Services   │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. API Layer (FastAPI)

**Location**: `decoyable/api/`
**Purpose**: REST API interface for all platform interactions

**Key Features:**
- OpenAPI/Swagger documentation
- Request validation and serialization
- Authentication and authorization
- Rate limiting and security middleware
- Prometheus metrics integration

**Endpoints:**
- `/health` - Health checks
- `/scan/*` - Security scanning operations
- `/analysis/*` - Threat analysis
- `/honeypot/*` - Honeypot management

### 2. Analysis Engine

**Location**: `decoyable/defense/`
**Purpose**: Core security analysis and threat detection

**Components:**
- **Adaptive Defense**: Dynamic response strategies
- **Knowledge Base**: Threat intelligence storage
- **LLM Analysis**: AI-powered threat assessment
- **Pattern Recognition**: Attack pattern matching

### 3. LLM Integration

**Location**: `decoyable/llm/`
**Purpose**: AI-powered analysis and decision making

**Architecture:**
```
LLM Router
├── Provider Factory
├── Provider Implementations
│   ├── OpenAI
│   ├── Anthropic
│   └── Google
└── Routing Strategies
    ├── Priority-based
    ├── Load balancing
    └── Failover
```

**Features:**
- Multi-provider support
- Intelligent routing
- Fallback mechanisms
- Performance monitoring

### 4. Honeypot System

**Location**: `decoyable/defense/honeypot.py`
**Purpose**: Active defense through deceptive services

**Capabilities:**
- Dynamic honeypot generation
- Attack pattern learning
- Automated response generation
- Threat intelligence gathering

### 5. Scanning Modules

**Location**: `decoyable/scanners/`
**Purpose**: Specialized security scanning tools

**Available Scanners:**
- **Secrets Scanner**: API keys, tokens, credentials
- **Dependency Scanner**: Vulnerable packages
- **Custom Scanners**: Extensible plugin system

### 6. Data Layer

**Components:**
- **Cache Layer**: Redis-based caching for performance
- **Database Layer**: PostgreSQL for persistent storage
- **Metrics Storage**: Prometheus-compatible metrics

## Design Decisions

### 1. Modular Architecture

**Decision**: Component-based design with clear separation of concerns

**Rationale:**
- Easier maintenance and testing
- Independent scaling of components
- Simplified feature development
- Better code reusability

**Implementation:**
- Each module in separate package
- Dependency injection pattern
- Interface-based design

### 2. AI-First Approach

**Decision**: Integrate AI/LLM capabilities throughout the platform

**Rationale:**
- Advanced threat detection
- Automated analysis and response
- Reduced false positives
- Enhanced decision making

**Implementation:**
- LLM router for multiple providers
- AI-powered analysis pipelines
- Machine learning model integration
- Intelligent routing algorithms

### 3. API-First Design

**Decision**: REST API as primary interface

**Rationale:**
- Platform accessibility
- Integration capabilities
- Tool ecosystem compatibility
- Future web UI support

**Implementation:**
- FastAPI framework
- OpenAPI specification
- Comprehensive documentation
- Versioned endpoints

### 4. Security by Design

**Decision**: Security considerations in every component

**Rationale:**
- Trust and reliability
- Compliance requirements
- Enterprise adoption
- Risk mitigation

**Implementation:**
- Input validation and sanitization
- Secure defaults
- Audit logging
- Access control

### 5. Container-Native

**Decision**: Docker-first deployment strategy

**Rationale:**
- Consistent environments
- Easy deployment and scaling
- Isolation and security
- CI/CD integration

**Implementation:**
- Multi-stage Docker builds
- Minimal base images
- Security scanning
- Orchestration ready

## Data Flow

### Scanning Workflow

```
1. API Request → 2. Validation → 3. Cache Check → 4. Scanner Execution
      ↓                    ↓              ↓                    ↓
   FastAPI          Pydantic      Redis Cache      Scanner Module
      ↓                    ↓              ↓                    ↓
5. Result Processing → 6. AI Analysis → 7. Database Storage → 8. Response
      ↓                      ↓                    ↓                  ↓
  Result Formatting    LLM Router      PostgreSQL         JSON Response
```

### Analysis Workflow

```
Raw Data → Pattern Matching → AI Analysis → Risk Scoring → Recommendations
     ↓             ↓                ↓           ↓              ↓
 Input     Rule Engine     LLM Router   Algorithm    Response Logic
Validation   Matching     Assessment   Calculation   Generation
```

## Security Considerations

### 1. Input Security
- Path traversal prevention
- Command injection protection
- File access restrictions
- Input sanitization

### 2. API Security
- Rate limiting
- Authentication/authorization
- CORS configuration
- Request validation

### 3. Data Security
- Encryption at rest
- Secure credential handling
- Audit logging
- Access control

### 4. Infrastructure Security
- Container security scanning
- Minimal attack surface
- Secure defaults
- Regular updates

## Performance Characteristics

### Scalability
- Horizontal scaling through containers
- Database connection pooling
- Caching for performance
- Asynchronous processing

### Performance Targets
- API response time: <500ms
- Scan completion: <30 seconds (small projects)
- Concurrent users: 1000+
- Uptime: 99.9%

## Deployment Options

### 1. Docker Compose (Development)
```yaml
version: '3.8'
services:
  decoyable:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://...
      - REDIS_URL=redis://...
```

### 2. Kubernetes (Production)
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: decoyable
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: decoyable
        image: kolerr/decoyable:latest
        ports:
        - containerPort: 8000
```

### 3. Cloud Platforms
- AWS ECS/Fargate
- Google Cloud Run
- Azure Container Instances
- DigitalOcean App Platform

## Monitoring and Observability

### Metrics
- Prometheus metrics endpoint
- Custom business metrics
- Performance monitoring
- Error tracking

### Logging
- Structured logging
- Log aggregation
- Error tracking
- Audit trails

### Alerting
- Health check endpoints
- Performance thresholds
- Security incident alerts
- System resource monitoring

## Future Architecture Evolution

### Phase 1: Microservices (v2.0)
- Service decomposition
- Event-driven architecture
- API gateway
- Service mesh

### Phase 2: Multi-Cloud (v3.0)
- Cloud-native architecture
- Multi-region deployment
- Global load balancing
- Cross-cloud failover

### Phase 3: AI Platform (v4.0)
- Custom model training
- Advanced ML pipelines
- Predictive analytics
- Autonomous operation

## Contributing to Architecture

When making architectural changes:

1. **Document Decisions**: Update this document
2. **Consider Impact**: Security, performance, scalability
3. **Test Thoroughly**: Unit, integration, and performance tests
4. **Review Security**: Security team review for sensitive changes
5. **Update Diagrams**: Keep architecture diagrams current

## Contact

For architecture questions or contributions:
- **Technical Lead**: [GitHub Profile]
- **Architecture Discussions**: [GitHub Discussions]
- **Security Review**: ricky@kolerr.com 
 
