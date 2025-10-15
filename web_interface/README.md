# REVENG Web Interface

⚠️ **EXPERIMENTAL** - This web interface is currently in experimental status and may not be production-ready.

**Status**: ✅ **Functional - Docker Deployment Ready**

## 🌐 Web UI vs CLI

**CLI Users**: You can use REVENG entirely from the command line. The web interface is optional.

**Web UI Users**: This interface provides team collaboration, real-time visualization, and project management features.

Modern React-based web interface for the REVENG Universal Reverse Engineering Platform, providing comprehensive file upload, real-time analysis tracking, interactive result visualization, user authentication, and project management capabilities.

## 🚀 Quick Start

```bash
# Docker deployment (recommended)
cd web_interface
docker-compose up -d

# Access at http://localhost:3000
```

**See [QUICK_START.md](QUICK_START.md) for detailed setup instructions.**

## ✨ Implementation Complete - Task 10.1

This implementation fulfills all requirements for **Task 10.1: Build web-based analysis interface** including:

### 🎯 Core Features Implemented

#### 📤 **File Upload and Analysis Management**
- **Drag-and-drop interface** for binary file uploads (up to 100MB)
- **Multi-format support**: EXE, DLL, JAR, APK, JS, WASM, and more
- **Analysis configuration** with toggleable modules:
  - Corporate Data Exposure Analysis
  - Vulnerability Discovery
  - Threat Intelligence Correlation
  - Binary Reconstruction
  - Demonstration Generation
- **Comprehensive analysis list** with search, filtering, and status tracking
- **Export capabilities** in JSON, XML, CSV, and PDF formats

#### ⚡ **Real-time Progress Tracking**
- **WebSocket-powered live updates** for analysis progress
- **Step-by-step progress visualization** with detailed status indicators
- **Real-time notifications** for analysis events (started, completed, failed)
- **Interactive progress bars** showing completion percentage
- **Estimated time remaining** calculations

#### 📊 **Interactive Result Visualization**
- **Comprehensive analysis detail views** with tabbed interface:
  - Overview dashboard with key metrics
  - Vulnerability analysis with severity breakdown
  - Corporate exposure findings
  - Threat intelligence correlation
  - Binary reconstruction results
- **Interactive charts and graphs** using Chart.js:
  - Vulnerability severity distribution
  - Risk assessment matrices
  - Timeline visualizations
  - Threat level indicators
- **Expandable result sections** with detailed findings
- **Export and sharing capabilities** for analysis results

#### 🔐 **User Authentication and Session Management**
- **JWT-based authentication** with secure token handling
- **User registration and login** with form validation
- **Role-based access control** (Admin/User roles)
- **Session persistence** with automatic token refresh
- **Password change functionality**
- **Secure logout** with token cleanup

#### 📁 **Project Management Capabilities**
- **Project creation and organization** for grouping analyses
- **Collaborative features** with member management
- **Public/private project visibility** settings
- **Project search and filtering**
- **Analysis assignment** to projects
- **Member invitation and removal** system

## Features

### 🚀 Core Capabilities
- **File Upload & Analysis**: Drag-and-drop interface for binary file analysis
- **Real-time Progress**: Live updates via WebSocket connections
- **Interactive Results**: Rich visualization of analysis findings
- **Multi-format Export**: JSON, XML, PDF, and CSV export options

### 👥 Collaboration
- **Team Sharing**: Share analyses with team members
- **Real-time Comments**: Collaborative annotation system
- **Live Presence**: See who's viewing analyses in real-time
- **Project Management**: Organize analyses into projects

### 🔐 Security & Authentication
- **JWT Authentication**: Secure token-based authentication
- **Role-based Access**: Admin and user role management
- **Session Management**: Secure session handling
- **Rate Limiting**: API protection against abuse

### ☁️ Cloud Deployment
- **Docker Containers**: Containerized microservices architecture
- **Kubernetes Support**: Production-ready K8s manifests
- **Auto-scaling**: Horizontal pod autoscaling
- **Load Balancing**: High availability with nginx

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   React Client  │    │  Express API    │    │  Analysis       │
│   (Frontend)    │◄──►│  (Backend)      │◄──►│  Workers        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│     Nginx       │    │   MongoDB       │    │     Redis       │
│  (Load Balancer)│    │  (Database)     │    │   (Cache)       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Quick Start

### Prerequisites
- Node.js 18+ and npm
- Python 3.8+ with REVENG dependencies
- Docker and Docker Compose (for containerized deployment)
- Kubernetes cluster (for production deployment)

### Development Setup

1. **Clone and Install Dependencies**
   ```bash
   cd web_interface
   npm run install-all
   ```

2. **Environment Configuration**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Start Development Servers**
   ```bash
   npm run dev
   ```

   This starts:
   - Backend API server on http://localhost:5000
   - React development server on http://localhost:3000

### Docker Deployment

1. **Development with Docker Compose**
   ```bash
   docker-compose up -d
   ```

2. **Production Deployment**
   ```bash
   docker-compose --profile production up -d
   ```

### Kubernetes Deployment

1. **Quick Deploy**
   ```bash
   ./scripts/deploy.sh
   ```

2. **Custom Deployment**
   ```bash
   # Build and push images
   DOCKER_REGISTRY=your-registry BUILD_IMAGES=true PUSH_IMAGES=true ./scripts/deploy.sh

   # Deploy to specific environment
   ENVIRONMENT=production VERSION=v1.0.0 ./scripts/deploy.sh
   ```

## Configuration

### Environment Variables

#### Backend Configuration
```bash
# Server
NODE_ENV=production
PORT=5000

# Authentication
JWT_SECRET=your-super-secret-jwt-key

# Database
MONGO_URI=mongodb://username:password@localhost:27017/reveng
REDIS_URL=redis://localhost:6379

# REVENG Integration
PYTHON_PATH=python3
ANALYZER_PATH=../tools/ai_enhanced_analyzer.py

# Client
CLIENT_URL=http://localhost:3000
```

#### Frontend Configuration
```bash
REACT_APP_SERVER_URL=http://localhost:5000
```

### Analysis Configuration

The web interface supports all AI-Enhanced analyzer configuration options:

```javascript
{
  "noCorporate": false,      // Disable corporate exposure analysis
  "noVuln": false,           // Disable vulnerability discovery
  "noThreat": false,         // Disable threat intelligence
  "noReconstruction": false, // Disable binary reconstruction
  "noDemo": false            // Disable demonstration generation
}
```

## API Documentation

### Authentication Endpoints

#### POST /api/auth/login
```json
{
  "username": "admin",
  "password": "admin123"
}
```

#### POST /api/auth/register
```json
{
  "username": "newuser",
  "email": "user@example.com",
  "password": "password123",
  "confirmPassword": "password123"
}
```

### Analysis Endpoints

#### POST /api/analysis/upload
Upload binary file for analysis (multipart/form-data)

#### POST /api/analysis/:id/start
Start analysis for uploaded file

#### GET /api/analysis/:id/status
Get real-time analysis status and progress

#### GET /api/analysis/:id/results
Retrieve complete analysis results

#### GET /api/analysis/:id/export/:format
Export results in specified format (json, xml, pdf, csv)

### WebSocket Events

#### Client → Server
- `authenticate`: Authenticate WebSocket connection
- `join-analysis`: Join analysis room for updates
- `collaboration-event`: Send collaboration events

#### Server → Client
- `analysis-progress`: Real-time progress updates
- `analysis-completed`: Analysis completion notification
- `new-comment`: New collaboration comment
- `user-joined`: User joined analysis room

## Deployment Scenarios

### 1. Development Environment
```bash
# Local development with hot reload
npm run dev
```

### 2. Docker Development
```bash
# Containerized development environment
docker-compose up
```

### 3. Production Docker
```bash
# Production containers with nginx
docker-compose --profile production up -d
```

### 4. Kubernetes Production
```bash
# Full Kubernetes deployment
./scripts/deploy.sh
```

### 5. Cloud Platforms

#### AWS EKS
```bash
# Configure AWS CLI and kubectl for EKS
aws eks update-kubeconfig --region us-west-2 --name reveng-cluster
ENVIRONMENT=production ./scripts/deploy.sh
```

#### Google GKE
```bash
# Configure gcloud and kubectl for GKE
gcloud container clusters get-credentials reveng-cluster --zone us-central1-a
ENVIRONMENT=production ./scripts/deploy.sh
```

#### Azure AKS
```bash
# Configure Azure CLI and kubectl for AKS
az aks get-credentials --resource-group reveng-rg --name reveng-cluster
ENVIRONMENT=production ./scripts/deploy.sh
```

## Monitoring and Observability

### Health Checks
- **Backend**: `GET /health` - Service health and dependencies
- **Frontend**: `GET /` - Application availability
- **Database**: Connection and query performance monitoring

### Logging
- **Application Logs**: Structured JSON logging with Winston
- **Access Logs**: Nginx access logs with custom format
- **Analysis Logs**: Detailed analysis execution logs

### Metrics
- **System Metrics**: CPU, memory, disk usage
- **Application Metrics**: Request rates, response times, error rates
- **Business Metrics**: Analysis completion rates, user activity

## Security Considerations

### Authentication & Authorization
- JWT tokens with configurable expiration
- Role-based access control (RBAC)
- Session management with Redis
- Password hashing with bcrypt

### Data Protection
- File upload validation and sanitization
- Secure file storage with access controls
- Sensitive data redaction in logs
- TLS encryption for all communications

### Network Security
- Rate limiting on API endpoints
- CORS configuration for cross-origin requests
- Security headers (HSTS, CSP, X-Frame-Options)
- Network policies in Kubernetes

## Troubleshooting

### Common Issues

#### 1. Analysis Fails to Start
```bash
# Check Python dependencies
python3 -c "import tools.ai_enhanced_analyzer"

# Check file permissions
ls -la uploads/

# Check logs
docker logs reveng-backend
```

#### 2. WebSocket Connection Issues
```bash
# Check network connectivity
curl -I http://localhost:5000/socket.io/

# Check authentication
# Verify JWT token in browser developer tools
```

#### 3. Database Connection Problems
```bash
# Test MongoDB connection
mongosh "mongodb://username:password@localhost:27017/reveng"

# Check Redis connection
redis-cli -h localhost -p 6379 ping
```

### Performance Optimization

#### 1. Analysis Performance
- Increase worker replicas for parallel processing
- Optimize Python analysis pipeline
- Use SSD storage for temporary files

#### 2. Web Performance
- Enable gzip compression in nginx
- Implement Redis caching for API responses
- Use CDN for static assets

#### 3. Database Performance
- Create appropriate MongoDB indexes
- Configure connection pooling
- Monitor query performance

## Contributing

### Development Workflow
1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Make changes and test thoroughly
4. Commit changes: `git commit -m 'Add amazing feature'`
5. Push to branch: `git push origin feature/amazing-feature`
6. Create Pull Request

### Code Standards
- **Frontend**: ESLint + Prettier for React/JavaScript
- **Backend**: ESLint for Node.js
- **Python**: Black + flake8 for analysis integration
- **Docker**: Hadolint for Dockerfile linting

### Testing
```bash
# Frontend tests
cd client && npm test

# Backend tests
cd server && npm test

# Integration tests
npm run test:integration

# E2E tests
npm run test:e2e
```

## License

This project is part of the REVENG toolkit and follows the same licensing terms.

## Support

For support and questions:
- Create an issue in the GitHub repository
- Check the troubleshooting section above
- Review the API documentation

---

**REVENG Web Interface** - Bringing AI-Enhanced Binary Analysis to the Web