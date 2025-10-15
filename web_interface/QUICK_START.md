# REVENG Web Interface - Quick Start

**Status**: ✅ **Functional - Docker Deployment Ready**

The REVENG web interface provides a modern, interactive web-based frontend for binary analysis with real-time tracking, interactive visualizations, and project management.

## 🚀 Quick Start

### Prerequisites

- **Docker** and **Docker Compose**
- **Node.js 18+** (for development)
- **Python 3.11+** (for backend)
- **MongoDB** (for data storage)
- **Redis** (for caching)

### Docker Deployment (Recommended)

```bash
# Clone the repository
git clone https://github.com/oimiragieo/reveng-main.git
cd reveng-main/web_interface

# Start all services
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f
```

**Access Points:**
- **Web Interface**: http://localhost:3000
- **API Server**: http://localhost:8000
- **MongoDB**: localhost:27017
- **Redis**: localhost:6379

### Development Setup

```bash
# Backend setup
cd web_interface/server
pip install -r requirements.txt
python app.py

# Frontend setup (new terminal)
cd web_interface/client
npm install
npm start
```

## 🏗️ Architecture

### Services Overview

| Service | Port | Purpose |
|---------|------|---------|
| **React Client** | 3000 | Modern web interface |
| **Express API** | 8000 | REST API server |
| **MongoDB** | 27017 | Data storage |
| **Redis** | 6379 | Caching and sessions |
| **Nginx** | 80 | Reverse proxy |

### Technology Stack

**Frontend:**
- **React 18** - Modern UI framework
- **TypeScript** - Type safety
- **Material-UI** - Component library
- **Chart.js** - Interactive visualizations
- **WebSocket** - Real-time updates

**Backend:**
- **Express.js** - REST API server
- **Socket.io** - Real-time communication
- **MongoDB** - Document database
- **Redis** - Caching and sessions
- **Multer** - File upload handling

**Infrastructure:**
- **Docker** - Containerization
- **Kubernetes** - Orchestration
- **Nginx** - Reverse proxy
- **Helm** - Package management

## 📋 Features

### Core Features

- ✅ **File Upload** - Drag-and-drop binary upload
- ✅ **Real-time Tracking** - Live analysis progress
- ✅ **Interactive Visualization** - Call graphs, dependency diagrams
- ✅ **Project Management** - Save and organize analyses
- ✅ **Authentication** - User management and security
- ✅ **API Integration** - RESTful API for external tools

### Analysis Features

- ✅ **Multi-format Support** - PE, ELF, Mach-O, Java, C#
- ✅ **AI Integration** - Ollama/Anthropic/OpenAI support
- ✅ **Visualization** - Interactive call graphs and heatmaps
- ✅ **Export Options** - JSON, XML, PDF reports
- ✅ **Collaboration** - Share analyses with team members

### Enterprise Features

- ✅ **Audit Logging** - Complete activity tracking
- ✅ **User Management** - Role-based access control
- ✅ **Project Organization** - Folder structure and tagging
- ✅ **API Access** - Programmatic analysis capabilities
- ✅ **Monitoring** - Health checks and performance metrics

## 🔧 Configuration

### Environment Variables

Create `.env` file in `web_interface/`:

```bash
# Database
MONGODB_URI=mongodb://localhost:27017/reveng
REDIS_URL=redis://localhost:6379

# API Configuration
API_PORT=8000
CLIENT_PORT=3000

# Authentication
JWT_SECRET=your-secret-key
SESSION_SECRET=your-session-secret

# AI Integration
OLLAMA_URL=http://localhost:11434
ANTHROPIC_API_KEY=your-api-key
OPENAI_API_KEY=your-api-key

# File Storage
UPLOAD_DIR=./uploads
MAX_FILE_SIZE=100MB

# Security
CORS_ORIGIN=http://localhost:3000
RATE_LIMIT=100
```

### Docker Configuration

**docker-compose.yml:**
```yaml
version: '3.8'
services:
  client:
    build: ./client
    ports:
      - "3000:3000"
    environment:
      - REACT_APP_API_URL=http://localhost:8000
    depends_on:
      - server

  server:
    build: ./server
    ports:
      - "8000:8000"
    environment:
      - MONGODB_URI=mongodb://mongo:27017/reveng
      - REDIS_URL=redis://redis:6379
    depends_on:
      - mongo
      - redis

  mongo:
    image: mongo:latest
    ports:
      - "27017:27017"
    volumes:
      - mongo_data:/data/db

  redis:
    image: redis:latest
    ports:
      - "6379:6379"

volumes:
  mongo_data:
```

## 🚀 Usage

### Basic Workflow

1. **Upload Binary**
   - Drag and drop file to upload area
   - Select analysis options
   - Click "Start Analysis"

2. **Monitor Progress**
   - Real-time progress bar
   - Live status updates
   - Error notifications

3. **View Results**
   - Interactive call graphs
   - Function analysis
   - Export reports

4. **Manage Projects**
   - Save analyses
   - Organize by folders
   - Share with team

### API Usage

```bash
# Upload file
curl -X POST http://localhost:8000/api/upload \
  -F "file=@binary.exe" \
  -F "options={\"ai_analysis\": true}"

# Check analysis status
curl http://localhost:8000/api/analysis/123/status

# Get results
curl http://localhost:8000/api/analysis/123/results

# Download report
curl http://localhost:8000/api/analysis/123/report.pdf
```

### WebSocket Events

```javascript
// Connect to WebSocket
const socket = io('http://localhost:8000');

// Listen for analysis updates
socket.on('analysis_progress', (data) => {
  console.log(`Progress: ${data.progress}%`);
});

// Listen for completion
socket.on('analysis_complete', (data) => {
  console.log('Analysis complete:', data.results);
});
```

## 🔧 Development

### Project Structure

```
web_interface/
├── client/                 # React frontend
│   ├── src/
│   │   ├── components/    # React components
│   │   ├── pages/         # Page components
│   │   ├── services/      # API services
│   │   └── utils/         # Utility functions
│   ├── public/            # Static assets
│   └── package.json       # Dependencies
├── server/                # Express backend
│   ├── routes/            # API routes
│   ├── models/            # Database models
│   ├── middleware/        # Express middleware
│   └── app.js             # Main server file
├── docker-compose.yml     # Docker configuration
├── Dockerfile.client      # Frontend Dockerfile
├── Dockerfile.server      # Backend Dockerfile
└── kubernetes/            # K8s manifests
```

### Adding New Features

1. **Frontend Component**
   ```bash
   cd web_interface/client/src/components
   # Create new React component
   ```

2. **Backend Route**
   ```bash
   cd web_interface/server/routes
   # Add new API endpoint
   ```

3. **Database Model**
   ```bash
   cd web_interface/server/models
   # Create new MongoDB model
   ```

### Testing

```bash
# Frontend tests
cd web_interface/client
npm test

# Backend tests
cd web_interface/server
python -m pytest tests/

# Integration tests
docker-compose -f docker-compose.test.yml up --abort-on-container-exit
```

## 🐛 Troubleshooting

### Common Issues

**Docker Services Not Starting:**
```bash
# Check Docker status
docker-compose ps

# View logs
docker-compose logs service_name

# Restart services
docker-compose restart
```

**Database Connection Issues:**
```bash
# Check MongoDB
docker-compose exec mongo mongosh

# Check Redis
docker-compose exec redis redis-cli ping
```

**Frontend Build Issues:**
```bash
# Clear node_modules
rm -rf client/node_modules
npm install

# Clear build cache
npm run build -- --no-cache
```

**API Connection Issues:**
```bash
# Check server logs
docker-compose logs server

# Test API endpoint
curl http://localhost:8000/api/health
```

### Performance Optimization

**Database Indexing:**
```javascript
// Add indexes for better performance
db.analyses.createIndex({ "user_id": 1, "created_at": -1 })
db.analyses.createIndex({ "status": 1 })
```

**Caching Strategy:**
```javascript
// Redis caching for frequent queries
const cacheKey = `analysis:${analysisId}`
await redis.setex(cacheKey, 3600, JSON.stringify(results))
```

**Frontend Optimization:**
```javascript
// Code splitting for better performance
const AnalysisPage = lazy(() => import('./pages/AnalysisPage'))
```

## 📊 Monitoring

### Health Checks

```bash
# Check all services
curl http://localhost:8000/api/health

# Check database
curl http://localhost:8000/api/health/database

# Check Redis
curl http://localhost:8000/api/health/redis
```

### Metrics

- **Response Time**: API endpoint performance
- **Throughput**: Requests per second
- **Error Rate**: Failed requests percentage
- **Resource Usage**: CPU, memory, disk usage

### Logging

```bash
# View all logs
docker-compose logs -f

# View specific service
docker-compose logs -f server

# View with timestamps
docker-compose logs -f --timestamps
```

## 🔒 Security

### Authentication

- **JWT Tokens** - Secure API authentication
- **Session Management** - Redis-based sessions
- **Role-based Access** - User permissions
- **Rate Limiting** - API abuse prevention

### Data Protection

- **File Encryption** - Encrypt uploaded files
- **Database Security** - MongoDB authentication
- **CORS Configuration** - Cross-origin security
- **Input Validation** - Prevent injection attacks

### Best Practices

- **HTTPS Only** - Encrypt all communications
- **Regular Updates** - Keep dependencies current
- **Security Headers** - Add security headers
- **Audit Logging** - Track all activities

## 📚 Related Documentation

- **[Main README](../README.md)** - Project overview
- **[Web Interface README](README.md)** - Detailed web interface documentation
- **[API Documentation](api.md)** - Complete API reference
- **[Deployment Guide](deployment.md)** - Production deployment

## 🆘 Support

### Getting Help

- **Documentation**: Check this guide and README files
- **Issues**: Create GitHub issues for bugs
- **Discussions**: Use GitHub Discussions for questions
- **Community**: Join our community Discord

### Reporting Issues

When reporting issues, please include:

1. **Environment**: OS, Docker version, Node.js version
2. **Steps**: Exact steps to reproduce
3. **Logs**: Relevant error logs
4. **Screenshots**: If applicable
5. **Expected vs Actual**: What should happen vs what happens

---

**Last Updated**: January 2025  
**Status**: ✅ Functional - Docker Deployment Ready  
**Maintainer**: REVENG Development Team
