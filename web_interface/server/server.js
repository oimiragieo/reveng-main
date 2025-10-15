#!/usr/bin/env node
/**
 * REVENG Web Interface Server
 * ===========================
 * 
 * Express.js server providing REST API and WebSocket support for
 * AI-Enhanced Universal Binary Analysis Engine web interface.
 * 
 * Features:
 * - File upload and analysis management
 * - Real-time progress tracking via WebSocket
 * - User authentication and project management
 * - RESTful API for analysis operations
 * - Collaborative analysis and team sharing
 */

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

// Import route handlers
const authRoutes = require('./routes/auth');
const analysisRoutes = require('./routes/analysis');
const projectRoutes = require('./routes/projects');
const userRoutes = require('./routes/users');
const adminRoutes = require('./routes/admin');

// Import middleware
const authMiddleware = require('./middleware/auth');
const errorHandler = require('./middleware/errorHandler');

// Import services
const AnalysisService = require('./services/analysisService');
const WebSocketService = require('./services/websocketService');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: process.env.CLIENT_URL || "http://localhost:3000",
    methods: ["GET", "POST"]
  }
});

// Configuration
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "ws:", "wss:"]
    }
  }
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Upload rate limiting (more restrictive)
const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // limit each IP to 10 uploads per hour
  message: 'Upload limit exceeded, please try again later.'
});

// Middleware
app.use(compression());
app.use(morgan('combined'));
app.use(cors({
  origin: process.env.CLIENT_URL || "http://localhost:3000",
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Static file serving
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));
app.use('/reports', express.static(path.join(__dirname, '../reports')));

// Create required directories
const requiredDirs = [
  path.join(__dirname, '../uploads'),
  path.join(__dirname, '../reports'),
  path.join(__dirname, '../temp'),
  path.join(__dirname, '../logs')
];

requiredDirs.forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

// Initialize services
const analysisService = new AnalysisService();
const websocketService = new WebSocketService(io);

// Make services available to routes
app.locals.analysisService = analysisService;
app.locals.websocketService = websocketService;

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    environment: NODE_ENV,
    services: {
      analysis: analysisService.isHealthy(),
      websocket: websocketService.isHealthy()
    }
  });
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/analysis', uploadLimiter, analysisRoutes);
app.use('/api/projects', authMiddleware, projectRoutes);
app.use('/api/users', authMiddleware, userRoutes);
app.use('/api/admin', authMiddleware, adminRoutes);

// WebSocket connection handling
io.on('connection', (socket) => {
  console.log(`Client connected: ${socket.id}`);
  
  // Handle authentication
  socket.on('authenticate', (token) => {
    websocketService.authenticateSocket(socket, token);
  });
  
  // Handle joining analysis rooms
  socket.on('join-analysis', (analysisId) => {
    websocketService.joinAnalysisRoom(socket, analysisId);
  });
  
  // Handle leaving analysis rooms
  socket.on('leave-analysis', (analysisId) => {
    websocketService.leaveAnalysisRoom(socket, analysisId);
  });
  
  // Handle collaboration events
  socket.on('collaboration-event', (data) => {
    websocketService.handleCollaborationEvent(socket, data);
  });
  
  socket.on('disconnect', () => {
    console.log(`Client disconnected: ${socket.id}`);
    websocketService.handleDisconnect(socket);
  });
});

// Serve React app in production
if (NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '../client/build')));
  
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../client/build/index.html'));
  });
}

// Error handling middleware
app.use(errorHandler);

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: 'The requested resource was not found on this server.'
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
    process.exit(0);
  });
});

// Start server
server.listen(PORT, () => {
  console.log('='.repeat(60));
  console.log(' REVENG Web Interface Server');
  console.log('='.repeat(60));
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${NODE_ENV}`);
  console.log(`Client URL: ${process.env.CLIENT_URL || 'http://localhost:3000'}`);
  console.log('='.repeat(60));
});

module.exports = { app, server, io };