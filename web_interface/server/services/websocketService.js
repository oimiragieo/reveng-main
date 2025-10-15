/**
 * WebSocket Service
 * =================
 * 
 * Real-time communication service for:
 * - Analysis progress updates
 * - Collaborative features
 * - Live notifications
 * - Team sharing events
 */

const jwt = require('jsonwebtoken');

class WebSocketService {
  constructor(io) {
    this.io = io;
    this.authenticatedSockets = new Map(); // socketId -> user info
    this.analysisRooms = new Map(); // analysisId -> Set of socketIds
    this.userSockets = new Map(); // userId -> Set of socketIds
    this.isHealthy_ = true;
    
    console.log('WebSocket Service initialized');
  }

  /**
   * Authenticate socket connection
   */
  authenticateSocket(socket, token) {
    try {
      if (!token) {
        socket.emit('auth-error', { message: 'No token provided' });
        return;
      }

      // Verify JWT token
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default-secret');
      
      // Store authenticated user info
      this.authenticatedSockets.set(socket.id, {
        userId: decoded.id,
        username: decoded.username,
        role: decoded.role,
        authenticatedAt: new Date().toISOString()
      });

      // Track user sockets
      if (!this.userSockets.has(decoded.id)) {
        this.userSockets.set(decoded.id, new Set());
      }
      this.userSockets.get(decoded.id).add(socket.id);

      socket.emit('auth-success', { 
        message: 'Authentication successful',
        userId: decoded.id,
        username: decoded.username
      });

      console.log(`Socket authenticated: ${socket.id} for user ${decoded.username}`);

    } catch (error) {
      console.error('Socket authentication error:', error.message);
      socket.emit('auth-error', { message: 'Invalid token' });
    }
  }

  /**
   * Join analysis room for real-time updates
   */
  joinAnalysisRoom(socket, analysisId) {
    const userInfo = this.authenticatedSockets.get(socket.id);
    
    if (!userInfo) {
      socket.emit('error', { message: 'Not authenticated' });
      return;
    }

    // TODO: Check if user has access to this analysis
    // For now, allow all authenticated users

    socket.join(`analysis-${analysisId}`);
    
    // Track room membership
    if (!this.analysisRooms.has(analysisId)) {
      this.analysisRooms.set(analysisId, new Set());
    }
    this.analysisRooms.get(analysisId).add(socket.id);

    socket.emit('joined-analysis', { 
      analysisId: analysisId,
      message: 'Joined analysis room'
    });

    // Notify other users in the room
    socket.to(`analysis-${analysisId}`).emit('user-joined', {
      analysisId: analysisId,
      userId: userInfo.userId,
      username: userInfo.username
    });

    console.log(`User ${userInfo.username} joined analysis room: ${analysisId}`);
  }

  /**
   * Leave analysis room
   */
  leaveAnalysisRoom(socket, analysisId) {
    const userInfo = this.authenticatedSockets.get(socket.id);
    
    if (!userInfo) {
      return;
    }

    socket.leave(`analysis-${analysisId}`);
    
    // Remove from room tracking
    if (this.analysisRooms.has(analysisId)) {
      this.analysisRooms.get(analysisId).delete(socket.id);
      
      // Clean up empty rooms
      if (this.analysisRooms.get(analysisId).size === 0) {
        this.analysisRooms.delete(analysisId);
      }
    }

    // Notify other users in the room
    socket.to(`analysis-${analysisId}`).emit('user-left', {
      analysisId: analysisId,
      userId: userInfo.userId,
      username: userInfo.username
    });

    console.log(`User ${userInfo.username} left analysis room: ${analysisId}`);
  }

  /**
   * Handle collaboration events (comments, annotations, etc.)
   */
  handleCollaborationEvent(socket, data) {
    const userInfo = this.authenticatedSockets.get(socket.id);
    
    if (!userInfo) {
      socket.emit('error', { message: 'Not authenticated' });
      return;
    }

    const { analysisId, eventType, payload } = data;

    // Add user info to the event
    const collaborationEvent = {
      analysisId: analysisId,
      eventType: eventType,
      payload: payload,
      userId: userInfo.userId,
      username: userInfo.username,
      timestamp: new Date().toISOString()
    };

    // Broadcast to all users in the analysis room
    this.io.to(`analysis-${analysisId}`).emit('collaboration-event', collaborationEvent);

    console.log(`Collaboration event: ${eventType} in analysis ${analysisId} by ${userInfo.username}`);
  }

  /**
   * Handle socket disconnection
   */
  handleDisconnect(socket) {
    const userInfo = this.authenticatedSockets.get(socket.id);
    
    if (userInfo) {
      // Remove from user sockets tracking
      if (this.userSockets.has(userInfo.userId)) {
        this.userSockets.get(userInfo.userId).delete(socket.id);
        
        // Clean up empty user socket sets
        if (this.userSockets.get(userInfo.userId).size === 0) {
          this.userSockets.delete(userInfo.userId);
        }
      }

      // Remove from analysis rooms
      for (const [analysisId, socketIds] of this.analysisRooms) {
        if (socketIds.has(socket.id)) {
          socketIds.delete(socket.id);
          
          // Notify other users in the room
          socket.to(`analysis-${analysisId}`).emit('user-left', {
            analysisId: analysisId,
            userId: userInfo.userId,
            username: userInfo.username
          });
          
          // Clean up empty rooms
          if (socketIds.size === 0) {
            this.analysisRooms.delete(analysisId);
          }
        }
      }

      console.log(`User ${userInfo.username} disconnected: ${socket.id}`);
    }

    // Remove from authenticated sockets
    this.authenticatedSockets.delete(socket.id);
  }

  /**
   * Notify analysis created
   */
  notifyAnalysisCreated(analysis) {
    // Notify the user who created the analysis
    this._notifyUser(analysis.userId, 'analysis-created', {
      analysisId: analysis.id,
      fileName: analysis.fileName,
      status: analysis.status,
      message: 'Analysis job created successfully'
    });
  }

  /**
   * Notify analysis started
   */
  notifyAnalysisStarted(analysisId) {
    // Notify all users in the analysis room
    this.io.to(`analysis-${analysisId}`).emit('analysis-started', {
      analysisId: analysisId,
      status: 'running',
      message: 'Analysis started'
    });
  }

  /**
   * Notify analysis progress update
   */
  notifyAnalysisProgress(analysisId, progress, stage) {
    // Notify all users in the analysis room
    this.io.to(`analysis-${analysisId}`).emit('analysis-progress', {
      analysisId: analysisId,
      progress: progress,
      stage: stage,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Notify analysis completed
   */
  notifyAnalysisCompleted(analysisId, results) {
    // Notify all users in the analysis room
    this.io.to(`analysis-${analysisId}`).emit('analysis-completed', {
      analysisId: analysisId,
      status: 'completed',
      message: 'Analysis completed successfully',
      hasResults: !!results
    });
  }

  /**
   * Notify analysis failed
   */
  notifyAnalysisError(analysisId, error) {
    // Notify all users in the analysis room
    this.io.to(`analysis-${analysisId}`).emit('analysis-error', {
      analysisId: analysisId,
      status: 'failed',
      error: error,
      message: 'Analysis failed'
    });
  }

  /**
   * Notify analysis deleted
   */
  notifyAnalysisDeleted(analysisId) {
    // Notify all users in the analysis room
    this.io.to(`analysis-${analysisId}`).emit('analysis-deleted', {
      analysisId: analysisId,
      message: 'Analysis has been deleted'
    });
  }

  /**
   * Notify analysis shared
   */
  notifyAnalysisShared(analysisId, sharedUserIds) {
    // Notify the shared users
    sharedUserIds.forEach(userId => {
      this._notifyUser(userId, 'analysis-shared', {
        analysisId: analysisId,
        message: 'An analysis has been shared with you'
      });
    });
  }

  /**
   * Notify new comment added
   */
  notifyNewComment(analysisId, comment) {
    // Notify all users in the analysis room except the commenter
    this.io.to(`analysis-${analysisId}`).emit('new-comment', {
      analysisId: analysisId,
      comment: comment,
      message: 'New comment added'
    });
  }

  /**
   * Send notification to specific user
   */
  _notifyUser(userId, eventType, data) {
    if (this.userSockets.has(userId)) {
      const userSocketIds = this.userSockets.get(userId);
      userSocketIds.forEach(socketId => {
        const socket = this.io.sockets.sockets.get(socketId);
        if (socket) {
          socket.emit(eventType, data);
        }
      });
    }
  }

  /**
   * Get connected users for analysis
   */
  getConnectedUsers(analysisId) {
    const connectedUsers = [];
    
    if (this.analysisRooms.has(analysisId)) {
      const socketIds = this.analysisRooms.get(analysisId);
      
      socketIds.forEach(socketId => {
        const userInfo = this.authenticatedSockets.get(socketId);
        if (userInfo) {
          connectedUsers.push({
            userId: userInfo.userId,
            username: userInfo.username,
            connectedAt: userInfo.authenticatedAt
          });
        }
      });
    }
    
    return connectedUsers;
  }

  /**
   * Get service statistics
   */
  getStats() {
    return {
      connectedSockets: this.authenticatedSockets.size,
      activeUsers: this.userSockets.size,
      activeAnalysisRooms: this.analysisRooms.size,
      totalConnections: this.io.engine.clientsCount
    };
  }

  /**
   * Health check
   */
  isHealthy() {
    return this.isHealthy_;
  }
}

module.exports = WebSocketService;