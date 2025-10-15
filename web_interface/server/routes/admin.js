/**
 * Admin Routes
 * ============
 * 
 * Administrative endpoints for system management, user administration, and monitoring
 */

const express = require('express');
const os = require('os');

const router = express.Router();

// Admin middleware to check admin role
const adminMiddleware = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({
      error: 'Access denied',
      message: 'Admin access required'
    });
  }
  next();
};

/**
 * GET /api/admin/stats
 * Get system statistics
 */
router.get('/stats', adminMiddleware, async (req, res) => {
  try {
    const analysisService = req.app.locals.analysisService;
    const websocketService = req.app.locals.websocketService;

    // Get system metrics
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    
    const stats = {
      system: {
        uptime: Math.floor(process.uptime()),
        version: '1.0.0',
        nodeVersion: process.version,
        platform: os.platform(),
        arch: os.arch()
      },
      performance: {
        cpu: Math.round(os.loadavg()[0] * 100 / os.cpus().length),
        memory: Math.round((usedMem / totalMem) * 100),
        disk: 45 // Mock disk usage - would need actual implementation
      },
      websocket: websocketService.getStats ? websocketService.getStats() : { connections: 0 },
      analysis: {
        total: analysisService.analysisHistory ? analysisService.analysisHistory.size : 0,
        active: analysisService.activeAnalyses ? analysisService.activeAnalyses.size : 0
      }
    };

    res.json({
      success: true,
      stats: stats
    });

  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({
      error: 'Failed to get stats',
      message: error.message
    });
  }
});

/**
 * GET /api/admin/users
 * Get all users (admin only)
 */
router.get('/users', adminMiddleware, async (req, res) => {
  try {
    // Mock user data - in real implementation, this would come from database
    const users = [
      {
        id: '1',
        username: 'admin',
        email: 'admin@example.com',
        role: 'admin',
        isActive: true,
        createdAt: new Date().toISOString(),
        lastActive: new Date().toISOString()
      },
      {
        id: '2',
        username: 'user1',
        email: 'user1@example.com',
        role: 'user',
        isActive: true,
        createdAt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
        lastActive: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString()
      }
    ];

    res.json({
      success: true,
      users: users
    });

  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({
      error: 'Failed to get users',
      message: error.message
    });
  }
});

/**
 * DELETE /api/admin/users/:userId
 * Delete user (admin only)
 */
router.delete('/users/:userId', adminMiddleware, async (req, res) => {
  try {
    const userId = req.params.userId;
    
    // Prevent admin from deleting themselves
    if (userId === req.user.id) {
      return res.status(400).json({
        error: 'Cannot delete yourself',
        message: 'You cannot delete your own account'
      });
    }

    // Mock deletion - in real implementation, this would delete from database
    console.log(`Admin ${req.user.id} deleted user ${userId}`);

    res.json({
      success: true,
      message: 'User deleted successfully',
      userId: userId
    });

  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({
      error: 'Failed to delete user',
      message: error.message
    });
  }
});

/**
 * PATCH /api/admin/users/:userId
 * Update user (admin only)
 */
router.patch('/users/:userId', adminMiddleware, async (req, res) => {
  try {
    const userId = req.params.userId;
    const updates = req.body;

    // Mock update - in real implementation, this would update database
    console.log(`Admin ${req.user.id} updated user ${userId}:`, updates);

    res.json({
      success: true,
      message: 'User updated successfully',
      userId: userId,
      updates: updates
    });

  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({
      error: 'Failed to update user',
      message: error.message
    });
  }
});

/**
 * GET /api/admin/analyses
 * Get all analyses (admin only)
 */
router.get('/analyses', adminMiddleware, async (req, res) => {
  try {
    const analysisService = req.app.locals.analysisService;
    
    // Get all analyses from all users
    const allAnalyses = [];
    
    if (analysisService.analysisHistory) {
      for (const [id, analysis] of analysisService.analysisHistory) {
        allAnalyses.push({
          id: analysis.id,
          fileName: analysis.fileName,
          fileSize: analysis.fileSize,
          status: analysis.status,
          progress: analysis.progress,
          createdAt: analysis.createdAt,
          completedAt: analysis.completedAt,
          userId: analysis.userId,
          userName: `User ${analysis.userId}` // Mock username - would come from user lookup
        });
      }
    }

    // Sort by creation date (newest first)
    allAnalyses.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    res.json({
      success: true,
      analyses: allAnalyses
    });

  } catch (error) {
    console.error('Get all analyses error:', error);
    res.status(500).json({
      error: 'Failed to get analyses',
      message: error.message
    });
  }
});

/**
 * DELETE /api/admin/analyses/:analysisId
 * Delete analysis (admin only)
 */
router.delete('/analyses/:analysisId', adminMiddleware, async (req, res) => {
  try {
    const analysisId = req.params.analysisId;
    const analysisService = req.app.locals.analysisService;
    const websocketService = req.app.locals.websocketService;

    // Get analysis to check if it exists
    const analysis = analysisService.analysisHistory.get(analysisId);
    if (!analysis) {
      return res.status(404).json({
        error: 'Analysis not found',
        message: 'The specified analysis does not exist'
      });
    }

    // Delete analysis (admin can delete any analysis)
    await analysisService.deleteAnalysis(analysisId, analysis.userId);

    // Notify connected clients
    websocketService.notifyAnalysisDeleted(analysisId);

    res.json({
      success: true,
      message: 'Analysis deleted successfully',
      analysisId: analysisId
    });

  } catch (error) {
    console.error('Admin delete analysis error:', error);
    res.status(500).json({
      error: 'Failed to delete analysis',
      message: error.message
    });
  }
});

/**
 * GET /api/admin/system/health
 * Get detailed system health information
 */
router.get('/system/health', adminMiddleware, async (req, res) => {
  try {
    const analysisService = req.app.locals.analysisService;
    const websocketService = req.app.locals.websocketService;

    const health = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      services: {
        analysis: {
          status: analysisService.isHealthy() ? 'healthy' : 'unhealthy',
          activeJobs: analysisService.activeAnalyses ? analysisService.activeAnalyses.size : 0,
          totalJobs: analysisService.analysisHistory ? analysisService.analysisHistory.size : 0
        },
        websocket: {
          status: 'healthy',
          connections: websocketService.getConnectionCount ? websocketService.getConnectionCount() : 0
        },
        database: {
          status: 'healthy', // Mock status
          connections: 1
        }
      },
      system: {
        uptime: Math.floor(process.uptime()),
        memory: {
          used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
          total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024)
        },
        cpu: {
          usage: Math.round(os.loadavg()[0] * 100 / os.cpus().length),
          cores: os.cpus().length
        }
      }
    };

    res.json({
      success: true,
      health: health
    });

  } catch (error) {
    console.error('Get system health error:', error);
    res.status(500).json({
      error: 'Failed to get system health',
      message: error.message
    });
  }
});

/**
 * POST /api/admin/system/maintenance
 * Trigger system maintenance tasks
 */
router.post('/system/maintenance', adminMiddleware, async (req, res) => {
  try {
    const { task } = req.body;

    switch (task) {
      case 'cleanup':
        // Mock cleanup task
        console.log('Running cleanup task...');
        break;
      case 'restart':
        // Mock restart task
        console.log('Restarting services...');
        break;
      default:
        return res.status(400).json({
          error: 'Invalid task',
          message: 'Unknown maintenance task'
        });
    }

    res.json({
      success: true,
      message: `Maintenance task '${task}' completed successfully`
    });

  } catch (error) {
    console.error('Maintenance task error:', error);
    res.status(500).json({
      error: 'Failed to execute maintenance task',
      message: error.message
    });
  }
});

module.exports = router;