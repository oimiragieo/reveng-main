/**
 * Analysis Routes
 * ===============
 * 
 * REST API endpoints for binary analysis operations including:
 * - File upload and validation
 * - Analysis job management
 * - Real-time progress tracking
 * - Result retrieval and export
 */

const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const authMiddleware = require('../middleware/auth');

const router = express.Router();

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '../../uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${uuidv4()}-${file.originalname}`;
    cb(null, uniqueName);
  }
});

const fileFilter = (req, file, cb) => {
  // Allow all file types for binary analysis
  cb(null, true);
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 100 * 1024 * 1024, // 100MB limit
    files: 1
  }
});

/**
 * POST /api/analysis/upload
 * Upload binary file for analysis
 */
router.post('/upload', authMiddleware, upload.single('binary'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        error: 'No file uploaded',
        message: 'Please select a binary file to upload'
      });
    }

    const analysisService = req.app.locals.analysisService;
    const websocketService = req.app.locals.websocketService;

    // Create analysis job
    const analysisJob = await analysisService.createAnalysisJob({
      userId: req.user.id,
      fileName: req.file.originalname,
      filePath: req.file.path,
      fileSize: req.file.size,
      mimeType: req.file.mimetype,
      analysisConfig: req.body.config ? JSON.parse(req.body.config) : {}
    });

    // Notify connected clients
    websocketService.notifyAnalysisCreated(analysisJob);

    res.status(201).json({
      success: true,
      message: 'File uploaded successfully',
      analysisId: analysisJob.id,
      analysis: analysisJob
    });

  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({
      error: 'Upload failed',
      message: error.message
    });
  }
});

/**
 * POST /api/analysis/:id/start
 * Start analysis for uploaded file
 */
router.post('/:id/start', authMiddleware, async (req, res) => {
  try {
    const analysisId = req.params.id;
    const analysisService = req.app.locals.analysisService;
    const websocketService = req.app.locals.websocketService;

    // Start analysis
    const result = await analysisService.startAnalysis(analysisId, req.user.id);

    // Notify connected clients
    websocketService.notifyAnalysisStarted(analysisId);

    res.json({
      success: true,
      message: 'Analysis started successfully',
      analysisId: analysisId,
      status: result.status
    });

  } catch (error) {
    console.error('Start analysis error:', error);
    res.status(500).json({
      error: 'Failed to start analysis',
      message: error.message
    });
  }
});

/**
 * GET /api/analysis/:id/status
 * Get analysis status and progress
 */
router.get('/:id/status', authMiddleware, async (req, res) => {
  try {
    const analysisId = req.params.id;
    const analysisService = req.app.locals.analysisService;

    const status = await analysisService.getAnalysisStatus(analysisId, req.user.id);

    res.json({
      success: true,
      analysisId: analysisId,
      status: status
    });

  } catch (error) {
    console.error('Status check error:', error);
    res.status(500).json({
      error: 'Failed to get analysis status',
      message: error.message
    });
  }
});

/**
 * GET /api/analysis/:id/results
 * Get analysis results
 */
router.get('/:id/results', authMiddleware, async (req, res) => {
  try {
    const analysisId = req.params.id;
    const analysisService = req.app.locals.analysisService;

    const results = await analysisService.getAnalysisResults(analysisId, req.user.id);

    res.json({
      success: true,
      analysisId: analysisId,
      results: results
    });

  } catch (error) {
    console.error('Results retrieval error:', error);
    res.status(500).json({
      error: 'Failed to get analysis results',
      message: error.message
    });
  }
});

/**
 * GET /api/analysis/:id/export/:format
 * Export analysis results in specified format
 */
router.get('/:id/export/:format', authMiddleware, async (req, res) => {
  try {
    const analysisId = req.params.id;
    const format = req.params.format;
    const analysisService = req.app.locals.analysisService;

    const exportData = await analysisService.exportResults(analysisId, format, req.user.id);

    // Set appropriate headers based on format
    const contentTypes = {
      'json': 'application/json',
      'xml': 'application/xml',
      'pdf': 'application/pdf',
      'csv': 'text/csv'
    };

    const extensions = {
      'json': 'json',
      'xml': 'xml', 
      'pdf': 'pdf',
      'csv': 'csv'
    };

    res.setHeader('Content-Type', contentTypes[format] || 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="analysis-${analysisId}.${extensions[format]}"`);

    if (format === 'pdf') {
      res.send(exportData);
    } else {
      res.json(exportData);
    }

  } catch (error) {
    console.error('Export error:', error);
    res.status(500).json({
      error: 'Failed to export results',
      message: error.message
    });
  }
});

/**
 * DELETE /api/analysis/:id
 * Delete analysis and associated files
 */
router.delete('/:id', authMiddleware, async (req, res) => {
  try {
    const analysisId = req.params.id;
    const analysisService = req.app.locals.analysisService;
    const websocketService = req.app.locals.websocketService;

    await analysisService.deleteAnalysis(analysisId, req.user.id);

    // Notify connected clients
    websocketService.notifyAnalysisDeleted(analysisId);

    res.json({
      success: true,
      message: 'Analysis deleted successfully',
      analysisId: analysisId
    });

  } catch (error) {
    console.error('Delete analysis error:', error);
    res.status(500).json({
      error: 'Failed to delete analysis',
      message: error.message
    });
  }
});

/**
 * GET /api/analysis/user
 * Get all analyses for current user
 */
router.get('/user', authMiddleware, async (req, res) => {
  try {
    const analysisService = req.app.locals.analysisService;
    const analyses = await analysisService.getUserAnalyses(req.user.id);

    res.json({
      success: true,
      userId: req.user.id,
      analyses: analyses
    });

  } catch (error) {
    console.error('Get user analyses error:', error);
    res.status(500).json({
      error: 'Failed to get user analyses',
      message: error.message
    });
  }
});

/**
 * GET /api/analysis/user/:userId
 * Get all analyses for a user (admin only)
 */
router.get('/user/:userId', authMiddleware, async (req, res) => {
  try {
    const userId = req.params.userId;
    const analysisService = req.app.locals.analysisService;

    // Ensure user can only access their own analyses (or admin)
    if (req.user.id !== userId && req.user.role !== 'admin') {
      return res.status(403).json({
        error: 'Access denied',
        message: 'You can only access your own analyses'
      });
    }

    const analyses = await analysisService.getUserAnalyses(userId);

    res.json({
      success: true,
      userId: userId,
      analyses: analyses
    });

  } catch (error) {
    console.error('Get user analyses error:', error);
    res.status(500).json({
      error: 'Failed to get user analyses',
      message: error.message
    });
  }
});

/**
 * POST /api/analysis/:id/share
 * Share analysis with other users
 */
router.post('/:id/share', authMiddleware, async (req, res) => {
  try {
    const analysisId = req.params.id;
    const { userIds, permissions } = req.body;
    const analysisService = req.app.locals.analysisService;
    const websocketService = req.app.locals.websocketService;

    const shareResult = await analysisService.shareAnalysis(
      analysisId, 
      req.user.id, 
      userIds, 
      permissions
    );

    // Notify shared users
    websocketService.notifyAnalysisShared(analysisId, userIds);

    res.json({
      success: true,
      message: 'Analysis shared successfully',
      analysisId: analysisId,
      sharedWith: shareResult.sharedWith
    });

  } catch (error) {
    console.error('Share analysis error:', error);
    res.status(500).json({
      error: 'Failed to share analysis',
      message: error.message
    });
  }
});

/**
 * POST /api/analysis/:id/comment
 * Add comment to analysis (collaboration feature)
 */
router.post('/:id/comment', authMiddleware, async (req, res) => {
  try {
    const analysisId = req.params.id;
    const { comment, section } = req.body;
    const analysisService = req.app.locals.analysisService;
    const websocketService = req.app.locals.websocketService;

    const commentResult = await analysisService.addComment(
      analysisId,
      req.user.id,
      comment,
      section
    );

    // Notify collaborators in real-time
    websocketService.notifyNewComment(analysisId, commentResult);

    res.json({
      success: true,
      message: 'Comment added successfully',
      comment: commentResult
    });

  } catch (error) {
    console.error('Add comment error:', error);
    res.status(500).json({
      error: 'Failed to add comment',
      message: error.message
    });
  }
});

module.exports = router;