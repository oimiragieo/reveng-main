/**
 * Users Routes
 * ============
 * 
 * User management endpoints
 */

const express = require('express');

const router = express.Router();

/**
 * GET /api/users/profile
 * Get user profile
 */
router.get('/profile', async (req, res) => {
  try {
    res.json({
      success: true,
      user: {
        id: req.user.id,
        username: req.user.username,
        role: req.user.role
      }
    });

  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      error: 'Failed to get profile',
      message: error.message
    });
  }
});

module.exports = router;