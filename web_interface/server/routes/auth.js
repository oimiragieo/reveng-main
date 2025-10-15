/**
 * Authentication Routes
 * =====================
 * 
 * User authentication and authorization endpoints including:
 * - User registration and login
 * - JWT token management
 * - Password reset functionality
 * - User profile management
 */

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const router = express.Router();

// In-memory user store (in production, use a proper database)
const users = new Map();
const sessions = new Map();

// Default admin user
const adminUser = {
  id: 'admin-001',
  username: 'admin',
  email: 'admin@reveng.local',
  password: bcrypt.hashSync('admin123', 10), // Default password
  role: 'admin',
  createdAt: new Date().toISOString(),
  isActive: true
};
users.set(adminUser.id, adminUser);

/**
 * POST /api/auth/register
 * Register new user
 */
router.post('/register', async (req, res) => {
  try {
    const { username, email, password, confirmPassword } = req.body;

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({
        error: 'Missing required fields',
        message: 'Username, email, and password are required'
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        error: 'Password mismatch',
        message: 'Password and confirm password do not match'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: 'Weak password',
        message: 'Password must be at least 6 characters long'
      });
    }

    // Check if user already exists
    const existingUser = Array.from(users.values()).find(
      user => user.username === username || user.email === email
    );

    if (existingUser) {
      return res.status(409).json({
        error: 'User already exists',
        message: 'Username or email already registered'
      });
    }

    // Create new user
    const userId = uuidv4();
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      id: userId,
      username: username,
      email: email,
      password: hashedPassword,
      role: 'user',
      createdAt: new Date().toISOString(),
      isActive: true,
      lastLogin: null
    };

    users.set(userId, newUser);

    // Generate JWT token
    const token = jwt.sign(
      { 
        id: userId, 
        username: username, 
        role: 'user' 
      },
      process.env.JWT_SECRET || 'default-secret',
      { expiresIn: '24h' }
    );

    // Store session
    sessions.set(token, {
      userId: userId,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
    });

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      token: token,
      user: {
        id: userId,
        username: username,
        email: email,
        role: 'user'
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      error: 'Registration failed',
      message: error.message
    });
  }
});

/**
 * POST /api/auth/login
 * User login
 */
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Validation
    if (!username || !password) {
      return res.status(400).json({
        error: 'Missing credentials',
        message: 'Username and password are required'
      });
    }

    // Find user
    const user = Array.from(users.values()).find(
      u => u.username === username || u.email === username
    );

    if (!user) {
      return res.status(401).json({
        error: 'Invalid credentials',
        message: 'Username or password is incorrect'
      });
    }

    if (!user.isActive) {
      return res.status(401).json({
        error: 'Account disabled',
        message: 'Your account has been disabled'
      });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({
        error: 'Invalid credentials',
        message: 'Username or password is incorrect'
      });
    }

    // Update last login
    user.lastLogin = new Date().toISOString();

    // Generate JWT token
    const token = jwt.sign(
      { 
        id: user.id, 
        username: user.username, 
        role: user.role 
      },
      process.env.JWT_SECRET || 'default-secret',
      { expiresIn: '24h' }
    );

    // Store session
    sessions.set(token, {
      userId: user.id,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
    });

    res.json({
      success: true,
      message: 'Login successful',
      token: token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        lastLogin: user.lastLogin
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      error: 'Login failed',
      message: error.message
    });
  }
});

/**
 * POST /api/auth/logout
 * User logout
 */
router.post('/logout', (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');

    if (token && sessions.has(token)) {
      sessions.delete(token);
    }

    res.json({
      success: true,
      message: 'Logout successful'
    });

  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      error: 'Logout failed',
      message: error.message
    });
  }
});

/**
 * GET /api/auth/me
 * Get current user info
 */
router.get('/me', (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');

    if (!token) {
      return res.status(401).json({
        error: 'No token provided',
        message: 'Authorization token is required'
      });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default-secret');
    const user = users.get(decoded.id);

    if (!user) {
      return res.status(401).json({
        error: 'User not found',
        message: 'Invalid token'
      });
    }

    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin
      }
    });

  } catch (error) {
    console.error('Get user error:', error);
    res.status(401).json({
      error: 'Invalid token',
      message: error.message
    });
  }
});

/**
 * POST /api/auth/change-password
 * Change user password
 */
router.post('/change-password', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const { currentPassword, newPassword, confirmPassword } = req.body;

    if (!token) {
      return res.status(401).json({
        error: 'No token provided',
        message: 'Authorization token is required'
      });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default-secret');
    const user = users.get(decoded.id);

    if (!user) {
      return res.status(401).json({
        error: 'User not found',
        message: 'Invalid token'
      });
    }

    // Validation
    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({
        error: 'Missing required fields',
        message: 'Current password, new password, and confirm password are required'
      });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        error: 'Password mismatch',
        message: 'New password and confirm password do not match'
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        error: 'Weak password',
        message: 'New password must be at least 6 characters long'
      });
    }

    // Verify current password
    const isValidPassword = await bcrypt.compare(currentPassword, user.password);

    if (!isValidPassword) {
      return res.status(401).json({
        error: 'Invalid current password',
        message: 'Current password is incorrect'
      });
    }

    // Update password
    user.password = await bcrypt.hash(newPassword, 10);

    res.json({
      success: true,
      message: 'Password changed successfully'
    });

  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({
      error: 'Password change failed',
      message: error.message
    });
  }
});

/**
 * GET /api/auth/sessions
 * Get active sessions (admin only)
 */
router.get('/sessions', (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');

    if (!token) {
      return res.status(401).json({
        error: 'No token provided',
        message: 'Authorization token is required'
      });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default-secret');
    const user = users.get(decoded.id);

    if (!user || user.role !== 'admin') {
      return res.status(403).json({
        error: 'Access denied',
        message: 'Admin access required'
      });
    }

    // Get all active sessions
    const activeSessions = [];
    for (const [sessionToken, session] of sessions) {
      const sessionUser = users.get(session.userId);
      if (sessionUser) {
        activeSessions.push({
          token: sessionToken.substring(0, 10) + '...',
          userId: session.userId,
          username: sessionUser.username,
          createdAt: session.createdAt,
          expiresAt: session.expiresAt
        });
      }
    }

    res.json({
      success: true,
      sessions: activeSessions,
      totalSessions: activeSessions.length
    });

  } catch (error) {
    console.error('Get sessions error:', error);
    res.status(500).json({
      error: 'Failed to get sessions',
      message: error.message
    });
  }
});

module.exports = router;