/**
 * Error Handler Middleware
 * ========================
 * 
 * Global error handling middleware for Express application
 */

const errorHandler = (err, req, res, next) => {
  console.error('Error:', err);

  // Default error response
  let status = 500;
  let message = 'Internal server error';
  let details = null;

  // Handle specific error types
  if (err.name === 'ValidationError') {
    status = 400;
    message = 'Validation error';
    details = err.message;
  } else if (err.name === 'CastError') {
    status = 400;
    message = 'Invalid data format';
    details = err.message;
  } else if (err.code === 11000) {
    status = 409;
    message = 'Duplicate entry';
    details = 'Resource already exists';
  } else if (err.name === 'JsonWebTokenError') {
    status = 401;
    message = 'Invalid token';
    details = err.message;
  } else if (err.name === 'TokenExpiredError') {
    status = 401;
    message = 'Token expired';
    details = 'Please login again';
  } else if (err.status) {
    status = err.status;
    message = err.message;
  } else if (err.message) {
    message = err.message;
  }

  // Don't expose stack trace in production
  const response = {
    error: message,
    status: status
  };

  if (details) {
    response.details = details;
  }

  if (process.env.NODE_ENV === 'development') {
    response.stack = err.stack;
  }

  res.status(status).json(response);
};

module.exports = errorHandler;