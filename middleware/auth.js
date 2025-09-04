// middleware/auth.js
const jwt = require('jsonwebtoken');
const User = require('../models/User');

module.exports = async function (req, res, next) {
  // Get token from header, cookie, or authorization header
  let token;
  
  // Check Authorization header first (Bearer token)
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  }
  // Check x-auth-token header
  else if (req.header('x-auth-token')) {
    token = req.header('x-auth-token');
  }
  // Check cookie
  else if (req.cookies && req.cookies.token) {
    token = req.cookies.token;
  }
  
  // Check if not token
  if (!token) {
    return res.status(401).json({ 
      success: false,
      error: 'No token provided',
      message: 'Authorization denied - No token found'
    });
  }
  
  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Add user from payload
    req.user = await User.findById(decoded.id).select('-password');
    
    // Check if user exists
    if (!req.user) {
      return res.status(401).json({ 
        success: false,
        error: 'User not found',
        message: 'Token is not valid - User does not exist'
      });
    }
    
    // Check if user is active
    if (!req.user.isActive) {
      return res.status(401).json({ 
        success: false,
        error: 'Account deactivated',
        message: 'Your account has been deactivated. Please contact administrator.'
      });
    }
    
    next();
  } catch (err) {
    console.error('Authentication error:', {
      error: err.message,
      stack: err.stack,
      token: token.substring(0, 10) + '...' // Log only part of token for security
    });
    
    // Handle specific JWT errors
    let errorMessage = 'Token is not valid';
    if (err.name === 'TokenExpiredError') {
      errorMessage = 'Token expired - Please login again';
    } else if (err.name === 'JsonWebTokenError') {
      errorMessage = 'Invalid token format';
    } else if (err.name === 'NotBeforeError') {
      errorMessage = 'Token not active yet';
    }
    
    res.status(401).json({ 
      success: false,
      error: err.name || 'AuthenticationError',
      message: errorMessage
    });
  }
};