// routes/auth.js
const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

// Rate limiting for authentication routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: {
    success: false,
    error: 'Too many attempts',
    message: 'Too many authentication attempts, please try again later'
  }
});

// @route   POST api/auth/register
// @desc    Register a user
// @access  Public
router.post('/register', [
  // Input validation
  check('name', 'Name is required').not().isEmpty(),
  check('name', 'Name must be less than 50 characters').isLength({ max: 50 }),
  check('email', 'Please include a valid email').isEmail(),
  check('password', 'Password is required').exists(),
  check('password', 'Password must be at least 6 characters').isLength({ min: 6 }),
  check('role', 'Invalid role').optional().isIn(['employee', 'ceo', 'cto', 'cfo', 'coo'])
], authLimiter, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation Error',
      message: 'Invalid input data',
      errors: errors.array()
    });
  }

  const { name, email, password, role } = req.body;
  
  try {
    // Check if user already exists
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({
        success: false,
        error: 'UserExistsError',
        message: 'User with this email already exists'
      });
    }
    
    // Create new user
    user = new User({
      name,
      email,
      password,
      role: role || 'employee'
    });
    
    // Save user (password will be hashed by pre-save hook)
    await user.save();
    
    // Generate JWT token
    const token = user.getSignedJwtToken();
    
    // Return response
    res.status(201).json({
      success: true,
      token,
      user: { 
        id: user.id, 
        name: user.name, 
        email: user.email, 
        role: user.role,
        department: user.department
      }
    });
  } catch (err) {
    console.error('Registration error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error during registration'
    });
  }
});

// @route   POST api/auth/login
// @desc    Authenticate user & get token
// @access  Public
router.post('/login', [
  // Input validation
  check('email', 'Please include a valid email').isEmail(),
  check('password', 'Password is required').exists()
], authLimiter, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation Error',
      message: 'Invalid input data',
      errors: errors.array()
    });
  }

  const { email, password } = req.body;
  
  try {
    // Check if user exists
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'InvalidCredentials',
        message: 'Invalid email or password'
      });
    }
    
    // Validate password
    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        error: 'InvalidCredentials',
        message: 'Invalid email or password'
      });
    }
    
    // Update login information
    await user.updateLoginInfo();
    
    // Generate JWT token
    const token = user.getSignedJwtToken();
    
    // Return response
    res.json({
      success: true,
      token,
      user: { 
        id: user.id, 
        name: user.name, 
        email: user.email, 
        role: user.role,
        department: user.department,
        lastLogin: user.lastLogin
      }
    });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error during login'
    });
  }
});

// @route   GET api/auth/current
// @desc    Get current logged in user
// @access  Private
router.get('/current', async (req, res) => {
  try {
    // Get token from header
    const token = req.header('x-auth-token') || 
                 req.headers.authorization?.split(' ')[1] || 
                 req.cookies?.token;
    
    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'NoToken',
        message: 'No token, authorization denied'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Get user from database
    const user = await User.findById(decoded.id).select('-password');
    
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'UserNotFound',
        message: 'User not found'
      });
    }
    
    // Return user data
    res.json({
      success: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        department: user.department,
        isActive: user.isActive,
        lastLogin: user.lastLogin,
        createdAt: user.createdAt
      }
    });
  } catch (err) {
    console.error('Get current user error:', err.message);
    res.status(401).json({
      success: false,
      error: 'TokenError',
      message: 'Token is not valid'
    });
  }
});

// @route   POST api/auth/logout
// @desc    Logout user (invalidate token)
// @access  Private
router.post('/logout', async (req, res) => {
  try {
    // In a stateless JWT system, logout is typically handled client-side
    // For true logout, you would need to implement token blacklisting
    res.json({
      success: true,
      message: 'User logged out successfully'
    });
  } catch (err) {
    console.error('Logout error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error during logout'
    });
  }
});

// @route   POST api/auth/forgot-password
// @desc    Send password reset email
// @access  Public
router.post('/forgot-password', [
  check('email', 'Please include a valid email').isEmail()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation Error',
      message: 'Invalid input data',
      errors: errors.array()
    });
  }

  const { email } = req.body;
  
  try {
    const user = await User.findOne({ email });
    
    if (!user) {
      // Don't reveal that user doesn't exist for security
      return res.json({
        success: true,
        message: 'If an account with that email exists, a reset link has been sent'
      });
    }
    
    // Generate reset token
    const resetToken = user.getResetPasswordToken();
    await user.save({ validateBeforeSave: false });
    
    // Create reset URL
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
    
    // In a real app, you would send an email here
    console.log('Reset URL:', resetUrl);
    
    res.json({
      success: true,
      message: 'Password reset email sent'
    });
  } catch (err) {
    console.error('Forgot password error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error during password reset'
    });
  }
});

// @route   POST api/auth/reset-password/:token
// @desc    Reset password
// @access  Public
router.post('/reset-password/:token', [
  check('password', 'Password is required').exists(),
  check('password', 'Password must be at least 6 characters').isLength({ min: 6 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation Error',
      message: 'Invalid input data',
      errors: errors.array()
    });
  }

  const { password } = req.body;
  const { token } = req.params;
  
  try {
    // Hash token to compare with stored token
    const resetPasswordToken = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');
    
    // Find user by token and check if token is still valid
    const user = await User.findOne({
      resetPasswordToken,
      resetPasswordExpire: { $gt: Date.now() }
    });
    
    if (!user) {
      return res.status(400).json({
        success: false,
        error: 'InvalidToken',
        message: 'Invalid or expired reset token'
      });
    }
    
    // Set new password
    user.password = password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    
    await user.save();
    
    res.json({
      success: true,
      message: 'Password has been reset successfully'
    });
  } catch (err) {
    console.error('Reset password error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error during password reset'
    });
  }
});

module.exports = router;