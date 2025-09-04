//routes/users.js
const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const auth = require('../middleware/auth');
const authorize = require('../middleware/authorize');
const rateLimit = require('express-rate-limit');

// Rate limiting for user management operations
const userManagementLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 requests per windowMs
  message: {
    success: false,
    error: 'Too many requests',
    message: 'Too many user management attempts, please try again later'
  }
});

// @route   GET api/users
// @desc    Get all users (Admin only) with pagination and filtering
// @access  Private (Admin only)
router.get('/', [
  auth,
  authorize('ceo', 'cto', 'cfo', 'coo'),
  userManagementLimiter
], async (req, res) => {
  try {
    const { page = 1, limit = 10, role, department, isActive } = req.query;
    
    // Build query
    let query = {};
    if (role) query.role = role;
    if (department) query.department = department;
    if (isActive !== undefined) query.isActive = isActive === 'true';
    
    // Calculate pagination
    const skip = (page - 1) * limit;
    
    // Execute query with pagination
    const users = await User.find(query)
      .select('-password -resetPasswordToken -resetPasswordExpire')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(skip);
    
    // Get total count for pagination
    const total = await User.countDocuments(query);
    
    res.json({
      success: true,
      users,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error('Get users error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error fetching users'
    });
  }
});

// @route   GET api/users/profile
// @desc    Get current user profile
// @access  Private
router.get('/profile', auth, async (req, res) => {
  try {
    // Get fresh user data from database
    const user = await User.findById(req.user.id)
      .select('-password -resetPasswordToken -resetPasswordExpire');
    
    res.json({
      success: true,
      user
    });
  } catch (err) {
    console.error('Get profile error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error fetching profile'
    });
  }
});

// @route   GET api/users/:id
// @desc    Get single user by ID (Admin only)
// @access  Private (Admin only)
router.get('/:id', [
  auth,
  authorize('ceo', 'cto', 'cfo', 'coo')
], async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password -resetPasswordToken -resetPasswordExpire');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'NotFound',
        message: 'User not found'
      });
    }
    
    res.json({
      success: true,
      user
    });
  } catch (err) {
    console.error('Get user error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error fetching user'
    });
  }
});

// @route   POST api/users
// @desc    Create new user (Admin only)
// @access  Private (Admin only)
router.post('/', [
  auth,
  authorize('ceo', 'cto', 'cfo', 'coo'),
  userManagementLimiter,
  check('name', 'Name is required').not().isEmpty(),
  check('name', 'Name must be less than 50 characters').isLength({ max: 50 }),
  check('email', 'Please include a valid email').isEmail(),
  check('password', 'Password is required').exists(),
  check('password', 'Password must be at least 6 characters').isLength({ min: 6 }),
  check('role', 'Invalid role').isIn(['employee', 'ceo', 'cto', 'cfo', 'coo']),
  check('department', 'Invalid department').optional().isIn(['HR', 'Finance', 'IT', 'Operations', 'Marketing', 'Sales', 'Legal', 'Other'])
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

  try {
    const { name, email, password, role, department } = req.body;
    
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: 'UserExistsError',
        message: 'Email already in use'
      });
    }
    
    // Create new user
    const user = new User({
      name,
      email,
      password,
      role: role || 'employee',
      department: department || 'Other'
    });
    
    const newUser = await user.save();
    
    res.status(201).json({
      success: true,
      user: {
        _id: newUser._id,
        name: newUser.name,
        email: newUser.email,
        role: newUser.role,
        department: newUser.department,
        isActive: newUser.isActive,
        createdAt: newUser.createdAt
      }
    });
  } catch (err) {
    console.error('Create user error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error creating user'
    });
  }
});

// @route   PUT api/users/:id
// @desc    Update user by ID (Admin only)
// @access  Private (Admin only)
router.put('/:id', [
  auth,
  authorize('ceo', 'cto', 'cfo', 'coo'),
  userManagementLimiter,
  check('name', 'Name must be less than 50 characters').optional().isLength({ max: 50 }),
  check('email', 'Please include a valid email').optional().isEmail(),
  check('role', 'Invalid role').optional().isIn(['employee', 'ceo', 'cto', 'cfo', 'coo']),
  check('department', 'Invalid department').optional().isIn(['HR', 'Finance', 'IT', 'Operations', 'Marketing', 'Sales', 'Legal', 'Other'])
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

  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'NotFound',
        message: 'User not found'
      });
    }
    
    // Update fields if provided
    const { name, email, role, department, isActive } = req.body;
    
    if (name) user.name = name;
    if (email) user.email = email;
    if (role) user.role = role;
    if (department) user.department = department;
    if (isActive !== undefined) user.isActive = isActive;
    
    const updatedUser = await user.save();
    
    res.json({
      success: true,
      user: {
        _id: updatedUser._id,
        name: updatedUser.name,
        email: updatedUser.email,
        role: updatedUser.role,
        department: updatedUser.department,
        isActive: updatedUser.isActive,
        updatedAt: updatedUser.updatedAt
      }
    });
  } catch (err) {
    console.error('Update user error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error updating user'
    });
  }
});

// @route   PUT api/users/:id/password
// @desc    Reset user password (Admin only)
// @access  Private (Admin only)
router.put('/:id/password', [
  auth,
  authorize('ceo', 'cto', 'cfo', 'coo'),
  userManagementLimiter,
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

  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'NotFound',
        message: 'User not found'
      });
    }
    
    // Update password
    user.password = req.body.password;
    await user.save();
    
    res.json({
      success: true,
      message: 'Password reset successfully'
    });
  } catch (err) {
    console.error('Reset password error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error resetting password'
    });
  }
});

// @route   PUT api/users/:id/activate
// @desc    Activate user account (Admin only)
// @access  Private (Admin only)
router.put('/:id/activate', [
  auth,
  authorize('ceo', 'cto', 'cfo', 'coo'),
  userManagementLimiter
], async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'NotFound',
        message: 'User not found'
      });
    }
    
    // Activate user
    user.isActive = true;
    await user.save();
    
    res.json({
      success: true,
      message: 'User activated successfully',
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        isActive: user.isActive
      }
    });
  } catch (err) {
    console.error('Activate user error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error activating user'
    });
  }
});

// @route   PUT api/users/:id/deactivate
// @desc    Deactivate user account (Admin only)
// @access  Private (Admin only)
router.put('/:id/deactivate', [
  auth,
  authorize('ceo', 'cto', 'cfo', 'coo'),
  userManagementLimiter
], async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'NotFound',
        message: 'User not found'
      });
    }
    
    // Deactivate user
    user.isActive = false;
    await user.save();
    
    res.json({
      success: true,
      message: 'User deactivated successfully',
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        isActive: user.isActive
      }
    });
  } catch (err) {
    console.error('Deactivate user error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error deactivating user'
    });
  }
});

// @route   DELETE api/users/:id
// @desc    Soft delete user (Admin only)
// @access  Private (Admin only)
router.delete('/:id', [
  auth,
  authorize('ceo', 'cto', 'cfo', 'coo'),
  userManagementLimiter
], async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'NotFound',
        message: 'User not found'
      });
    }
    
    // Soft delete - mark as inactive
    user.isActive = false;
    await user.save();
    
    res.json({
      success: true,
      message: 'User deactivated successfully'
    });
  } catch (err) {
    console.error('Delete user error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error deactivating user'
    });
  }
});

module.exports = router;