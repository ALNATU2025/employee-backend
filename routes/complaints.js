// routes/complaints.js
const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator');
const multer = require('multer');
const path = require('path');
const auth = require('../middleware/auth');
const authorize = require('../middleware/authorize');
const Complaint = require('../models/Complaint');
const User = require('../models/User');

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/complaints/');
  },
  filename: function (req, file, cb) {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: function (req, file, cb) {
    const allowedFileTypes = ['.pdf', '.doc', '.docx', '.jpg', '.jpeg', '.png', '.txt'];
    const extname = path.extname(file.originalname).toLowerCase();
    
    if (allowedFileTypes.includes(extname)) {
      return cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only PDF, DOC, DOCX, JPG, JPEG, PNG, and TXT files are allowed.'));
    }
  }
});

// @route   POST api/complaints
// @desc    Create a new complaint
// @access  Private
router.post('/', [
  auth,
  upload.array('attachments', 5), // Max 5 files
  check('title', 'Title is required').not().isEmpty(),
  check('title', 'Title must be less than 100 characters').isLength({ max: 100 }),
  check('description', 'Description is required').not().isEmpty(),
  check('description', 'Description must be less than 2000 characters').isLength({ max: 2000 }),
  check('category', 'Category is required').isIn(['harassment', 'discrimination', 'workplace_safety', 'unfair_treatment', 'pay_dispute', 'work_conditions', 'management', 'other']),
  check('priority', 'Priority must be low, medium, high, or urgent').optional().isIn(['low', 'medium', 'high', 'urgent']),
  check('severity', 'Severity must be minor, moderate, major, or critical').optional().isIn(['minor', 'moderate', 'major', 'critical']),
  check('isAnonymous', 'IsAnonymous must be a boolean').optional().isBoolean(),
  check('isConfidential', 'IsConfidential must be a boolean').optional().isBoolean()
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
    const { title, description, category, priority, severity, isAnonymous, isConfidential } = req.body;
    
    // Process attachments
    const attachments = req.files ? req.files.map(file => ({
      filename: file.filename,
      originalName: file.originalname,
      path: file.path,
      size: file.size,
      mimetype: file.mimetype
    })) : [];
    
    // Create new complaint
    const newComplaint = new Complaint({
      employeeId: isAnonymous ? null : req.user.id,
      title,
      description,
      category,
      priority: priority || 'medium',
      severity: severity || 'moderate',
      isAnonymous: isAnonymous || false,
      isConfidential: isConfidential !== false, // Default to true unless explicitly set to false
      attachments,
      lastUpdatedBy: req.user.id
    });
    
    const complaint = await newComplaint.save();
    await complaint.populate('employeeId', ['name', 'email', 'department']);
    
    res.status(201).json({
      success: true,
      complaint
    });
  } catch (err) {
    console.error('Create complaint error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error creating complaint'
    });
  }
});

// @route   GET api/complaints
// @desc    Get all complaints (filtered by role and query parameters)
// @access  Private
router.get('/', auth, async (req, res) => {
  try {
    const { page = 1, limit = 10, status, category, priority, severity, sort = 'createdAt' } = req.query;
    
    // Build query based on user role
    let query = {};
    
    // CEO and HR can see all complaints
    if (req.user.role === 'ceo' || req.user.department === 'HR') {
      // No filter needed
    } 
    // Employees can see only their own complaints
    else if (req.user.role === 'employee') {
      query.employeeId = req.user.id;
    }
    // Other executives see only complaints in their department
    else {
      query.department = req.user.department;
    }
    
    // Add filters from query parameters
    if (status) query.status = status;
    if (category) query.category = category;
    if (priority) query.priority = priority;
    if (severity) query.severity = severity;
    
    // Calculate pagination
    const skip = (page - 1) * limit;
    
    // Execute query with pagination
    const complaints = await Complaint.find(query)
      .populate('employeeId', ['name', 'email', 'department'])
      .populate('assignedTo', ['name', 'email', 'department'])
      .sort({ [sort]: -1 })
      .limit(parseInt(limit))
      .skip(skip);
    
    // Get total count for pagination
    const total = await Complaint.countDocuments(query);
    
    res.json({
      success: true,
      complaints,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error('Get complaints error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error fetching complaints'
    });
  }
});

// @route   GET api/complaints/:id
// @desc    Get a complaint by ID
// @access  Private
router.get('/:id', auth, async (req, res) => {
  try {
    const complaint = await Complaint.findById(req.params.id)
      .populate('employeeId', ['name', 'email', 'department'])
      .populate('assignedTo', ['name', 'email', 'department'])
      .populate('resolvedBy', ['name', 'email']);
    
    if (!complaint) {
      return res.status(404).json({
        success: false,
        error: 'NotFound',
        message: 'Complaint not found'
      });
    }
    
    // Check if user has permission to view this complaint
    const hasAccess = checkComplaintAccess(req.user, complaint);
    if (!hasAccess) {
      return res.status(403).json({
        success: false,
        error: 'AccessDenied',
        message: 'You do not have permission to view this complaint'
      });
    }
    
    res.json({
      success: true,
      complaint
    });
  } catch (err) {
    console.error('Get complaint error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error fetching complaint'
    });
  }
});

// @route   PUT api/complaints/:id
// @desc    Update a complaint
// @access  Private
router.put('/:id', [
  auth,
  upload.array('attachments', 5),
  check('title', 'Title must be less than 100 characters').optional().isLength({ max: 100 }),
  check('description', 'Description must be less than 2000 characters').optional().isLength({ max: 2000 }),
  check('category', 'Category must be valid').optional().isIn(['harassment', 'discrimination', 'workplace_safety', 'unfair_treatment', 'pay_dispute', 'work_conditions', 'management', 'other']),
  check('priority', 'Priority must be low, medium, high, or urgent').optional().isIn(['low', 'medium', 'high', 'urgent']),
  check('severity', 'Severity must be minor, moderate, major, or critical').optional().isIn(['minor', 'moderate', 'major', 'critical']),
  check('status', 'Status must be valid').optional().isIn(['pending', 'under_review', 'investigation', 'action_required', 'resolved', 'dismissed', 'escalated'])
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
    const complaint = await Complaint.findById(req.params.id);
    
    if (!complaint) {
      return res.status(404).json({
        success: false,
        error: 'NotFound',
        message: 'Complaint not found'
      });
    }
    
    // Check if user has permission to update this complaint
    const hasAccess = checkComplaintAccess(req.user, complaint);
    if (!hasAccess) {
      return res.status(403).json({
        success: false,
        error: 'AccessDenied',
        message: 'You do not have permission to update this complaint'
      });
    }
    
    // Update fields
    const { title, description, category, priority, severity, status } = req.body;
    
    if (title) complaint.title = title;
    if (description) complaint.description = description;
    if (category) complaint.category = category;
    if (priority) complaint.priority = priority;
    if (severity) complaint.severity = severity;
    if (status) complaint.status = status;
    
    // Handle new attachments
    if (req.files && req.files.length > 0) {
      const newAttachments = req.files.map(file => ({
        filename: file.filename,
        originalName: file.originalname,
        path: file.path,
        size: file.size,
        mimetype: file.mimetype
      }));
      complaint.attachments = [...complaint.attachments, ...newAttachments];
    }
    
    // Set last modified by
    complaint.lastUpdatedBy = req.user.id;
    
    const updatedComplaint = await complaint.save();
    await updatedComplaint.populate('employeeId', ['name', 'email', 'department']);
    await updatedComplaint.populate('assignedTo', ['name', 'email', 'department']);
    
    res.json({
      success: true,
      complaint: updatedComplaint
    });
  } catch (err) {
    console.error('Update complaint error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error updating complaint'
    });
  }
});

// @route   POST api/complaints/:id/status
// @desc    Update complaint status
// @access  Private (HR and Executives only)
router.post('/:id/status', [
  auth,
  authorize('ceo', 'cto', 'cfo', 'coo', 'employee'),
  check('status', 'Status is required').isIn(['pending', 'under_review', 'investigation', 'action_required', 'resolved', 'dismissed', 'escalated']),
  check('comments', 'Comments must be less than 500 characters').optional().isLength({ max: 500 })
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
    const complaint = await Complaint.findById(req.params.id);
    
    if (!complaint) {
      return res.status(404).json({
        success: false,
        error: 'NotFound',
        message: 'Complaint not found'
      });
    }
    
    // Check if user has permission to update this complaint
    const hasAccess = checkComplaintAccess(req.user, complaint);
    if (!hasAccess) {
      return res.status(403).json({
        success: false,
        error: 'AccessDenied',
        message: 'You do not have permission to update this complaint'
      });
    }
    
    const { status, comments } = req.body;
    
    // Update status using the model method
    await complaint.updateStatus(status, req.user.id, comments);
    
    // Get updated complaint with populated fields
    const updatedComplaint = await Complaint.findById(complaint._id)
      .populate('employeeId', ['name', 'email', 'department'])
      .populate('assignedTo', ['name', 'email', 'department'])
      .populate('resolvedBy', ['name', 'email']);
    
    res.json({
      success: true,
      complaint: updatedComplaint
    });
  } catch (err) {
    console.error('Update complaint status error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error updating complaint status'
    });
  }
});

// @route   GET api/complaints/high-priority
// @desc    Get high-priority complaints
// @access  Private (HR and Executives only)
router.get('/filter/high-priority', [
  auth,
  authorize('ceo', 'cto', 'cfo', 'coo', 'employee')
], async (req, res) => {
  try {
    const highPriorityComplaints = await Complaint.findHighPriority()
      .populate('employeeId', ['name', 'email', 'department'])
      .populate('assignedTo', ['name', 'email', 'department']);
    
    res.json({
      success: true,
      complaints: highPriorityComplaints,
      count: highPriorityComplaints.length
    });
  } catch (err) {
    console.error('Get high-priority complaints error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error fetching high-priority complaints'
    });
  }
});

// @route   GET api/complaints/overdue
// @desc    Get overdue complaints
// @access  Private (HR and Executives only)
router.get('/filter/overdue', [
  auth,
  authorize('ceo', 'cto', 'cfo', 'coo', 'employee')
], async (req, res) => {
  try {
    const overdueComplaints = await Complaint.findOverdue()
      .populate('employeeId', ['name', 'email', 'department'])
      .populate('assignedTo', ['name', 'email', 'department']);
    
    res.json({
      success: true,
      complaints: overdueComplaints,
      count: overdueComplaints.length
    });
  } catch (err) {
    console.error('Get overdue complaints error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error fetching overdue complaints'
    });
  }
});

// Helper function to check complaint access
function checkComplaintAccess(user, complaint) {
  // CEO can access all complaints
  if (user.role === 'ceo') {
    return true;
  }
  
  // HR can access all complaints
  if (user.department === 'HR') {
    return true;
  }
  
  // Employees can only access their own complaints
  if (user.role === 'employee') {
    return complaint.employeeId && complaint.employeeId._id.toString() === user.id;
  }
  
  // Other executives can access complaints in their department
  if (['cto', 'cfo', 'coo'].includes(user.role)) {
    return complaint.employeeId && complaint.employeeId.department === user.department;
  }
  
  // All other roles are denied
  return false;
}

module.exports = router;