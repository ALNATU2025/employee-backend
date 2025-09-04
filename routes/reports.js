// routes/reports.js
const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator');
const multer = require('multer');
const path = require('path');
const auth = require('../middleware/auth');
const authorize = require('../middleware/authorize');
const Report = require('../models/Report');
const User = require('../models/User');

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/reports/');
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
    const allowedFileTypes = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt'];
    const extname = path.extname(file.originalname).toLowerCase();
    
    if (allowedFileTypes.includes(extname)) {
      return cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX, and TXT files are allowed.'));
    }
  }
});

// @route   POST api/reports
// @desc    Create a new report
// @access  Private (Employee only)
router.post('/', [
  auth,
  authorize('employee'),
  upload.array('attachments', 5), // Max 5 files
  check('title', 'Title is required').not().isEmpty(),
  check('title', 'Title must be less than 100 characters').isLength({ max: 100 }),
  check('content', 'Content is required').not().isEmpty(),
  check('content', 'Content must be less than 5000 characters').isLength({ max: 5000 }),
  check('category', 'Category is required').isIn(['technical', 'financial', 'operations', 'hr', 'marketing', 'legal']),
  check('priority', 'Priority must be low, medium, high, or critical').optional().isIn(['low', 'medium', 'high', 'critical']),
  check('department', 'Department is required').isIn(['HR', 'Finance', 'IT', 'Operations', 'Marketing', 'Sales', 'Legal', 'Other']),
  check('dueDate', 'Due date must be a valid date').optional().isISO8601()
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
    const { title, content, category, priority, department, dueDate, tags } = req.body;
    
    // Process attachments
    const attachments = req.files ? req.files.map(file => ({
      filename: file.filename,
      originalName: file.originalname,
      path: file.path,
      size: file.size,
      mimetype: file.mimetype
    })) : [];
    
    // Create new report
    const newReport = new Report({
      employeeId: req.user.id,
      title,
      content,
      category,
      priority: priority || 'medium',
      department,
      dueDate: dueDate || null,
      tags: tags ? tags.split(',').map(tag => tag.trim()) : [],
      attachments,
      lastModifiedBy: req.user.id
    });
    
    const report = await newReport.save();
    await report.populate('employeeId', ['name', 'email', 'department']);
    
    res.status(201).json({
      success: true,
      report
    });
  } catch (err) {
    console.error('Create report error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error creating report'
    });
  }
});

// @route   GET api/reports
// @desc    Get all reports (filtered by role and query parameters)
// @access  Private
router.get('/', auth, async (req, res) => {
  try {
    const { page = 1, limit = 10, status, category, priority, department, sort = 'createdAt' } = req.query;
    
    // Build query based on user role
    let query = {};
    
    // CEO can see all reports
    if (req.user.role === 'ceo') {
      // No filter needed
    } 
    // Other executives see only reports in their category
    else if (['cto', 'cfo', 'coo'].includes(req.user.role)) {
      const categoryMap = {
        'cto': 'technical',
        'cfo': 'financial',
        'coo': 'operations'
      };
      query.category = categoryMap[req.user.role];
    } 
    // Employees can see only their own reports
    else if (req.user.role === 'employee') {
      query.employeeId = req.user.id;
    }
    
    // Add filters from query parameters
    if (status) query.status = status;
    if (category) query.category = category;
    if (priority) query.priority = priority;
    if (department) query.department = department;
    
    // Exclude archived reports by default
    query.isArchived = { $ne: true };
    
    // Calculate pagination
    const skip = (page - 1) * limit;
    
    // Execute query with pagination
    const reports = await Report.find(query)
      .populate('employeeId', ['name', 'email', 'department'])
      .sort({ [sort]: -1 })
      .limit(parseInt(limit))
      .skip(skip);
    
    // Get total count for pagination
    const total = await Report.countDocuments(query);
    
    res.json({
      success: true,
      reports,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error('Get reports error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error fetching reports'
    });
  }
});

// @route   GET api/reports/:id
// @desc    Get a report by ID
// @access  Private
router.get('/:id', auth, async (req, res) => {
  try {
    const report = await Report.findById(req.params.id)
      .populate('employeeId', ['name', 'email', 'department'])
      .populate('reviewedBy', ['name', 'email']);
    
    if (!report) {
      return res.status(404).json({
        success: false,
        error: 'NotFound',
        message: 'Report not found'
      });
    }
    
    // Check if user has permission to view this report
    const hasAccess = checkReportAccess(req.user, report);
    if (!hasAccess) {
      return res.status(403).json({
        success: false,
        error: 'AccessDenied',
        message: 'You do not have permission to view this report'
      });
    }
    
    res.json({
      success: true,
      report
    });
  } catch (err) {
    console.error('Get report error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error fetching report'
    });
  }
});

// @route   PUT api/reports/:id
// @desc    Update a report
// @access  Private
router.put('/:id', [
  auth,
  upload.array('attachments', 5),
  check('title', 'Title must be less than 100 characters').optional().isLength({ max: 100 }),
  check('content', 'Content must be less than 5000 characters').optional().isLength({ max: 5000 }),
  check('category', 'Category must be valid').optional().isIn(['technical', 'financial', 'operations', 'hr', 'marketing', 'legal']),
  check('priority', 'Priority must be low, medium, high, or critical').optional().isIn(['low', 'medium', 'high', 'critical']),
  check('status', 'Status must be valid').optional().isIn(['draft', 'submitted', 'under_review', 'approved', 'rejected'])
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
    const report = await Report.findById(req.params.id);
    
    if (!report) {
      return res.status(404).json({
        success: false,
        error: 'NotFound',
        message: 'Report not found'
      });
    }
    
    // Check if user has permission to update this report
    const hasAccess = checkReportAccess(req.user, report);
    if (!hasAccess) {
      return res.status(403).json({
        success: false,
        error: 'AccessDenied',
        message: 'You do not have permission to update this report'
      });
    }
    
    // Only employees can update draft reports
    if (req.user.role === 'employee' && report.status !== 'draft') {
      return res.status(403).json({
        success: false,
        error: 'AccessDenied',
        message: 'Employees can only update draft reports'
      });
    }
    
    // Update fields
    const { title, content, category, priority, department, dueDate, tags, status } = req.body;
    
    if (title) report.title = title;
    if (content) report.content = content;
    if (category) report.category = category;
    if (priority) report.priority = priority;
    if (department) report.department = department;
    if (dueDate) report.dueDate = dueDate;
    if (tags) report.tags = tags.split(',').map(tag => tag.trim());
    if (status) report.status = status;
    
    // Handle new attachments
    if (req.files && req.files.length > 0) {
      const newAttachments = req.files.map(file => ({
        filename: file.filename,
        originalName: file.originalname,
        path: file.path,
        size: file.size,
        mimetype: file.mimetype
      }));
      report.attachments = [...report.attachments, ...newAttachments];
    }
    
    // Set last modified by
    report.lastModifiedBy = req.user.id;
    
    const updatedReport = await report.save();
    await updatedReport.populate('employeeId', ['name', 'email', 'department']);
    
    res.json({
      success: true,
      report: updatedReport
    });
  } catch (err) {
    console.error('Update report error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error updating report'
    });
  }
});

// @route   DELETE api/reports/:id
// @desc    Delete a report
// @access  Private
router.delete('/:id', auth, async (req, res) => {
  try {
    const report = await Report.findById(req.params.id);
    
    if (!report) {
      return res.status(404).json({
        success: false,
        error: 'NotFound',
        message: 'Report not found'
      });
    }
    
    // Check if user has permission to delete this report
    const hasAccess = checkReportAccess(req.user, report);
    if (!hasAccess) {
      return res.status(403).json({
        success: false,
        error: 'AccessDenied',
        message: 'You do not have permission to delete this report'
      });
    }
    
    // Only employees can delete their own draft reports
    if (req.user.role === 'employee' && report.status !== 'draft') {
      return res.status(403).json({
        success: false,
        error: 'AccessDenied',
        message: 'Employees can only delete draft reports'
      });
    }
    
    // Archive instead of deleting
    report.isArchived = true;
    report.lastModifiedBy = req.user.id;
    await report.save();
    
    res.json({
      success: true,
      message: 'Report archived successfully'
    });
  } catch (err) {
    console.error('Delete report error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error deleting report'
    });
  }
});

// @route   POST api/reports/:id/status
// @desc    Update report status
// @access  Private (Executives only)
router.post('/:id/status', [
  auth,
  authorize('ceo', 'cto', 'cfo', 'coo'),
  check('status', 'Status is required').isIn(['draft', 'submitted', 'under_review', 'approved', 'rejected']),
  check('reviewComments', 'Review comments must be less than 1000 characters').optional().isLength({ max: 1000 })
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
    const report = await Report.findById(req.params.id);
    
    if (!report) {
      return res.status(404).json({
        success: false,
        error: 'NotFound',
        message: 'Report not found'
      });
    }
    
    // Check if user has permission to update this report
    const hasAccess = checkReportAccess(req.user, report);
    if (!hasAccess) {
      return res.status(403).json({
        success: false,
        error: 'AccessDenied',
        message: 'You do not have permission to update this report'
      });
    }
    
    const { status, reviewComments } = req.body;
    
    // Update status and review info
    report.status = status;
    report.reviewedBy = req.user.id;
    if (reviewComments) report.reviewComments = reviewComments;
    
    const updatedReport = await report.save();
    await updatedReport.populate('employeeId', ['name', 'email', 'department']);
    await updatedReport.populate('reviewedBy', ['name', 'email']);
    
    res.json({
      success: true,
      report: updatedReport
    });
  } catch (err) {
    console.error('Update report status error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error updating report status'
    });
  }
});

// @route   GET api/reports/overdue
// @desc    Get overdue reports
// @access  Private (Executives only)
router.get('/filter/overdue', [
  auth,
  authorize('ceo', 'cto', 'cfo', 'coo')
], async (req, res) => {
  try {
    const overdueReports = await Report.findOverdue()
      .populate('employeeId', ['name', 'email', 'department']);
    
    res.json({
      success: true,
      reports: overdueReports,
      count: overdueReports.length
    });
  } catch (err) {
    console.error('Get overdue reports error:', err.message);
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error fetching overdue reports'
    });
  }
});

// Helper function to check report access
function checkReportAccess(user, report) {
  // CEO can access all reports
  if (user.role === 'ceo') {
    return true;
  }
  
  // Employees can only access their own reports
  if (user.role === 'employee') {
    return report.employeeId._id.toString() === user.id;
  }
  
  // Executives can only access reports in their category
  const categoryMap = {
    'cto': 'technical',
    'cfo': 'financial',
    'coo': 'operations'
  };
  
  if (['cto', 'cfo', 'coo'].includes(user.role)) {
    return report.category === categoryMap[user.role];
  }
  
  // All other roles are denied
  return false;
}

module.exports = router;