// routes/reports.js
const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const Report = require('../models/Report');

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

// @route   POST api/reports
// @desc    Create a new report
// @access  Private (Employee only)
router.post('/', auth, async (req, res) => {
  const { title, content, category } = req.body;
  
  try {
    // Check if user is an employee
    if (req.user.role !== 'employee') {
      return res.status(403).json({ msg: 'Only employees can submit reports' });
    }
    
    // Validate category
    const validCategories = ['technical', 'financial', 'operations'];
    if (!validCategories.includes(category)) {
      return res.status(400).json({ 
        msg: 'Invalid category. Must be one of: technical, financial, operations' 
      });
    }
    
    // Validate required fields
    if (!title || !content) {
      return res.status(400).json({ msg: 'Title and content are required' });
    }
    
    const newReport = new Report({
      employeeId: req.user.id,
      title,
      content,
      category,
    });
    
    const report = await newReport.save();
    await report.populate('employeeId', ['name', 'email']);
    
    res.json(report);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

// @route   GET api/reports
// @desc    Get all reports (filtered by executive role)
// @access  Private
router.get('/', auth, async (req, res) => {
  try {
    let reports;
    
    // CEO can see all reports
    if (req.user.role === 'ceo') {
      reports = await Report.find().populate('employeeId', ['name', 'email']);
    } 
    // Other executives see only reports in their category
    else if (['cto', 'cfo', 'coo'].includes(req.user.role)) {
      const categoryMap = {
        'cto': 'technical',
        'cfo': 'financial',
        'coo': 'operations'
      };
      
      reports = await Report.find({ category: categoryMap[req.user.role] })
        .populate('employeeId', ['name', 'email']);
    } 
    // Employees can see only their own reports
    else if (req.user.role === 'employee') {
      reports = await Report.find({ employeeId: req.user.id })
        .populate('employeeId', ['name', 'email']);
    } else {
      return res.status(403).json({ msg: 'Access denied' });
    }
    
    res.json(reports);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

// @route   GET api/reports/:id
// @desc    Get a report by ID
// @access  Private
router.get('/:id', auth, async (req, res) => {
  try {
    const report = await Report.findById(req.params.id)
      .populate('employeeId', ['name', 'email']);
    
    if (!report) {
      return res.status(404).json({ msg: 'Report not found' });
    }
    
    // Check if user has permission to view this report
    const hasAccess = checkReportAccess(req.user, report);
    if (!hasAccess) {
      return res.status(403).json({ msg: 'Access denied' });
    }
    
    res.json(report);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

module.exports = router;