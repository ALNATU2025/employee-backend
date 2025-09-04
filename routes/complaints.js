// routes/complaints.js
const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const Complaint = require('../models/Complaint');

// Helper function to check if user is an executive
const isExecutive = (role) => ['ceo', 'cto', 'cfo', 'coo'].includes(role);

// @route   POST api/complaints
// @desc    Create a new complaint
// @access  Private (Employee only)
router.post('/', auth, async (req, res) => {
  const { message } = req.body;
  
  try {
    // Check if user is an employee
    if (req.user.role !== 'employee') {
      return res.status(403).json({ msg: 'Only employees can submit complaints' });
    }
    
    // Validate message
    if (!message || message.trim() === '') {
      return res.status(400).json({ msg: 'Message is required' });
    }
    
    const newComplaint = new Complaint({
      employeeId: req.user.id,
      message,
    });
    
    const complaint = await newComplaint.save();
    await complaint.populate('employeeId', ['name', 'email']);
    
    res.json(complaint);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

// @route   GET api/complaints
// @desc    Get all complaints
// @access  Private
router.get('/', auth, async (req, res) => {
  try {
    let complaints;
    
    // Executives can see all complaints
    if (isExecutive(req.user.role)) {
      complaints = await Complaint.find()
        .populate('employeeId', ['name', 'email'])
        .sort({ date: -1 }); // Sort by newest first
    } 
    // Employees can see only their own complaints
    else if (req.user.role === 'employee') {
      complaints = await Complaint.find({ employeeId: req.user.id })
        .populate('employeeId', ['name', 'email'])
        .sort({ date: -1 });
    } else {
      return res.status(403).json({ msg: 'Access denied' });
    }
    
    res.json(complaints);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

// @route   GET api/complaints/:id
// @desc    Get a complaint by ID
// @access  Private
router.get('/:id', auth, async (req, res) => {
  try {
    const complaint = await Complaint.findById(req.params.id)
      .populate('employeeId', ['name', 'email']);
    
    if (!complaint) {
      return res.status(404).json({ msg: 'Complaint not found' });
    }
    
    // Check if user has permission to view this complaint
    if (!isExecutive(req.user.role) && complaint.employeeId._id.toString() !== req.user.id) {
      return res.status(403).json({ msg: 'Access denied' });
    }
    
    res.json(complaint);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

// @route   PUT api/complaints/:id
// @desc    Update a complaint
// @access  Private (Executives only)
router.put('/:id', auth, async (req, res) => {
  const { message, status } = req.body;
  
  try {
    // Only executives can update complaints
    if (!isExecutive(req.user.role)) {
      return res.status(403).json({ msg: 'Access denied' });
    }
    
    const complaint = await Complaint.findById(req.params.id);
    
    if (!complaint) {
      return res.status(404).json({ msg: 'Complaint not found' });
    }
    
    // Update message if provided
    if (message && message.trim() !== '') {
      complaint.message = message;
    }
    
    // Update status if provided
    if (status && ['pending', 'in-progress', 'resolved'].includes(status)) {
      complaint.status = status;
    }
    
    const updatedComplaint = await complaint.save();
    await updatedComplaint.populate('employeeId', ['name', 'email']);
    
    res.json(updatedComplaint);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

// @route   DELETE api/complaints/:id
// @desc    Delete a complaint
// @access  Private (Executives only)
router.delete('/:id', auth, async (req, res) => {
  try {
    // Only executives can delete complaints
    if (!isExecutive(req.user.role)) {
      return res.status(403).json({ msg: 'Access denied' });
    }
    
    const complaint = await Complaint.findById(req.params.id);
    
    if (!complaint) {
      return res.status(404).json({ msg: 'Complaint not found' });
    }
    
    await complaint.remove();
    res.json({ msg: 'Complaint deleted successfully' });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

module.exports = router;