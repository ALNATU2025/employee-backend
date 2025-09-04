//routes/users.js
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const auth = require('../middleware/auth');

// GET all users (Admin only)
router.get('/', auth, async (req, res) => {
  try {
    // Check if user is admin
    const adminRoles = ['ceo', 'cto', 'cfo', 'coo'];
    if (!adminRoles.includes(req.user.role)) {
      return res.status(403).json({ msg: 'Access denied. Admin privileges required.' });
    }

    const users = await User.find().select('-password');
    res.json(users);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

// GET current user profile
router.get('/profile', auth, async (req, res) => {
  try {
    res.json(req.user);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

// GET single user by ID (Admin only)
router.get('/:id', auth, async (req, res) => {
  try {
    // Check if user is admin
    const adminRoles = ['ceo', 'cto', 'cfo', 'coo'];
    if (!adminRoles.includes(req.user.role)) {
      return res.status(403).json({ msg: 'Access denied. Admin privileges required.' });
    }

    const user = await User.findById(req.params.id).select('-password');
    if (!user) return res.status(404).json({ msg: 'User not found' });
    res.json(user);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

// POST create new user (Admin only)
router.post('/', auth, async (req, res) => {
  try {
    // Check if user is admin
    const adminRoles = ['ceo', 'cto', 'cfo', 'coo'];
    if (!adminRoles.includes(req.user.role)) {
      return res.status(403).json({ msg: 'Access denied. Admin privileges required.' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email: req.body.email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already in use' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);

    // Create new user
    const user = new User({
      name: req.body.name,
      email: req.body.email,
      password: hashedPassword,
      role: req.body.role || 'employee'
    });

    const newUser = await user.save();
    res.status(201).json({
      _id: newUser._id,
      name: newUser.name,
      email: newUser.email,
      role: newUser.role,
      date: newUser.date
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ message: err.message });
  }
});

// PUT update user by ID (Admin only)
router.put('/:id', auth, async (req, res) => {
  try {
    // Check if user is admin
    const adminRoles = ['ceo', 'cto', 'cfo', 'coo'];
    if (!adminRoles.includes(req.user.role)) {
      return res.status(403).json({ msg: 'Access denied. Admin privileges required.' });
    }

    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Update fields if provided
    if (req.body.name) user.name = req.body.name;
    if (req.body.email) user.email = req.body.email;
    if (req.body.role) user.role = req.body.role;
    
    // Update password if provided
    if (req.body.password) {
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(req.body.password, salt);
    }

    const updatedUser = await user.save();
    res.json({
      _id: updatedUser._id,
      name: updatedUser.name,
      email: updatedUser.email,
      role: updatedUser.role,
      date: updatedUser.date
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ message: err.message });
  }
});

// DELETE user by ID (Admin only)
router.delete('/:id', auth, async (req, res) => {
  try {
    // Check if user is admin
    const adminRoles = ['ceo', 'cto', 'cfo', 'coo'];
    if (!adminRoles.includes(req.user.role)) {
      return res.status(403).json({ msg: 'Access denied. Admin privileges required.' });
    }

    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    await user.remove();
    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;