// server.js
const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');
const { check, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const multer = require('multer');
const rateLimit = require('express-rate-limit');

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();

// Middleware
const allowedOrigins = [
  'http://localhost:3000',                     // Development frontend
  process.env.FRONTEND_URL,                     // Production frontend (set in environment)
  'https://employee-backend-mcg5.onrender.com'  // Backend domain (for API calls)
].filter(Boolean); // Remove any undefined/empty values

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);
    
    // Check if origin is in allowed list
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`Origin ${origin} not allowed by CORS`));
    }
  },
  credentials: true
}));

app.use(express.json());
app.use(morgan('dev'));

// Health check endpoint (required by Render)
app.get('/', (req, res) => {
  res.status(200).json({ 
    message: 'Server is running',
    environment: process.env.NODE_ENV,
    timestamp: new Date().toISOString()
  });
});

// Database connection
const connectDB = async () => {
  // Set mongoose options to suppress deprecation warnings
  mongoose.set('strictQuery', false);
  
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI, {
      // Modern connection options (Mongoose 8+)
      maxPoolSize: 10, // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5000, // Keep trying to send operations for 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
      family: 4, // Use IPv4, skip trying IPv6
      // Add these for better connection handling
      retryWrites: true,
      w: 'majority'
    });
    console.log(`MongoDB Connected: ${conn.connection.host}`);
    
    // Connection event listeners for better monitoring
    mongoose.connection.on('connected', () => {
      console.log('Mongoose connected to DB');
    });
    mongoose.connection.on('error', (err) => {
      console.error(`Mongoose connection error: ${err.message}`);
    });
    mongoose.connection.on('disconnected', () => {
      console.log('Mongoose disconnected');
      // Attempt to reconnect after 5 seconds
      setTimeout(connectDB, 5000);
    });
    // Handle application termination
    process.on('SIGINT', async () => {
      await mongoose.connection.close();
      console.log('MongoDB connection closed through app termination');
      process.exit(0);
    });
  } catch (err) {
    console.error('Database connection error:', {
      message: err.message,
      stack: err.stack,
      name: err.name
    });
    
    // Retry connection after 5 seconds
    console.log('Retrying connection in 5 seconds...');
    setTimeout(connectDB, 5000);
  }
};

// Connect Database
connectDB();

// User Schema
const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Name is required'],
    trim: true,
    maxlength: [50, 'Name cannot exceed 50 characters']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please add a valid email']
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters'],
    select: false
  },
  role: {
    type: String,
    enum: ['employee', 'ceo', 'cto', 'cfo', 'coo'],
    default: 'employee'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  lastLogin: {
    type: Date,
    default: null
  },
  loginCount: {
    type: Number,
    default: 0
  },
  resetPasswordToken: {
    type: String,
    select: false
  },
  resetPasswordExpire: {
    type: Date,
    select: false
  },
  avatar: {
    type: String,
    default: ''
  },
  department: {
    type: String,
    enum: ['HR', 'Finance', 'IT', 'Operations', 'Marketing', 'Sales', 'Legal', 'Other'],
    default: 'Other'
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual for full name (if needed in future)
UserSchema.virtual('fullName').get(function() {
  return this.name;
});

// Encrypt password using bcrypt
UserSchema.pre('save', async function(next) {
  // Only hash password if it's modified
  if (!this.isModified('password')) {
    return next();
  }
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Match user entered password to hashed password in database
UserSchema.methods.matchPassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Generate JWT Token
UserSchema.methods.getSignedJwtToken = function() {
  return jwt.sign(
    { 
      id: this._id, 
      role: this.role,
      email: this.email 
    },
    process.env.JWT_SECRET,
    { 
      expiresIn: process.env.JWT_EXPIRE || '30d' 
    }
  );
};

// Generate and hash password token
UserSchema.methods.getResetPasswordToken = function() {
  // Generate token
  const resetToken = crypto.randomBytes(20).toString('hex');
  // Hash token and set to resetPasswordToken field
  this.resetPasswordToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
  // Set expire
  this.resetPasswordExpire = Date.now() + 10 * 60 * 1000; // 10 minutes
  return resetToken;
};

// Method to update login information
UserSchema.methods.updateLoginInfo = function() {
  this.lastLogin = new Date();
  this.loginCount += 1;
  return this.save();
};

// Static method to find active users
UserSchema.statics.findActive = function() {
  return this.find({ isActive: true });
};

// Create indexes for better query performance
UserSchema.index({ role: 1 });
UserSchema.index({ department: 1 });
UserSchema.index({ isActive: 1 });

const User = mongoose.model('User', UserSchema);

// Report Schema
const ReportSchema = new mongoose.Schema({
  employeeId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Employee ID is required'],
    index: true
  },
  title: {
    type: String,
    required: [true, 'Title is required'],
    trim: true,
    maxlength: [100, 'Title cannot exceed 100 characters']
  },
  content: {
    type: String,
    required: [true, 'Content is required'],
    trim: true,
    maxlength: [5000, 'Content cannot exceed 5000 characters']
  },
  category: {
    type: String,
    enum: ['technical', 'financial', 'operations', 'hr', 'marketing', 'legal'],
    required: [true, 'Category is required'],
    index: true
  },
  status: {
    type: String,
    enum: ['draft', 'submitted', 'under_review', 'approved', 'rejected'],
    default: 'draft',
    index: true
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'medium',
    index: true
  },
  department: {
    type: String,
    enum: ['HR', 'Finance', 'IT', 'Operations', 'Marketing', 'Sales', 'Legal', 'Other'],
    required: [true, 'Department is required'],
    index: true
  },
  dueDate: {
    type: Date,
    validate: {
      validator: function(value) {
        // Due date must be in the future
        return !value || value > Date.now();
      },
      message: 'Due date must be in the future'
    }
  },
  reviewedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  reviewedAt: {
    type: Date,
    default: null
  },
  reviewComments: {
    type: String,
    trim: true,
    maxlength: [1000, 'Review comments cannot exceed 1000 characters']
  },
  attachments: [{
    filename: {
      type: String,
      required: true
    },
    originalName: {
      type: String,
      required: true
    },
    path: {
      type: String,
      required: true
    },
    size: {
      type: Number,
      required: true
    },
    mimetype: {
      type: String,
      required: true
    },
    uploadedAt: {
      type: Date,
      default: Date.now
    }
  }],
  tags: [{
    type: String,
    trim: true,
    maxlength: [30, 'Tag cannot exceed 30 characters']
  }],
  isArchived: {
    type: Boolean,
    default: false,
    index: true
  },
  lastModifiedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual for report age (in days)
ReportSchema.virtual('ageInDays').get(function() {
  return Math.floor((Date.now() - this.createdAt) / (1000 * 60 * 60 * 24));
});

// Virtual for due status
ReportSchema.virtual('dueStatus').get(function() {
  if (!this.dueDate) return 'not_set';
  const now = new Date();
  const due = new Date(this.dueDate);
  const diffTime = due - now;
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  
  if (diffDays < 0) return 'overdue';
  if (diffDays === 0) return 'due_today';
  if (diffDays <= 3) return 'due_soon';
  return 'on_time';
});

// Pre-save hook to update timestamps
ReportSchema.pre('save', function(next) {
  if (this.isModified('status') && this.status === 'submitted') {
    this.submittedAt = new Date();
  }
  if (this.isModified('status') && (this.status === 'approved' || this.status === 'rejected')) {
    this.reviewedAt = new Date();
  }
  next();
});

// Static method to find reports by status
ReportSchema.statics.findByStatus = function(status) {
  return this.find({ status, isArchived: false });
};

// Static method to find overdue reports
ReportSchema.statics.findOverdue = function() {
  return this.find({
    dueDate: { $lt: Date.now() },
    status: { $ne: 'approved' },
    isArchived: false
  });
};

// Instance method to add attachment
ReportSchema.methods.addAttachment = function(attachment) {
  this.attachments.push(attachment);
  return this.save();
};

// Instance method to remove attachment
ReportSchema.methods.removeAttachment = function(attachmentId) {
  this.attachments = this.attachments.filter(
    att => att._id.toString() !== attachmentId.toString()
  );
  return this.save();
};

// Create compound indexes for better query performance
ReportSchema.index({ employeeId: 1, status: 1 });
ReportSchema.index({ department: 1, status: 1 });
ReportSchema.index({ category: 1, priority: 1 });
ReportSchema.index({ dueDate: 1, status: 1 });
ReportSchema.index({ tags: 1 });

const Report = mongoose.model('Report', ReportSchema);

// Complaint Schema
const ComplaintSchema = new mongoose.Schema({
  employeeId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Employee ID is required'],
    index: true
  },
  title: {
    type: String,
    required: [true, 'Title is required'],
    trim: true,
    maxlength: [100, 'Title cannot exceed 100 characters']
  },
  description: {
    type: String,
    required: [true, 'Description is required'],
    trim: true,
    maxlength: [2000, 'Description cannot exceed 2000 characters']
  },
  category: {
    type: String,
    enum: [
      'harassment', 
      'discrimination', 
      'workplace_safety', 
      'unfair_treatment',
      'pay_dispute',
      'work_conditions',
      'management',
      'other'
    ],
    required: [true, 'Category is required'],
    index: true
  },
  status: {
    type: String,
    enum: [
      'pending',           // Just submitted
      'under_review',      // Being investigated
      'investigation',     // Detailed investigation
      'action_required',   // Solution identified
      'resolved',          // Fully resolved
      'dismissed',         // Deemed invalid
      'escalated'          // Sent to higher authority
    ],
    default: 'pending',
    index: true
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'urgent'],
    default: 'medium',
    index: true
  },
  severity: {
    type: String,
    enum: ['minor', 'moderate', 'major', 'critical'],
    default: 'moderate',
    index: true
  },
  assignedTo: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  assignedAt: {
    type: Date,
    default: null
  },
  resolvedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  resolvedAt: {
    type: Date,
    default: null
  },
  resolution: {
    type: String,
    trim: true,
    maxlength: [2000, 'Resolution cannot exceed 2000 characters']
  },
  resolutionSatisfaction: {
    type: Number,
    min: [1, 'Satisfaction must be at least 1'],
    max: [5, 'Satisfaction cannot exceed 5'],
    default: null
  },
  isAnonymous: {
    type: Boolean,
    default: false
  },
  attachments: [{
    filename: {
      type: String,
      required: true
    },
    originalName: {
      type: String,
      required: true
    },
    path: {
      type: String,
      required: true
    },
    size: {
      type: Number,
      required: true
    },
    mimetype: {
      type: String,
      required: true
    },
    uploadedAt: {
      type: Date,
      default: Date.now
    }
  }],
  statusHistory: [{
    status: {
      type: String,
      required: true
    },
    updatedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    updatedAt: {
      type: Date,
      default: Date.now
    },
    comments: {
      type: String,
      maxlength: [500, 'Comments cannot exceed 500 characters']
    }
  }],
  isConfidential: {
    type: Boolean,
    default: true
  },
  lastUpdatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual for complaint age (in days)
ComplaintSchema.virtual('ageInDays').get(function() {
  return Math.floor((Date.now() - this.createdAt) / (1000 * 60 * 60 * 24));
});

// Virtual for resolution time (in days)
ComplaintSchema.virtual('resolutionTimeInDays').get(function() {
  if (!this.resolvedAt) return null;
  return Math.floor((this.resolvedAt - this.createdAt) / (1000 * 60 * 60 * 24));
});

// Virtual for time since last update
ComplaintSchema.virtual('daysSinceLastUpdate').get(function() {
  const lastUpdate = this.updatedAt;
  return Math.floor((Date.now() - lastUpdate) / (1000 * 60 * 60 * 24));
});

// Pre-save hook to update status history
ComplaintSchema.pre('save', function(next) {
  if (this.isModified('status')) {
    this.statusHistory.push({
      status: this.status,
      updatedBy: this.lastUpdatedBy,
      comments: this.resolutionComments || ''
    });
    
    // Update timestamps based on status
    if (this.status === 'under_review' && !this.assignedAt) {
      this.assignedAt = new Date();
    }
    if (this.status === 'resolved' && !this.resolvedAt) {
      this.resolvedAt = new Date();
    }
  }
  next();
});

// Static method to find complaints by status
ComplaintSchema.statics.findByStatus = function(status) {
  return this.find({ status });
};

// Static method to find high-priority complaints
ComplaintSchema.statics.findHighPriority = function() {
  return this.find({
    priority: { $in: ['high', 'urgent'] },
    status: { $nin: ['resolved', 'dismissed'] }
  });
};

// Static method to find overdue complaints
ComplaintSchema.statics.findOverdue = function() {
  return this.find({
    status: { $nin: ['resolved', 'dismissed'] },
    createdAt: { $lt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } // Older than 7 days
  });
};

// Instance method to add attachment
ComplaintSchema.methods.addAttachment = function(attachment) {
  this.attachments.push(attachment);
  return this.save();
};

// Instance method to update status
ComplaintSchema.methods.updateStatus = function(status, updatedBy, comments = '') {
  this.status = status;
  this.lastUpdatedBy = updatedBy;
  if (comments) this.resolutionComments = comments;
  return this.save();
};

// Create indexes for better query performance
ComplaintSchema.index({ employeeId: 1, status: 1 });
ComplaintSchema.index({ category: 1, priority: 1 });
ComplaintSchema.index({ status: 1, priority: 1 });
ComplaintSchema.index({ assignedTo: 1 });
ComplaintSchema.index({ createdAt: -1 });

const Complaint = mongoose.model('Complaint', ComplaintSchema);

// Authentication middleware
const auth = async function (req, res, next) {
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

// Authorization middleware
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ 
        success: false,
        error: 'Unauthorized',
        message: 'Authentication required'
      });
    }
    
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ 
        success: false,
        error: 'Forbidden',
        message: `User role ${req.user.role} is not authorized to access this resource`
      });
    }
    
    next();
  };
};

// Configure multer for file uploads (reports)
const reportStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    // Create uploads directory if it doesn't exist
    const fs = require('fs');
    const dir = 'uploads/reports/';
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    cb(null, dir);
  },
  filename: function (req, file, cb) {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});

const reportUpload = multer({
  storage: reportStorage,
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

// Configure multer for file uploads (complaints)
const complaintStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    // Create uploads directory if it doesn't exist
    const fs = require('fs');
    const dir = 'uploads/complaints/';
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    cb(null, dir);
  },
  filename: function (req, file, cb) {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});

const complaintUpload = multer({
  storage: complaintStorage,
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

// Authentication Routes
const authRouter = express.Router();

// @route   POST api/auth/register
// @desc    Register a user
// @access  Public
authRouter.post('/register', [
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
authRouter.post('/login', [
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
authRouter.get('/current', async (req, res) => {
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
authRouter.post('/logout', async (req, res) => {
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
authRouter.post('/forgot-password', [
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
authRouter.post('/reset-password/:token', [
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

// User Routes
const userRouter = express.Router();

// @route   GET api/users
// @desc    Get all users (Admin only) with pagination and filtering
// @access  Private (Admin only)
userRouter.get('/', [
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
userRouter.get('/profile', auth, async (req, res) => {
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
userRouter.get('/:id', [
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
userRouter.post('/', [
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
userRouter.put('/:id', [
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
userRouter.put('/:id/password', [
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
userRouter.put('/:id/activate', [
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
userRouter.put('/:id/deactivate', [
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
userRouter.delete('/:id', [
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

// Report Routes
const reportRouter = express.Router();

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
reportRouter.post('/', [
  auth,
  authorize('employee'),
  reportUpload.array('attachments', 5), // Max 5 files
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
reportRouter.get('/', auth, async (req, res) => {
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
reportRouter.get('/:id', auth, async (req, res) => {
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
reportRouter.put('/:id', [
  auth,
  reportUpload.array('attachments', 5),
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
reportRouter.delete('/:id', auth, async (req, res) => {
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
reportRouter.post('/:id/status', [
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
reportRouter.get('/filter/overdue', [
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

// Complaint Routes
const complaintRouter = express.Router();

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

// @route   POST api/complaints
// @desc    Create a new complaint
// @access  Private
complaintRouter.post('/', [
  auth,
  complaintUpload.array('attachments', 5), // Max 5 files
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
complaintRouter.get('/', auth, async (req, res) => {
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
complaintRouter.get('/:id', auth, async (req, res) => {
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
complaintRouter.put('/:id', [
  auth,
  complaintUpload.array('attachments', 5),
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
complaintRouter.post('/:id/status', [
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
complaintRouter.get('/filter/high-priority', [
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
complaintRouter.get('/filter/overdue', [
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

// Routes
app.use('/api/auth', authRouter);
app.use('/api/users', userRouter);
app.use('/api/reports', reportRouter);
app.use('/api/complaints', complaintRouter);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'production' ? {} : err
  });
});

// Handle 404 errors
app.use('*', (req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));