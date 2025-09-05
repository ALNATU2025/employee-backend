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
const helmet = require('helmet');
const xss = require('xss-clean');
const hpp = require('hpp');

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();

// Security middleware
app.use(helmet());
app.use(xss());
app.use(hpp());

// Middleware
const allowedOrigins = [
  'http://localhost:3000',
  process.env.FRONTEND_URL,
  'https://employee-backend-mcg5.onrender.com'
].filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`Origin ${origin} not allowed by CORS`));
    }
  },
  credentials: true
}));

app.use(express.json({ limit: '10kb' }));
app.use(morgan('dev'));

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: {
    success: false,
    error: 'Too many attempts',
    message: 'Too many authentication attempts, please try again later'
  }
});

const userManagementLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: {
    success: false,
    error: 'Too many requests',
    message: 'Too many user management attempts, please try again later'
  }
});

// Health check endpoint
app.get('/', (req, res) => {
  res.status(200).json({ 
    message: 'Server is running',
    environment: process.env.NODE_ENV,
    timestamp: new Date().toISOString()
  });
});

// Database connection
const connectDB = async () => {
  mongoose.set('strictQuery', false);
  
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI, {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      family: 4,
      retryWrites: true,
      w: 'majority'
    });
    console.log(`MongoDB Connected: ${conn.connection.host}`);
    
    mongoose.connection.on('connected', () => {
      console.log('Mongoose connected to DB');
    });
    mongoose.connection.on('error', (err) => {
      console.error(`Mongoose connection error: ${err.message}`);
    });
    mongoose.connection.on('disconnected', () => {
      console.log('Mongoose disconnected');
      setTimeout(connectDB, 5000);
    });
    
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
    setTimeout(connectDB, 5000);
  }
};

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

UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

UserSchema.methods.matchPassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

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

UserSchema.methods.getResetPasswordToken = function() {
  const resetToken = crypto.randomBytes(20).toString('hex');
  this.resetPasswordToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
  this.resetPasswordExpire = Date.now() + 10 * 60 * 1000;
  return resetToken;
};

UserSchema.methods.updateLoginInfo = function() {
  this.lastLogin = new Date();
  this.loginCount += 1;
  return this.save();
};

UserSchema.statics.findActive = function() {
  return this.find({ isActive: true });
};

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

ReportSchema.virtual('ageInDays').get(function() {
  return Math.floor((Date.now() - this.createdAt) / (1000 * 60 * 60 * 24));
});

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

ReportSchema.pre('save', function(next) {
  if (this.isModified('status') && this.status === 'submitted') {
    this.submittedAt = new Date();
  }
  if (this.isModified('status') && (this.status === 'approved' || this.status === 'rejected')) {
    this.reviewedAt = new Date();
  }
  next();
});

ReportSchema.statics.findByStatus = function(status) {
  return this.find({ status, isArchived: false });
};

ReportSchema.statics.findOverdue = function() {
  return this.find({
    dueDate: { $lt: Date.now() },
    status: { $ne: 'approved' },
    isArchived: false
  });
};

ReportSchema.methods.addAttachment = function(attachment) {
  this.attachments.push(attachment);
  return this.save();
};

ReportSchema.methods.removeAttachment = function(attachmentId) {
  this.attachments = this.attachments.filter(
    att => att._id.toString() !== attachmentId.toString()
  );
  return this.save();
};

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
      'pending',           
      'under_review',      
      'investigation',     
      'action_required',   
      'resolved',          
      'dismissed',         
      'escalated'          
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

ComplaintSchema.virtual('ageInDays').get(function() {
  return Math.floor((Date.now() - this.createdAt) / (1000 * 60 * 60 * 24));
});

ComplaintSchema.virtual('resolutionTimeInDays').get(function() {
  if (!this.resolvedAt) return null;
  return Math.floor((this.resolvedAt - this.createdAt) / (1000 * 60 * 60 * 24));
});

ComplaintSchema.virtual('daysSinceLastUpdate').get(function() {
  const lastUpdate = this.updatedAt;
  return Math.floor((Date.now() - lastUpdate) / (1000 * 60 * 60 * 24));
});

ComplaintSchema.pre('save', function(next) {
  if (this.isModified('status')) {
    this.statusHistory.push({
      status: this.status,
      updatedBy: this.lastUpdatedBy,
      comments: this.resolutionComments || ''
    });
    
    if (this.status === 'under_review' && !this.assignedAt) {
      this.assignedAt = new Date();
    }
    if (this.status === 'resolved' && !this.resolvedAt) {
      this.resolvedAt = new Date();
    }
  }
  next();
});

ComplaintSchema.statics.findByStatus = function(status) {
  return this.find({ status });
};

ComplaintSchema.statics.findHighPriority = function() {
  return this.find({
    priority: { $in: ['high', 'urgent'] },
    status: { $nin: ['resolved', 'dismissed'] }
  });
};

ComplaintSchema.statics.findOverdue = function() {
  return this.find({
    status: { $nin: ['resolved', 'dismissed'] },
    createdAt: { $lt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
  });
};

ComplaintSchema.methods.addAttachment = function(attachment) {
  this.attachments.push(attachment);
  return this.save();
};

ComplaintSchema.methods.updateStatus = function(status, updatedBy, comments = '') {
  this.status = status;
  this.lastUpdatedBy = updatedBy;
  if (comments) this.resolutionComments = comments;
  return this.save();
};

ComplaintSchema.index({ employeeId: 1, status: 1 });
ComplaintSchema.index({ category: 1, priority: 1 });
ComplaintSchema.index({ status: 1, priority: 1 });
ComplaintSchema.index({ assignedTo: 1 });
ComplaintSchema.index({ createdAt: -1 });

const Complaint = mongoose.model('Complaint', ComplaintSchema);

// Authentication middleware
const auth = async function (req, res, next) {
  let token;
  
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  }
  else if (req.header('x-auth-token')) {
    token = req.header('x-auth-token');
  }
  else if (req.cookies && req.cookies.token) {
    token = req.cookies.token;
  }
  
  if (!token) {
    return res.status(401).json({ 
      success: false,
      error: 'No token provided',
      message: 'Authorization denied - No token found'
    });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id).select('-password');
    
    if (!req.user) {
      return res.status(401).json({ 
        success: false,
        error: 'User not found',
        message: 'Token is not valid - User does not exist'
      });
    }
    
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
      token: token.substring(0, 10) + '...'
    });
    
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
    fileSize: 5 * 1024 * 1024,
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
    fileSize: 5 * 1024 * 1024,
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

// Authentication Routes
const authRouter = express.Router();

authRouter.post('/register', [
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
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({
        success: false,
        error: 'UserExistsError',
        message: 'User with this email already exists'
      });
    }
    
    user = new User({
      name,
      email,
      password,
      role: role || 'employee'
    });
    
    await user.save();
    
    const token = user.getSignedJwtToken();
    
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

authRouter.post('/login', [
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
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'InvalidCredentials',
        message: 'Invalid email or password'
      });
    }
    
    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        error: 'InvalidCredentials',
        message: 'Invalid email or password'
      });
    }
    
    await user.updateLoginInfo();
    
    const token = user.getSignedJwtToken();
    
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

authRouter.get('/current', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'UserNotFound',
        message: 'User not found'
      });
    }
    
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
    res.status(500).json({
      success: false,
      error: 'ServerError',
      message: 'Server error fetching user data'
    });
  }
});

authRouter.post('/logout', auth, async (req, res) => {
  try {
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
      return res.json({
        success: true,
        message: 'If an account with that email exists, a reset link has been sent'
      });
    }
    
    const resetToken = user.getResetPasswordToken();
    await user.save({ validateBeforeSave: false });
    
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
    
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
    const resetPasswordToken = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');
    
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

userRouter.get('/', [
  auth,
  authorize('ceo', 'cto', 'cfo', 'coo'),
  userManagementLimiter
], async (req, res) => {
  try {
    const { page = 1, limit = 10, role, department, isActive } = req.query;
    
    let query = {};
    if (role) query.role = role;
    if (department) query.department = department;
    if (isActive !== undefined) query.isActive = isActive === 'true';
    
    const skip = (page - 1) * limit;
    
    const users = await User.find(query)
      .select('-password -resetPasswordToken -resetPasswordExpire')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(skip);
    
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

userRouter.get('/profile', auth, async (req, res) => {
  try {
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
    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: 'UserExistsError',
        message: 'Email already in use'
      });
    }
    
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

function checkReportAccess(user, report) {
  if (user.role === 'ceo') {
    return true;
  }
  
  if (user.role === 'employee') {
    return report.employeeId._id.toString() === user.id;
  }
  
  const categoryMap = {
    'cto': 'technical',
    'cfo': 'financial',
    'coo': 'operations'
  };
  
  if (['cto', 'cfo', 'coo'].includes(user.role)) {
    return report.category === categoryMap[user.role];
  }
  
  return false;
}

reportRouter.post('/', [
  auth,
  authorize('employee'),
  reportUpload.array('attachments', 5),
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
    
    const attachments = req.files ? req.files.map(file => ({
      filename: file.filename,
      originalName: file.originalname,
      path: file.path,
      size: file.size,
      mimetype: file.mimetype
    })) : [];
    
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

reportRouter.get('/', auth, async (req, res) => {
  try {
    const { page = 1, limit = 10, status, category, priority, department, sort = 'createdAt' } = req.query;
    
    let query = {};
    
    if (req.user.role === 'ceo') {
    } 
    else if (['cto', 'cfo', 'coo'].includes(req.user.role)) {
      const categoryMap = {
        'cto': 'technical',
        'cfo': 'financial',
        'coo': 'operations'
      };
      query.category = categoryMap[req.user.role];
    } 
    else if (req.user.role === 'employee') {
      query.employeeId = req.user.id;
    }
    
    if (status) query.status = status;
    if (category) query.category = category;
    if (priority) query.priority = priority;
    if (department) query.department = department;
    
    query.isArchived = { $ne: true };
    
    const skip = (page - 1) * limit;
    
    const reports = await Report.find(query)
      .populate('employeeId', ['name', 'email', 'department'])
      .sort({ [sort]: -1 })
      .limit(parseInt(limit))
      .skip(skip);
    
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
    
    const hasAccess = checkReportAccess(req.user, report);
    if (!hasAccess) {
      return res.status(403).json({
        success: false,
        error: 'AccessDenied',
        message: 'You do not have permission to update this report'
      });
    }
    
    if (req.user.role === 'employee' && report.status !== 'draft') {
      return res.status(403).json({
        success: false,
        error: 'AccessDenied',
        message: 'Employees can only update draft reports'
      });
    }
    
    const { title, content, category, priority, department, dueDate, tags, status } = req.body;
    
    if (title) report.title = title;
    if (content) report.content = content;
    if (category) report.category = category;
    if (priority) report.priority = priority;
    if (department) report.department = department;
    if (dueDate) report.dueDate = dueDate;
    if (tags) report.tags = tags.split(',').map(tag => tag.trim());
    if (status) report.status = status;
    
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
    
    const hasAccess = checkReportAccess(req.user, report);
    if (!hasAccess) {
      return res.status(403).json({
        success: false,
        error: 'AccessDenied',
        message: 'You do not have permission to delete this report'
      });
    }
    
    if (req.user.role === 'employee' && report.status !== 'draft') {
      return res.status(403).json({
        success: false,
        error: 'AccessDenied',
        message: 'Employees can only delete draft reports'
      });
    }
    
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
    
    const hasAccess = checkReportAccess(req.user, report);
    if (!hasAccess) {
      return res.status(403).json({
        success: false,
        error: 'AccessDenied',
        message: 'You do not have permission to update this report'
      });
    }
    
    const { status, reviewComments } = req.body;
    
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

function checkComplaintAccess(user, complaint) {
  if (user.role === 'ceo') {
    return true;
  }
  
  if (user.department === 'HR') {
    return true;
  }
  
  if (user.role === 'employee') {
    return complaint.employeeId && complaint.employeeId._id.toString() === user.id;
  }
  
  if (['cto', 'cfo', 'coo'].includes(user.role)) {
    return complaint.employeeId && complaint.employeeId.department === user.department;
  }
  
  return false;
}

complaintRouter.post('/', [
  auth,
  complaintUpload.array('attachments', 5),
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
    
    const attachments = req.files ? req.files.map(file => ({
      filename: file.filename,
      originalName: file.originalname,
      path: file.path,
      size: file.size,
      mimetype: file.mimetype
    })) : [];
    
    const newComplaint = new Complaint({
      employeeId: isAnonymous ? null : req.user.id,
      title,
      description,
      category,
      priority: priority || 'medium',
      severity: severity || 'moderate',
      isAnonymous: isAnonymous || false,
      isConfidential: isConfidential !== false,
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

complaintRouter.get('/', auth, async (req, res) => {
  try {
    const { page = 1, limit = 10, status, category, priority, severity, sort = 'createdAt' } = req.query;
    
    let query = {};
    
    if (req.user.role === 'ceo' || req.user.department === 'HR') {
    } 
    else if (req.user.role === 'employee') {
      query.employeeId = req.user.id;
    }
    else {
      query.department = req.user.department;
    }
    
    if (status) query.status = status;
    if (category) query.category = category;
    if (priority) query.priority = priority;
    if (severity) query.severity = severity;
    
    const skip = (page - 1) * limit;
    
    const complaints = await Complaint.find(query)
      .populate('employeeId', ['name', 'email', 'department'])
      .populate('assignedTo', ['name', 'email', 'department'])
      .sort({ [sort]: -1 })
      .limit(parseInt(limit))
      .skip(skip);
    
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
    
    const hasAccess = checkComplaintAccess(req.user, complaint);
    if (!hasAccess) {
      return res.status(403).json({
        success: false,
        error: 'AccessDenied',
        message: 'You do not have permission to update this complaint'
      });
    }
    
    const { title, description, category, priority, severity, status } = req.body;
    
    if (title) complaint.title = title;
    if (description) complaint.description = description;
    if (category) complaint.category = category;
    if (priority) complaint.priority = priority;
    if (severity) complaint.severity = severity;
    if (status) complaint.status = status;
    
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
    
    const hasAccess = checkComplaintAccess(req.user, complaint);
    if (!hasAccess) {
      return res.status(403).json({
        success: false,
        error: 'AccessDenied',
        message: 'You do not have permission to update this complaint'
      });
    }
    
    const { status, comments } = req.body;
    
    await complaint.updateStatus(status, req.user.id, comments);
    
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