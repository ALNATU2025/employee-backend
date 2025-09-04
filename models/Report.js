// models/Report.js
const mongoose = require('mongoose');

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

module.exports = mongoose.model('Report', ReportSchema);