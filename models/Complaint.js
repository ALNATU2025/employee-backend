// models/Complaint.js
const mongoose = require('mongoose');

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

module.exports = mongoose.model('Complaint', ComplaintSchema);