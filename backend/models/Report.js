const mongoose = require("mongoose");

// Check if the model already exists to prevent overwrite error
const reportSchema = new mongoose.Schema({
  reporterId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  reportedId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  reason: {
    type: String,
    required: true,
    trim: true
  },
  roomId: {
    type: String,
    default: null
  },
  status: {
    type: String,
    enum: ['pending', 'reviewed', 'resolved', 'dismissed'],
    default: 'pending'
  },
  adminNotes: {
    type: String,
    default: null
  },
  reviewedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Admin',
    default: null
  },
  reviewedAt: {
    type: Date,
    default: null
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
}, {
  // Add timestamps to track when reports are created/updated
  timestamps: true
});

// Add indexes for better query performance
reportSchema.index({ reporterId: 1, reportedId: 1 });
reportSchema.index({ status: 1 });
reportSchema.index({ timestamp: -1 });

// Export the model, checking if it already exists to prevent OverwriteModelError
module.exports = mongoose.models.Report || mongoose.model("Report", reportSchema);