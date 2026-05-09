const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  studentId: { type: String, unique: true, sparse: true },
  role: { type: String, enum: ['student', 'admin', 'instructor'], default: 'student' },
  isActive: { type: Boolean, default: true },
  isVerified: { type: Boolean, default: false },
  grade: { type: Number, min: 9, max: 12 },
  school: { type: String },
  bio: { type: String, default: '' },
  avatar: { type: String, default: '' },
  streak: { type: Number, default: 0 },
  quizScore: { type: Number, default: 0 },
  quizTotal: { type: Number, default: 0 },
  progress: { type: Number, default: 0 },
  totalStudyTime: { type: Number, default: 0 },
  lastActive: { type: Date },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date },
  otp: { type: String },
  otpExpire: { type: Date },
  resetToken: { type: String },
  resetTokenExpire: { type: Date }
});

// Virtual field for full name (backward compatibility)
userSchema.virtual('name').get(function() {
  return `${this.firstName} ${this.lastName}`.trim();
});

// Ensure virtuals are included in JSON output
userSchema.set('toJSON', { virtuals: true });
userSchema.set('toObject', { virtuals: true });

module.exports = mongoose.model('User', userSchema);