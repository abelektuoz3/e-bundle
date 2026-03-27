const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: true,
    trim: true,
  },
  lastName: {
    type: String,
    required: true,
    trim: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
  },
  studentId: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  grade: {
    type: String,
    required: true,
  },
  school: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    default: "student",
  },
  // OTP Verification Fields
  otp: {
    type: String,
    default: null,
  },
  otpExpire: {
    type: Date,
    default: null,
  },
  isVerified: {
    type: Boolean,
    default: false,
  },
  // Password Reset Fields
  resetToken: {
    type: String,
    default: null,
  },
  resetTokenExpire: {
    type: Date,
    default: null,
  },
  // Profile Fields
  bio: {
    type: String,
    default: "",
  },
  avatar: {
    type: String,
    default: "",
  },
  // Stats Fields - ADD THESE IF MISSING
  quizScore: {
    type: Number,
    default: 0,
  },
  quizTotal: {
    type: Number,
    default: 0,
  },
  streak: {
    type: Number,
    default: 0,
  },
  lastActive: {
    type: Date,
    default: null,
  },
  totalStudyTime: {
    type: Number,
    default: 0,
  },
  progress: {
    type: Number,
    default: 0,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model("User", userSchema);
