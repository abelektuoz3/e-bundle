const mongoose = require("mongoose");

const progressSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  courseId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Course",
    required: true,
  },
  completedLessons: {
    type: Number,
    default: 0,
  },
  totalLessons: {
    type: Number,
    default: 0,
  },
  percentage: {
    type: Number,
    default: 0,
    min: 0,
    max: 100,
  },
  timeSpent: {
    type: Number,
    default: 0,
  },
  lastAccessed: {
    type: Date,
    default: Date.now,
  },
  completed: {
    type: Boolean,
    default: false,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Compound index to ensure one progress document per user-course pair
progressSchema.index({ userId: 1, courseId: 1 }, { unique: true });

module.exports = mongoose.model("Progress", progressSchema);