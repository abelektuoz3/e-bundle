const mongoose = require("mongoose");

const activitySchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  type: {
    type: String,
    enum: ["lesson", "quiz", "login", "achievement", "streak"],
    required: true,
  },
  title: {
    type: String,
    required: true,
  },
  description: {
    type: String,
    required: true,
  },
  xp: {
    type: Number,
    default: 0,
  },
  courseId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Course",
    default: null,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model("Activity", activitySchema);
