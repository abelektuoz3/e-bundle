const mongoose = require("mongoose");

const courseSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true,
  },
  subject: {
    type: String,
    required: true,
    enum: [
      "math",
      "physics",
      "chemistry",
      "biology",
      "english",
      "amharic",
      "history",
      "geography",
      "cs",
    ],
  },
  grade: {
    type: Number,
    required: true,
    min: 9,
    max: 12,
  },
  description: {
    type: String,
    required: true,
  },
  totalLessons: {
    type: Number,
    default: 0,
  },
  color: {
    type: String,
    default: "from-blue-500 to-cyan-500",
  },
  icon: {
    type: String,
    default: "fa-book",
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model("Course", courseSchema);
