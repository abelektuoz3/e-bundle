const mongoose = require('mongoose');

const lessonSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  mediaId: { type: mongoose.Schema.Types.ObjectId, ref: 'Media' },
  duration: String,
  isFree: { type: Boolean, default: false },
  order: { type: Number, default: 0 }
});

const moduleSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  order: { type: Number, default: 0 },
  lessons: [lessonSchema]
});

const courseSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  thumbnail: String,
  category: { type: String, default: "" },
  grade: { type: Number, required: true, min: 9, max: 12 },
  subject: { type: String, required: true },
  price: { type: Number, default: 0 },
  published: { type: Boolean, default: false },
  mediaFiles: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Media' }],
  color: { type: String, default: "from-blue-500 to-cyan-500" },
  icon: { type: String, default: "fa-book" },
  modules: [moduleSchema],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Course', courseSchema);