const mongoose = require("mongoose");

const mediaSchema = new mongoose.Schema({
  title: { type: String, required: true },
  originalName: { type: String, required: true },
  filename: { type: String, required: true, unique: true },
  type: {
    type: String,
    required: true,
    enum: ["video", "audio", "pdf"],
  },
  size: { type: Number, required: true }, // in bytes
  sizeFormatted: { type: String, required: true }, // human readable
  category: {
    type: String,
    default: "general",
    enum: ["general", "tutorial", "documentation", "entertainment"],
  },
  description: { type: String, default: "" },
  mimeType: { type: String, required: true },
  url: { type: String, required: true },
  uploadedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Admin",
    required: true,
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

// Index for faster queries
mediaSchema.index({ type: 1, createdAt: -1 });
mediaSchema.index({ title: "text", description: "text" });

module.exports = mongoose.model("Media", mediaSchema);
