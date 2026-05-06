const mongoose = require("mongoose");

const chatMessageSchema = new mongoose.Schema(
  {
    messageId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    groupId: {
      type: String,
      required: true,
      index: true,
    },
    userId: {
      type: String,
      required: true,
    },
    userName: {
      type: String,
      required: true,
    },
    userAvatar: {
      type: String,
      default: "",
    },
    text: {
      type: String,
      required: true,
      maxlength: 2000,
    },
    edited: {
      type: Boolean,
      default: false,
    },
    deletedAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

// Compound index for efficient group message queries
chatMessageSchema.index({ groupId: 1, createdAt: -1 });

module.exports = mongoose.model("ChatMessage", chatMessageSchema);
