const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");
const crypto = require("crypto");
require("dotenv").config();
const fs = require("fs");
const { upload, formatFileSize } = require("./middleware/upload");
const Media = require("./models/Media");
const User = require("./models/User");
const Activity = require("./models/Activity");
const Course = require("./models/Course");
const Progress = require("./models/Progress");
const sgMail = require("@sendgrid/mail");
const ChatMessage = require("./models/ChatMessage");
const Admin = require("./models/Admin");
const { authenticateToken, authenticateAdmin } = require("./middleware/auth");

const dashboardRoutes = require("./routes/dashboard");
const userRoutes = require("./routes/users");
const courseRoutes = require("./routes/courses");
const enrollmentRoutes = require("./routes/enrollments");

const app = express();

// ================= ENVIRONMENT VARIABLES VALIDATION =================
const requiredEnvVars = ["MONGO_URI", "JWT_SECRET"];

const missingEnvVars = requiredEnvVars.filter(
  (varName) => !process.env[varName],
);
if (missingEnvVars.length > 0) {
  console.error(
    `❌ Missing required environment variables: ${missingEnvVars.join(", ")}`,
  );
  if (process.env.NODE_ENV === "production") {
    console.error(
      "Please set these variables in your Render environment variables.",
    );
  }
}

// Initialize SendGrid with API key
if (process.env.SENDGRID_API_KEY) {
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
  console.log("✅ SendGrid initialized");
} else {
  console.warn("⚠️ SENDGRID_API_KEY not found in environment variables");
}

// Initialize Africa's Talking
let africastalking;
let sms;
if (process.env.AFRICASTALKING_USERNAME && process.env.AFRICASTALKING_API_KEY) {
  africastalking = require("africastalking")({
    username: process.env.AFRICASTALKING_USERNAME,
    apiKey: process.env.AFRICASTALKING_API_KEY,
  });
  sms = africastalking.SMS;
  console.log("✅ Africa's Talking initialized");
} else {
  console.warn(
    "⚠️ AFRICASTALKING_USERNAME or AFRICASTALKING_API_KEY not found in environment variables",
  );
}

// ================= CORS CONFIGURATION =================
const allowedOrigins =
  process.env.ALLOWED_ORIGINS ?
    process.env.ALLOWED_ORIGINS.split(",")
  : [
      "http://localhost:3000",
      "http://localhost:5000",
      "https://e-bundle.onrender.com",
      "https://ebundle-ethiopia.netlify.app",
    ];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
      if (
        allowedOrigins.indexOf(origin) !== -1 ||
        process.env.NODE_ENV !== "production"
      ) {
        callback(null, true);
      } else {
        console.warn(`Origin ${origin} not allowed by CORS`);
        callback(null, true);
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

// ================= STATIC FILE SERVING =================
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  const mediaDir = path.join(uploadsDir, "media");
  if (!fs.existsSync(mediaDir)) {
    fs.mkdirSync(mediaDir, { recursive: true });
  }
}

// ================= GRIDFS SETUP =================
let gridFSBucket;

// ================= MONGODB CONNECTION =================
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("✅ MongoDB Connected Successfully");

    // Initialize GridFS bucket after connection
    gridFSBucket = new mongoose.mongo.GridFSBucket(mongoose.connection.db, {
      bucketName: "media",
    });
    console.log("✅ GridFS bucket initialized");
  } catch (err) {
    console.error("❌ MongoDB Connection Error:", err.message);
    console.log("Retrying connection in 5 seconds...");
    setTimeout(connectDB, 5000);
  }
};

connectDB();

mongoose.connection.on("error", (err) => {
  console.error("MongoDB connection error:", err);
});

mongoose.connection.on("disconnected", () => {
  console.log("MongoDB disconnected. Attempting to reconnect...");
  setTimeout(connectDB, 5000);
});

// Authentication middleware removed and imported from middleware/auth.js

// ================= MEDIA UPLOAD (Admin Only) =================
app.post(
  "/api/media/upload",
  authenticateAdmin,
  upload.single("file"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          success: false,
          message: "No file uploaded",
        });
      }

      const { title, category, description } = req.body;

      if (!title) {
        if (fs.existsSync(req.file.path)) {
          fs.unlinkSync(req.file.path);
        }
        return res.status(400).json({
          success: false,
          message: "Title is required",
        });
      }

      // Determine file type
      let fileType = "pdf";
      if (req.file.mimetype.startsWith("video")) fileType = "video";
      else if (req.file.mimetype.startsWith("audio")) fileType = "audio";
      else if (req.file.mimetype === "application/pdf") fileType = "pdf";

      // Upload file to GridFS
      const uploadStream = gridFSBucket.openUploadStream(req.file.filename, {
        contentType: req.file.mimetype,
        metadata: {
          originalName: req.file.originalname,
          title: title,
          uploadedBy: req.admin.id,
        },
      });

      const fileStream = fs.createReadStream(req.file.path);
      fileStream.pipe(uploadStream);

      await new Promise((resolve, reject) => {
        uploadStream.on("finish", resolve);
        uploadStream.on("error", reject);
        fileStream.on("error", reject);
      });

      const media = new Media({
        title: title || req.file.originalname,
        originalName: req.file.originalname,
        filename: req.file.filename,
        fileId: uploadStream.id,
        type: fileType,
        size: req.file.size,
        sizeFormatted: formatFileSize(req.file.size),
        category: category || "general",
        description: description || "",
        mimeType: req.file.mimetype,
        url: `/api/media/stream/${uploadStream.id}`,
        uploadedBy: req.admin.id,
      });

      await media.save();

      // Clean up local file
      if (fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }

      res.status(201).json({
        success: true,
        message: "File uploaded successfully",
        media: {
          id: media._id,
          title: media.title,
          type: media.type,
          size: media.sizeFormatted,
          category: media.category,
          url: media.url,
          createdAt: media.createdAt,
        },
      });
    } catch (err) {
      if (req.file && fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }
      console.error("Upload error:", err);
      res.status(500).json({
        success: false,
        message: "Server error during upload",
      });
    }
  },
);

// Get All Media (Protected - Admin only)
app.get("/api/media", authenticateAdmin, async (req, res) => {
  try {
    const { type, search, page = 1, limit = 50 } = req.query;

    let query = {};

    if (type && type !== "all") {
      query.type = type;
    }

    if (search) {
      query.$or = [
        { title: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } },
      ];
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const [media, total] = await Promise.all([
      Media.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Media.countDocuments(query),
    ]);

    const stats = await Media.aggregate([
      {
        $group: {
          _id: "$type",
          count: { $sum: 1 },
          totalSize: { $sum: "$size" },
        },
      },
    ]);

    const typeStats = {
      video: { count: 0, size: 0 },
      audio: { count: 0, size: 0 },
      pdf: { count: 0, size: 0 },
    };

    stats.forEach((stat) => {
      if (typeStats[stat._id]) {
        typeStats[stat._id].count = stat.count;
        typeStats[stat._id].size = stat.totalSize;
      }
    });

    const totalSize = stats.reduce((acc, curr) => acc + curr.totalSize, 0);

    res.json({
      success: true,
      media: media.map((m) => ({
        id: m._id,
        title: m.title,
        originalName: m.originalName,
        type: m.type,
        size: m.sizeFormatted,
        category: m.category,
        description: m.description,
        url: m.url,
        createdAt: m.createdAt,
      })),
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit)),
      },
      stats: {
        total,
        ...typeStats,
        totalSize: formatFileSize(totalSize),
        totalSizeBytes: totalSize,
      },
    });
  } catch (err) {
    console.error("Get media error:", err);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

// Get Single Media
app.get("/api/media/:id", authenticateAdmin, async (req, res) => {
  try {
    const media = await Media.findById(req.params.id);

    if (!media) {
      return res.status(404).json({
        success: false,
        message: "Media not found",
      });
    }

    res.json({
      success: true,
      media: {
        id: media._id,
        title: media.title,
        originalName: media.originalName,
        type: media.type,
        size: media.sizeFormatted,
        category: media.category,
        description: media.description,
        url: media.url,
        createdAt: media.createdAt,
      },
    });
  } catch (err) {
    console.error("Get media error:", err);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

// Delete Media
app.delete("/api/media/:id", authenticateAdmin, async (req, res) => {
  try {
    const media = await Media.findById(req.params.id);

    if (!media) {
      return res.status(404).json({
        success: false,
        message: "Media not found",
      });
    }

    // Delete from GridFS if fileId exists
    if (media.fileId && gridFSBucket) {
      try {
        await gridFSBucket.delete(media.fileId);
      } catch (err) {
        console.error("GridFS delete error:", err);
      }
    }

    await Media.findByIdAndDelete(req.params.id);

    res.json({
      success: true,
      message: "Media deleted successfully",
    });
  } catch (err) {
    console.error("Delete media error:", err);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

// Delete All Media
app.delete("/api/media", authenticateAdmin, async (req, res) => {
  try {
    const { confirm } = req.body;

    if (confirm !== "DELETE_ALL_MEDIA") {
      return res.status(400).json({
        success: false,
        message: "Confirmation required. Send confirm: 'DELETE_ALL_MEDIA'",
      });
    }

    const allMedia = await Media.find({});

    // Delete all files from GridFS
    for (const media of allMedia) {
      if (media.fileId && gridFSBucket) {
        try {
          await gridFSBucket.delete(media.fileId);
        } catch (err) {
          console.error("GridFS delete error:", err);
        }
      }
    }

    await Media.deleteMany({});

    res.json({
      success: true,
      message: `Deleted ${allMedia.length} media files`,
    });
  } catch (err) {
    console.error("Delete all media error:", err);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

// ================= PUBLIC MEDIA ACCESS =================

app.get("/api/library/media", authenticateToken, async (req, res) => {
  try {
    const { type, search } = req.query;

    let query = {};
    if (type && type !== "all") query.type = type;
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } },
      ];
    }

    query.category = { $in: ["general", "tutorial", "documentation"] };

    const media = await Media.find(query)
      .select(
        "title description type category sizeFormatted url fileId createdAt",
      )
      .sort({ createdAt: -1 });

    res.json({
      success: true,
      media: media.map((m) => ({
        id: m._id,
        fileId: m.fileId,
        title: m.title,
        description: m.description,
        type: m.type,
        category: m.category,
        size: m.sizeFormatted,
        url: m.url,
        createdAt: m.createdAt,
      })),
    });
  } catch (err) {
    console.error("Library media error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ================= STREAM MEDIA FROM GRIDFS =================
app.get("/api/media/stream/:id", authenticateToken, async (req, res) => {
  try {
    const mediaId = req.params.id;
    let media;
    let fileIdToUse = mediaId;

    // Primary: try by media _id (library frontend sends this)
    if (mongoose.Types.ObjectId.isValid(mediaId)) {
      media = await Media.findById(mediaId);
    }

    // Fallback: try by GridFS fileId
    if (!media && mongoose.Types.ObjectId.isValid(mediaId)) {
      media = await Media.findOne({ fileId: mediaId });
      if (media) {
        fileIdToUse = media.fileId;
      }
    }

    if (!media) {
      return res.status(404).json({
        success: false,
        message: "Media not found in database",
      });
    }

    // Ensure we have a valid GridFS file id.
    // Backward compatibility: older media docs may not have fileId saved,
    // but may still contain a stream url with the GridFS id.
    if (media.fileId) {
      fileIdToUse = media.fileId;
    } else if (media.url) {
      const urlMatch = media.url.match(/\/api\/media\/stream\/([a-fA-F0-9]{24})/);
      if (urlMatch && urlMatch[1]) {
        fileIdToUse = urlMatch[1];
      } else {
        return res.status(404).json({
          success: false,
          message: "No file associated with this media",
        });
      }
    } else {
      return res.status(404).json({
        success: false,
        message: "No file associated with this media",
      });
    }

    if (!gridFSBucket) {
      return res.status(500).json({
        success: false,
        message: "GridFS not initialized",
      });
    }

    const fileIdObj = new mongoose.Types.ObjectId(fileIdToUse);

    // Check if file exists in GridFS
    const files = await mongoose.connection.db
      .collection("media.files")
      .findOne({ _id: fileIdObj });

    if (!files) {
      return res.status(404).json({
        success: false,
        message: "File not found in storage",
      });
    }

    // Set proper headers
    res.setHeader(
      "Content-Type",
      files.contentType || media.mimeType || "application/octet-stream",
    );
    res.setHeader(
      "Content-Disposition",
      `inline; filename="${media.originalName || media.title}"`,
    );

    // Create download stream from GridFS
    const downloadStream = gridFSBucket.openDownloadStream(fileIdObj);

    // Handle errors
    downloadStream.on("error", (err) => {
      console.error("GridFS stream error:", err);
      if (!res.headersSent) {
        res.status(500).json({ message: "Error streaming file" });
      }
    });

    // Pipe to response
    downloadStream.pipe(res);
  } catch (err) {
    console.error("Stream error:", err);
    res.status(500).json({
      success: false,
      message: "Server error while streaming file",
      error: err.message,
    });
  }
});

// ================= DIAGNOSTIC ENDPOINT - Step 1 Complete ✅ =================
// GET /api/media/diagnose/:id - Admin only - Debug PDF stream issues
app.get("/api/media/diagnose/:id", authenticateAdmin, async (req, res) => {
  try {
    const paramId = req.params.id;
    console.log(`🔍 DIAGNOSE: Checking media ID/fileId: ${paramId}`);

    let media = null;
    let gridFSFile = null;
    let validation = {};

    // Step 1: Try as GridFS fileId first
    if (mongoose.Types.ObjectId.isValid(paramId)) {
      media = await Media.findOne({ fileId: paramId });
      if (media) {
        console.log(`✅ Found Media by fileId: ${media._id} -> ${media.title}`);
        validation.primaryMatch = "fileId";
      }
    }

    // Step 2: Try as Media document _id (library frontend pattern)
    if (!media && mongoose.Types.ObjectId.isValid(paramId)) {
      media = await Media.findById(paramId);
      if (media) {
        console.log(`✅ Found Media by _id: ${media._id} -> ${media.title}`);
        validation.primaryMatch = "_id";
      }
    }

    if (!media) {
      return res.status(404).json({
        success: false,
        message: "Media not found by _id OR fileId",
        diagnostics: {
          paramId,
          validObjectId: mongoose.Types.ObjectId.isValid(paramId),
        },
      });
    }

    // Step 3: GridFS file validation
    if (!gridFSBucket) {
      return res.status(500).json({
        success: false,
        message: "GridFS not available",
        diagnostics: { mediaId: media._id, hasFileId: !!media.fileId },
      });
    }

    const fileIdObj = new mongoose.Types.ObjectId(media.fileId);
    gridFSFile = await mongoose.connection.db
      .collection("media.files")
      .findOne({ _id: fileIdObj });

    validation.gridFSExists = !!gridFSFile;
    validation.fileId = media.fileId.toString();
    validation.mediaId = media._id.toString();
    validation.expectedStreamUrl = `/api/media/stream/${media.fileId}`;
    validation.libraryUsesMediaId = true; // Frontend bug

    if (gridFSFile) {
      console.log(
        `✅ GridFS file EXISTS: ${gridFSFile.filename} (${gridFSFile.length} bytes)`,
      );
    } else {
      console.log(`❌ GridFS file MISSING for fileId: ${media.fileId}`);
    }

    res.json({
      success: true,
      message: "Diagnostic complete",
      media: {
        id: media._id,
        title: media.title,
        type: media.type,
        fileId: media.fileId,
        url: media.url,
        size: media.sizeFormatted,
        category: media.category,
      },
      gridFS:
        gridFSFile ?
          {
            exists: true,
            filename: gridFSFile.filename,
            length: gridFSFile.length,
            contentType: gridFSFile.contentType,
            uploadDate: gridFSFile.uploadDate,
          }
        : { exists: false },
      validation,
      fixRequired: !gridFSFile,
      testStreamUrl: `${req.protocol}://${req.get("host")}/api/media/stream/${media.fileId}?token=${req.query.token || "your-token"}`,
      nextSteps:
        gridFSFile ?
          ["✅ File OK - Frontend needs url fix"]
        : [
            "❌ Re-upload PDF",
            "Delete orphan Media doc: DELETE /api/media/{media._id}",
          ],
    });
  } catch (err) {
    console.error("Diagnose error:", err);
    res.status(500).json({
      success: false,
      message: "Diagnostic failed",
      error: err.message,
    });
  }
});

// ================= SENDGRID EMAIL FUNCTIONS =================

const FROM_EMAIL =
  process.env.EMAIL_FROM ||
  process.env.EMAIL_USER ||
  "noreply@ebundleethiopia.com";

const sendAdminResetEmail = async (email, otp, firstName) => {
  const msg = {
    to: email,
    from: FROM_EMAIL,
    subject: "Admin Password Reset Code - E-Bundle Ethiopia",
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f4f4f4;">
        <div style="background: linear-gradient(135deg, #3b82f6, #8b5cf6); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="color: white; margin: 0; font-size: 24px;">E-Bundle Ethiopia</h1>
          <p style="color: #e0e0e0; margin: 10px 0 0 0;">Admin Portal - Password Reset</p>
        </div>
        <div style="background-color: white; padding: 40px; border-radius: 0 0 10px 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
          <h2 style="color: #333; margin-top: 0;">Hello ${firstName || "Admin"},</h2>
          <p style="color: #666; font-size: 16px; line-height: 1.6;">
            You requested a password reset for your admin account. Use the following verification code to complete the process:
          </p>
          <div style="text-align: center; margin: 30px 0;">
            <div style="background: linear-gradient(135deg, #3b82f6, #8b5cf6); color: white; font-size: 32px; font-weight: bold; letter-spacing: 10px; padding: 20px; border-radius: 10px; display: inline-block;">
              ${otp}
            </div>
          </div>
          <p style="color: #666; font-size: 14px; text-align: center;">
            This code will expire in <strong>10 minutes</strong>.
          </p>
          <p style="color: #999; font-size: 12px; text-align: center; margin-top: 30px;">
            If you didn't request this code, please ignore this email or contact support immediately.
          </p>
        </div>
      </div>
    `,
    text: `Your E-Bundle Ethiopia admin password reset code is: ${otp}. This code will expire in 10 minutes.`,
  };

  try {
    await sgMail.send(msg);
    console.log(`✅ Admin reset email sent to ${email}`);
    return true;
  } catch (error) {
    console.error(
      `❌ Failed to send admin reset email to ${email}:`,
      error.response?.body || error.message,
    );
    return false;
  }
};

const sendOTPEmail = async (email, otp, firstName) => {
  const msg = {
    to: email,
    from: FROM_EMAIL,
    subject: "Your Email Verification Code - E-Bundle Ethiopia",
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f4f4f4;">
        <div style="background: linear-gradient(135deg, #4F46E5, #7C3AED); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="color: white; margin: 0; font-size: 24px;">E-Bundle Ethiopia</h1>
          <p style="color: #e0e0e0; margin: 10px 0 0 0;">Email Verification</p>
        </div>
        <div style="background-color: white; padding: 40px; border-radius: 0 0 10px 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
          <h2 style="color: #333; margin-top: 0;">Hello ${firstName || "Student"},</h2>
          <p style="color: #666; font-size: 16px; line-height: 1.6;">
            Thank you for signing up with E-Bundle Ethiopia! To complete your registration, please use the following verification code:
          </p>
          <div style="text-align: center; margin: 30px 0;">
            <div style="background: linear-gradient(135deg, #4F46E5, #7C3AED); color: white; font-size: 32px; font-weight: bold; letter-spacing: 10px; padding: 20px; border-radius: 10px; display: inline-block;">
              ${otp}
            </div>
          </div>
          <p style="color: #666; font-size: 14px; text-align: center;">
            This code will expire in <strong>10 minutes</strong>.
          </p>
          <p style="color: #999; font-size: 12px; text-align: center; margin-top: 30px;">
            If you didn't request this code, please ignore this email.
          </p>
        </div>
      </div>
    `,
    text: `Your E-Bundle Ethiopia verification code is: ${otp}. This code will expire in 10 minutes.`,
  };

  try {
    await sgMail.send(msg);
    console.log(`✅ OTP email sent to ${email}`);
    return true;
  } catch (error) {
    console.error(
      `❌ Failed to send OTP email to ${email}:`,
      error.response?.body || error.message,
    );
    return false;
  }
};

const sendResetLinkEmail = async (email, resetLink, firstName) => {
  const msg = {
    to: email,
    from: FROM_EMAIL,
    subject: "Reset Your Password - E-Bundle Ethiopia",
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f4f4f4;">
        <div style="background: linear-gradient(135deg, #4F46E5, #7C3AED); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="color: white; margin: 0;">E-Bundle Ethiopia</h1>
        </div>
        <div style="background-color: white; padding: 40px; border-radius: 0 0 10px 10px;">
          <h2 style="color: #333;">Password Reset Request</h2>
          <p style="color: #666;">Hello ${firstName || "Student"},</p>
          <p style="color: #666;">Click the link below to reset your password:</p>
          <div style="text-align: center; margin: 20px 0;">
            <a href="${resetLink}" style="display: inline-block; background: linear-gradient(135deg, #4F46E5, #7C3AED); color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px;">Reset Password</a>
          </div>
          <p style="color: #666; font-size: 14px;">Or copy and paste this link into your browser:</p>
          <p style="color: #4F46E5; font-size: 12px; word-break: break-all;">${resetLink}</p>
          <p style="color: #999; font-size: 12px; margin-top: 20px;">This link expires in 1 hour.</p>
          <p style="color: #999; font-size: 12px;">If you didn't request this, please ignore this email.</p>
        </div>
      </div>
    `,
    text: `Hello ${firstName || "Student"},\n\nClick the link below to reset your password:\n${resetLink}\n\nThis link expires in 1 hour.\n\nIf you didn't request this, please ignore this email.`,
  };

  try {
    await sgMail.send(msg);
    console.log(`✅ Reset link email sent to ${email}`);
    return true;
  } catch (error) {
    console.error(
      `❌ Failed to send reset link email to ${email}:`,
      error.response?.body || error.message,
    );
    return false;
  }
};

const generateAndSendModerationEmail = async (user, actionType, reason = "") => {
  const axios = require("axios");
  const userName = `${user.firstName || ""} ${user.lastName || ""}`.trim() || "Student";
  const actionText = actionType === "suspension" ? "Suspended" : "Removed / Deleted";
  
  let subject = "";
  let htmlBody = "";
  let textContent = "";

  const groqApiKey = process.env.GROQ_API_KEY;

  if (groqApiKey) {
    try {
      console.log(`🤖 Requesting Groq AI explanation for user ${user.email} (${actionType})...`);
      const response = await axios.post(
        "https://api.groq.com/openai/v1/chat/completions",
        {
          model: "llama-3.3-70b-versatile",
          messages: [
            {
              role: "system",
              content: `You are an AI administrator for E-Bundle Ethiopia, a premium unified learning platform for Ethiopian students. 
Draft a professional, respectful, empathetic yet firm email notifying a student about their account action (${actionType}).
You must output a raw JSON object containing exactly two keys: "subject" and "htmlBody".
The "htmlBody" must be beautiful HTML with inline CSS. Use a premium card layout on a light gray (#f4f4f4) body wrapper background, with a header banner using background: linear-gradient(135deg, #4F46E5, #7C3AED) (white E-Bundle Ethiopia title, light gray subtitle), a white card container with border-radius: 0 0 10px 10px and box-shadow: 0 2px 10px rgba(0,0,0,0.1), and an account action reason block styled with background-color: #F5F3FF and border-left: 4px solid #7C3AED. 
Do not include any markdown backticks or formatting outside the JSON itself. Returning valid JSON is critical.`
            },
            {
              role: "user",
              content: `Draft a ${actionType} email for student "${userName}".
Admin Reason for ${actionType}: "${reason || "Violating platform guidelines"}"`
            }
          ],
          response_format: { type: "json_object" },
          temperature: 0.7
        },
        {
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${groqApiKey}`
          },
          timeout: 10000
        }
      );

      const responseText = response.data.choices[0].message.content.trim();
      const parsed = JSON.parse(responseText);
      subject = parsed.subject;
      htmlBody = parsed.htmlBody;
      textContent = htmlBody.replace(/<[^>]*>/g, "");
      console.log(`🤖 Groq AI email draft generated successfully!`);
    } catch (err) {
      console.error("❌ Groq API failed or returned invalid JSON. Using fallback template.", err.message);
    }
  }

  // Fallback if GROQ_API_KEY is missing or request fails
  if (!subject || !htmlBody) {
    const isSuspension = actionType === "suspension";
    subject = isSuspension 
      ? "Account Status Update: Suspended - E-Bundle Ethiopia" 
      : "Account Status Update: Removed - E-Bundle Ethiopia";

    const reasonText = reason || "Violating the terms of service and community guidelines.";

    htmlBody = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f4f4f4;">
        <div style="background: linear-gradient(135deg, #4F46E5, #7C3AED); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="color: white; margin: 0; font-size: 24px;">E-Bundle Ethiopia</h1>
          <p style="color: #e0e0e0; margin: 10px 0 0 0;">Account ${actionText}</p>
        </div>
        <div style="background-color: white; padding: 40px; border-radius: 0 0 10px 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
          <h2 style="color: #333; margin-top: 0;">Hello ${userName},</h2>
          <p style="color: #666; font-size: 16px; line-height: 1.6;">
            We are writing to inform you that your E-Bundle Ethiopia account has been <strong>${actionText.toLowerCase()}</strong>.
          </p>
          <div style="background-color: #F5F3FF; border-left: 4px solid #7C3AED; padding: 15px; margin: 20px 0; border-radius: 4px;">
            <p style="margin: 0; color: #5B21B6; font-weight: bold;">Reason for Action:</p>
            <p style="margin: 5px 0 0 0; color: #4C1D95; line-height: 1.5;">${reasonText}</p>
          </div>
          ${isSuspension ? `
          <p style="color: #666; font-size: 15px; line-height: 1.6;">
            If you believe this was done in error or would like to request an appeal, please reply to this email or contact support.
          </p>
          ` : `
          <p style="color: #666; font-size: 15px; line-height: 1.6;">
            Your personal data, enrolled courses, and activity history have been removed from our system. If you wish to rejoin the platform, you will need to register for a new account in compliance with our policies.
          </p>
          `}
          <p style="color: #999; font-size: 12px; text-align: center; margin-top: 30px; border-top: 1px solid #eee; padding-top: 20px;">
            This is an automated notification. E-Bundle Ethiopia Administration.
          </p>
        </div>
      </div>
    `;
    textContent = `Hello ${userName},\n\nWe are writing to inform you that your E-Bundle Ethiopia account has been ${actionText.toLowerCase()}.\n\nReason: ${reasonText}\n\nE-Bundle Ethiopia Administration.`;
  }

  const msg = {
    to: user.email,
    from: FROM_EMAIL,
    subject: subject,
    html: htmlBody,
    text: textContent
  };

  try {
    await sgMail.send(msg);
    console.log(`✅ Moderation email (${actionType}) sent to ${user.email}`);
    return true;
  } catch (error) {
    console.error(
      `❌ Failed to send moderation email to ${user.email}:`,
      error.response?.body || error.message
    );
    return false;
  }
};

const sendSMS = async (phoneNumber, message) => {
  if (!sms) {
    console.error("❌ SMS service not initialized. Check your environment variables.");
    return false;
  }

  // Normalize phone number (ensure it starts with +)
  let normalizedPhone = phoneNumber.trim();
  if (!normalizedPhone.startsWith("+")) {
    normalizedPhone = "+" + normalizedPhone;
    console.log(`ℹ️ Normalized phone number to: ${normalizedPhone}`);
  }

  try {
    const result = await sms.send({
      to: [normalizedPhone],
      message: message,
      // from: 'YOUR_SHORT_CODE' // Optional: Uncomment if you have a Sender ID
    });
    
    // Africa's Talking returns a complex object. Let's check the status of each recipient.
    const recipient = result.SMSMessageData.Recipients[0];
    if (recipient && (recipient.status === "Success" || recipient.statusCode === 101)) {
      console.log(`✅ SMS successfully handed to Africa's Talking for ${normalizedPhone}`);
      return true;
    } else {
      console.error(`❌ Africa's Talking failed for ${normalizedPhone}:`, recipient);
      return false;
    }
  } catch (error) {
    console.error(`❌ Africa's Talking API Error for ${normalizedPhone}:`, error);
    return false;
  }
};

const sendPhoneOTP = async (phoneNumber, otp) => {
  const message = `Your E-Bundle Ethiopia verification code is: ${otp}. This code will expire in 10 minutes.`;
  return await sendSMS(phoneNumber, message);
};

const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Admin model moved to models/Admin.js

// ================= ADMIN AUTHENTICATION ENDPOINTS =================

app.post("/api/admin/signup", async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;

    if (!firstName || !lastName || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "All fields are required",
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 8 characters long",
      });
    }

    const existingAdmin = await Admin.findOne({ email: email.toLowerCase() });
    if (existingAdmin) {
      return res.status(400).json({
        success: false,
        message: "An account with this email already exists",
      });
    }

    const newAdmin = new Admin({
      firstName,
      lastName,
      email: email.toLowerCase(),
      password,
    });

    await newAdmin.save();

    const token = jwt.sign(
      { id: newAdmin._id, email: newAdmin.email, role: newAdmin.role },
      process.env.JWT_SECRET || "adminsecretkey",
      { expiresIn: "7d" },
    );

    res.status(201).json({
      success: true,
      message: "Admin account created successfully",
      token,
      admin: {
        id: newAdmin._id,
        firstName: newAdmin.firstName,
        lastName: newAdmin.lastName,
        email: newAdmin.email,
        role: newAdmin.role,
      },
    });
  } catch (err) {
    console.error("Admin signup error:", err);
    res.status(500).json({
      success: false,
      message: "Server error during signup",
    });
  }
});

app.post("/api/admin/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required",
      });
    }

    const admin = await Admin.findOne({ email: email.toLowerCase() });

    if (!admin) {
      return res.status(400).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    if (admin.isLocked()) {
      return res.status(403).json({
        success: false,
        message:
          "Account is temporarily locked due to multiple failed login attempts. Please try again later.",
      });
    }

    if (!admin.isActive) {
      return res.status(403).json({
        success: false,
        message: "Account has been deactivated. Please contact support.",
      });
    }

    const isMatch = await admin.comparePassword(password);

    if (!isMatch) {
      admin.loginAttempts += 1;
      if (admin.loginAttempts >= 5) {
        admin.lockUntil = new Date(Date.now() + 30 * 60 * 1000);
      }
      await admin.save();

      return res.status(400).json({
        success: false,
        message: "Invalid email or password",
        attemptsLeft: Math.max(0, 5 - admin.loginAttempts),
      });
    }

    admin.loginAttempts = 0;
    admin.lockUntil = undefined;
    admin.lastLogin = new Date();
    await admin.save();

    const token = jwt.sign(
      { id: admin._id, email: admin.email, role: admin.role },
      process.env.JWT_SECRET || "adminsecretkey",
      { expiresIn: "7d" },
    );

    res.json({
      success: true,
      message: "Login successful",
      token,
      admin: {
        id: admin._id,
        firstName: admin.firstName,
        lastName: admin.lastName,
        email: admin.email,
        role: admin.role,
        lastLogin: admin.lastLogin,
      },
    });
  } catch (err) {
    console.error("Admin login error:", err);
    res.status(500).json({
      success: false,
      message: "Server error during login",
    });
  }
});

app.get("/api/admin/profile", authenticateAdmin, async (req, res) => {
  try {
    const admin = await Admin.findById(req.admin.id).select(
      "-password -resetToken -resetOTP -loginAttempts -lockUntil",
    );

    res.json({
      success: true,
      admin: {
        id: admin._id,
        firstName: admin.firstName,
        lastName: admin.lastName,
        email: admin.email,
        role: admin.role,
        isActive: admin.isActive,
        lastLogin: admin.lastLogin,
        createdAt: admin.createdAt,
      },
    });
  } catch (err) {
    console.error("Get admin profile error:", err);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

app.put("/api/admin/profile", authenticateAdmin, async (req, res) => {
  try {
    const { firstName, lastName, email } = req.body;
    const updates = {};

    if (firstName) updates.firstName = firstName;
    if (lastName) updates.lastName = lastName;
    if (email) updates.email = email.toLowerCase();
    updates.updatedAt = new Date();

    if (email) {
      const existingAdmin = await Admin.findOne({
        email: email.toLowerCase(),
        _id: { $ne: req.admin.id },
      });
      if (existingAdmin) {
        return res.status(400).json({
          success: false,
          message: "Email is already in use by another account",
        });
      }
    }

    const updatedAdmin = await Admin.findByIdAndUpdate(req.admin.id, updates, {
      new: true,
    }).select("-password -resetToken -resetOTP -loginAttempts -lockUntil");

    res.json({
      success: true,
      message: "Profile updated successfully",
      admin: updatedAdmin,
    });
  } catch (err) {
    console.error("Update admin profile error:", err);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

app.post("/api/admin/change-password", authenticateAdmin, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: "Current password and new password are required",
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({
        success: false,
        message: "New password must be at least 8 characters long",
      });
    }

    const admin = await Admin.findById(req.admin.id);
    const isMatch = await admin.comparePassword(currentPassword);

    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: "Current password is incorrect",
      });
    }

    admin.password = newPassword;
    await admin.save();

    res.json({
      success: true,
      message: "Password changed successfully",
    });
  } catch (err) {
    console.error("Change admin password error:", err);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

app.post("/api/admin/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email is required",
      });
    }

    const admin = await Admin.findOne({ email: email.toLowerCase() });

    if (!admin) {
      return res.json({
        success: true,
        message:
          "If an account exists with this email, a verification code has been sent.",
      });
    }

    const otp = generateOTP();
    admin.resetOTP = otp;
    admin.resetOTPExpire = new Date(Date.now() + 10 * 60 * 1000);
    await admin.save();

    const emailSent = await sendAdminResetEmail(email, otp, admin.firstName);

    if (!emailSent) {
      return res.status(500).json({
        success: false,
        message: "Failed to send verification email. Please try again later.",
      });
    }

    res.json({
      success: true,
      message:
        "If an account exists with this email, a verification code has been sent.",
    });
  } catch (err) {
    console.error("Admin forgot password error:", err);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

app.post("/api/admin/verify-reset-code", async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({
        success: false,
        message: "Email and verification code are required",
      });
    }

    const admin = await Admin.findOne({ email: email.toLowerCase() });

    if (!admin) {
      return res.status(400).json({
        success: false,
        message: "Invalid email or code",
      });
    }

    if (!admin.resetOTP || !admin.resetOTPExpire) {
      return res.status(400).json({
        success: false,
        message: "No verification code found. Please request a new one.",
      });
    }

    if (admin.resetOTPExpire < Date.now()) {
      return res.status(400).json({
        success: false,
        message: "Verification code has expired. Please request a new one.",
      });
    }

    if (admin.resetOTP !== code) {
      return res.status(400).json({
        success: false,
        message: "Invalid verification code. Please try again.",
      });
    }

    const resetToken = crypto.randomBytes(32).toString("hex");
    admin.resetToken = resetToken;
    admin.resetTokenExpire = new Date(Date.now() + 15 * 60 * 1000);
    await admin.save();

    res.json({
      success: true,
      message: "Code verified successfully",
      resetToken: resetToken,
    });
  } catch (err) {
    console.error("Verify reset code error:", err);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

app.post("/api/admin/reset-password", async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;

    if (!email || !code || !newPassword) {
      return res.status(400).json({
        success: false,
        message: "Email, verification code, and new password are required",
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 8 characters long",
      });
    }

    const admin = await Admin.findOne({ email: email.toLowerCase() });

    if (!admin) {
      return res.status(400).json({
        success: false,
        message: "Invalid request",
      });
    }

    if (!admin.resetOTP || admin.resetOTP !== code) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired verification code",
      });
    }

    if (admin.resetOTPExpire < Date.now()) {
      return res.status(400).json({
        success: false,
        message: "Verification code has expired. Please request a new one.",
      });
    }

    admin.password = newPassword;
    admin.resetOTP = undefined;
    admin.resetOTPExpire = undefined;
    admin.resetToken = undefined;
    admin.resetTokenExpire = undefined;
    admin.loginAttempts = 0;
    admin.lockUntil = undefined;
    await admin.save();

    res.json({
      success: true,
      message:
        "Password reset successfully. You can now log in with your new password.",
    });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

app.post("/api/admin/logout", authenticateAdmin, async (req, res) => {
  try {
    res.json({
      success: true,
      message: "Logged out successfully",
    });
  } catch (err) {
    console.error("Admin logout error:", err);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

// ================= ADMIN DASHBOARD + MANAGEMENT ENDPOINTS =================
app.get("/api/admin/overview", authenticateAdmin, async (req, res) => {
  try {
    const { range = "weekly" } = req.query;
    const validRange = range === "monthly" ? "monthly" : "weekly";

    const [totalUsers, totalCourses, totalEnrollments] = await Promise.all([
      User.countDocuments({}),
      Course.countDocuments({}),
      Progress.countDocuments({}),
    ]);

    const recentActivity = await Activity.find({})
      .sort({ createdAt: -1 })
      .limit(10)
      .populate("userId", "firstName lastName email")
      .lean();

    // Revenue estimate based on progress records + course price.
    // Replace this with payment-based data if you add transaction records later.
    const revenueAggregation = await Progress.aggregate([
      {
        $lookup: {
          from: "courses",
          localField: "courseId",
          foreignField: "_id",
          as: "course",
        },
      },
      { $unwind: { path: "$course", preserveNullAndEmptyArrays: true } },
      {
        $addFields: {
          effectivePrice: { $ifNull: ["$course.price", 0] },
          bucket:
            validRange === "monthly" ?
              { $dateToString: { format: "%Y-%m", date: "$createdAt" } }
            : { $dateToString: { format: "%Y-W%V", date: "$createdAt" } },
        },
      },
      {
        $group: {
          _id: "$bucket",
          revenue: { $sum: "$effectivePrice" },
        },
      },
      { $sort: { _id: 1 } },
      { $limit: 12 },
    ]);

    res.json({
      success: true,
      overview: {
        totalUsers,
        totalCourses,
        totalEnrollments,
      },
      revenue: {
        range: validRange,
        points: revenueAggregation.map((item) => ({
          label: item._id,
          amount: Number(item.revenue || 0),
        })),
      },
      recentActivity: recentActivity.map((activity) => ({
        id: activity._id,
        type: activity.type,
        title: activity.title,
        description: activity.description,
        xp: activity.xp || 0,
        user:
          activity.userId ?
            {
              id: activity.userId._id,
              name:
                `${activity.userId.firstName || ""} ${activity.userId.lastName || ""}`.trim(),
              email: activity.userId.email || "",
            }
          : null,
        createdAt: activity.createdAt,
      })),
    });
  } catch (err) {
    console.error("Admin overview error:", err);
    res.status(500).json({
      success: false,
      message: "Failed to load admin overview",
    });
  }
});

app.get("/api/admin/users", authenticateAdmin, async (req, res) => {
  try {
    const { search = "", status = "all", page = 1, limit = 20 } = req.query;
    const parsedPage = Math.max(parseInt(page, 10) || 1, 1);
    const parsedLimit = Math.min(Math.max(parseInt(limit, 10) || 20, 1), 100);
    const skip = (parsedPage - 1) * parsedLimit;

    const query = {};
    if (search) {
      query.$or = [
        { firstName: { $regex: search, $options: "i" } },
        { lastName: { $regex: search, $options: "i" } },
        { email: { $regex: search, $options: "i" } },
      ];
    }
    if (status === "active") query.isActive = true;
    if (status === "inactive") query.isActive = false;

    const [users, total] = await Promise.all([
      User.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parsedLimit)
        .select("-password -otp -otpExpire -resetToken -resetTokenExpire")
        .lean(),
      User.countDocuments(query),
    ]);

    res.json({
      success: true,
      users: users.map((user) => ({
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        name: `${user.firstName || ""} ${user.lastName || ""}`.trim(),
        email: user.email,
        studentId: user.studentId,
        grade: user.grade,
        school: user.school,
        status: user.isActive === false ? "inactive" : "active",
        joinedDate: user.createdAt,
        isVerified: !!user.isVerified,
      })),
      pagination: {
        page: parsedPage,
        limit: parsedLimit,
        total,
        pages: Math.ceil(total / parsedLimit),
      },
    });
  } catch (err) {
    console.error("Admin users list error:", err);
    res.status(500).json({
      success: false,
      message: "Failed to load users",
    });
  }
});

app.get("/api/admin/users/:id", authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: "Invalid user id" });
    }

    const user = await User.findById(id)
      .select("-password -otp -otpExpire -resetToken -resetTokenExpire")
      .lean();
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    const progressDocs = await Progress.find({ userId: id })
      .populate("courseId", "title subject grade")
      .lean();

    const activities = await Activity.find({ userId: id })
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();

    res.json({
      success: true,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        name: `${user.firstName || ""} ${user.lastName || ""}`.trim(),
        email: user.email,
        studentId: user.studentId,
        grade: user.grade,
        school: user.school,
        status: user.isActive === false ? "inactive" : "active",
        joinedDate: user.createdAt,
      },
      enrolledCourses: progressDocs.map((progress) => ({
        progressId: progress._id,
        courseId: progress.courseId?._id || null,
        title: progress.courseId?.title || "Unknown course",
        subject: progress.courseId?.subject || null,
        grade: progress.courseId?.grade || null,
        percentage: progress.percentage || 0,
        completedLessons: progress.completedLessons || 0,
      })),
      activities: activities.map(act => ({
        id: act._id,
        type: act.type,
        title: act.title,
        description: act.description,
        createdAt: act.createdAt
      }))
    });
  } catch (err) {
    console.error("Admin user detail error:", err);
    res.status(500).json({
      success: false,
      message: "Failed to load user detail",
    });
  }
});

app.patch("/api/admin/users/:id/status", authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { isActive, reason } = req.body;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: "Invalid user id" });
    }
    if (typeof isActive !== "boolean") {
      return res.status(400).json({
        success: false,
        message: "isActive (boolean) is required",
      });
    }

    const updated = await User.findByIdAndUpdate(
      id,
      { isActive },
      { new: true },
    ).select("firstName lastName email isActive createdAt");

    if (!updated) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    if (isActive === false) {
      console.log(`User deactivation/suspension requested. Sending moderation email to ${updated.email}`);
      generateAndSendModerationEmail(updated, "suspension", reason).catch((err) => {
        console.error("Failed to send suspension email in background:", err);
      });
    }

    res.json({
      success: true,
      message: `User ${isActive ? "activated" : "deactivated"} successfully`,
      user: {
        id: updated._id,
        name: `${updated.firstName || ""} ${updated.lastName || ""}`.trim(),
        email: updated.email,
        status: updated.isActive ? "active" : "inactive",
        joinedDate: updated.createdAt,
      },
    });
  } catch (err) {
    console.error("Admin user status update error:", err);
    res.status(500).json({
      success: false,
      message: "Failed to update user status",
    });
  }
});

app.delete("/api/admin/users/:id", authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const reason = req.body.reason || req.query.reason;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: "Invalid user id" });
    }

    const user = await User.findById(id);
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    console.log(`User deletion requested. Sending moderation email to ${user.email}`);
    generateAndSendModerationEmail(user, "removal", reason).catch((err) => {
      console.error("Failed to send account removal email in background:", err);
    });

    await User.findByIdAndDelete(id);

    await Promise.all([
      Progress.deleteMany({ userId: id }),
      Activity.deleteMany({ userId: id }),
      mongoose.model('Enrollment').deleteMany({ userId: id }),
    ]);

    res.json({
      success: true,
      message: "User deleted successfully",
    });
  } catch (err) {
    console.error("Admin delete user error:", err);
    res.status(500).json({
      success: false,
      message: "Failed to delete user",
    });
  }
});

app.get("/api/admin/courses", authenticateAdmin, async (req, res) => {
  try {
    const { search = "", published = "all", page = 1, limit = 20 } = req.query;
    const parsedPage = Math.max(parseInt(page, 10) || 1, 1);
    const parsedLimit = Math.min(Math.max(parseInt(limit, 10) || 20, 1), 100);
    const skip = (parsedPage - 1) * parsedLimit;

    const query = {};
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } },
        { subject: { $regex: search, $options: "i" } },
        { category: { $regex: search, $options: "i" } },
      ];
    }
    if (published === "true") query.published = true;
    if (published === "false") query.published = false;

    const [courses, total] = await Promise.all([
      Course.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parsedLimit)
        .populate("mediaFiles", "title type url")
        .lean(),
      Course.countDocuments(query),
    ]);

    res.json({
      success: true,
      courses: courses.map((course) => ({
        id: course._id,
        title: course.title,
        description: course.description,
        thumbnail: course.thumbnail || "",
        category: course.category || course.subject || "",
        subject: course.subject,
        grade: course.grade,
        price: Number(course.price || 0),
        published: !!course.published,
        totalLessons: course.totalLessons || 0,
        mediaFiles: (course.mediaFiles || []).map((media) => ({
          id: media._id,
          title: media.title,
          type: media.type,
          url: media.url,
        })),
        createdAt: course.createdAt,
      })),
      pagination: {
        page: parsedPage,
        limit: parsedLimit,
        total,
        pages: Math.ceil(total / parsedLimit),
      },
    });
  } catch (err) {
    console.error("Admin courses list error:", err);
    res.status(500).json({
      success: false,
      message: "Failed to load courses",
    });
  }
});

app.post("/api/admin/courses", authenticateAdmin, async (req, res) => {
  try {
    const {
      title,
      description = "",
      thumbnail = "",
      category = "",
      subject,
      grade,
      price = 0,
      published = false,
      mediaFiles = [],
      lessons = [],
      totalLessons = 0,
      color = "from-blue-500 to-cyan-500",
      icon = "fa-book",
    } = req.body;

    if (!title || !description) {
      return res.status(400).json({
        success: false,
        message: "title and description are required",
      });
    }

    const allowedSubjects = [
      "math",
      "physics",
      "chemistry",
      "biology",
      "english",
      "amharic",
      "history",
      "geography",
      "cs",
    ];
    const normalizedSubject = allowedSubjects.includes(subject) ? subject : "cs";
    const normalizedGrade =
      Number.isInteger(grade) && grade >= 9 && grade <= 12 ? grade : 9;

    const course = await Course.create({
      title,
      description,
      thumbnail,
      category,
      subject: normalizedSubject,
      grade: normalizedGrade,
      price: Math.max(Number(price) || 0, 0),
      published: !!published,
      mediaFiles: Array.isArray(mediaFiles) ? mediaFiles : [],
      lessons: Array.isArray(lessons) ? lessons : [],
      totalLessons: Number(totalLessons) || 0,
      color,
      icon,
    });

    res.status(201).json({
      success: true,
      message: "Course created successfully",
      course: {
        id: course._id,
        title: course.title,
        description: course.description,
        thumbnail: course.thumbnail,
        category: course.category,
        subject: course.subject,
        grade: course.grade,
        price: course.price,
        published: course.published,
        totalLessons: course.totalLessons,
      },
    });
  } catch (err) {
    console.error("Admin create course error:", err);
    res.status(500).json({
      success: false,
      message: "Failed to create course",
    });
  }
});

app.put("/api/admin/courses/:id", authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid course id" });
    }

    const updates = { ...req.body };
    if (updates.price !== undefined) {
      updates.price = Math.max(Number(updates.price) || 0, 0);
    }
    if (updates.subject) {
      const allowedSubjects = [
        "math",
        "physics",
        "chemistry",
        "biology",
        "english",
        "amharic",
        "history",
        "geography",
        "cs",
      ];
      if (!allowedSubjects.includes(updates.subject)) {
        updates.subject = "cs";
      }
    }
    if (updates.grade !== undefined) {
      const parsedGrade = Number(updates.grade);
      updates.grade = parsedGrade >= 9 && parsedGrade <= 12 ? parsedGrade : 9;
    }

    const updatedCourse = await Course.findByIdAndUpdate(id, updates, {
      new: true,
      runValidators: true,
    }).lean();

    if (!updatedCourse) {
      return res
        .status(404)
        .json({ success: false, message: "Course not found" });
    }

    res.json({
      success: true,
      message: "Course updated successfully",
      course: {
        id: updatedCourse._id,
        title: updatedCourse.title,
        description: updatedCourse.description,
        thumbnail: updatedCourse.thumbnail || "",
        category: updatedCourse.category || "",
        subject: updatedCourse.subject,
        grade: updatedCourse.grade,
        price: Number(updatedCourse.price || 0),
        published: !!updatedCourse.published,
      },
    });
  } catch (err) {
    console.error("Admin update course error:", err);
    res.status(500).json({
      success: false,
      message: "Failed to update course",
    });
  }
});

app.patch(
  "/api/admin/courses/:id/publish",
  authenticateAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { published } = req.body;
      if (!mongoose.Types.ObjectId.isValid(id)) {
        return res
          .status(400)
          .json({ success: false, message: "Invalid course id" });
      }
      if (typeof published !== "boolean") {
        return res.status(400).json({
          success: false,
          message: "published (boolean) is required",
        });
      }

      const updatedCourse = await Course.findByIdAndUpdate(
        id,
        { published },
        { new: true },
      ).select("title published");

      if (!updatedCourse) {
        return res
          .status(404)
          .json({ success: false, message: "Course not found" });
      }

      res.json({
        success: true,
        message: `Course ${published ? "published" : "unpublished"} successfully`,
        course: {
          id: updatedCourse._id,
          title: updatedCourse.title,
          published: updatedCourse.published,
        },
      });
    } catch (err) {
      console.error("Admin publish toggle error:", err);
      res.status(500).json({
        success: false,
        message: "Failed to toggle publish status",
      });
    }
  },
);

app.delete("/api/admin/courses/:id", authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid course id" });
    }

    const deletedCourse = await Course.findByIdAndDelete(id);
    if (!deletedCourse) {
      return res
        .status(404)
        .json({ success: false, message: "Course not found" });
    }

    await Promise.all([
      Progress.deleteMany({ courseId: id }),
      Activity.deleteMany({ courseId: id }),
    ]);

    res.json({
      success: true,
      message: "Course deleted successfully",
    });
  } catch (err) {
    console.error("Admin delete course error:", err);
    res.status(500).json({
      success: false,
      message: "Failed to delete course",
    });
  }
});

// ================= USER ENDPOINTS (Students) =================

app.post("/signup", async (req, res) => {
  try {
    const {
      email,
      studentId,
      password,
      firstName,
      lastName,
      grade,
      school,
      phoneNumber,
    } = req.body;

    // Validate required fields
    if (
      !email ||
      !studentId ||
      !password ||
      !firstName ||
      !lastName ||
      !grade ||
      !school
    ) {
      return res.status(400).json({
        success: false,
        message:
          "All fields are required: email, studentId, password, firstName, lastName, grade, school",
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [{ email: email.toLowerCase() }, { studentId }],
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User already exists with this email or student ID",
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate OTPs
    const otp = generateOTP();
    const otpExpire = new Date(Date.now() + 10 * 60 * 1000);

    const phoneOtp = generateOTP();
    const phoneOtpExpire = new Date(Date.now() + 10 * 60 * 1000);

    // Create new user
    const newUser = new User({
      firstName,
      lastName,
      email: email.toLowerCase(),
      studentId,
      password: hashedPassword,
      grade: parseInt(grade),
      school,
      otp,
      otpExpire,
      phoneNumber,
      phoneOtp: phoneNumber ? phoneOtp : undefined,
      phoneOtpExpire: phoneNumber ? phoneOtpExpire : undefined,
      isVerified: false,
      isPhoneVerified: false,
      createdAt: new Date(),
    });

    await newUser.save();

    // Send OTP based on preference
    const { verificationMethod } = req.body;
    let emailSent = false;
    let phoneSent = false;

    if (verificationMethod === "phone" && phoneNumber) {
      phoneSent = await sendPhoneOTP(phoneNumber, phoneOtp);
    } else {
      // Default to email if no preference or email preferred
      emailSent = await sendOTPEmail(email, otp, firstName);
    }

    if (!emailSent && !phoneSent) {
      console.error(`Failed to send verification code to ${email}`);
      return res.status(201).json({
        success: false,
        message:
          "Account created but failed to send verification code. Please use resend OTP.",
        email: email,
      });
    }

    console.log(`✅ User created successfully: ${email}`);
    res.status(201).json({
      success: true,
      message:
        verificationMethod === "phone" ?
          "User created successfully. Please check your phone for verification code."
        : "User created successfully. Please check your email for verification code.",
      email: email,
      phoneNumber: phoneNumber,
    });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({
      success: false,
      message: "Error saving user: " + err.message,
    });
  }
});

app.post("/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        message: "Email and OTP are required",
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    if (user.isVerified) {
      return res.status(400).json({
        success: false,
        message: "Email is already verified",
      });
    }

    if (!user.otp) {
      return res.status(400).json({
        success: false,
        message: "No OTP found. Please request a new one.",
      });
    }

    if (user.otpExpire < Date.now()) {
      return res.status(400).json({
        success: false,
        message: "OTP has expired. Please request a new one.",
      });
    }

    if (user.otp !== otp) {
      return res.status(400).json({
        success: false,
        message: "Invalid OTP. Please try again.",
      });
    }

    user.isVerified = true;
    user.otp = null;
    user.otpExpire = null;
    await user.save();

    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET || "secretkey",
      { expiresIn: "7d" },
    );

    res.json({
      success: true,
      message: "Email verified successfully!",
      token,
      user: {
        firstName: user.firstName,
        email: user.email,
        studentId: user.studentId,
        isVerified: user.isVerified,
      },
    });
  } catch (err) {
    console.error("Verify OTP error:", err);
    res.status(500).json({
      success: false,
      message: "Server error during verification",
    });
  }
});

app.post("/resend-otp", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email is required",
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    if (user.isVerified) {
      return res.status(400).json({
        success: false,
        message: "Email is already verified",
      });
    }

    const otp = generateOTP();
    const otpExpire = new Date(Date.now() + 10 * 60 * 1000);

    user.otp = otp;
    user.otpExpire = otpExpire;
    await user.save();

    const emailSent = await sendOTPEmail(email, otp, user.firstName);

    if (!emailSent) {
      return res.status(500).json({
        success: false,
        message: "Failed to send verification email. Please try again.",
      });
    }

    res.json({
      success: true,
      message: "New verification code sent to your email",
    });
  } catch (err) {
    console.error("Resend OTP error:", err);
    res.status(500).json({
      success: false,
      message: "Server error while resending OTP",
    });
  }
});

app.post("/send-phone-otp", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email is required to find user",
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    if (!user.phoneNumber) {
      return res.status(400).json({
        success: false,
        message: "No phone number associated with this account",
      });
    }

    const otp = generateOTP();
    const otpExpire = new Date(Date.now() + 10 * 60 * 1000);

    user.phoneOtp = otp;
    user.phoneOtpExpire = otpExpire;
    await user.save();

    const phoneSent = await sendPhoneOTP(user.phoneNumber, otp);

    if (!phoneSent) {
      return res.status(500).json({
        success: false,
        message: "Failed to send SMS. Please try again later.",
      });
    }

    res.json({
      success: true,
      message: "New verification code sent to your phone",
    });
  } catch (err) {
    console.error("Send Phone OTP error:", err);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

app.post("/verify-phone-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        message: "Email and OTP are required",
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    if (!user.phoneOtp || user.phoneOtpExpire < Date.now()) {
      return res.status(400).json({
        success: false,
        message: "OTP has expired or not found. Please request a new one.",
      });
    }

    if (user.phoneOtp !== otp) {
      return res.status(400).json({
        success: false,
        message: "Invalid OTP",
      });
    }

    user.isPhoneVerified = true;
    user.isVerified = true; // Either email or phone makes it verified
    user.phoneOtp = null;
    user.phoneOtpExpire = null;
    await user.save();

    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET || "secretkey",
      { expiresIn: "7d" },
    );

    res.json({
      success: true,
      message: "Phone number verified successfully!",
      token,
      user: {
        firstName: user.firstName,
        email: user.email,
        studentId: user.studentId,
        isVerified: user.isVerified,
        isPhoneVerified: user.isPhoneVerified,
      },
    });
  } catch (err) {
    console.error("Verify Phone OTP error:", err);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

app.get("/test-sms", async (req, res) => {
  const { phone } = req.query;
  if (!phone) return res.send("Please provide a phone number: /test-sms?phone=+251...");
  
  const testOtp = Math.floor(100000 + Math.random() * 900000).toString();
  const success = await sendPhoneOTP(phone, testOtp);
  
  if (success) {
    res.send(`✅ Test SMS successfully handed to Africa's Talking for ${phone}. OTP was ${testOtp}. Please check your phone.`);
  } else {
    res.status(500).send(`❌ Test SMS failed for ${phone}. Check server logs for details.`);
  }
});

app.post("/login", async (req, res) => {
  try {
    const { loginId, password } = req.body;

    const user = await User.findOne({
      $or: [{ email: loginId }, { studentId: loginId }],
    });

    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    if (user.isActive === false) {
      return res.status(403).json({
        message: "you're suspended by the admin",
      });
    }

    if (!user.isVerified) {
      return res.status(403).json({
        message:
          "Please verify your email before logging in. Check your email for the verification code.",
        needsVerification: true,
        email: user.email,
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: "Invalid password" });
    }

    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET || "secretkey",
      { expiresIn: "7d" },
    );

    res.json({
      message: "Login successful",
      token,
      user: {
        firstName: user.firstName,
        email: user.email,
        studentId: user.studentId,
        isVerified: user.isVerified,
      },
    });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/profile", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select(
      "-password -otp -resetToken",
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({
      success: true,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        studentId: user.studentId,
        grade: user.grade,
        school: user.school,
        role: user.role || "student",
        isVerified: user.isVerified,
        bio: user.bio,
        avatar: user.avatar,
        quizScore: user.quizScore,
        quizTotal: user.quizTotal,
        streak: user.streak,
        progress: user.progress,
        totalStudyTime: user.totalStudyTime || 0,
      },
    });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.put("/profile", authenticateToken, async (req, res) => {
  try {
    const { firstName, lastName, email, grade, school, bio, avatar } = req.body;

    if (!firstName || !lastName || !email || !school) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    if (email) {
      const existingUser = await User.findOne({
        email,
        _id: { $ne: req.user.id },
      });
      if (existingUser) {
        return res
          .status(400)
          .json({ message: "Email already in use by another account" });
      }
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      {
        $set: {
          firstName,
          lastName,
          email,
          grade,
          school,
          bio: bio || "",
          avatar: avatar || "",
        },
      },
      { new: true },
    ).select("-password -otp -resetToken");

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({
      success: true,
      message: "Profile updated successfully",
      user: {
        id: updatedUser._id,
        firstName: updatedUser.firstName,
        lastName: updatedUser.lastName,
        email: updatedUser.email,
        studentId: updatedUser.studentId,
        grade: updatedUser.grade,
        school: updatedUser.school,
        bio: updatedUser.bio,
        avatar: updatedUser.avatar,
        role: updatedUser.role,
        isVerified: updatedUser.isVerified,
        quizScore: updatedUser.quizScore || 0,
        quizTotal: updatedUser.quizTotal || 0,
        streak: updatedUser.streak || 0,
        progress: updatedUser.progress || 0,
      },
    });
  } catch (err) {
    console.error("Profile update error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/track-media", authenticateToken, async (req, res) => {
  try {
    const { mediaId, mediaType, courseId, progress, completed, timeSpent } =
      req.body;

    let progressRecord = await Progress.findOne({
      userId: req.user.id,
      courseId: courseId || mediaId,
    });

    if (!progressRecord) {
      progressRecord = new Progress({
        userId: req.user.id,
        courseId: courseId || mediaId,
        completedLessons: 0,
        totalLessons: 1,
        percentage: 0,
        timeSpent: 0,
        mediaProgress: {},
      });
    }

    if (!progressRecord.mediaProgress) {
      progressRecord.mediaProgress = {};
    }

    progressRecord.mediaProgress[mediaId] = {
      progress: progress,
      completed: completed,
      lastAccessed: new Date(),
      type: mediaType,
    };

    const mediaKeys = Object.keys(progressRecord.mediaProgress);
    const completedMedia = mediaKeys.filter(
      (k) => progressRecord.mediaProgress[k].completed,
    ).length;

    progressRecord.completedLessons = completedMedia;
    progressRecord.percentage = Math.round(
      (completedMedia / progressRecord.totalLessons) * 100,
    );
    progressRecord.completed = progressRecord.percentage >= 100;
    progressRecord.timeSpent =
      (progressRecord.timeSpent || 0) + (timeSpent || 0);
    progressRecord.lastAccessed = new Date();

    await progressRecord.save();

    const activity = new Activity({
      userId: req.user.id,
      type: "lesson",
      title: completed ? "Completed lesson" : "Progress updated",
      description: `${completed ? "Finished" : "Continued"} ${mediaType} content`,
      xp: completed ? 10 : 5,
      courseId: courseId || mediaId,
    });
    await activity.save();

    res.json({
      success: true,
      progress: progressRecord.percentage,
      completed: progressRecord.completed,
    });
  } catch (err) {
    console.error("Track media error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/media-progress", authenticateToken, async (req, res) => {
  try {
    const progressRecords = await Progress.find({ userId: req.user.id });

    const mediaProgress = {};
    progressRecords.forEach((record) => {
      if (record.mediaProgress) {
        Object.entries(record.mediaProgress).forEach(([mediaId, data]) => {
          mediaProgress[mediaId] = data.progress || 0;
        });
      }
      mediaProgress[record.courseId?.toString()] = record.percentage || 0;
    });

    res.json({
      success: true,
      progress: mediaProgress,
    });
  } catch (err) {
    console.error("Get media progress error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/change-password", authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res
        .status(400)
        .json({ message: "Current password and new password are required" });
    }

    if (newPassword.length < 6) {
      return res
        .status(400)
        .json({ message: "New password must be at least 6 characters" });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Current password is incorrect" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.json({
      success: true,
      message: "Password changed successfully",
    });
  } catch (err) {
    console.error("Change password error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ================= FIXED FORGOT PASSWORD ENDPOINT =================
app.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const token = crypto.randomBytes(32).toString("hex");
    user.resetToken = token;
    user.resetTokenExpire = Date.now() + 3600000;
    await user.save();

    const frontendUrl =
      process.env.FRONTEND_URL || "https://ebundle-ethiopia.netlify.app";

    const resetLink = `${frontendUrl}/change-password?token=${token}`;

    console.log(`Sending reset link to ${email}: ${resetLink}`);

    const emailSent = await sendResetLinkEmail(
      email,
      resetLink,
      user.firstName,
    );

    if (!emailSent) {
      return res.status(500).json({ message: "Failed to send reset email" });
    }

    res.json({
      success: true,
      message: "Reset link sent to your email",
    });
  } catch (err) {
    console.error("Forgot password error:", err);
    res.status(500).json({ message: "Error sending email" });
  }
});

app.post("/reset-password", async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    const user = await User.findOne({
      resetToken: token,
      resetTokenExpire: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ message: "Invalid or expired token" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpire = undefined;
    await user.save();

    res.json({
      success: true,
      message: "Password reset successful",
    });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.delete("/delete-account", authenticateToken, async (req, res) => {
  try {
    const { password, confirmation } = req.body;

    if (confirmation !== "DELETE") {
      return res.status(400).json({
        message:
          "Confirmation text does not match. Please type DELETE to confirm.",
      });
    }

    if (!password) {
      return res.status(400).json({
        message: "Password is required to delete account",
      });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Incorrect password" });
    }

    await Activity.deleteMany({ userId: req.user.id });
    await Progress.deleteMany({ userId: req.user.id });
    await User.findByIdAndDelete(req.user.id);

    res.json({
      success: true,
      message: "Account deleted successfully",
    });
  } catch (err) {
    console.error("Delete account error:", err);
    res.status(500).json({ message: "Server error while deleting account" });
  }
});

app.post("/log-activity", authenticateToken, async (req, res) => {
  try {
    const { type, title, description, xp, courseId, timeSpent } = req.body;

    const activity = new Activity({
      userId: req.user.id,
      type,
      title,
      description,
      xp: xp || 0,
      courseId: courseId || null,
    });

    await activity.save();

    const updateFields = {};
    if (xp && xp > 0) updateFields.quizScore = xp;
    if (timeSpent) updateFields.totalStudyTime = timeSpent;

    if (Object.keys(updateFields).length > 0) {
      await User.findByIdAndUpdate(req.user.id, { $inc: updateFields });
    }

    res.json({
      success: true,
      message: "Activity logged successfully",
    });
  } catch (err) {
    console.error("Log activity error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/user-stats", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select(
      "streak quizScore quizTotal progress lastActive totalStudyTime",
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const rank =
      (await User.countDocuments({ quizScore: { $gt: user.quizScore || 0 } })) +
      1;

    res.json({
      success: true,
      stats: {
        streak: user.streak || 0,
        quizScore: user.quizScore || 0,
        quizTotal: user.quizTotal || 0,
        progress: user.progress || 0,
        rank: rank,
        totalStudyTime: user.totalStudyTime || 0,
        lastActive: user.lastActive,
      },
    });
  } catch (err) {
    console.error("Get stats error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/update-progress", authenticateToken, async (req, res) => {
  try {
    const { courseId, completedLessons, totalLessons, timeSpent } = req.body;
    const userId = req.user.id;

    let progress = await Progress.findOne({ userId, courseId });
    if (!progress) {
      progress = new Progress({
        userId,
        courseId,
        completedLessons: 0,
        totalLessons: totalLessons || 0,
        percentage: 0,
        timeSpent: 0,
      });
    }

    if (completedLessons !== undefined) progress.completedLessons = completedLessons;
    if (totalLessons !== undefined) progress.totalLessons = totalLessons;
    if (timeSpent) progress.timeSpent = (progress.timeSpent || 0) + timeSpent;
    progress.lastAccessed = new Date();

    if (progress.totalLessons > 0) {
      progress.percentage = Math.round((progress.completedLessons / progress.totalLessons) * 100);
    }
    progress.completed = progress.percentage >= 100;
    await progress.save();

    // Update User Stats
    if (timeSpent) {
      const user = await User.findById(userId);
      if (user) {
        const today = new Date().toISOString().split('T')[0];
        if (user.lastStudyDate !== today) {
          user.dailyStudyTime = 0;
          user.lastStudyDate = today;
        }
        user.dailyStudyTime += timeSpent;
        user.totalStudyTime += timeSpent;
        user.lastActive = new Date();
        await user.save();
      }
    }

    res.json({ success: true, progress: progress.percentage });
  } catch (err) {
    console.error("Update progress error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/api/media-progress/report", authenticateToken, async (req, res) => {
  try {
    const { mediaId, progress, timeSpent, completed } = req.body;
    const userId = req.user.id;

    let p = await Progress.findOne({ userId, courseId: mediaId });
    if (!p) {
      p = new Progress({
        userId,
        courseId: mediaId,
        percentage: 0,
        timeSpent: 0
      });
    }

    p.percentage = Math.max(p.percentage || 0, progress || 0);
    if (timeSpent) p.timeSpent = (p.timeSpent || 0) + timeSpent;
    if (completed) p.completed = true;
    p.lastAccessed = new Date();
    await p.save();

    // Update user stats
    const user = await User.findById(userId);
    if (user) {
      const today = new Date().toISOString().split('T')[0];
      if (user.lastStudyDate !== today) {
        user.dailyStudyTime = 0;
        user.lastStudyDate = today;
      }
      if (timeSpent) {
        user.dailyStudyTime += timeSpent;
        user.totalStudyTime += timeSpent;
      }
      user.lastActive = new Date();
      await user.save();
    }

    res.json({ success: true, progress: p.percentage });
  } catch (err) {
    console.error("Media progress report error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ================= LIBRARY ENDPOINTS =================

app.get("/api/library", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("grade");
    const userGrade = parseInt(user.grade) || 9;

    const materials = [
      {
        id: 1,
        type: "audio",
        title: "Biology: Cell Structure and Function",
        subject: "Science",
        duration: "12:00",
        icon: "fa-headphones",
        color: "text-green-400",
        grade: 9,
        description: "Learn about cell organelles and their functions",
        url: "/content/audio/biology-cells.mp3",
      },
      {
        id: 2,
        type: "audio",
        title: "Math: Algebra Basics - Linear Equations",
        subject: "Math",
        duration: "15:30",
        icon: "fa-headphones",
        color: "text-blue-400",
        grade: 9,
        description: "Master linear equations with step-by-step examples",
        url: "/content/audio/math-algebra.mp3",
      },
      {
        id: 3,
        type: "video",
        title: "Physics: Understanding Gravity",
        subject: "Science",
        duration: "08:45",
        icon: "fa-video",
        color: "text-red-400",
        grade: 9,
        description: "Visual explanation of gravitational force",
        thumbnail: "https://img.youtube.com/vi/0fKBhvDjuy0/0.jpg",
        url: "https://www.youtube.com/embed/0fKBhvDjuy0",
      },
      {
        id: 4,
        type: "pdf",
        title: "Chemistry Cheat Sheet - Grade 9",
        subject: "Science",
        size: "2.4 MB",
        icon: "fa-file-pdf",
        color: "text-purple-400",
        grade: 9,
        description: "Quick reference for all grade 9 chemistry topics",
        url: "/content/pdfs/chemistry-cheatsheet.pdf",
      },
    ];

    const progressRecords = await Progress.find({ userId: req.user.id });
    const progressMap = {};
    progressRecords.forEach((p) => {
      progressMap[p.courseId?.toString()] = p.percentage;
    });

    const materialsWithProgress = materials.map((m) => ({
      ...m,
      progress: progressMap[m.id] || 0,
    }));

    res.json({
      success: true,
      materials: materialsWithProgress,
      count: materials.length,
    });
  } catch (err) {
    console.error("Library fetch error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/progress", authenticateToken, async (req, res) => {
  try {
    const progress = await Progress.find({ userId: req.user.id });

    const progressMap = {};
    progress.forEach((p) => {
      progressMap[p.courseId?.toString() || p.materialId] = p.percentage || 0;
    });

    res.json({
      success: true,
      progress: progressMap,
    });
  } catch (err) {
    console.error("Progress fetch error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ================= COMMUNITY ENDPOINTS =================

app.get("/api/study-groups", authenticateToken, async (req, res) => {
  try {
    const groups = [
      {
        id: "grade9-prep",
        name: "Grade 9 Prep",
        icon: "fa-hashtag",
        color: "primary",
        online: 89,
        subject: "General",
        unread: 0,
      },
      {
        id: "grade10-prep",
        name: "Grade 10 Prep",
        icon: "fa-hashtag",
        color: "primary",
        online: 124,
        subject: "General",
        unread: 3,
      },
      {
        id: "grade12-egsece",
        name: "Grade 12 EGSECE",
        icon: "fa-graduation-cap",
        color: "secondary",
        online: 156,
        subject: "Exam Prep",
        unread: 0,
      },
      {
        id: "math-help",
        name: "Math Help Center",
        icon: "fa-calculator",
        color: "green",
        online: 67,
        subject: "Math",
        unread: 1,
      },
      {
        id: "science-lab",
        name: "Science Lab",
        icon: "fa-flask",
        color: "purple",
        online: 45,
        subject: "Science",
        unread: 0,
      },
    ];

    res.json({
      success: true,
      groups: groups,
    });
  } catch (err) {
    console.error("Study groups error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ================= MESSAGE SCHEMA FOR PERSISTENT CHAT =================
const messageSchema = new mongoose.Schema({
  groupId: { type: String, required: true, index: true },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    index: true,
  },
  user: { type: String, required: true },
  avatar: { type: String, default: "" },
  text: { type: String, required: true },
  edited: { type: Boolean, default: false },
  editedAt: { type: Date },
  createdAt: { type: Date, default: Date.now, index: true },
  updatedAt: { type: Date, default: Date.now },
});

const Message = mongoose.model("Message", messageSchema);

app.get("/api/messages", authenticateToken, async (req, res) => {
  try {
    const { group, limit = 100, before } = req.query;

    let query = { groupId: group || "general" };

    if (before) {
      query.createdAt = { $lt: new Date(before) };
    }

    const messages = await Message.find(query)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .lean();

    const userIds = [...new Set(messages.map((m) => m.userId))];
    const users = await User.find({ _id: { $in: userIds } }).select(
      "firstName lastName avatar",
    );
    const userMap = {};
    users.forEach((u) => {
      userMap[u._id.toString()] = u;
    });

    const enrichedMessages = messages
      .map((m) => ({
        id: m._id,
        userId: m.userId,
        user: m.user,
        avatar:
          m.avatar ||
          userMap[m.userId]?.avatar ||
          `https://api.dicebear.com/7.x/avataaars/svg?seed=${m.user}`,
        text: m.text,
        edited: m.edited || false,
        createdAt: m.createdAt,
        updatedAt: m.updatedAt,
      }))
      .reverse();

    res.json({
      success: true,
      messages: enrichedMessages,
      count: enrichedMessages.length,
    });
  } catch (err) {
    console.error("Get messages error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/api/messages", authenticateToken, async (req, res) => {
  try {
    const { groupId, text } = req.body;

    if (!text || !text.trim()) {
      return res
        .status(400)
        .json({ success: false, message: "Message text is required" });
    }

    const user = await User.findById(req.user.id).select(
      "firstName lastName avatar",
    );

    const newMessage = new Message({
      groupId: groupId || "general",
      userId: req.user.id,
      user: `${user.firstName} ${user.lastName ? user.lastName.charAt(0) + "." : ""}`,
      avatar:
        user.avatar ||
        `https://api.dicebear.com/7.x/avataaars/svg?seed=${user.firstName}`,
      text: text.trim(),
      edited: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    await newMessage.save();

    const activity = new Activity({
      userId: req.user.id,
      type: "community",
      title: "Posted in community",
      description: `Sent message to ${groupId}`,
      xp: 2,
    });
    await activity.save();

    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const lastActive = user.lastActive ? new Date(user.lastActive) : null;
    if (lastActive) {
      lastActive.setHours(0, 0, 0, 0);
      const diffTime = today - lastActive;
      const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));
      if (diffDays === 1) {
        user.streak = (user.streak || 0) + 1;
      } else if (diffDays > 1) {
        user.streak = 1;
      }
    } else {
      user.streak = 1;
    }
    user.lastActive = new Date();
    await user.save();

    res.json({
      success: true,
      message: {
        id: newMessage._id,
        userId: newMessage.userId,
        user: newMessage.user,
        avatar: newMessage.avatar,
        text: newMessage.text,
        edited: false,
        createdAt: newMessage.createdAt,
      },
    });
  } catch (err) {
    console.error("Send message error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.put("/api/messages/:messageId", authenticateToken, async (req, res) => {
  try {
    const { messageId } = req.params;
    const { text } = req.body;

    if (!text || !text.trim()) {
      return res
        .status(400)
        .json({ success: false, message: "Message text is required" });
    }

    const message = await Message.findById(messageId);

    if (!message) {
      return res
        .status(404)
        .json({ success: false, message: "Message not found" });
    }

    if (message.userId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: "You can only edit your own messages",
      });
    }

    message.text = text.trim();
    message.edited = true;
    message.editedAt = new Date();
    message.updatedAt = new Date();

    await message.save();

    res.json({
      success: true,
      message: {
        id: message._id,
        text: message.text,
        edited: true,
        editedAt: message.editedAt,
      },
    });
  } catch (err) {
    console.error("Edit message error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.delete("/api/messages/:messageId", authenticateToken, async (req, res) => {
  try {
    const { messageId } = req.params;

    const message = await Message.findById(messageId);

    if (!message) {
      return res
        .status(404)
        .json({ success: false, message: "Message not found" });
    }

    if (message.userId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: "You can only delete your own messages",
      });
    }

    await Message.findByIdAndDelete(messageId);

    res.json({
      success: true,
      message: "Message deleted successfully",
    });
  } catch (err) {
    console.error("Delete message error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/api/direct-messages", authenticateToken, async (req, res) => {
  try {
    const messages = [
      {
        id: 1,
        name: "Almaz T.",
        avatar: "https://api.dicebear.com/7.x/avataaars/svg?seed=Almaz",
        status: "online",
        lastMessage: "2m ago",
        unread: 2,
      },
      {
        id: 2,
        name: "Kebede A.",
        avatar: "https://api.dicebear.com/7.x/avataaars/svg?seed=Kebede",
        status: "offline",
        lastMessage: "1h ago",
        unread: 0,
      },
    ];

    res.json({
      success: true,
      messages: messages,
    });
  } catch (err) {
    console.error("Direct messages error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/seed-courses", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (user.role !== "admin") {
      return res.status(403).json({ message: "Admin access required" });
    }

    const courses = [
      {
        title: "Mathematics",
        subject: "math",
        grade: 9,
        description: "Algebra, Geometry, and Statistics",
        totalLessons: 45,
        published: true,
        color: "from-blue-500 to-cyan-500",
        icon: "fa-calculator",
      },
      {
        title: "Physics",
        subject: "physics",
        grade: 9,
        description: "Mechanics, Heat, and Waves",
        totalLessons: 38,
        published: true,
        color: "from-orange-500 to-red-500",
        icon: "fa-atom",
      },
      {
        title: "Chemistry",
        subject: "chemistry",
        grade: 9,
        description: "Atomic Structure and Reactions",
        totalLessons: 35,
        published: true,
        color: "from-green-500 to-emerald-500",
        icon: "fa-flask",
      },
      {
        title: "Biology",
        subject: "biology",
        grade: 9,
        description: "Cell Biology and Ecology",
        totalLessons: 42,
        published: true,
        color: "from-purple-500 to-pink-500",
        icon: "fa-dna",
      },
      {
        title: "English",
        subject: "english",
        grade: 9,
        description: "Grammar and Literature",
        totalLessons: 50,
        published: true,
        color: "from-indigo-500 to-blue-500",
        icon: "fa-book",
      },
      {
        title: "Amharic",
        subject: "amharic",
        grade: 9,
        description: "Language and Literature",
        totalLessons: 48,
        published: true,
        color: "from-yellow-500 to-orange-500",
        icon: "fa-language",
      },
      {
        title: "Mathematics",
        subject: "math",
        grade: 10,
        description: "Advanced Algebra and Geometry",
        totalLessons: 50,
        published: true,
        color: "from-blue-500 to-cyan-500",
        icon: "fa-calculator",
      },
      {
        title: "Physics",
        subject: "physics",
        grade: 10,
        description: "Electricity and Magnetism",
        totalLessons: 40,
        published: true,
        color: "from-orange-500 to-red-500",
        icon: "fa-atom",
      },
    ];

    for (const courseData of courses) {
      await Course.findOneAndUpdate(
        { title: courseData.title, grade: courseData.grade },
        courseData,
        { upsert: true, new: true },
      );
    }

    res.json({
      success: true,
      message: "Courses seeded successfully",
    });
  } catch (err) {
    console.error("Seed courses error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ================= COURSES ENDPOINTS =================

// Get all courses for library
app.get("/api/courses", authenticateToken, async (req, res) => {
  try {
    const { subject, grade, search, page = 1, limit = 50 } = req.query;

    let query = {};

    if (subject && subject !== "all") {
      query.subject = subject;
    }

    if (grade && grade !== "all") {
      query.grade = parseInt(grade);
    }

    if (search) {
      query.$or = [
        { title: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } },
        { subject: { $regex: search, $options: "i" } },
      ];
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const [courses, total] = await Promise.all([
      Course.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Course.countDocuments(query),
    ]);

    // Get user progress for these courses
    const progressRecords = await Progress.find({
      userId: req.user.id,
      courseId: { $in: courses.map((c) => c._id) },
    });

    const progressMap = {};
    progressRecords.forEach((record) => {
      progressMap[record.courseId.toString()] = {
        percentage: record.percentage || 0,
        completedLessons: record.completedLessons || 0,
        totalLessons: record.totalLessons || 0,
      };
    });

    // Get unique subjects for filter
    const subjects = await Course.distinct("subject");
    const grades = await Course.distinct("grade");

    res.json({
      success: true,
      courses: courses.map((course) => ({
        id: course._id,
        title: course.title,
        subject: course.subject,
        grade: course.grade,
        description: course.description,
        totalLessons: course.totalLessons || 0,
        icon: course.icon || "fa-book",
        color: course.color || "from-blue-500 to-cyan-500",
        thumbnail: course.thumbnail || null,
        createdAt: course.createdAt,
        progress: progressMap[course._id.toString()]?.percentage || 0,
        completedLessons:
          progressMap[course._id.toString()]?.completedLessons || 0,
      })),
      filters: {
        subjects: subjects,
        grades: grades.sort((a, b) => a - b),
      },
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit)),
      },
    });
  } catch (err) {
    console.error("Get courses error:", err);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

// Get single course details
app.get("/api/courses/:id", authenticateToken, async (req, res) => {
  try {
    const course = await Course.findById(req.params.id).lean();

    if (!course) {
      return res.status(404).json({
        success: false,
        message: "Course not found",
      });
    }

    // Get user progress for this course
    const progress = await Progress.findOne({
      userId: req.user.id,
      courseId: course._id,
    });

    res.json({
      success: true,
      course: {
        id: course._id,
        title: course.title,
        subject: course.subject,
        grade: course.grade,
        description: course.description,
        totalLessons: course.totalLessons || 0,
        content: course.content || [],
        icon: course.icon || "fa-book",
        color: course.color || "from-blue-500 to-cyan-500",
        thumbnail: course.thumbnail || null,
        createdAt: course.createdAt,
        progress: progress?.percentage || 0,
        completedLessons: progress?.completedLessons || 0,
      },
    });
  } catch (err) {
    console.error("Get course error:", err);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

// ================= API ROUTES =================
app.use("/api/dashboard", dashboardRoutes);
app.use("/api/enrollments", enrollmentRoutes);

// ================= AI TUTOR CHAT (GROQ API) =================
const axios = require("axios");

// Get the model from environment or use default - UPDATED to current available models
const getGroqModel = () => {
  const envModel = process.env.GROQ_MODEL;

  // List of currently active Groq models (as of April 2026)
  const activeModels = [
    "llama-3.3-70b-versatile",
    "llama-3.3-70b-specdec",
    "llama-3.2-90b-text-preview",
    "llama-3.2-11b-text-preview",
    "llama-3.2-3b-preview",
    "llama-3.2-1b-preview",
    "mixtral-8x7b-32768",
    "gemma2-9b-it",
    "gemma-7b-it",
    "deepseek-r1-distill-llama-70b",
    "qwen-2.5-32b",
    "qwen-2.5-7b",
  ];

  // If environment variable is set and valid, use it
  if (envModel && activeModels.includes(envModel)) {
    return envModel;
  }

  // Otherwise use the recommended default (Llama 3.3 70B)
  return "llama-3.3-70b-versatile";
};

// Test endpoint to verify Groq configuration
app.get("/api/groq-status", authenticateToken, async (req, res) => {
  const hasKey = !!process.env.GROQ_API_KEY;
  const model = getGroqModel();

  res.json({
    configured: hasKey,
    model: model,
    message:
      hasKey ?
        "Groq API is configured and ready"
      : "GROQ_API_KEY is missing. Please add it to your environment variables.",
    howToGetKey: "Get your free API key from https://console.groq.com",
  });
});

// Test endpoint to verify the route is working
app.get("/api/chat-test", authenticateToken, (req, res) => {
  res.json({
    success: true,
    message: "Chat endpoint is reachable",
    groqConfigured: !!process.env.GROQ_API_KEY,
    timestamp: new Date().toISOString(),
  });
});

// Main chat endpoint with fallback to multiple models
app.post("/api/chat", authenticateToken, async (req, res) => {
  console.log("\n========== NEW CHAT REQUEST ==========");
  console.log("Timestamp:", new Date().toISOString());

  try {
    const { message } = req.body;
    const userId = req.user.id;

    if (!message || message.trim().length === 0) {
      return res.status(400).json({
        success: false,
        error: "Message is required",
      });
    }

    const user = await User.findById(userId).select("firstName grade");

    const GROQ_API_KEY = process.env.GROQ_API_KEY;

    if (!GROQ_API_KEY) {
      console.error("❌ GROQ_API_KEY not found");
      return res.status(500).json({
        success: false,
        error: "AI service not configured - API key missing",
      });
    }

    // List of models to try in order (fallback)
    const modelsToTry = [
      getGroqModel(),
      "llama-3.2-3b-preview",
      "mixtral-8x7b-32768",
      "gemma2-9b-it",
      "qwen-2.5-7b",
    ];

    const systemContent = `You are an AI tutor for Ethiopian students${user ? ` named ${user.firstName}` : ""}${user?.grade ? ` in grade ${user.grade}` : ""}. 
              
Your role is to help students learn and understand academic subjects including:
- Mathematics (Algebra, Geometry, Calculus, Statistics)
- Physics (Mechanics, Electricity, Waves, Thermodynamics)
- Chemistry (Organic, Inorganic, Physical Chemistry)
- Biology (Cell Biology, Genetics, Ecology, Human Anatomy)
- English Language and Literature
- History (Ethiopian and World History)
- Geography
- Computer Science

Guidelines:
- Provide clear, step-by-step explanations
- Use examples relevant to Ethiopian context when possible
- Be encouraging and supportive
- If unsure, admit it and suggest resources
- Keep responses concise but thorough (under 500 words)
- Use formatting like **bold** for key terms and *bullet points* for lists
- For math problems, show all work clearly`;

    let lastError = null;
    let aiResponse = null;

    for (const model of modelsToTry) {
      try {
        console.log(`Trying Groq model: ${model}`);

        const response = await axios.post(
          "https://api.groq.com/openai/v1/chat/completions",
          {
            model: model,
            messages: [
              { role: "system", content: systemContent },
              { role: "user", content: message },
            ],
            temperature: 0.7,
            max_tokens: 1024,
            top_p: 0.9,
          },
          {
            headers: {
              Authorization: `Bearer ${GROQ_API_KEY}`,
              "Content-Type": "application/json",
            },
            timeout: 30000,
          },
        );

        aiResponse = response.data.choices[0].message.content;
        console.log(`✅ Successfully used model: ${model}`);
        break;
      } catch (modelError) {
        console.warn(
          `Model ${model} failed:`,
          modelError.response?.data?.error?.message || modelError.message,
        );
        lastError = modelError;
      }
    }

    if (aiResponse) {
      return res.json({
        success: true,
        response: aiResponse,
      });
    }

    console.error("🚨 ALL AI MODELS FAILED");
    return res.status(500).json({
      success: false,
      error: "All AI models are currently unavailable. Please try again later.",
      details: lastError?.response?.data?.error?.message || lastError?.message,
    });
  } catch (error) {
    console.error("❌ Chat error:", error.message);
    if (error.response) {
      console.error("Response status:", error.response.status);
      console.error(
        "Response data:",
        JSON.stringify(error.response.data, null, 2),
      );
    }

    res.status(500).json({
      success: false,
      error: "Failed to get AI response. Please try again later.",
    });
  }
});

// ================= TEST ENDPOINT =================
app.get("/api/test", async (req, res) => {
  try {
    const GROQ_API_KEY = process.env.GROQ_API_KEY;

    if (!GROQ_API_KEY) {
      return res.json({
        success: false,
        error: "GROQ_API_KEY not found in .env",
      });
    }

    const modelsToTest = [
      getGroqModel(),
      "llama-3.2-3b-preview",
      "mixtral-8x7b-32768",
    ];

    let workingModel = null;
    let testResponse = null;

    for (const model of modelsToTest) {
      try {
        console.log(`Testing model: ${model}`);
        const response = await axios.post(
          "https://api.groq.com/openai/v1/chat/completions",
          {
            model: model,
            messages: [
              {
                role: "user",
                content: "Say 'API is working!' if you receive this.",
              },
            ],
            max_tokens: 50,
          },
          {
            headers: {
              Authorization: `Bearer ${GROQ_API_KEY}`,
              "Content-Type": "application/json",
            },
            timeout: 10000,
          },
        );

        workingModel = model;
        testResponse = response.data.choices[0].message.content;
        break;
      } catch (err) {
        console.warn(
          `Model ${model} test failed:`,
          err.response?.data?.error?.message,
        );
      }
    }

    if (workingModel) {
      return res.json({
        success: true,
        message: "Groq API test successful",
        workingModel: workingModel,
        response: testResponse,
      });
    } else {
      return res.json({
        success: false,
        error: "No working models found. Please check your Groq API key.",
      });
    }
  } catch (error) {
    console.error("Test endpoint error:", error.message);
    res.json({
      success: false,
      error: error.message,
    });
  }
});

// ================= HEALTH CHECK ENDPOINT =================
app.get("/health", (req, res) => {
  const dbState = mongoose.connection.readyState;
  const dbStatus = {
    0: "disconnected",
    1: "connected",
    2: "connecting",
    3: "disconnecting",
  }[dbState];

  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    mongodb: dbStatus,
    environment: process.env.NODE_ENV || "development",
  });
});

// ================= COMMUNITY CHAT REST API =================

// GET messages for a group (last 60, non-deleted)
app.get("/api/community/:groupId/messages", authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    const limit = Math.min(parseInt(req.query.limit) || 60, 200);
    const messages = await ChatMessage.find({
      groupId,
      deletedAt: null,
    })
      .sort({ createdAt: -1 })
      .limit(limit)
      .lean();
    // Return in chronological order
    res.json({ success: true, messages: messages.reverse() });
  } catch (err) {
    console.error("Community GET messages error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// PUT /api/community/messages/:messageId — edit own message
app.put("/api/community/messages/:messageId", authenticateToken, async (req, res) => {
  try {
    const { messageId } = req.params;
    const { text } = req.body;
    if (!text || !text.trim()) {
      return res.status(400).json({ success: false, message: "Text is required" });
    }
    const msg = await ChatMessage.findOne({ messageId, deletedAt: null });
    if (!msg) return res.status(404).json({ success: false, message: "Message not found" });
    if (msg.userId !== req.user.id && msg.userId !== String(req.user._id)) {
      return res.status(403).json({ success: false, message: "Not your message" });
    }
    msg.text = text.trim().slice(0, 2000);
    msg.edited = true;
    await msg.save();
    res.json({ success: true, message: msg });
  } catch (err) {
    console.error("Community edit message error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// DELETE /api/community/messages/:messageId — soft-delete own message
app.delete("/api/community/messages/:messageId", authenticateToken, async (req, res) => {
  try {
    const { messageId } = req.params;
    const msg = await ChatMessage.findOne({ messageId, deletedAt: null });
    if (!msg) return res.status(404).json({ success: false, message: "Message not found" });
    if (msg.userId !== req.user.id && msg.userId !== String(req.user._id)) {
      return res.status(403).json({ success: false, message: "Not your message" });
    }
    msg.deletedAt = new Date();
    await msg.save();
    res.json({ success: true });
  } catch (err) {
    console.error("Community delete message error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ================= ERROR HANDLING =================
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

// ================= STATIC FILE SERVING - AFTER API ROUTES =================
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use(express.static(path.join(__dirname, "public")));

// ================= VIDEO CHAT WEBRTC SIGNALING =================
const http = require("http");
const socketIo = require("socket.io");

const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: function (origin, callback) {
      callback(null, true);
    },
    credentials: true,
    methods: ["GET", "POST"],
  },
  transports: ["websocket", "polling"],
});

// Store connected users and waiting queue
const connectedUsers = new Map();
const waitingUsers = [];
const activeRooms = new Map();

// ================= COMMUNITY CHAT SOCKET.IO =================
// In-memory map: groupId -> Set of { socketId, userId, userName }
const communityGroups = new Map();

function getCommunityRoomName(groupId) {
  return `community:${groupId}`;
}

function broadcastGroupCount(groupId) {
  const members = communityGroups.get(groupId) || new Set();
  io.to(getCommunityRoomName(groupId)).emit("group_online_count", {
    groupId,
    count: members.size,
  });
}

// Socket.io connection handling
io.on("connection", (socket) => {
  console.log("User connected:", socket.id);

  let currentUserId = null;
  let currentRoom = null;
  let isInCall = false;

  // ---- Community Chat Events ----
  let communityUser = null;    // { userId, userName, userAvatar }
  const joinedGroups = new Set(); // groups this socket is currently in

  socket.on("join_group", async ({ groupId, userId, userName, userAvatar }) => {
    if (!groupId || !userId) return;
    const room = getCommunityRoomName(groupId);
    socket.join(room);
    joinedGroups.add(groupId);

    communityUser = { userId, userName, userAvatar };

    // Track in group member set
    if (!communityGroups.has(groupId)) communityGroups.set(groupId, new Set());
    communityGroups.get(groupId).add({ socketId: socket.id, userId, userName });

    broadcastGroupCount(groupId);

    // Notify others in group
    socket.to(room).emit("user_joined", { groupId, userId, userName });

    // Send last 60 messages to the joining socket
    try {
      const messages = await ChatMessage.find({ groupId, deletedAt: null })
        .sort({ createdAt: -1 })
        .limit(60)
        .lean();
      socket.emit("group_history", { groupId, messages: messages.reverse() });
    } catch (e) {
      console.error("join_group history error:", e);
    }
  });

  socket.on("leave_group", ({ groupId, userId }) => {
    if (!groupId) return;
    const room = getCommunityRoomName(groupId);
    socket.leave(room);
    joinedGroups.delete(groupId);

    if (communityGroups.has(groupId)) {
      const members = communityGroups.get(groupId);
      for (const m of members) {
        if (m.socketId === socket.id) { members.delete(m); break; }
      }
    }
    broadcastGroupCount(groupId);
    socket.to(room).emit("user_left", { groupId, userId, userName: communityUser?.userName || "Someone" });
  });

  socket.on("send_message", async (data) => {
    const { groupId, messageId, userId, userName, userAvatar, text } = data;
    if (!groupId || !text || !messageId) return;
    try {
      const msg = new ChatMessage({
        messageId,
        groupId,
        userId,
        userName,
        userAvatar: userAvatar || "",
        text: String(text).slice(0, 2000),
      });
      await msg.save();
      const payload = {
        messageId: msg.messageId,
        groupId: msg.groupId,
        userId: msg.userId,
        userName: msg.userName,
        userAvatar: msg.userAvatar,
        text: msg.text,
        edited: false,
        createdAt: msg.createdAt,
        time: msg.createdAt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      };
      io.to(getCommunityRoomName(groupId)).emit("new_message", payload);
    } catch (e) {
      console.error("send_message error:", e);
      socket.emit("message_error", { error: "Failed to send message" });
    }
  });

  socket.on("edit_message", async ({ messageId, groupId, userId, newText }) => {
    if (!messageId || !newText || !userId) return;
    try {
      const msg = await ChatMessage.findOne({ messageId, deletedAt: null });
      if (!msg) return;
      if (msg.userId !== userId) {
        socket.emit("message_error", { error: "Not authorized to edit this message" });
        return;
      }
      msg.text = String(newText).slice(0, 2000);
      msg.edited = true;
      await msg.save();
      io.to(getCommunityRoomName(groupId)).emit("message_edited", {
        messageId,
        groupId,
        newText: msg.text,
      });
    } catch (e) {
      console.error("edit_message error:", e);
    }
  });

  socket.on("delete_message", async ({ messageId, groupId, userId }) => {
    if (!messageId || !userId) return;
    try {
      const msg = await ChatMessage.findOne({ messageId, deletedAt: null });
      if (!msg) return;
      if (msg.userId !== userId) {
        socket.emit("message_error", { error: "Not authorized to delete this message" });
        return;
      }
      msg.deletedAt = new Date();
      await msg.save();
      io.to(getCommunityRoomName(groupId)).emit("message_deleted", { messageId, groupId });
    } catch (e) {
      console.error("delete_message error:", e);
    }
  });

  socket.on("typing", ({ groupId, userId, userName }) => {
    if (!groupId) return;
    socket.to(getCommunityRoomName(groupId)).emit("user_typing", { groupId, userId, userName });
  });
  // ---- End Community Chat Events ----

  socket.on("register", (userData) => {
    currentUserId = userData.userId;
    connectedUsers.set(currentUserId, {
      socketId: socket.id,
      name: userData.name,
      grade: userData.grade,
      avatar: userData.avatar,
      socket: socket,
    });
    console.log(`User registered: ${userData.name} (Grade ${userData.grade})`);
  });

  socket.on("join-room", (pin) => {
    const room = io.sockets.adapter.rooms.get(pin);
    
    if (!room || room.size === 0) {
      socket.emit("room-error", "Invalid PIN. Room does not exist.");
      return;
    }
    
    // Increased capacity to 20 for group sessions
    if (room.size >= 20) {
      socket.emit("room-error", "Room is already full.");
      return;
    }

    socket.join(pin);
    currentRoom = pin;

    let thisUser = Array.from(connectedUsers.values()).find(
      (u) => u.socketId === socket.id,
    );
    if (!thisUser) thisUser = { socketId: socket.id, name: "Student", grade: "?", avatar: "" };

    // Update participants in activeRooms
    let participants = activeRooms.get(pin) || [];
    participants.push(socket.id);
    activeRooms.set(pin, participants);

    // Notify others in the room that someone new joined
    socket.to(pin).emit("user-joined", {
      socketId: socket.id,
      name: thisUser.name,
      grade: thisUser.grade,
      avatar: thisUser.avatar
    });

    // Send existing participants to the new user so they can initiate connections
    const existingParticipants = participants
      .filter(id => id !== socket.id)
      .map(id => {
        const u = Array.from(connectedUsers.values()).find(user => user.socketId === id);
        return {
          socketId: id,
          name: u ? u.name : "Partner",
          grade: u ? u.grade : "?",
          avatar: u ? u.avatar : ""
        };
      });

    socket.emit("room-joined", {
      pin: pin,
      participants: existingParticipants
    });

    isInCall = true;
    console.log(`User ${thisUser.name} joined room ${pin}. Total: ${participants.length}`);
  });

  function generatePIN() {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  socket.on("create-room", (userData) => {
    currentUserId = userData.userId;

    let pin;
    do {
      pin = generatePIN();
    } while (activeRooms.has(pin) || io.sockets.adapter.rooms.has(pin));

    socket.join(pin);
    currentRoom = pin;

    // Store room host data
    activeRooms.set(pin, [socket.id]);
    
    socket.emit("room-created", { pin: pin });
    console.log(`Room created with PIN: ${pin} by ${userData.name}`);
  });

  socket.on("cancel-create", () => {
    if (currentRoom) {
      socket.leave(currentRoom);
      activeRooms.delete(currentRoom);
      console.log(`Room ${currentRoom} cancelled by host`);
      currentRoom = null;
    }
  });

  socket.on("offer", (data) => {
    const targetSocket = io.sockets.sockets.get(data.target);
    if (targetSocket) {
      targetSocket.emit("offer", {
        offer: data.offer,
        from: socket.id,
        fromUser: data.fromUser,
      });
    }
  });

  socket.on("answer", (data) => {
    const targetSocket = io.sockets.sockets.get(data.target);
    if (targetSocket) {
      targetSocket.emit("answer", {
        answer: data.answer,
        from: socket.id,
      });
    }
  });

  socket.on("ice-candidate", (data) => {
    const targetSocket = io.sockets.sockets.get(data.target);
    if (targetSocket) {
      targetSocket.emit("ice-candidate", {
        candidate: data.candidate,
        from: socket.id,
      });
    }
  });

  socket.on("end-call", (data) => {
    if (data.target) {
      const targetSocket = io.sockets.sockets.get(data.target);
      if (targetSocket) {
        targetSocket.emit("call-ended", { from: socket.id });
      }
    }

    if (currentRoom) {
      activeRooms.delete(currentRoom);
      socket.leave(currentRoom);
    }
    isInCall = false;
  });

  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);

    // Clean up community group memberships
    for (const groupId of joinedGroups) {
      if (communityGroups.has(groupId)) {
        const members = communityGroups.get(groupId);
        for (const m of members) {
          if (m.socketId === socket.id) { members.delete(m); break; }
        }
      }
      broadcastGroupCount(groupId);
      if (communityUser) {
        socket.to(getCommunityRoomName(groupId)).emit("user_left", {
          groupId,
          userId: communityUser.userId,
          userName: communityUser.userName,
        });
      }
    }

    const queueIndex = waitingUsers.findIndex((u) => u.socketId === socket.id);
    if (queueIndex !== -1) {
      waitingUsers.splice(queueIndex, 1);
    }

    if (currentUserId) {
      connectedUsers.delete(currentUserId);
    }

    if (currentRoom) {
      const participants = activeRooms.get(currentRoom);
      if (participants) {
        const updatedParticipants = participants.filter(id => id !== socket.id);
        if (updatedParticipants.length > 0) {
          activeRooms.set(currentRoom, updatedParticipants);
          // Notify others in the room
          socket.to(currentRoom).emit("user-left", { socketId: socket.id });
        } else {
          activeRooms.delete(currentRoom);
        }
      }
      socket.leave(currentRoom);
    }
  });
});

// ================= START SERVER =================
const PORT = process.env.PORT || 5000;
server.listen(PORT, "0.0.0.0", () => {
  console.log(`\n✅ Server running on http://localhost:${PORT}`);
  console.log(`📧 SendGrid email service ready (From: ${FROM_EMAIL})`);
  console.log(`📊 Dashboard endpoints ready`);
  console.log(`📚 Library endpoints ready`);
  console.log(`💬 Community endpoints ready`);
  console.log(`🤖 AI Chat endpoint: http://localhost:${PORT}/api/chat`);
  console.log(`📹 WebRTC signaling server ready`);
  console.log(`🏥 Health check: http://localhost:${PORT}/health`);
  console.log(`👨‍💼 Admin endpoints:`);
  console.log(`   - POST /api/admin/signup`);
  console.log(`   - POST /api/admin/login`);
  console.log(`   - GET  /api/admin/profile`);
  console.log(`   - PUT  /api/admin/profile`);
  console.log(`   - POST /api/admin/change-password`);
  console.log(`   - POST /api/admin/forgot-password`);
  console.log(`   - POST /api/admin/verify-reset-code`);
  console.log(`   - POST /api/admin/reset-password`);
  console.log(`   - POST /api/admin/logout\n`);
});
