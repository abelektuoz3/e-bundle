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

// ================= CORS CONFIGURATION =================
const allowedOrigins =
  process.env.ALLOWED_ORIGINS ?
    process.env.ALLOWED_ORIGINS.split(",")
  : [
      "http://localhost:3000",
      "http://localhost:5000",
      "https://e-bundle.onrender.com",
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
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
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

// ================= MONGODB CONNECTION =================
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("✅ MongoDB Connected Successfully");
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

// ================= MIDDLEWARE DEFINITIONS =================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const tokenFromQuery = req.query.token;
  const token = authHeader ? authHeader.split(" ")[1] : tokenFromQuery;

  if (!token) {
    return res.status(401).json({ message: "Access denied" });
  }

  jwt.verify(token, process.env.JWT_SECRET || "secretkey", (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token" });
    }
    req.user = user;
    next();
  });
};

async function authenticateAdmin(req, res, next) {
  try {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
      return res
        .status(401)
        .json({ message: "Access denied. No token provided." });
    }

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || "adminsecretkey",
    );
    const admin = await Admin.findById(decoded.id).select(
      "-password -resetToken -resetOTP",
    );

    if (!admin) {
      return res
        .status(403)
        .json({ message: "Invalid token. Admin not found." });
    }

    if (!admin.isActive) {
      return res.status(403).json({ message: "Account is deactivated." });
    }

    if (admin.isLocked()) {
      return res.status(403).json({
        message:
          "Account is temporarily locked due to multiple failed login attempts.",
      });
    }

    req.admin = admin;
    next();
  } catch (err) {
    return res.status(403).json({ message: "Invalid token." });
  }
}

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

      const media = new Media({
        title: title || req.file.originalname,
        originalName: req.file.originalname,
        filename: req.file.filename,
        type: req.fileType,
        size: req.file.size,
        sizeFormatted: formatFileSize(req.file.size),
        category: category || "general",
        description: description || "",
        mimeType: req.file.mimetype,
        url: `/uploads/media/${req.file.filename}`,
        uploadedBy: req.admin.id,
      });

      await media.save();

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

    const filePath = path.join(__dirname, "uploads", "media", media.filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
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

    const allMedia = await Media.find({}, "filename");

    for (const media of allMedia) {
      const filePath = path.join(__dirname, "uploads", "media", media.filename);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
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
    const { type } = req.query;

    let query = {};
    if (type && type !== "all") query.type = type;

    query.category = { $in: ["general", "tutorial", "documentation"] };

    const media = await Media.find(query)
      .select("title description type category sizeFormatted url createdAt")
      .sort({ createdAt: -1 });

    res.json({
      success: true,
      media: media.map((m) => ({
        id: m._id,
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

app.get("/api/media/stream/:id", authenticateToken, async (req, res) => {
  try {
    const media = await Media.findById(req.params.id);

    if (!media) {
      return res.status(404).json({ message: "Media not found" });
    }

    const filePath = path.join(__dirname, "uploads", "media", media.filename);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ message: "File not found" });
    }

    const mimeType =
      media.mimeType ||
      (media.type === "video" ? "video/mp4"
      : media.type === "audio" ? "audio/mpeg"
      : "application/pdf");

    res.setHeader("Content-Type", mimeType);

    const stream = fs.createReadStream(filePath);
    stream.pipe(res);
  } catch (err) {
    console.error("Stream error:", err);
    res.status(500).json({ message: "Server error" });
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

const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// ================= ADMIN AUTHENTICATION SCHEMA =================
const adminSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: "admin" },
  isActive: { type: Boolean, default: true },
  lastLogin: { type: Date },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  resetOTP: { type: String },
  resetOTPExpire: { type: Date },
  resetToken: { type: String },
  resetTokenExpire: { type: Date },
  loginAttempts: { type: Number, default: 0 },
  lockUntil: { type: Date },
});

adminSchema.pre("save", async function () {
  if (!this.isModified("password")) return;
  this.password = await bcrypt.hash(this.password, 10);
});

adminSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

adminSchema.methods.isLocked = function () {
  return !!(this.lockUntil && this.lockUntil > Date.now());
};

const Admin = mongoose.model("Admin", adminSchema);

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

// ================= USER ENDPOINTS (Students) =================

app.post("/signup", async (req, res) => {
  try {
    const { email, studentId, password, firstName, lastName, grade, school } =
      req.body;

    const existingUser = await User.findOne({
      $or: [{ email }, { studentId }],
    });

    if (existingUser) {
      return res.status(400).json({
        message: "User already exists with this email or student ID",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = generateOTP();
    const otpExpire = new Date(Date.now() + 10 * 60 * 1000);

    const newUser = new User({
      firstName,
      lastName,
      email,
      studentId,
      password: hashedPassword,
      grade,
      school,
      otp,
      otpExpire,
      isVerified: false,
    });

    await newUser.save();

    const emailSent = await sendOTPEmail(email, otp, firstName);

    if (!emailSent) {
      return res.status(201).json({
        message:
          "Account created but failed to send verification email. Please use resend OTP.",
        email: email,
      });
    }

    res.status(201).json({
      message:
        "User created successfully. Please check your email for verification code.",
      email: email,
    });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ message: "Error saving user" });
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

app.post("/login", async (req, res) => {
  try {
    const { loginId, password } = req.body;

    const user = await User.findOne({
      $or: [{ email: loginId }, { studentId: loginId }],
    });

    if (!user) {
      return res.status(400).json({ message: "User not found" });
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
// This now points to your frontend route instead of an HTML file
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
    user.resetTokenExpire = Date.now() + 3600000; // 1 hour
    await user.save();

    // Use FRONTEND_URL from environment or fallback to your Render URL
    const frontendUrl =
      process.env.FRONTEND_URL || "https://ebundle-ethiopia.netlify.app";

    // Point to your frontend's forgot-password page with the token
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

// ================= DASHBOARD ENDPOINTS =================

app.get("/dashboard", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select(
      "-password -otp -resetToken",
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const courses = await Course.find({
      grade: parseInt(user.grade) || 9,
    }).limit(6);

    const userProgress = await Progress.find({ userId: user._id }).populate(
      "courseId",
    );

    const totalLessons = courses.reduce(
      (acc, course) => acc + (course.totalLessons || 0),
      0,
    );
    const completedLessons = userProgress.reduce(
      (acc, p) => acc + (p.completedLessons || 0),
      0,
    );
    const studyHours = Math.floor((user.totalStudyTime || 0) / 60);

    const higherScoredUsers = await User.countDocuments({
      quizScore: { $gt: user.quizScore || 0 },
    });
    const rank = higherScoredUsers + 1;

    const leaderboard = await User.find({})
      .select("firstName lastName streak avatar")
      .sort({ streak: -1 })
      .limit(10);

    const recentActivity = await Activity.find({ userId: user._id })
      .sort({ createdAt: -1 })
      .limit(5);

    const coursesWithProgress = courses.map((course) => {
      const progress = userProgress.find(
        (p) =>
          p.courseId && p.courseId._id.toString() === course._id.toString(),
      );
      return {
        id: course._id,
        title: course.title,
        subject: course.subject,
        grade: course.grade,
        description: course.description,
        progress: progress ? progress.percentage : 0,
        total: course.totalLessons || 0,
        completed: progress ? progress.completedLessons : 0,
        color: course.color || "from-blue-500 to-cyan-500",
        icon: course.icon || "fa-book",
      };
    });

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
        avatar:
          user.avatar ||
          `https://api.dicebear.com/7.x/avataaars/svg?seed=${user.firstName}`,
        streak: user.streak || 0,
        quizScore: user.quizScore || 0,
        quizTotal: user.quizTotal || 0,
        progress: user.progress || 0,
        totalStudyTime: user.totalStudyTime || 0,
      },
      stats: {
        courses: courses.length,
        completedLessons: completedLessons,
        totalLessons: totalLessons,
        studyHours: studyHours,
        rank: rank,
      },
      courses: coursesWithProgress,
      leaderboard: leaderboard.map((u, index) => ({
        rank: index + 1,
        name: `${u.firstName} ${u.lastName ? u.lastName.charAt(0) + "." : ""}`,
        streak: u.streak || 0,
        avatar:
          u.avatar ||
          `https://api.dicebear.com/7.x/avataaars/svg?seed=${u.firstName}`,
      })),
      recentActivity: recentActivity.map((activity) => ({
        type: activity.type,
        title: activity.title,
        description: activity.description,
        xp: activity.xp || 0,
        createdAt: activity.createdAt,
      })),
    });
  } catch (err) {
    console.error("Dashboard error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/update-streak", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const lastActive = user.lastActive ? new Date(user.lastActive) : null;
    let streakUpdated = false;

    if (lastActive) {
      lastActive.setHours(0, 0, 0, 0);
      const diffTime = today - lastActive;
      const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));

      if (diffDays === 1) {
        user.streak = (user.streak || 0) + 1;
        streakUpdated = true;
      } else if (diffDays > 1) {
        user.streak = 1;
        streakUpdated = true;
      }
    } else {
      user.streak = 1;
      streakUpdated = true;
    }

    user.lastActive = new Date();
    await user.save();

    if (streakUpdated && user.streak > 1) {
      const activity = new Activity({
        userId: user._id,
        type: "streak",
        title: `${user.streak} Day Streak!`,
        description: `You've maintained a ${user.streak}-day learning streak!`,
        xp: 10,
      });
      await activity.save();
    }

    res.json({
      success: true,
      streak: user.streak,
      message: "Streak updated successfully",
    });
  } catch (err) {
    console.error("Update streak error:", err);
    res.status(500).json({ message: "Server error" });
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

app.post("/update-progress", authenticateToken, async (req, res) => {
  try {
    const { courseId, completedLessons, totalLessons, timeSpent } = req.body;

    let progress = await Progress.findOne({
      userId: req.user.id,
      courseId: courseId,
    });

    if (!progress) {
      progress = new Progress({
        userId: req.user.id,
        courseId: courseId,
        completedLessons: 0,
        totalLessons: totalLessons || 0,
        percentage: 0,
        timeSpent: 0,
      });
    }

    progress.completedLessons = completedLessons || progress.completedLessons;
    progress.totalLessons = totalLessons || progress.totalLessons;
    progress.timeSpent = (progress.timeSpent || 0) + (timeSpent || 0);
    progress.lastAccessed = new Date();

    if (progress.totalLessons > 0) {
      progress.percentage = Math.round(
        (progress.completedLessons / progress.totalLessons) * 100,
      );
    }

    progress.completed = progress.percentage >= 100;
    await progress.save();

    if (timeSpent) {
      await User.findByIdAndUpdate(req.user.id, {
        $inc: { totalStudyTime: timeSpent },
      });
    }

    res.json({
      success: true,
      progress: {
        courseId: progress.courseId,
        completedLessons: progress.completedLessons,
        totalLessons: progress.totalLessons,
        percentage: progress.percentage,
        completed: progress.completed,
      },
    });
  } catch (err) {
    console.error("Update progress error:", err);
    res.status(500).json({ message: "Server error" });
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
        color: "from-blue-500 to-cyan-500",
        icon: "fa-calculator",
      },
      {
        title: "Physics",
        subject: "physics",
        grade: 9,
        description: "Mechanics, Heat, and Waves",
        totalLessons: 38,
        color: "from-orange-500 to-red-500",
        icon: "fa-atom",
      },
      {
        title: "Chemistry",
        subject: "chemistry",
        grade: 9,
        description: "Atomic Structure and Reactions",
        totalLessons: 35,
        color: "from-green-500 to-emerald-500",
        icon: "fa-flask",
      },
      {
        title: "Biology",
        subject: "biology",
        grade: 9,
        description: "Cell Biology and Ecology",
        totalLessons: 42,
        color: "from-purple-500 to-pink-500",
        icon: "fa-dna",
      },
      {
        title: "English",
        subject: "english",
        grade: 9,
        description: "Grammar and Literature",
        totalLessons: 50,
        color: "from-indigo-500 to-blue-500",
        icon: "fa-book",
      },
      {
        title: "Amharic",
        subject: "amharic",
        grade: 9,
        description: "Language and Literature",
        totalLessons: 48,
        color: "from-yellow-500 to-orange-500",
        icon: "fa-language",
      },
      {
        title: "Mathematics",
        subject: "math",
        grade: 10,
        description: "Advanced Algebra and Geometry",
        totalLessons: 50,
        color: "from-blue-500 to-cyan-500",
        icon: "fa-calculator",
      },
      {
        title: "Physics",
        subject: "physics",
        grade: 10,
        description: "Electricity and Magnetism",
        totalLessons: 40,
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

// ================= AI TUTOR CHAT (GROQ API) =================
const axios = require("axios");

// Make sure this endpoint is BEFORE any wildcard routes or static file handlers
app.post("/api/chat", authenticateToken, async (req, res) => {
  console.log("\n========== NEW CHAT REQUEST ==========");
  console.log("Timestamp:", new Date().toISOString());
  console.log("Request body:", req.body);

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
    const GROQ_MODEL = process.env.GROQ_MODEL || "llama3-70b-8192";

    if (!GROQ_API_KEY) {
      console.error("❌ GROQ_API_KEY not found");
      return res.status(500).json({
        success: false,
        error: "AI service not configured - API key missing",
      });
    }

    console.log("Using Groq API with model:", GROQ_MODEL);
    console.log("User:", user?.firstName, "Grade:", user?.grade);
    console.log("Message:", message.substring(0, 100));

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

    const response = await axios.post(
      "https://api.groq.com/openai/v1/chat/completions",
      {
        model: GROQ_MODEL,
        messages: [
          { role: "system", content: systemContent },
          { role: "user", content: message },
        ],
        temperature: 0.7,
        max_tokens: 1024,
        top_p: 0.9,
        stream: false,
      },
      {
        headers: {
          Authorization: `Bearer ${GROQ_API_KEY}`,
          "Content-Type": "application/json",
        },
        timeout: 30000,
      },
    );

    const aiResponse = response.data.choices[0].message.content;

    console.log("✅ AI response sent successfully");
    console.log("Response length:", aiResponse.length);

    res.json({
      success: true,
      response: aiResponse,
    });
  } catch (error) {
    console.error("❌ Chat error:", error.message);

    if (error.response) {
      console.error("Status:", error.response.status);
      console.error("Data:", error.response.data);
    }

    res.status(500).json({
      success: false,
      error: "Failed to get AI response. Please try again later.",
    });
  }
});

// Add a test endpoint to verify the route is working
app.get("/api/chat-test", authenticateToken, (req, res) => {
  res.json({
    success: true,
    message: "Chat endpoint is reachable",
    groqConfigured: !!process.env.GROQ_API_KEY,
  });
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

    const response = await axios.post(
      "https://api.groq.com/openai/v1/chat/completions",
      {
        model: process.env.GROQ_MODEL || "llama3-70b-8192",
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

    res.json({
      success: true,
      message: "Groq API test successful",
      response: response.data.choices[0].message.content,
    });
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
    origin: allowedOrigins,
    credentials: true,
    methods: ["GET", "POST"],
  },
  transports: ["websocket", "polling"],
});

// Store connected users and waiting queue
const connectedUsers = new Map();
const waitingUsers = [];
const activeRooms = new Map(); // roomId -> [socket1, socket2]

// Socket.io connection handling
io.on("connection", (socket) => {
  console.log("User connected:", socket.id);

  let currentUserId = null;
  let currentRoom = null;
  let isInCall = false;

  // Register user info
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

  // Join specific room (for named rooms)
  socket.on("join-room", (roomId) => {
    socket.join(roomId);
    currentRoom = roomId;

    // Check if room has other users
    const room = io.sockets.adapter.rooms.get(roomId);
    if (room && room.size === 2) {
      // Room has 2 people, they can start calling each other
      const sockets = Array.from(room);
      const otherSocketId = sockets.find((id) => id !== socket.id);
      const otherSocket = io.sockets.sockets.get(otherSocketId);

      if (otherSocket) {
        const otherUser = Array.from(connectedUsers.values()).find(
          (u) => u.socketId === otherSocketId,
        );
        const thisUser = Array.from(connectedUsers.values()).find(
          (u) => u.socketId === socket.id,
        );

        if (otherUser && thisUser) {
          // Notify both users they can start the call
          socket.emit("matched", {
            partner: otherUser,
            room: roomId,
          });
          otherSocket.emit("matched", {
            partner: thisUser,
            room: roomId,
          });
        }
      }
    }
  });

  // Find random partner
  socket.on("find-random-partner", (userData) => {
    currentUserId = userData.userId;

    // Remove from waiting if already there
    const existingIndex = waitingUsers.findIndex(
      (u) => u.socketId === socket.id,
    );
    if (existingIndex !== -1) {
      waitingUsers.splice(existingIndex, 1);
    }

    // Try to find match with same grade
    const sameGradeIndex = waitingUsers.findIndex(
      (u) => u.grade === userData.grade,
    );

    if (
      sameGradeIndex !== -1 &&
      waitingUsers[sameGradeIndex].socketId !== socket.id
    ) {
      // Found match
      const partner = waitingUsers[sameGradeIndex];
      waitingUsers.splice(sameGradeIndex, 1);

      const user = {
        socketId: socket.id,
        name: userData.name,
        grade: userData.grade,
        userId: userData.userId,
      };

      // Create room
      const roomName = `random_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      socket.join(roomName);
      partner.socket.join(roomName);
      currentRoom = roomName;

      // Store in active rooms
      activeRooms.set(roomName, [socket.id, partner.socketId]);
      isInCall = true;

      // Notify both
      socket.emit("matched", {
        partner: partner,
        room: roomName,
      });

      io.to(partner.socketId).emit("matched", {
        partner: user,
        room: roomName,
      });

      console.log(
        `Matched ${user.name} with ${partner.name} in room ${roomName}`,
      );
    } else {
      // No match, add to waiting
      waitingUsers.push({
        socketId: socket.id,
        userId: userData.userId,
        name: userData.name,
        grade: userData.grade,
        socket: socket,
      });
      console.log(
        `${userData.name} added to waiting queue. Size: ${waitingUsers.length}`,
      );
    }
  });

  // Leave waiting queue
  socket.on("leave-queue", () => {
    const index = waitingUsers.findIndex((u) => u.socketId === socket.id);
    if (index !== -1) {
      waitingUsers.splice(index, 1);
      console.log("User left queue");
    }
  });

  // WebRTC Signaling Events

  socket.on("offer", (data) => {
    const targetSocket = io.sockets.sockets.get(data.target);
    if (targetSocket) {
      targetSocket.emit("offer", {
        offer: data.offer,
        from: socket.id,
        fromUser: data.fromUser,
      });
      console.log(`Offer sent from ${socket.id} to ${data.target}`);
    }
  });

  socket.on("answer", (data) => {
    const targetSocket = io.sockets.sockets.get(data.target);
    if (targetSocket) {
      targetSocket.emit("answer", {
        answer: data.answer,
        from: socket.id,
      });
      console.log(`Answer sent from ${socket.id} to ${data.target}`);
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
      // Clean up room
      activeRooms.delete(currentRoom);
      socket.leave(currentRoom);
    }
    isInCall = false;
  });

  // Handle disconnect
  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);

    // Remove from waiting queue
    const queueIndex = waitingUsers.findIndex((u) => u.socketId === socket.id);
    if (queueIndex !== -1) {
      waitingUsers.splice(queueIndex, 1);
      console.log("Removed from waiting queue");
    }

    // Remove from connected users
    if (currentUserId) {
      connectedUsers.delete(currentUserId);
    }

    // Notify partner if in call
    if (currentRoom && isInCall) {
      const room = activeRooms.get(currentRoom);
      if (room) {
        const partnerId = room.find((id) => id !== socket.id);
        if (partnerId) {
          const partnerSocket = io.sockets.sockets.get(partnerId);
          if (partnerSocket) {
            partnerSocket.emit("partner-disconnected");
          }
        }
        activeRooms.delete(currentRoom);
      }
    }

    // Leave all rooms
    if (currentRoom) {
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
