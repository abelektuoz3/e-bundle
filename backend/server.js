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
  (varName) => !process.env[varName]
);
if (missingEnvVars.length > 0) {
  console.error(
    `❌ Missing required environment variables: ${missingEnvVars.join(", ")}`
  );
  console.error(
    "Please set these variables in your Render environment variables."
  );
  if (process.env.NODE_ENV === "production") {
    process.exit(1);
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
  process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(",")
    : [
        "http://localhost:3000",
        "http://localhost:5000",
        "https://your-render-app.onrender.com",
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
  })
);

// Add CORS headers as backup
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (
    allowedOrigins.includes(origin) ||
    process.env.NODE_ENV !== "production"
  ) {
    res.header("Access-Control-Allow-Origin", origin || "*");
  }
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, Authorization"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }
  next();
});

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
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use(express.static(path.join(__dirname, "public")));

// ================= MONGODB CONNECTION - FIXED VERSION =================
// REMOVED all deprecated options - only use the connection string
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
  console.error("MongoDB connection error:", err.message);
});

mongoose.connection.on("disconnected", () => {
  console.log("MongoDB disconnected. Attempting to reconnect...");
  setTimeout(connectDB, 5000);
});

// ================= MIDDLEWARE DEFINITIONS =================

// Authentication Middleware
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

// Admin Authentication Middleware
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
      process.env.JWT_SECRET || "adminsecretkey"
    );
    const admin = await Admin.findById(decoded.id).select(
      "-password -resetToken -resetOTP"
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

// ================= SENDGRID EMAIL FUNCTIONS =================

const FROM_EMAIL =
  process.env.EMAIL_FROM ||
  process.env.EMAIL_USER ||
  "noreply@ebundleethiopia.com";

const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

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
      error.response?.body || error.message
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
      error.response?.body || error.message
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
          <a href="${resetLink}" style="display: inline-block; background: linear-gradient(135deg, #4F46E5, #7C3AED); color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; margin: 20px 0;">Reset Password</a>
          <p style="color: #999; font-size: 12px;">This link expires in 1 hour.</p>
          <p style="color: #999; font-size: 12px; margin-top: 20px;">If you didn't request this, please ignore this email.</p>
        </div>
      </div>
    `,
    text: `Hello ${firstName || "Student"},\n\nClick the link below to reset your password:\n${resetLink}\n\nThis link expires in 1 hour.`,
  };

  try {
    await sgMail.send(msg);
    console.log(`✅ Reset link email sent to ${email}`);
    return true;
  } catch (error) {
    console.error(
      `❌ Failed to send reset link email to ${email}:`,
      error.response?.body || error.message
    );
    return false;
  }
};

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
      { expiresIn: "7d" }
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
      { expiresIn: "7d" }
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
      "-password -resetToken -resetOTP -loginAttempts -lockUntil"
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

// ================= ROOT ENDPOINT =================
app.get("/", (req, res) => {
  res.json({
    name: "E-Bundle Ethiopia API",
    version: "1.0.0",
    status: "running",
    endpoints: {
      health: "/health",
      admin: "/api/admin",
      dashboard: "/dashboard",
      library: "/api/library",
      community: "/api/study-groups",
      chat: "/api/chat",
    },
  });
});

// ================= ERROR HANDLING =================
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

// ================= VIDEO CHAT WEBRTC SIGNALING =================
const http = require("http");
const socketIo = require("socket.io");

const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: true,
    credentials: true,
    methods: ["GET", "POST"],
  },
  transports: ["websocket", "polling"],
});

// Store connected users
const connectedUsers = new Map();
const waitingUsers = [];

// Socket.io connection handling
io.on("connection", (socket) => {
  console.log("User connected:", socket.id);

  let currentUserId = null;
  let currentRoom = null;

  socket.on("register", (userData) => {
    currentUserId = userData.userId;
    connectedUsers.set(currentUserId, {
      socketId: socket.id,
      name: userData.name,
      grade: userData.grade,
      avatar: userData.avatar,
    });
    console.log(`User ${userData.name} (${userData.grade}) registered`);
  });

  socket.on("find-random-partner", (userData) => {
    currentUserId = userData.userId;

    waitingUsers.push({
      userId: currentUserId,
      socketId: socket.id,
      name: userData.name,
      grade: userData.grade,
    });

    console.log(
      `User ${userData.name} looking for partner. Queue size: ${waitingUsers.length}`
    );

    matchUsers();
  });

  socket.on("leave-queue", () => {
    const index = waitingUsers.findIndex((u) => u.socketId === socket.id);
    if (index !== -1) {
      waitingUsers.splice(index, 1);
      console.log("User left queue");
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
      socket.leave(currentRoom);
    }
  });

  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);

    const queueIndex = waitingUsers.findIndex((u) => u.socketId === socket.id);
    if (queueIndex !== -1) {
      waitingUsers.splice(queueIndex, 1);
    }

    if (currentUserId) {
      connectedUsers.delete(currentUserId);
    }

    if (currentRoom) {
      socket.to(currentRoom).emit("partner-disconnected");
    }
  });
});

function matchUsers() {
  while (waitingUsers.length >= 2) {
    const user1 = waitingUsers.shift();
    const user2 = waitingUsers.shift();

    const socket1 = io.sockets.sockets.get(user1.socketId);
    const socket2 = io.sockets.sockets.get(user2.socketId);

    if (socket1 && socket2) {
      const roomName = `room_${user1.userId}_${user2.userId}`;

      socket1.join(roomName);
      socket2.join(roomName);

      socket1.emit("matched", {
        partner: {
          socketId: user2.socketId,
          name: user2.name,
          grade: user2.grade,
        },
        room: roomName,
      });

      socket2.emit("matched", {
        partner: {
          socketId: user1.socketId,
          name: user1.name,
          grade: user1.grade,
        },
        room: roomName,
      });

      console.log(`Matched ${user1.name} with ${user2.name}`);
    }
  }
}

// ================= START SERVER =================
const PORT = process.env.PORT || 5000;
server.listen(PORT, "0.0.0.0", () => {
  console.log(`\n✅ Server running on port ${PORT}`);
  console.log(`📧 SendGrid email service ready (From: ${FROM_EMAIL})`);
  console.log(`📊 Dashboard endpoints ready`);
  console.log(`📚 Library endpoints ready`);
  console.log(`💬 Community endpoints ready`);
  console.log(`🤖 AI Chat endpoint: /api/chat`);
  console.log(`📹 WebRTC signaling server ready`);
  console.log(`🏥 Health check: /health`);
  console.log(`👨‍💼 Admin endpoints available`);
  console.log(`\n🚀 Ready for production!\n`);
});