const multer = require("multer");
const path = require("path");
const { v4: uuidv4 } = require("uuid");
const fs = require("fs");

// Ensure uploads directory exists
const uploadDir = path.join(__dirname, "..", "uploads", "media");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${uuidv4()}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  },
});

// File filter
const fileFilter = (req, file, cb) => {
  // Bypass strict type checking for admins
  if (req.admin) {
    console.log(`[ADMIN UPLOAD] Allowing file: ${file.originalname} (${file.mimetype}, ${formatFileSize(file.size)})`)
    req.fileType = file.mimetype.startsWith('video/') ? 'video' :
                   file.mimetype.startsWith('audio/') ? 'audio' :
                   file.mimetype === 'application/pdf' ? 'pdf' :
                   'admin';
    return cb(null, true);
  }

  // Strict checking for non-admins
  const allowedTypes = {
    "video/mp4": "video",
    "video/quicktime": "video",
    "video/x-msvideo": "video",
    "audio/mpeg": "audio",
    "audio/wav": "audio",
    "audio/mp3": "audio",
    "application/pdf": "pdf",
  };

  if (allowedTypes[file.mimetype]) {
    req.fileType = allowedTypes[file.mimetype];
    cb(null, true);
  } else {
    cb(
      new Error(
        `Invalid file type. Only MP4, MOV, AVI, MP3, WAV, PDF allowed (max 1GB). Got: ${file.mimetype}`,
      ),
      false,
    );
  }
};


// Configure multer
const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
limits: {
    fileSize: 1024 * 1024 * 1024, // 1GB max
  },

});

// Format file size
const formatFileSize = (bytes) => {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
};

module.exports = { upload, formatFileSize, uploadDir };
