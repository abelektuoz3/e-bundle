const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Admin = require('../models/Admin');

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

const authenticateAdmin = async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const tokenFromQuery = req.query.token;
  const token = authHeader ? authHeader.split(" ")[1] : tokenFromQuery;

  if (!token) {
    return res.status(401).json({ message: "Access denied" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secretkey");
    const userId = decoded.id || decoded.userId;
    
    // Try finding in User collection first
    let user = await User.findById(userId);
    
    // Fallback to Admin collection if not found in User or doesn't have role
    if (!user || user.role !== 'admin') {
      const admin = await Admin.findById(userId);
      if (admin) {
        user = admin;
      }
    }
    
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ message: "Admin access required" });
    }
    
    req.user = user;
    req.admin = user;
    next();
  } catch (err) {
    return res.status(403).json({ message: "Invalid token" });
  }
};

module.exports = { authenticateToken, authenticateAdmin };
