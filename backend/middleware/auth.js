const jwt = require('jsonwebtoken');
const User = require('../models/User');

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

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
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Access denied" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secretkey");
    // Supporting both 'id' and 'userId' in token payload
    const userId = decoded.id || decoded.userId;
    
    const user = await User.findById(userId);
    
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ message: "Admin access required" });
    }
    
    req.user = user;
    next();
  } catch (err) {
    return res.status(403).json({ message: "Invalid token" });
  }
};

module.exports = { authenticateToken, authenticateAdmin };
