const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Enrollment = require('../models/Enrollment');
const bcrypt = require('bcryptjs');
const { authenticateAdmin } = require('../middleware/auth');

// Get all users (admin only)
router.get('/', authenticateAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get single user with enrollments
router.get('/:id', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    const enrollments = await Enrollment.find({ userId: req.params.id }).populate('courseId');
    res.json({ user, enrollments });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create/Update user
router.post('/', authenticateAdmin, async (req, res) => {
  try {
    const { name, email, password, role, grade, isActive } = req.body;
    let user = await User.findOne({ email });
    
    if (user) {
      // Update existing
      user.name = name || user.name;
      user.role = role || user.role;
      user.grade = grade || user.grade;
      user.isActive = isActive !== undefined ? isActive : user.isActive;
      if (password) user.password = await bcrypt.hash(password, 10);
      await user.save();
    } else {
      // Create new
      user = new User({
        name,
        email,
        password: await bcrypt.hash(password, 10),
        role: role || 'student',
        grade,
        isActive: true
      });
      await user.save();
    }
    
    res.json({ success: true, user: { ...user.toObject(), password: undefined } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete user
router.delete('/:id', authenticateAdmin, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    await Enrollment.deleteMany({ userId: req.params.id });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;