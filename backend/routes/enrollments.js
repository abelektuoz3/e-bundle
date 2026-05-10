const express = require('express');
const router = express.Router();
const Enrollment = require('../models/Enrollment');
const Course = require('../models/Course');
const { authenticateToken, authenticateAdmin } = require('../middleware/auth');

// Get all enrollments (with populated data)
router.get('/', authenticateAdmin, async (req, res) => {
  try {
    const enrollments = await Enrollment.find()
      .populate('userId', 'name email grade')
      .populate('courseId', 'title thumbnail grade subject');
    res.json(enrollments);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create enrollment
router.post('/', authenticateToken, async (req, res) => {
  try {
    const { userId, courseId } = req.body;
    const existing = await Enrollment.findOne({ userId, courseId });
    if (existing) return res.status(400).json({ error: 'Already enrolled' });
    
    const enrollment = new Enrollment({ userId, courseId });
    await enrollment.save();
    res.json(enrollment);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update progress
router.put('/:id/progress', authenticateToken, async (req, res) => {
  try {
    const { progress, completedLessons } = req.body;
    const enrollment = await Enrollment.findByIdAndUpdate(
      req.params.id,
      { progress, completedLessons, completedAt: progress === 100 ? Date.now() : null },
      { new: true }
    );
    res.json(enrollment);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete enrollment
router.delete('/:id', authenticateAdmin, async (req, res) => {
  try {
    await Enrollment.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;