const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Course = require('../models/Course');
const Enrollment = require('../models/Enrollment');

router.get('/stats', async (req, res) => {
  try {
    const totalUsers = await User.countDocuments({ role: 'student' });
    const totalCourses = await Course.countDocuments();
    const totalEnrollments = await Enrollment.countDocuments();
    const totalRevenue = 0; // Implement with payment system later
    
    const recentEnrollments = await Enrollment.find()
      .sort({ enrolledAt: -1 })
      .limit(5)
      .populate('userId', 'name email')
      .populate('courseId', 'title');
    
    const courseStats = await Course.aggregate([
      { $lookup: { from: 'enrollments', localField: '_id', foreignField: 'courseId', as: 'enrolls' } },
      { $project: { title: 1, enrollments: { $size: '$enrolls' } } },
      { $sort: { enrollments: -1 } },
      { $limit: 5 }
    ]);
    
    res.json({
      totalUsers,
      totalCourses,
      totalEnrollments,
      totalRevenue,
      recentEnrollments,
      topCourses: courseStats
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;