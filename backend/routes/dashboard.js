const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Course = require('../models/Course');
const Enrollment = require('../models/Enrollment');
const Activity = require('../models/Activity');

const { authenticateToken, authenticateAdmin } = require('../middleware/auth');

// Student Dashboard Data
router.get('/', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const user = await User.findById(userId).select('-password');
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Fetch enrollments with course details
    const enrollments = await Enrollment.find({ userId, isActive: true })
      .populate('courseId')
      .lean();

    // Map enrollments to course objects expected by frontend
    const courses = enrollments.map(en => {
      const course = en.courseId;
      if (!course) return null;

      // Calculate total lessons across all modules
      const totalLessons = course.modules ? course.modules.reduce((sum, mod) => sum + (mod.lessons ? mod.lessons.length : 0), 0) : 0;
      const completedCount = en.completedLessons ? en.completedLessons.length : 0;
      const progress = totalLessons > 0 ? Math.round((completedCount / totalLessons) * 100) : 0;

      // Map subject to color/icon for UI aesthetics
      const subjectConfigs = {
        math: { color: 'from-blue-500 to-cyan-500', icon: 'fa-calculator' },
        physics: { color: 'from-purple-500 to-indigo-500', icon: 'fa-atom' },
        chemistry: { color: 'from-emerald-500 to-teal-500', icon: 'fa-flask' },
        biology: { color: 'from-green-500 to-emerald-500', icon: 'fa-dna' },
        english: { color: 'from-orange-500 to-amber-500', icon: 'fa-language' },
        amharic: { color: 'from-red-500 to-orange-500', icon: 'fa-font' },
        history: { color: 'from-yellow-600 to-orange-600', icon: 'fa-landmark' },
        geography: { color: 'from-blue-600 to-teal-600', icon: 'fa-globe' },
        cs: { color: 'from-gray-700 to-slate-900', icon: 'fa-code' }
      };

      const config = subjectConfigs[course.subject] || { color: 'from-primary to-secondary', icon: 'fa-book' };

      return {
        id: course._id,
        title: course.title,
        subject: course.subject,
        progress: progress,
        completed: completedCount,
        total: totalLessons,
        color: config.color,
        icon: config.icon
      };
    }).filter(c => c !== null);

    // Fetch Leaderboard (Top 5 streaks)
    const leaderboard = await User.find({ role: 'student', isActive: true })
      .sort({ streak: -1 })
      .limit(5)
      .select('firstName lastName avatar streak')
      .lean();

    const formattedLeaderboard = leaderboard.map((u, index) => ({
      rank: index + 1,
      name: `${u.firstName} ${u.lastName || ''}`.trim(),
      avatar: u.avatar || `https://api.dicebear.com/7.x/avataaars/svg?seed=${u.firstName}`,
      streak: u.streak || 0
    }));

    // Fetch Recent Activity
    const recentActivity = await Activity.find({ userId })
      .sort({ createdAt: -1 })
      .limit(5)
      .lean();

    // Fetch recommended courses (in their grade but not enrolled)
    const enrolledCourseIds = courses.map(c => c.id);
    const recommendedCourses = await Course.find({
      grade: user.grade || 9,
      _id: { $not: { $in: enrolledCourseIds } },
      isActive: true
    }).limit(3).lean();

    const formattedRecommended = recommendedCourses.map(course => {
      const subjectConfigs = {
        math: { color: 'from-blue-500 to-cyan-500', icon: 'fa-calculator' },
        physics: { color: 'from-purple-500 to-indigo-500', icon: 'fa-atom' },
        chemistry: { color: 'from-emerald-500 to-teal-500', icon: 'fa-flask' },
        biology: { color: 'from-green-500 to-emerald-500', icon: 'fa-dna' },
        english: { color: 'from-orange-500 to-amber-500', icon: 'fa-language' },
        amharic: { color: 'from-red-500 to-orange-500', icon: 'fa-font' },
        history: { color: 'from-yellow-600 to-orange-600', icon: 'fa-landmark' },
        geography: { color: 'from-blue-600 to-teal-600', icon: 'fa-globe' },
        cs: { color: 'from-gray-700 to-slate-900', icon: 'fa-code' }
      };
      const config = subjectConfigs[course.subject] || { color: 'from-primary to-secondary', icon: 'fa-book' };
      
      return {
        id: course._id,
        title: course.title,
        subject: course.subject,
        progress: 0,
        completed: 0,
        total: course.totalLessons || 0,
        color: config.color,
        icon: config.icon,
        isRecommended: true
      };
    });

    // Handle Daily Goal Logic
    const today = new Date().toISOString().split('T')[0];
    if (user.lastStudyDate !== today) {
      user.dailyStudyTime = 0;
      user.lastStudyDate = today;
      await user.save();
    }

    // Calculate rank
    const rank = await User.countDocuments({ 
      role: 'student', 
      quizScore: { $gt: user.quizScore || 0 } 
    }) + 1;

    res.json({
      success: true,
      user: {
        ...user.toObject(),
        dailyStudyTime: user.dailyStudyTime || 0
      },
      stats: {
        rank
      },
      courses: [...courses, ...formattedRecommended],
      leaderboard: formattedLeaderboard,
      recentActivity
    });
  } catch (err) {
    console.error('Dashboard Error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Update Streak
router.post('/update-streak', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const user = await User.findById(userId);
    
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    const now = new Date();
    const lastActive = user.lastActive ? new Date(user.lastActive) : null;
    
    let updatedStreak = user.streak || 0;
    let streakUpdated = false;

    if (!lastActive) {
      updatedStreak = 1;
      streakUpdated = true;
    } else {
      const diffTime = now.getTime() - lastActive.getTime();
      const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));
      
      const isSameDay = now.toDateString() === lastActive.toDateString();
      const isYesterday = new Date(now.getTime() - 86400000).toDateString() === lastActive.toDateString();

      if (!isSameDay) {
        if (isYesterday) {
          updatedStreak += 1;
          streakUpdated = true;
        } else {
          updatedStreak = 1;
          streakUpdated = true;
        }
      }
    }

    user.lastActive = now;
    if (streakUpdated) {
      user.streak = updatedStreak;
      
      // Log streak activity
      await new Activity({
        userId,
        type: 'streak',
        title: 'Daily Streak!',
        description: `You've reached a ${updatedStreak} day streak!`,
        xp: updatedStreak * 10
      }).save();
    }
    
    await user.save();
    res.json({ success: true, streak: updatedStreak });
  } catch (err) {
    console.error('Streak Update Error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Admin Stats
router.get('/stats', authenticateAdmin, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments({ role: 'student' });
    const totalCourses = await Course.countDocuments();
    const totalEnrollments = await Enrollment.countDocuments();
    const totalRevenue = 0; 
    
    const recentEnrollments = await Enrollment.find()
      .sort({ enrolledAt: -1 })
      .limit(5)
      .populate('userId', 'firstName lastName email')
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
