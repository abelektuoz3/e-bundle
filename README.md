<div align="center">
  <img src="e-bundle.png" alt="E-Bundle Logo" width="220" height="220" style="border-radius: 20px" onerror="this.style.display='none'"/>
  
  # 🎓 E-Bundle

  **A Modern, Interactive E-Learning Platform Built for Ethiopian Students (Grades 9-12)**
  
  *Empowering students with AI, collaborative study tools, and gamified learning experiences.*
  
  [![Frontend](https://img.shields.io/badge/Frontend-Netlify-00C7B7?style=flat-square&logo=netlify)](https://ebundle-ethiopia.netlify.app)
  [![Backend](https://img.shields.io/badge/Backend-Render-46E3B7?style=flat-square&logo=render)](https://e-bundle.onrender.com)

</div>

---

## 🌟 Overview

**E‑Bundle** is a comprehensive, full‑stack educational platform designed to elevate the learning experience for students in Ethiopia. By combining high‑quality educational materials with modern web technologies, E‑Bundle creates an engaging environment where students can study, collaborate, and track their progress seamlessly.

**Note:** This is a private, proprietary project; the source code is not publicly available.

Featuring a beautiful **Glassmorphism UI**, the platform is responsive and highly intuitive across mobile phones, tablets, and desktop computers.

**About:** E‑Bundle is a private, proprietary e‑learning platform tailored for Ethiopian secondary education, providing AI‑assisted tutoring, collaborative video study rooms, gamified progress tracking, and secure JWT‑based authentication. All content and services are hosted internally and not intended for public distribution.

## ✨ Core Features

*   📚 **Interactive Library:** A curated collection of Ethiopian curriculum PDFs, video lessons, and interactive quizzes. Media files are streamed from a CDN, and the frontend records watch progress in the user’s profile, enabling resume‑watch and progress analytics.

*   🤖 **AI Tutor:** Powered by OpenAI’s GPT‑4 (or a locally hosted LLM), the AI tutor receives student queries via the `/api/ai` endpoint, processes context‑aware prompts, and returns concise explanations, step‑by‑step solutions, or personalized study suggestions. It adapts to grade level and tracks usage for analytics.

*   🎥 **Peer-to-Peer Video Chat:** Built on WebRTC with Socket.io signaling. When a student creates a room, the server generates a unique 6‑digit PIN and stores the session metadata. Peers join by entering the PIN; signaling messages (SDP offers, ICE candidates) are exchanged through Socket.io channels, establishing a direct encrypted media stream. Supports screen sharing and in‑call chat.

*   🎮 **Gamification & Streaks:** Daily learning streak counters, achievement badges, and point rewards encourage consistent study habits. Leaderboards showcase top learners within each class.

*   🌐 **Community Hub:** Forum‑style discussion boards where students can post questions, share notes, and collaborate on projects. Threads are tagged by subject and grade, with moderation tools for teachers.

*   🧩 **Kahoot Integration:** Embedded Kahoot‑style quizzes that sync with the platform’s scoring system, providing immediate feedback and reinforcing concepts.

*   🛡️ **Secure Authentication:** JWT‑based authentication with OTP email verification (via SendGrid) for password recovery and account security. Passwords are hashed with bcryptjs; tokens include role claims for admin/student separation.

## 🛠️ Technology Stack

E-Bundle is built with a decoupled architecture, separating the client interface from the API backend.

### **Frontend**
*   **HTML5 & Vanilla JavaScript:** Lightweight and lightning-fast.
*   **Tailwind CSS:** For highly customizable, responsive, and modern glassmorphism UI designs.
*   **WebRTC & Socket.io-client:** Powering real-time peer-to-peer video streaming and chat signaling.

### **Backend**
*   **Node.js & Express.js:** Robust RESTful API architecture.
*   **MongoDB & Mongoose:** NoSQL database for flexible user, media, and progress modeling.
*   **Socket.io:** Real-time event-based communication for matchmaking and WebRTC signaling.
*   **SendGrid:** Reliable email delivery for OTP verification.
*   **JWT & bcryptjs:** Secure authentication and password hashing.



---
<div align="center">
  <p>Built with ❤️ for education in Ethiopia.</p>
</div>
