<div align="center">
  <img src="https://raw.githubusercontent.com/abelektuoz3/e-bundle/main/frontend/assets/logo.png" alt="E-Bundle Logo" width="120" style="border-radius: 20px" onerror="this.style.display='none'"/>
  
  # 🎓 E-Bundle

  **A Modern, Interactive E-Learning Platform Built for Ethiopian Students (Grades 9-12)**
  
  *Empowering students with AI, collaborative study tools, and gamified learning experiences.*
  
  [![Frontend](https://img.shields.io/badge/Frontend-Netlify-00C7B7?style=flat-square&logo=netlify)](https://ebundle-ethiopia.netlify.app)
  [![Backend](https://img.shields.io/badge/Backend-Render-46E3B7?style=flat-square&logo=render)](https://e-bundle.onrender.com)
  [![License](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)

</div>

---

## 🌟 Overview

**E-Bundle** is a comprehensive, full-stack educational platform designed to elevate the learning experience for students in Ethiopia. By combining high-quality educational materials with modern web technologies, E-Bundle creates an engaging environment where students can study, collaborate, and track their progress seamlessly.

Featuring a beautiful **Glassmorphism UI**, the platform is responsive and highly intuitive across mobile phones, tablets, and desktop computers.

## ✨ Core Features

*   📚 **Interactive Library:** Access course materials, stream educational videos, and read PDFs. The platform tracks your media progress automatically.
*   🤖 **AI Tutor:** A smart, AI-powered assistant ready to explain complex concepts, answer questions, and guide students through their curriculum.
*   🎥 **Peer-to-Peer Video Chat:** Start collaborative study sessions! Host a room, get a secure 6-digit PIN, and invite peers to study together using robust WebRTC technology.
*   🎮 **Gamification & Streaks:** Stay motivated! The dashboard tracks daily learning streaks and rewards consistent study habits.
*   🌐 **Community Hub:** Connect with other students, share notes, and participate in discussions.
*   🧩 **Kahoot Integration:** Play interactive quizzes and test your knowledge directly within the platform.
*   🛡️ **Secure Authentication:** JWT-based authentication with OTP email verification (via SendGrid) for password recovery and account security.

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

## 🚀 Getting Started

Want to run E-Bundle locally? Follow these steps:

### Prerequisites
*   [Node.js](https://nodejs.org/) (v16 or higher)
*   [MongoDB](https://www.mongodb.com/) (Local instance or MongoDB Atlas)
*   A [SendGrid](https://sendgrid.com/) API Key (for emails)

### 1. Clone the Repository
```bash
git clone https://github.com/abelektuoz3/e-bundle.git
cd e-bundle
```

### 2. Setup the Backend
```bash
cd backend
npm install
```

Create a `.env` file in the `backend` directory with the following variables:
```env
PORT=5000
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_super_secret_jwt_key
SENDGRID_API_KEY=your_sendgrid_api_key
EMAIL_FROM=your_verified_sender_email@domain.com
ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
```

Start the development server:
```bash
npm run dev
```

### 3. Setup the Frontend
The frontend requires no build step. Simply serve the `frontend` folder using any static server.
Using `npx` (Live Server):
```bash
cd ../frontend
npx serve .
```
Navigate to `http://localhost:3000` (or whichever port the server uses) in your browser.

## 🌐 Deployment Architecture

E-Bundle is optimized for modern cloud hosting:
*   **Frontend Hosting:** Deployed on **Netlify** for fast global CDN delivery.
*   **Backend API:** Hosted on **Render** utilizing web services for Node.js.
*   **Database:** Hosted securely on **MongoDB Atlas**.

## 📞 Real-Time Video Chat Flow (WebRTC)
The Video Chat feature was custom-built using standard WebRTC API. 
1. **Host Room:** User creates a room. The server generates a unique `6-digit PIN` and opens a Socket.io room.
2. **Join Room:** Partner enters the `PIN`. The server validates the room size.
3. **Signaling:** If valid, the server emits a `matched` event, designating one peer as the `initiator`.
4. **P2P Connection:** The initiator creates an Offer, the partner creates an Answer, and ICE Candidates are safely queued and exchanged to establish a direct video/audio stream!

---
<div align="center">
  <p>Built with ❤️ for education in Ethiopia.</p>
</div>
