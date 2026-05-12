require("dotenv").config({ path: process.env.DOTENV_CONFIG_PATH || ".env" });
const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");

const { connectDB } = require("./config/database");

const authRoutes = require("./routes/auth");
const settingsRoutes = require("./routes/settings");
const usersRoutes = require("./routes/users");
const leaveRoutes = require("./routes/leave");
const approvalRoutes = require("./routes/approval");
const meetingRoutes = require("./routes/meeting");
const meetingRoomMongoRoutes = require("./routes/meetingRoomMongo");
const internalRoutes = require("./routes/internal");
const gmailRoutes = require("./routes/gmail");

const app = express();
const PORT = process.env.PORT || 3001;

// ═══════════════════════════════════════════
// MIDDLEWARE
// ═══════════════════════════════════════════

// Rate limiting cho login — chống brute force
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 phút
  max: 10, // tối đa 10 lần đăng nhập
  message: { message: "Quá nhiều lần đăng nhập. Vui lòng thử lại sau 15 phút." },
  standardHeaders: true,
  legacyHeaders: false,
});

// CORS — cho phép frontend và domain production
const allowedOrigins = [
  process.env.FRONTEND_URL || "http://localhost:3000",
  process.env.ALLOWED_ORIGIN_1 || "",
  process.env.ALLOWED_ORIGIN_2 || "",
  "http://localhost:3000",
].filter(Boolean);

app.use(cors({
  origin: allowedOrigins,
  credentials: true,
}));
app.use(express.json());

// ═══════════════════════════════════════════
// ROUTES
// ═══════════════════════════════════════════

// Auth (có rate limiting chống brute force)
app.use("/api/auth", loginLimiter, authRoutes);

// Settings
app.use("/api/settings", settingsRoutes);

// Users
app.use("/api/users", usersRoutes);

// Leave
app.use("/api/leave", leaveRoutes);

// Approval
app.use("/api/approval", approvalRoutes);

// Meeting Room (canonical path — frontend uses /api/meeting-room/*)
app.use("/api/meeting-room", meetingRoutes);

// Backward compatibility — frontend v1 calls /api/rooms
app.use("/api/rooms", (req, res, next) => {
  req.url = `/rooms${req.url === "/" ? "" : req.url}`;
  meetingRoutes(req, res, next);
});

// Meeting Room Mongo API (for N8N workflows)
app.use("/api/meeting-room-mongo", meetingRoomMongoRoutes);

// Internal API (for N8N workflows)
app.use("/api/internal", internalRoutes);

// Gmail OAuth2
app.use("/api/gmail", gmailRoutes);

// ═══════════════════════════════════════════
// HEALTH CHECK
// ═══════════════════════════════════════════
app.get("/api/health", (req, res) => {
  res.json({ status: "OK", message: "Backend running as Data Layer" });
});

// ═══════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════
connectDB().then(() => {
  app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT} (Data Layer mode)`));
});
