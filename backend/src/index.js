require("dotenv").config({ path: require("path").join(__dirname, "../.env") });
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const crypto = require("crypto");
const axios = require("axios");
const User = require("./models/User");
const LeaveRequest = require("./models/LeaveRequest");
const Room = require("./models/Room");
const Booking = require("./models/Booking");
const Settings = require("./models/Settings");

const app = express();
const PORT = process.env.PORT || 3001;

// ═══════════════════════════════════════════
// MIDDLEWARE
// ═══════════════════════════════════════════
app.use(cors({
  origin: [
    process.env.FRONTEND_URL || "http://localhost:3000",
    "http://localhost:3000",
    "https://approvehub.internalautomation.io.vn",
  ],
  credentials: true,
}));
app.use(express.json());

// ═══════════════════════════════════════════
// DATABASE
// ═══════════════════════════════════════════
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("✅ MongoDB Atlas connected");
  } catch (error) {
    console.error("❌ MongoDB error:", error.message);
    process.exit(1);
  }
};

// ═══════════════════════════════════════════
// N8N WEBHOOK CALLER
// ═══════════════════════════════════════════
const triggerN8n = async (webhookUrl, payload) => {
  if (!webhookUrl || webhookUrl.includes("yourdomain.com")) {
    console.log("⏭️ N8n webhook not configured, skipping...");
    return { success: false, message: "N8n not configured" };
  }
  try {
    const response = await axios.post(webhookUrl, payload, { timeout: 15000 });
    console.log(`✅ N8n webhook triggered: ${webhookUrl}`);
    return { success: true, data: response.data };
  } catch (error) {
    console.error(`⚠️ N8n webhook error:`, error.message);
    return { success: false, message: error.message };
  }
};

// ═══════════════════════════════════════════
// AUTH MIDDLEWARE
// ═══════════════════════════════════════════
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "No token provided" });
  }
  const token = authHeader.split(" ")[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
};

// ═══════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════
const generateToken = () => crypto.randomBytes(32).toString("hex");
const buildLink = (token) => `${process.env.FRONTEND_URL}/approvals.html?token=${token}`;

// ═══════════════════════════════════════════
// ROUTES: AUTH
// ═══════════════════════════════════════════

// POST /api/auth/register
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password, department, role } = req.body;

    // Validate
    if (!name || !email || !password || !department) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Check exists
    if (await User.findOne({ email })) {
      return res.status(400).json({ message: "Email already registered" });
    }

    // Create user
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({
      name, email, password: hashed,
      department,
      role: role || "employee",
    });
    await user.save();

    res.status(201).json({
      message: "Registered successfully",
      user: { id: user._id, name, email, department, role: user.role },
    });
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({ message: "Registration failed" });
  }
});

// POST /api/auth/login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      {
        userId: user._id,
        email: user.email,
        name: user.name,
        role: user.role,
        department: user.department,
      },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        department: user.department,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Login failed" });
  }
});

// GET /api/auth/me
app.get("/api/auth/me", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-password");
    res.json(user || {});
  } catch (error) {
    res.status(500).json({ message: "Error" });
  }
});

// ═══════════════════════════════════════════
// ROUTES: USER MANAGEMENT (HR only)
// ═══════════════════════════════════════════

app.get("/api/users", verifyToken, async (req, res) => {
  if (req.user.role !== "hr") return res.status(403).json({ message: "Chỉ HR mới có quyền xem" });
  try {
    const users = await User.find().select("-password").sort({ createdAt: -1 });
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: "Error fetching users" });
  }
});

app.post("/api/users", verifyToken, async (req, res) => {
  if (req.user.role !== "hr") return res.status(403).json({ message: "Chỉ HR mới có quyền tạo" });
  try {
    const { name, email, password, department, role } = req.body;
    if (!name || !email || !password || !department || !role)
      return res.status(400).json({ message: "All fields required" });
    if (await User.findOne({ email: email.toLowerCase() }))
      return res.status(400).json({ message: "Email already exists" });
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashed, department, role });
    await user.save();
    res.status(201).json({ message: "User created", user: { ...user.toObject(), password: undefined } });
  } catch (error) {
    res.status(500).json({ message: "Error creating user" });
  }
});

app.put("/api/users/:id", verifyToken, async (req, res) => {
  if (req.user.role !== "hr") return res.status(403).json({ message: "Chỉ HR mới có quyền sửa" });
  try {
    const { name, department, role, password } = req.body;
    const update = {};
    if (name) update.name = name;
    if (department) update.department = department;
    if (role) update.role = role;
    if (password) update.password = await bcrypt.hash(password, 10);
    const user = await User.findByIdAndUpdate(req.params.id, update, { new: true }).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ message: "User updated", user });
  } catch (error) {
    res.status(500).json({ message: "Error updating user" });
  }
});

app.delete("/api/users/:id", verifyToken, async (req, res) => {
  if (req.user.role !== "hr") return res.status(403).json({ message: "Chỉ HR mới có quyền xóa" });
  try {
    if (req.params.id === req.user.userId)
      return res.status(400).json({ message: "Không thể xóa tài khoản của chính mình" });
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ message: "User deleted" });
  } catch (error) {
    res.status(500).json({ message: "Error deleting user" });
  }
});

// ═══════════════════════════════════════════
// ROUTES: SETTINGS (HR only)
// ═══════════════════════════════════════════

app.get("/api/settings/manager-emails", verifyToken, async (req, res) => {
  if (req.user.role !== "hr") return res.status(403).json({ message: "Chỉ HR mới có quyền xem" });
  try {
    const setting = await Settings.findOne({ key: "manager_emails" });
    res.json(setting ? setting.value : {});
  } catch (error) {
    res.status(500).json({ message: "Error fetching settings" });
  }
});

app.put("/api/settings/manager-emails", verifyToken, async (req, res) => {
  if (req.user.role !== "hr") return res.status(403).json({ message: "Chỉ HR mới có quyền cập nhật" });
  try {
    const { IT, Marketing, Finance, Sales, hrEmail } = req.body;
    const value = { IT, Marketing, Finance, Sales, hrEmail };
    await Settings.findOneAndUpdate({ key: "manager_emails" }, { key: "manager_emails", value }, { upsert: true });
    res.json({ message: "Cập nhật thành công", value });
  } catch (error) {
    res.status(500).json({ message: "Error saving settings" });
  }
});

// ═══════════════════════════════════════════
// ROUTES: LEAVE REQUEST
// ═══════════════════════════════════════════

// POST /api/leave - Tạo đơ nghỉ phép
app.post("/api/leave", verifyToken, async (req, res) => {
  try {
    const { leave_date, leave_days, reason } = req.body;
    const user = await User.findById(req.user.userId);

    // Validate
    if (!leave_date || !leave_days || !reason) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Tạo tokens
    const managerApprovalToken = generateToken();
    const hrApprovalToken = parseInt(leave_days) > 3 ? generateToken() : null;

    // Lấy manager email theo phòng ban từ Settings DB
    const settings = await Settings.findOne({ key: "manager_emails" });
    const managerEmails = settings ? settings.value : {};
    const deptManagerEmail = managerEmails[user.department] || process.env.MANAGER_EMAIL || "quanganh.hs2005@gmail.com";
    const hrEmail = managerEmails.hrEmail || process.env.HR_EMAIL || "quanganh.hs2004@gmail.com";

    // Tạo đơ
    const leave = new LeaveRequest({
      employeeId: user._id,
      employee_name: user.name,
      employee_email: user.email,
      department: user.department,
      leave_date,
      leave_days: parseInt(leave_days),
      reason,
      managerApprovalToken,
      hrApprovalToken,
      manager_status: "pending",
      hr_status: parseInt(leave_days) > 3 ? "pending" : "skipped",
      status: "pending",
    });
    await leave.save();

    // Gọi N8n Webhook - gửi dữ liệu để N8n xử lý email, etc
    const n8nPayload = {
      event: "leave_request_created",
      requestId: leave._id.toString(),
      employeeName: user.name,
      employeeEmail: user.email,
      department: user.department,
      leaveDate: leave_date,
      leaveDays: parseInt(leave_days),
      reason,
      managerApprovalToken,
      managerApprovalLink: buildLink(managerApprovalToken),
      managerEmail: deptManagerEmail,
      hrApprovalToken,
      hrApprovalLink: hrApprovalToken ? buildLink(hrApprovalToken) : null,
      hrEmail: hrEmail,
      requiresHrApproval: parseInt(leave_days) > 3,
    };

    // Gọi N8n (không block response)
    triggerN8n(process.env.N8N_LEAVE_WEBHOOK, n8nPayload);

    res.status(201).json({
      message: "Leave request submitted",
      leave,
    });
  } catch (error) {
    console.error("Leave error:", error.message || error);
    res.status(500).json({ message: "Failed to submit leave request", detail: error.message });
  }
});

// GET /api/leave - Lấy danh sách đơ
app.get("/api/leave", verifyToken, async (req, res) => {
  try {
    let query = {};
    if (req.user.role === "employee") {
      query = { employeeId: req.user.userId };
    } else if (req.user.role === "manager") {
      query = { department: req.user.department };
    }
    // HR thấy tất cả
    const requests = await LeaveRequest.find(query).sort({ createdAt: -1 });
    res.json(requests);
  } catch (error) {
    console.error("Get leave error:", error);
    res.status(500).json({ message: "Error fetching requests" });
  }
});

// GET /api/leave/:id - Chi tiết đơ
app.get("/api/leave/:id", verifyToken, async (req, res) => {
  try {
    const request = await LeaveRequest.findById(req.params.id);
    res.json(request || {});
  } catch (error) {
    res.status(500).json({ message: "Error" });
  }
});

// ═══════════════════════════════════════════
// ROUTES: APPROVAL
// ═══════════════════════════════════════════

// POST /api/approval/webhook-callback - n8n gọi sau khi gửi email thành công
// Chỉ log, không cập nhật gì — Backend là nguồn truth duy nhất
app.post("/api/approval/webhook-callback", async (req, res) => {
  const { event, requestId } = req.body;
  console.log(`📧 N8N email sent: event=${event}, requestId=${requestId}`);
  res.json({ ok: true });
});

// POST /api/approval/manager - Manager duyệt
app.post("/api/approval/manager", async (req, res) => {
  try {
    const { token, action } = req.body;

    if (!["approve", "reject"].includes(action)) {
      return res.status(400).json({ message: "Invalid action" });
    }

    const request = await LeaveRequest.findOne({ managerApprovalToken: token });
    if (!request) {
      return res.status(404).json({ message: "Invalid token" });
    }
    if (request.manager_status !== "pending") {
      return res.status(400).json({ message: "Already processed" });
    }

    request.manager_status = action === "approve" ? "approved" : "rejected";
    request.manager_decidedAt = new Date();

    if (action === "reject") {
      request.status = "rejected";
      await request.save();
      return res.json({ message: "Leave request rejected", status: "rejected" });
    }

    // ✅ Manager approved
    request.manager_decidedAt = new Date();

    if (request.leave_days > 3 && request.hrApprovalToken) {
      // > 3 ngày → Cần HR duyệt thêm
      await request.save();
      return res.json({
        message: "Approved by manager. Sent to HR for final approval",
        status: "pending",
        requiresHrApproval: true,
        hrApprovalToken: request.hrApprovalToken,
      });
    }

    // ≤ 3 ngày → Duyệt xong
    request.status = "approved";
    await request.save();
    res.json({ message: "Leave request fully approved", status: "approved" });
  } catch (error) {
    console.error("Manager approval error:", error);
    res.status(500).json({ message: "Error" });
  }
});

// POST /api/approval/hr - HR duyệt
app.post("/api/approval/hr", async (req, res) => {
  try {
    const { token, action } = req.body;

    if (!["approve", "reject"].includes(action)) {
      return res.status(400).json({ message: "Invalid action" });
    }

    const request = await LeaveRequest.findOne({ hrApprovalToken: token });
    if (!request) {
      return res.status(404).json({ message: "Invalid token" });
    }
    if (request.hr_status !== "pending") {
      return res.status(400).json({ message: "Already processed" });
    }
    if (request.manager_status !== "approved") {
      return res.status(400).json({ message: "Not approved by manager yet" });
    }

    request.hr_status = action === "approve" ? "approved" : "rejected";
    request.hr_decidedAt = new Date();
    request.status = action === "approved" ? "approved" : "rejected";
    await request.save();

    // Gọi N8n - HR decision → n8n gửi email thông báo employee
    await triggerN8n(process.env.N8N_APPROVAL_WEBHOOK, {
      event: request.status === "approved" ? "hr_approved" : "hr_rejected",
      requestId: request._id.toString(),
      employeeEmail: request.employee_email,
      employeeName: request.employee_name,
      leaveDate: request.leave_date,
      leaveDays: request.leave_days,
      reason: request.reason,
    });

    res.json({ message: `HR ${request.status}`, status: request.status });
  } catch (error) {
    console.error("HR approval error:", error);
    res.status(500).json({ message: "Error" });
  }
});

// GET /api/approval/token/:token - Kiểm tra token
app.get("/api/approval/token/:token", async (req, res) => {
  try {
    const { token } = req.params;

    let request = await LeaveRequest.findOne({ managerApprovalToken: token });
    let approvalType = "manager";

    if (!request) {
      request = await LeaveRequest.findOne({ hrApprovalToken: token });
      approvalType = "hr";
    }

    if (!request) {
      return res.status(404).json({ message: "Invalid or expired token" });
    }

    res.json({
      employee_name: request.employee_name,
      employee_email: request.employee_email,
      department: request.department,
      leave_date: request.leave_date,
      leave_days: request.leave_days,
      reason: request.reason,
      status: approvalType === "manager" ? request.manager_status : request.hr_status,
      approvalType,
      finalStatus: request.status,
    });
  } catch (error) {
    res.status(500).json({ message: "Error" });
  }
});

// ═══════════════════════════════════════════
// ROUTES: ROOMS
// ═══════════════════════════════════════════

// GET /api/rooms - Lấy danh sách phòng
app.get("/api/rooms", verifyToken, async (req, res) => {
  try {
    const rooms = await Room.find({ status: "active" }).sort({ room_id: 1 });
    res.json(rooms);
  } catch (error) {
    console.error("Get rooms error:", error);
    res.status(500).json({ message: "Error fetching rooms" });
  }
});

// GET /api/rooms/:id/slots - Lấy các khung giờ đã đặt của phòng
app.get("/api/rooms/:id/slots", verifyToken, async (req, res) => {
  try {
    const { date } = req.query;
    let query = { room_id: req.params.id, status: { $ne: "cancelled" } };
    if (date) query.meeting_date = date;
    const bookings = await Booking.find(query).select("meeting_date start_time end_time status");
    const booked_slots = bookings.map(b => `${b.start_time}-${b.end_time}`);
    res.json({ booked_slots });
  } catch (error) {
    res.status(500).json({ message: "Error" });
  }
});

// POST /api/meeting-room/book - Tạo booking (frontend endpoint)
app.post("/api/meeting-room/book", verifyToken, async (req, res) => {
  try {
    const { room_id, room_name, meeting_date, start_time, end_time, purpose, attendees, notes } = req.body;
    const user = await User.findById(req.user.userId);

    if (!room_id || !meeting_date || !start_time || !end_time || !purpose) {
      return res.status(400).json({ message: "All required fields must be filled" });
    }

    const room = await Room.findById(room_id);
    if (!room) return res.status(404).json({ message: "Room not found" });

    const [sh, sm] = start_time.split(":").map(Number);
    const [eh, em] = end_time.split(":").map(Number);
    const duration_minutes = (eh * 60 + em) - (sh * 60 + sm);
    if (duration_minutes <= 0) return res.status(400).json({ message: "End time must be after start time" });

    const conflict = await Booking.findOne({
      room_id,
      meeting_date,
      status: { $ne: "cancelled" },
      $or: [{ start_time: { $lt: end_time }, end_time: { $gt: start_time } }],
    });
    if (conflict) return res.status(409).json({ message: "Room already booked in this time slot" });

    const bookingId = `MTG-${Date.now()}`;
    const managerApprovalToken = require("crypto").randomBytes(32).toString("hex");
    const approval_link = `${process.env.FRONTEND_URL}/meeting-approvals.html?token=${managerApprovalToken}`;

    const booking = new Booking({
      booking_id: bookingId,
      requester_id: user._id,
      requester_name: user.name,
      requester_email: user.email,
      department: user.department,
      room_id: room._id,
      room_name: room_name || room.name,
      meeting_date,
      start_time,
      end_time,
      duration_minutes,
      purpose,
      attendees: attendees || 1,
      notes: notes || "",
      managerApprovalToken,
      manager_email: process.env.MANAGER_EMAIL || null,
      approval_link,
    });
    await booking.save();

    triggerN8n(process.env.N8N_MEETING_ROOM_WEBHOOK, {
      event: "booking_created",
      bookingId,
      requesterName: user.name,
      requesterEmail: user.email,
      roomName: room.name,
      meetingDate: meeting_date,
      startTime: start_time,
      endTime: end_time,
      purpose,
      approvalLink: approval_link,
      approvalToken: managerApprovalToken,
      managerEmail: process.env.MANAGER_EMAIL || null,
    });

    res.status(201).json({ message: "Booking submitted", booking_id: bookingId });
  } catch (error) {
    console.error("Booking error:", error);
    res.status(500).json({ message: "Failed to submit booking", detail: error.message });
  }
});

// ═══════════════════════════════════════════
// ROUTES: BOOKINGS
// ═══════════════════════════════════════════

// GET /api/bookings - Lấy danh sách booking
app.get("/api/bookings", verifyToken, async (req, res) => {
  try {
    let query = {};
    if (req.user.role === "employee") {
      query = { requester_id: req.user.userId };
    }
    // manager/HR thấy tất cả
    const bookings = await Booking.find(query).sort({ createdAt: -1 });
    res.json(bookings);
  } catch (error) {
    res.status(500).json({ message: "Error fetching bookings" });
  }
});

// GET /api/bookings/room/:roomId - Kiểm tra phòng đã đặt chưa
app.get("/api/bookings/room/:roomId", verifyToken, async (req, res) => {
  try {
    const { date } = req.query;
    let query = { room_id: req.params.roomId, status: { $ne: "cancelled" } };
    if (date) query.meeting_date = date;
    const bookings = await Booking.find(query).select("meeting_date start_time end_time status");
    res.json(bookings);
  } catch (error) {
    res.status(500).json({ message: "Error" });
  }
});

// GET /api/bookings/action - Manager duyệt booking qua query params (click từ email)
app.get("/api/bookings/action", async (req, res) => {
  try {
    const { token, action } = req.query;
    if (!["approve", "reject"].includes(action)) {
      return res.status(400).send("<h2>❌ Action không hợp lệ</h2>");
    }
    const booking = await Booking.findOne({ managerApprovalToken: token });
    if (!booking) return res.status(404).send("<h2>❌ Token không hợp lệ hoặc đã hết hạn</h2>");
    if (booking.manager_status !== "pending") {
      return res.send(`<html><body style="font-family:Arial;text-align:center;padding:60px"><h2>ℹ️ Yêu cầu này đã được xử lý</h2><p>Trạng thái: <b>${booking.status}</b></p></body></html>`);
    }
    booking.manager_status = action;
    booking.manager_decided_at = new Date();
    booking.status = action === "approve" ? "approved" : "rejected";
    await booking.save();

    // Trigger n8n để gửi email thông báo cho requester
    triggerN8n(process.env.N8N_MEETING_APPROVAL_WEBHOOK, {
      event: action === "approve" ? "booking_approved" : "booking_rejected",
      bookingId: booking.booking_id,
      requesterEmail: booking.requester_email,
      requesterName: booking.requester_name,
      roomName: booking.room_name,
      meetingDate: booking.meeting_date,
    });

    const isApprove = action === "approve";
    res.send(`<html><head><meta charset="UTF-8"></head><body style="font-family:Arial,sans-serif;text-align:center;padding:60px;background:#f9fafb"><div style="max-width:480px;margin:auto;background:#fff;border-radius:12px;padding:40px;box-shadow:0 2px 12px rgba(0,0,0,0.08);border:2px solid ${isApprove ? "#16a34a" : "#dc2626"}"><h2 style="color:${isApprove ? "#16a34a" : "#dc2626"}">${isApprove ? "✅ Đã Phê Duyệt" : "❌ Đã Từ Chối"}</h2><p style="color:#555">Yêu cầu đặt phòng <b>${booking.room_name}</b> của <b>${booking.requester_name}</b> đã được <b>${isApprove ? "phê duyệt" : "từ chối"}</b>.</p><p style="color:#888;font-size:13px">Mã Booking: <code>${booking.booking_id}</code></p><p style="color:#888;font-size:13px">Email thông báo đã được gửi đến nhân viên.</p></div></body></html>`);
  } catch (error) {
    res.status(500).send("<h2>❌ Lỗi hệ thống</h2>");
  }
});

// POST /api/bookings/approve - Manager duyệt booking
app.post("/api/bookings/approve", async (req, res) => {
  try {
    const { token, action } = req.body;
    if (!["approve", "reject"].includes(action)) {
      return res.status(400).json({ message: "Invalid action" });
    }

    const booking = await Booking.findOne({ managerApprovalToken: token });
    if (!booking) return res.status(400).json({ message: "Invalid token" });
    if (booking.manager_status !== "pending") {
      return res.status(400).json({ message: "Already processed" });
    }

    booking.manager_status = action;
    booking.manager_decided_at = new Date();
    booking.status = action === "approve" ? "approved" : "rejected";
    await booking.save();

    triggerN8n(process.env.N8N_MEETING_APPROVAL_WEBHOOK, {
      event: action === "approve" ? "booking_approved" : "booking_rejected",
      bookingId: booking.booking_id,
      requesterEmail: booking.requester_email,
      requesterName: booking.requester_name,
      roomName: booking.room_name,
      meetingDate: booking.meeting_date,
    });

    res.json({
      message: `Booking ${action}d`,
      status: booking.status,
      requester_name: booking.requester_name,
      requester_email: booking.requester_email,
      room_name: booking.room_name,
      meeting_date: booking.meeting_date,
      start_time: booking.start_time,
      end_time: booking.end_time,
      booking_id: booking.booking_id,
    });
  } catch (error) {
    res.status(500).json({ message: "Error" });
  }
});

// GET /api/bookings/token/:token - Kiểm tra booking token
app.get("/api/bookings/token/:token", async (req, res) => {
  try {
    const booking = await Booking.findOne({ managerApprovalToken: req.params.token });
    if (!booking) return res.status(404).json({ message: "Invalid or expired token" });
    res.json(booking);
  } catch (error) {
    res.status(500).json({ message: "Error" });
  }
});

// ═══════════════════════════════════════════
// HEALTH CHECK
// ═══════════════════════════════════════════
app.get("/api/health", (req, res) => {
  res.json({ status: "OK", message: "Backend running" });
});

// ═══════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════
connectDB().then(() => {
  app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
});
