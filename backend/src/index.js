require("dotenv").config();
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

const app = express();
const PORT = process.env.PORT || 3001;

// ═══════════════════════════════════════════
// MIDDLEWARE
// ═══════════════════════════════════════════
app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:3000",
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
      hrApprovalToken,
      managerApprovalLink: buildLink(managerApprovalToken),
      hrApprovalLink: hrApprovalToken ? buildLink(hrApprovalToken) : null,
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
