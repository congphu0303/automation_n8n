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
const Settings = require("./models/Settings");

const app = express();
const PORT = process.env.PORT || 3001;

// ═══════════════════════════════════════════
// MIDDLEWARE
// ═══════════════════════════════════════════
app.use(cors({
  origin: [
    process.env.FRONTEND_URL || "http://localhost:3000",
    "https://internalautomation.io.vn",
    "http://localhost:3000",
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
    console.log("MongoDB Atlas connected");
  } catch (error) {
    console.error("MongoDB error:", error.message);
    process.exit(1);
  }
};

// ═══════════════════════════════════════════
// N8N WEBHOOK CALLER
// ═══════════════════════════════════════════
const triggerN8n = async (webhookUrl, payload) => {
  if (!webhookUrl || webhookUrl.includes("yourdomain.com")) {
    console.log("N8n webhook not configured, skipping...");
    return { success: false, message: "N8n not configured" };
  }
  try {
    const response = await axios.post(webhookUrl, payload, { timeout: 15000 });
    console.log(`N8n webhook triggered: ${webhookUrl}`);
    return { success: true, data: response.data };
  } catch (error) {
    console.error(`N8n webhook error:`, error.message);
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
// ROUTES: SETTINGS (Manager email theo phòng ban)
// ═══════════════════════════════════════════

// GET /api/settings/manager-emails - Lấy email manager theo phòng ban (chỉ HR)
app.get("/api/settings/manager-emails", verifyToken, async (req, res) => {
  if (req.user.role !== "hr") {
    return res.status(403).json({ message: "Chỉ HR mới có quyền xem" });
  }
  try {
    const setting = await Settings.findOne({ key: "manager_emails" });
    res.json(setting ? setting.value : {});
  } catch (error) {
    res.status(500).json({ message: "Error fetching settings" });
  }
});

// PUT /api/settings/manager-emails - Cập nhật email manager theo phòng ban
app.put("/api/settings/manager-emails", verifyToken, async (req, res) => {
  if (req.user.role !== "hr") {
    return res.status(403).json({ message: "Chỉ HR mới có quyền cập nhật" });
  }
  try {
    const { IT, Marketing, Finance, Sales, hrEmail } = req.body;
    const value = { IT, Marketing, Finance, Sales, hrEmail };
    await Settings.findOneAndUpdate(
      { key: "manager_emails" },
      { key: "manager_emails", value },
      { upsert: true }
    );
    res.json({ message: "Cập nhật thành công", value });
  } catch (error) {
    res.status(500).json({ message: "Error saving settings" });
  }
});

// ═══════════════════════════════════════════
// ROUTES: USER MANAGEMENT
// ═══════════════════════════════════════════

// GET /api/users - Danh sách tất cả users (HR/Admin)
app.get("/api/users", verifyToken, async (req, res) => {
  if (req.user.role !== "hr") {
    return res.status(403).json({ message: "Chỉ HR mới có quyền xem" });
  }
  try {
    const users = await User.find().select("-password").sort({ createdAt: -1 });
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: "Error fetching users" });
  }
});

// POST /api/users - Tạo user mới (HR)
app.post("/api/users", verifyToken, async (req, res) => {
  if (req.user.role !== "hr") {
    return res.status(403).json({ message: "Chỉ HR mới có quyền tạo" });
  }
  try {
    const { name, email, password, department, role } = req.body;
    if (!name || !email || !password || !department || !role) {
      return res.status(400).json({ message: "All fields required" });
    }
    if (await User.findOne({ email: email.toLowerCase() })) {
      return res.status(400).json({ message: "Email already exists" });
    }
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashed, department, role });
    await user.save();
    res.status(201).json({ message: "User created", user: { ...user.toObject(), password: undefined } });
  } catch (error) {
    res.status(500).json({ message: "Error creating user" });
  }
});

// PUT /api/users/:id - Cập nhật user (HR)
app.put("/api/users/:id", verifyToken, async (req, res) => {
  if (req.user.role !== "hr") {
    return res.status(403).json({ message: "Chỉ HR mới có quyền sửa" });
  }
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

// DELETE /api/users/:id - Xóa user (HR)
app.delete("/api/users/:id", verifyToken, async (req, res) => {
  if (req.user.role !== "hr") {
    return res.status(403).json({ message: "Chỉ HR mới có quyền xóa" });
  }
  try {
    // Không cho xóa chính mình
    if (req.params.id === req.user.userId) {
      return res.status(400).json({ message: "Không thể xóa tài khoản của chính mình" });
    }
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ message: "User deleted" });
  } catch (error) {
    res.status(500).json({ message: "Error deleting user" });
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

    // Lấy manager email theo phòng ban từ Settings
    const settings = await Settings.findOne({ key: "manager_emails" });
    const managerEmails = settings ? settings.value : {};
    const deptManagerEmail = managerEmails[user.department] || managerEmails["HR"] || "phupc.23ite@vku.udn.vn";

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
      manager_email: deptManagerEmail,
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
      managerEmail: deptManagerEmail,
      hrEmail: managerEmails.hrEmail || "phupc.23ite@vku.udn.vn",
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

      // Gọi n8n → gửi email thông báo employee bị từ chối
      await triggerN8n(process.env.N8N_MANAGER_WEBHOOK, {
        action: "reject",
        employeeEmail: request.employee_email,
        employeeName: request.employee_name,
        leaveDate: request.leave_date,
        leaveDays: request.leave_days,
        reason: request.reason,
        body: {
          employeeName: request.employee_name,
          leaveDate: request.leave_date,
          leaveDays: request.leave_days,
          reason: request.reason,
        },
      });

      return res.json({ message: "Leave request rejected", status: "rejected" });
    }

    // Manager approved
    // (manager_status + manager_decidedAt đã set ở line 417-418, KHÔNG set lại)

    if (request.leave_days > 3 && request.hrApprovalToken) {
      // > 3 ngày → Cần HR duyệt thêm
      await request.save();

      // Gọi n8n → gửi email cho employee đang chờ HR + gửi email cho HR
      const hrLink = buildLink(request.hrApprovalToken);
      await triggerN8n(process.env.N8N_MANAGER_WEBHOOK, {
        action: "waiting_hr",
        employeeEmail: request.employee_email,
        employeeName: request.employee_name,
        leaveDate: request.leave_date,
        leaveDays: request.leave_days,
        reason: request.reason,
        hrApprovalLink: hrLink,
        body: {
          employeeName: request.employee_name,
          employeeEmail: request.employee_email,
          leaveDate: request.leave_date,
          leaveDays: request.leave_days,
          reason: request.reason,
          hrApprovalLink: hrLink,
        },
      });

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

    // Gọi n8n → gửi email thông báo employee được duyệt
    await triggerN8n(process.env.N8N_MANAGER_WEBHOOK, {
      action: "approve",
      employeeEmail: request.employee_email,
      employeeName: request.employee_name,
      leaveDate: request.leave_date,
      leaveDays: request.leave_days,
      reason: request.reason,
      body: {
        employeeName: request.employee_name,
        leaveDate: request.leave_date,
        leaveDays: request.leave_days,
        reason: request.reason,
      },
    });

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
    request.status = action === "approve" ? "approved" : "rejected";
    await request.save();

    // Gọi n8n HR webhook → gửi email thông báo employee
    await triggerN8n(process.env.N8N_HR_WEBHOOK, {
      action: action === "approve" ? "approve" : "reject",
      employeeEmail: request.employee_email,
      employeeName: request.employee_name,
      leaveDate: request.leave_date,
      leaveDays: request.leave_days,
      reason: request.reason,
      body: {
        employeeName: request.employee_name,
        employeeEmail: request.employee_email,
        leaveDate: request.leave_date,
        leaveDays: request.leave_days,
        reason: request.reason,
      },
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
      approvalType,
      // Trả về riêng để frontend phân biệt rõ luồng
      status: approvalType === "manager" ? request.manager_status : request.hr_status,
      finalStatus: request.status,
      // Trả về cả 2 để hiển thị luồng phê duyệt
      manager_status: request.manager_status,
      hr_status: request.hr_status,
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
