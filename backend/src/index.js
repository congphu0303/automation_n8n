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
    "https://approvehub.internalautomation.io.vn",
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
      { $set: { value } },
      { upsert: true, new: true }
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

// Helper lấy email từ Settings, không hardcoded
const getEmailFromSettings = async (department, type) => {
  try {
    const settings = await Settings.findOne({ key: "manager_emails" });
    if (!settings || !settings.value) {
      const defaultEmail = process.env.DEFAULT_MANAGER_EMAIL || "quanganh.hs2005@gmail.com";
      return defaultEmail;
    }
    if (type === "hr") {
      return settings.value.hrEmail || process.env.DEFAULT_MANAGER_EMAIL || "quanganh.hs2005@gmail.com";
    }
    return settings.value[department] || settings.value.hrEmail || process.env.DEFAULT_MANAGER_EMAIL || "quanganh.hs2005@gmail.com";
  } catch (error) {
    console.error("Error fetching settings:", error.message);
    return process.env.DEFAULT_MANAGER_EMAIL || "quanganh.hs2005@gmail.com";
  }
};

// Helper kiểm tra token có hết hạn chưa
const isTokenExpired = (expiresAt) => {
  if (!expiresAt) return false;
  return new Date() > new Date(expiresAt);
};

// ═══════════════════════════════════════════
// ROUTES: LEAVE REQUEST
// ═══════════════════════════════════════════

// POST /api/leave - Tạo đơ nghỉ phép (được gọi từ N8N webhook)
app.post("/api/leave", verifyToken, async (req, res) => {
  try {
    const { leave_date, leave_days, reason, employeeName, employeeEmail, department } = req.body;
    const userId = req.user?.userId;

    // Validate
    if (!leave_date || !leave_days || !reason) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Lấy email từ Settings
    const managerEmail = await getEmailFromSettings(department || req.user?.department, "manager");
    const hrEmail = await getEmailFromSettings(null, "hr");

    // Kiểm tra đã có manager email chưa
    if (!managerEmail) {
      return res.status(400).json({
        message: "Chưa cấu hình email Manager cho phòng ban này. Vui lòng liên hệ HR để cài đặt."
      });
    }

    // Tạo tokens với expiration 7 ngày
    const managerApprovalToken = generateToken();
    const hrApprovalToken = parseInt(leave_days) > 3 ? generateToken() : null;
    const tokenExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 ngày

    // Lấy user info nếu có userId (từ N8N payload hoặc auth)
    let employeeNameVal = employeeName;
    let employeeEmailVal = employeeEmail;
    let employeeIdVal = userId;

    if (userId && !employeeName) {
      const user = await User.findById(userId);
      if (user) {
        employeeNameVal = user.name;
        employeeEmailVal = user.email;
        employeeIdVal = user._id;
      }
    }

    // Tạo đơ
    const leave = new LeaveRequest({
      employeeId: employeeIdVal,
      employee_name: employeeNameVal,
      employee_email: employeeEmailVal,
      department: department || req.user?.department,
      leave_date,
      leave_days: parseInt(leave_days),
      reason,
      managerApprovalToken,
      hrApprovalToken,
      managerTokenExpiresAt: tokenExpiresAt,
      hrTokenExpiresAt: parseInt(leave_days) > 3 ? tokenExpiresAt : null,
      manager_status: "pending",
      hr_status: parseInt(leave_days) > 3 ? "pending" : "skipped",
      status: "pending",
      manager_email: managerEmail,
      hr_email: hrEmail,
    });
    await leave.save();

    // Trả về thông tin để N8N gửi email
    res.status(201).json({
      success: true,
      leaveId: leave._id.toString(),
      employeeName: leave.employee_name,
      employeeEmail: leave.employee_email,
      department: leave.department,
      leaveDate: leave_date,
      leaveDays: parseInt(leave_days),
      reason,
      managerApprovalToken,
      hrApprovalToken,
      managerApprovalLink: buildLink(managerApprovalToken),
      hrApprovalLink: hrApprovalToken ? buildLink(hrApprovalToken) : null,
      requiresHrApproval: parseInt(leave_days) > 3,
      managerEmail,
      hrEmail,
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
    // HR thấy tất cả đơ đã manager duyệt và > 3 ngày
    const requests = await LeaveRequest.find(query).sort({ createdAt: -1 });

    // Filter HR chỉ thấy đơ > 3 ngày đã manager duyệt
    let filtered = requests;
    if (req.user.role === "hr") {
      filtered = requests.filter(r => r.leave_days > 3 && r.manager_status === "approved");
    }

    res.json(filtered);
  } catch (error) {
    console.error("Get leave error:", error);
    res.status(500).json({ message: "Error fetching requests" });
  }
});

// GET /api/leave/:id - Chi tiết đơ
app.get("/api/leave/:id", verifyToken, async (req, res) => {
  try {
    const request = await LeaveRequest.findById(req.params.id);
    if (!request) {
      return res.status(404).json({ message: "Leave request not found" });
    }

    // Check quyền truy cập
    if (req.user.role === "employee" && request.employeeId.toString() !== req.user.userId) {
      return res.status(403).json({ message: "Không có quyền xem đơn này" });
    }
    if (req.user.role === "manager" && request.department !== req.user.department) {
      return res.status(403).json({ message: "Không có quyền xem đơn này" });
    }
    // HR có thể xem tất cả

    res.json(request || {});
  } catch (error) {
    res.status(500).json({ message: "Error" });
  }
});

// DELETE /api/leave/:id - Hủy đơn nghỉ phép (gọi từ N8N webhook)
app.delete("/api/leave/:id", verifyToken, async (req, res) => {
  try {
    const leaveId = req.params.id;
    const request = await LeaveRequest.findById(leaveId);
    if (!request) {
      return res.status(404).json({ message: "Leave request not found" });
    }

    // Nếu có auth (từ frontend), kiểm tra quyền
    if (req.user) {
      const user = await User.findById(req.user.userId);
      if (request.employeeId.toString() !== req.user.userId && user.role !== "hr") {
        return res.status(403).json({ message: "Không có quyền hủy đơn này" });
      }
    }

    // Chỉ đơn đang pending mới được hủy
    if (request.status !== "pending") {
      return res.status(400).json({ message: "Chỉ đơn đang chờ duyệt mới có thể hủy" });
    }

    request.status = "cancelled";
    request.cancelledAt = new Date();
    request.cancelledBy = req.user?.userId;
    await request.save();

    // Trả về thông tin để N8N gửi email
    res.json({
      success: true,
      message: "Đơn đã được hủy",
      status: "cancelled",
      leaveId: request._id.toString(),
      employeeName: request.employee_name,
      employeeEmail: request.employee_email,
      leaveDate: request.leave_date ? new Date(request.leave_date).toLocaleDateString("vi-VN") : "",
      leaveDays: request.leave_days,
      reason: request.reason,
      department: request.department,
      managerEmail: request.manager_email,
      hrEmail: request.hr_email,
    });
  } catch (error) {
    console.error("Cancel leave error:", error);
    res.status(500).json({ message: "Error cancelling leave" });
  }
});

// POST /api/leave/:id/return-early - Về sớm (gọi từ N8N webhook)
app.post("/api/leave/:id/return-early", verifyToken, async (req, res) => {
  try {
    const { actualReturnDate } = req.body;
    const request = await LeaveRequest.findById(req.params.id);

    if (!request) {
      return res.status(404).json({ message: "Leave request not found" });
    }

    // Nếu có auth (từ frontend), kiểm tra quyền
    if (req.user && request.employeeId.toString() !== req.user.userId) {
      return res.status(403).json({ message: "Không có quyền cập nhật đơn này" });
    }

    // Chỉ đơn đã duyệt mới được về sớm
    if (request.status !== "approved") {
      return res.status(400).json({ message: "Chỉ đơn đã duyệt mới có thể về sớm" });
    }

    // Tính số ngày hoàn lại
    const plannedEnd = new Date(request.leave_date);
    plannedEnd.setDate(plannedEnd.getDate() + request.leave_days - 1);

    const actualReturn = new Date(actualReturnDate || new Date());
    const diffTime = plannedEnd - actualReturn;
    const refundDays = Math.max(0, Math.ceil(diffTime / (1000 * 60 * 60 * 24)));

    request.actualReturnDate = actualReturn;
    request.refundDays = refundDays;
    await request.save();

    // Trả về thông tin để N8N gửi email
    res.json({
      success: true,
      message: `Đã cập nhật ngày về. Hoàn lại ${refundDays} ngày phép.`,
      refundDays,
      actualReturnDate: actualReturn,
      leaveId: request._id.toString(),
      employeeName: request.employee_name,
      employeeEmail: request.employee_email,
      leaveDate: request.leave_date ? new Date(request.leave_date).toLocaleDateString("vi-VN") : "",
      leaveDays: request.leave_days,
      reason: request.reason,
      department: request.department,
      managerEmail: request.manager_email,
      hrEmail: request.hr_email,
    });
  } catch (error) {
    console.error("Return early error:", error);
    res.status(500).json({ message: "Error processing return early" });
  }
});

// PUT /api/leave/:id - Cập nhật đơn nghỉ phép (gọi từ N8N webhook)
app.put("/api/leave/:id", verifyToken, async (req, res) => {
  try {
    const { leave_date, leave_days, reason, managerApprovalToken, hrApprovalToken } = req.body;
    const request = await LeaveRequest.findById(req.params.id);

    if (!request) {
      return res.status(404).json({ message: "Leave request not found" });
    }

    // Nếu có auth (từ frontend), kiểm tra quyền
    if (req.user && request.employeeId.toString() !== req.user.userId) {
      return res.status(403).json({ message: "Không có quyền cập nhật đơn này" });
    }

    // Chỉ đơn pending mới được sửa
    if (request.status !== "pending" || request.manager_status !== "pending") {
      return res.status(400).json({ message: "Chỉ đơn đang chờ duyệt mới có thể sửa" });
    }

    if (leave_date) request.leave_date = leave_date;
    if (leave_days) {
      request.leave_days = parseInt(leave_days);
      // Cập nhật HR token nếu số ngày thay đổi
      if (parseInt(leave_days) > 3 && !request.hrApprovalToken) {
        request.hrApprovalToken = generateToken();
        request.hrTokenExpiresAt = request.managerTokenExpiresAt;
        request.hr_status = "pending";
      }
    }
    if (reason) request.reason = reason;

    await request.save();

    // Trả về thông tin để N8N gửi email
    res.json({
      success: true,
      message: "Đơn đã được cập nhật",
      leaveId: request._id.toString(),
      employeeName: request.employee_name,
      employeeEmail: request.employee_email,
      leaveDate: request.leave_date ? new Date(request.leave_date).toLocaleDateString("vi-VN") : "",
      leaveDays: request.leave_days,
      reason: request.reason,
      department: request.department,
      managerApprovalToken: request.managerApprovalToken,
      hrApprovalToken: request.hrApprovalToken,
      managerApprovalLink: buildLink(request.managerApprovalToken),
      hrApprovalLink: request.hrApprovalToken ? buildLink(request.hrApprovalToken) : null,
      requiresHrApproval: request.leave_days > 3 && request.hrApprovalToken,
      managerEmail: request.manager_email,
      hrEmail: request.hr_email,
    });
  } catch (error) {
    console.error("Update leave error:", error);
    res.status(500).json({ message: "Error updating leave" });
  }
});

// POST /api/leave/send-reminder - Gửi email nhắc nhở cho manager về đơn chưa duyệt
app.post("/api/leave/send-reminder", verifyToken, async (req, res) => {
  try {
    const { leaveId } = req.body;
    
    if (!leaveId) {
      return res.status(400).json({ message: "leaveId is required" });
    }
    
    const request = await LeaveRequest.findById(leaveId);
    if (!request) {
      return res.status(404).json({ message: "Leave request not found" });
    }
    
    // Chỉ gửi reminder cho đơn đang pending
    if (request.status !== "pending" || request.manager_status !== "pending") {
      return res.status(400).json({ message: "Chỉ đơn đang chờ duyệt mới có thể gửi reminder" });
    }
    
    // Gọi N8n webhook để gửi email nhắc nhở
    try {
      const n8nPayload = {
        event: "leave_reminder",
        leaveId: request._id.toString(),
        employeeName: request.employee_name,
        employeeEmail: request.employee_email,
        leaveDate: request.leave_date ? new Date(request.leave_date).toLocaleDateString("vi-VN") : "",
        leaveDays: request.leave_days,
        reason: request.reason,
        department: request.department,
        managerEmail: request.manager_email,
        hrEmail: request.hr_email,
        managerApprovalLink: buildLink(request.managerApprovalToken),
      };
      await fetch(process.env.N8N_LEAVE_WEBHOOK.replace("/leave-request", "/leave-reminder"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(n8nPayload),
      });
    } catch (e) {
      console.error("N8n reminder webhook error:", e.message);
    }
    
    res.json({ message: "Đã gửi email nhắc nhở", leaveId: request._id.toString() });
  } catch (error) {
    console.error("Send reminder error:", error);
    res.status(500).json({ message: "Error sending reminder" });
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

// POST /api/approval/manager - Manager duyệt (được gọi từ N8N webhook)
app.post("/api/approval/manager", async (req, res) => {
  try {
    const { token, action, employeeName, employeeEmail, leaveDate, leaveDays, reason, department } = req.body;

    if (!["approve", "reject"].includes(action)) {
      return res.status(400).json({ message: "Invalid action" });
    }

    const request = await LeaveRequest.findOne({ managerApprovalToken: token });
    if (!request) {
      return res.status(404).json({ message: "Invalid token" });
    }

    // Kiểm tra token đã hết hạn chưa
    if (isTokenExpired(request.managerTokenExpiresAt)) {
      return res.status(410).json({ message: "Link đã hết hạn. Vui lòng yêu cầu nhân viên gửi lại đơn." });
    }

    if (request.manager_status !== "pending") {
      return res.status(400).json({ message: "Already processed" });
    }

    request.manager_status = action === "approve" ? "approved" : "rejected";
    request.manager_decidedAt = new Date();

    if (action === "reject") {
      request.status = "rejected";
      await request.save();

      return res.json({
        success: true,
        message: "Leave request rejected",
        status: "rejected",
        employeeName: request.employee_name,
        employeeEmail: request.employee_email,
        leaveDate: request.leave_date ? new Date(request.leave_date).toLocaleDateString("vi-VN") : "",
        leaveDays: request.leave_days,
        reason: request.reason,
        department: request.department,
      });
    }

    // Manager approved
    if (request.leave_days > 3 && request.hrApprovalToken) {
      await request.save();

      return res.json({
        success: true,
        message: "Approved by manager. Sent to HR for final approval",
        status: "pending",
        requiresHrApproval: true,
        hrApprovalToken: request.hrApprovalToken,
        hrApprovalLink: `${process.env.FRONTEND_URL}/approvals.html?token=${request.hrApprovalToken}`,
        employeeName: request.employee_name,
        employeeEmail: request.employee_email,
        leaveDate: request.leave_date ? new Date(request.leave_date).toLocaleDateString("vi-VN") : "",
        leaveDays: request.leave_days,
        reason: request.reason,
        department: request.department,
        hrEmail: request.hr_email,
      });
    }

    // ≤ 3 ngày → Duyệt xong
    request.status = "approved";
    await request.save();

    res.json({
      success: true,
      message: "Leave request fully approved",
      status: "approved",
      employeeName: request.employee_name,
      employeeEmail: request.employee_email,
      leaveDate: request.leave_date ? new Date(request.leave_date).toLocaleDateString("vi-VN") : "",
      leaveDays: request.leave_days,
      reason: request.reason,
      department: request.department,
    });
  } catch (error) {
    console.error("Manager approval error:", error);
    res.status(500).json({ message: "Error" });
  }
});

// POST /api/approval/hr - HR duyệt (được gọi từ N8N webhook)
app.post("/api/approval/hr", async (req, res) => {
  try {
    const { token, action } = req.body;

    if (!["approve", "reject", "approved", "rejected"].includes(action)) {
      return res.status(400).json({ message: "Invalid action" });
    }

    const request = await LeaveRequest.findOne({ hrApprovalToken: token });
    if (!request) {
      return res.status(404).json({ message: "Invalid token" });
    }

    // Kiểm tra token đã hết hạn chưa
    if (isTokenExpired(request.hrTokenExpiresAt)) {
      return res.status(410).json({ message: "Link đã hết hạn. Vui lòng yêu cầu nhân viên gửi lại đơn." });
    }

    if (request.hr_status !== "pending") {
      return res.status(400).json({ message: "Already processed" });
    }
    if (request.manager_status !== "approved") {
      return res.status(400).json({ message: "Not approved by manager yet" });
    }

    const isApprove = action === "approve" || action === "approved";
    request.hr_status = isApprove ? "approved" : "rejected";
    request.hr_decidedAt = new Date();
    request.status = isApprove ? "approved" : "rejected";
    await request.save();

    // Trả về thông tin để N8N gửi email
    res.json({
      success: true,
      message: `HR ${request.status}`,
      status: request.status,
      employeeName: request.employee_name,
      employeeEmail: request.employee_email,
      leaveDate: request.leave_date ? new Date(request.leave_date).toLocaleDateString("vi-VN") : "",
      leaveDays: request.leave_days,
      reason: request.reason,
      department: request.department,
    });
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

    // Kiểm tra token đã hết hạn chưa
    const expiresAt = approvalType === "manager" ? request.managerTokenExpiresAt : request.hrTokenExpiresAt;
    const expired = isTokenExpired(expiresAt);

    // Trả về thêm thông tin expiration để frontend hiển thị
    const expiresAtFormatted = expiresAt ? new Date(expiresAt).toLocaleString("vi-VN") : null;

    res.json({
      employee_name: request.employee_name,
      employee_email: request.employee_email,
      department: request.department,
      leave_date: request.leave_date,
      leave_days: request.leave_days,
      reason: request.reason,
      approvalType,
      status: approvalType === "manager" ? request.manager_status : request.hr_status,
      finalStatus: request.status,
      manager_status: request.manager_status,
      hr_status: request.hr_status,
      // Thêm thông tin expiration
      tokenExpired: expired,
      tokenExpiresAt: expiresAtFormatted,
    });
  } catch (error) {
    res.status(500).json({ message: "Error" });
  }
});

// ═══════════════════════════════════════════
// ROUTES: ROOMS
// ═══════════════════════════════════════════
app.get("/api/rooms", verifyToken, async (req, res) => {
  try {
    const rooms = await Room.find({ status: "active" }).sort({ floor: 1, name: 1 });
    res.json(rooms);
  } catch (error) {
    console.error("Get rooms error:", error);
    res.status(500).json({ message: "Error fetching rooms" });
  }
});

app.get("/api/rooms/:id/slots", verifyToken, async (req, res) => {
  try {
    const { date } = req.query;
    if (!date) return res.status(400).json({ message: "Date required" });

    const bookings = await Booking.find({
      room_id: req.params.id,
      meeting_date: date,
      status: { $in: ["pending", "pending_urgent", "approved"] },
    }).select("start_time end_time");

    const booked_slots = bookings.map((b) => `${b.start_time} - ${b.end_time}`);
    res.json({ booked_slots });
  } catch (error) {
    console.error("Get room slots error:", error);
    res.status(500).json({ message: "Error fetching slots" });
  }
});

// ═══════════════════════════════════════════
// ROUTES: MEETING ROOM BOOKING
// ═══════════════════════════════════════════
const parseTimeToMinutes = (timeString) => {
  if (!timeString || !timeString.includes(":")) return null;
  const [h, m] = timeString.split(":").map(Number);
  if (Number.isNaN(h) || Number.isNaN(m)) return null;
  return h * 60 + m;
};

const buildMeetingApprovalLink = (bookingId, action) => {
  const approvalBase = process.env.N8N_MEETING_APPROVAL_WEBHOOK;
  if (!approvalBase) return null;
  const separator = approvalBase.includes("?") ? "&" : "?";
  return `${approvalBase}${separator}booking_id=${encodeURIComponent(bookingId)}&action=${encodeURIComponent(action)}`;
};

app.post("/api/meeting-room/book", verifyToken, async (req, res) => {
  try {
    const {
      room_id,
      room_name,
      meeting_date,
      start_time,
      end_time,
      purpose,
      attendees,
      notes,
      priority,
      equipment_needed,
    } = req.body;

    if (!room_id || !meeting_date || !start_time || !end_time || !purpose) {
      return res.status(400).json({ message: "Missing required booking fields" });
    }

    const startMins = parseTimeToMinutes(start_time);
    const endMins = parseTimeToMinutes(end_time);
    if (startMins === null || endMins === null || endMins <= startMins) {
      return res.status(400).json({ message: "End time must be after start time" });
    }

    const user = await User.findById(req.user.userId).select("name email department");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const room = await Room.findById(room_id);
    if (!room || room.status !== "active") {
      return res.status(404).json({ message: "Room not found or unavailable" });
    }

    const attendeesCount = parseInt(attendees || 1, 10);
    if (attendeesCount > room.capacity) {
      return res.status(400).json({ message: `Attendees exceed room capacity (${room.capacity})` });
    }

    const sameDayBookings = await Booking.find({
      room_id,
      meeting_date,
      status: { $in: ["pending", "pending_urgent", "approved"] },
    }).select("start_time end_time booking_id");

    const hasConflict = sameDayBookings.some((item) => {
      const exStart = parseTimeToMinutes(item.start_time);
      const exEnd = parseTimeToMinutes(item.end_time);
      if (exStart === null || exEnd === null) return false;
      return startMins < exEnd && endMins > exStart;
    });

    if (hasConflict) {
      return res.status(409).json({ message: "Room already booked in selected timeslot" });
    }

    const managerEmail = await getEmailFromSettings(user.department, "manager");
    if (!managerEmail) {
      return res.status(400).json({
        message: "Manager email for this department is not configured",
      });
    }

    const bookingId = `BK-${Date.now()}`;
    const managerApprovalToken = generateToken();
    const status = priority === "urgent" ? "pending_urgent" : "pending";
    const safeRoomName = room_name || room.name;
    const approvalLink = buildMeetingApprovalLink(bookingId, "approve");
    const duration_minutes = endMins - startMins;

    const booking = await Booking.create({
      booking_id: bookingId,
      requester_id: user._id,
      requester_name: user.name,
      requester_email: user.email,
      department: user.department,
      room_id,
      room_name: safeRoomName,
      meeting_date,
      start_time,
      end_time,
      duration_minutes,
      purpose,
      attendees: attendeesCount,
      priority: priority || "normal",
      equipment_needed: Array.isArray(equipment_needed) ? equipment_needed : [],
      notes: notes || "",
      status,
      managerApprovalToken,
      manager_email: managerEmail,
      manager_status: "pending",
      approval_link: approvalLink,
    });

    const n8nPayload = {
      booking_id: booking.booking_id,
      bookingId: booking.booking_id,
      requester_name: booking.requester_name,
      requesterName: booking.requester_name,
      requester_email: booking.requester_email,
      requesterEmail: booking.requester_email,
      requester_dept: booking.department,
      department: booking.department,
      room_name: booking.room_name,
      roomName: booking.room_name,
      room_capacity: room.capacity,
      roomCapacity: room.capacity,
      meeting_date: booking.meeting_date,
      meetingDate: booking.meeting_date,
      start_time: booking.start_time,
      startTime: booking.start_time,
      end_time: booking.end_time,
      endTime: booking.end_time,
      purpose: booking.purpose,
      attendees: booking.attendees,
      priority: priority || "normal",
      equipment_needed: Array.isArray(equipment_needed) ? equipment_needed : [],
      equipmentNeeded: Array.isArray(equipment_needed) ? equipment_needed : [],
      manager_email: managerEmail,
      managerEmail: managerEmail,
      notes: booking.notes,
    };

    const n8nResult = await triggerN8n(process.env.N8N_MEETING_ROOM_WEBHOOK, n8nPayload);
    if (!n8nResult.success) {
      console.warn(`Meeting room n8n webhook failed for ${booking.booking_id}: ${n8nResult.message}`);
    }

    res.status(201).json({
      message: "Booking submitted successfully",
      booking_id: booking.booking_id,
      status: booking.status,
    });
  } catch (error) {
    console.error("Meeting room booking error:", error.message || error);
    res.status(500).json({ message: "Failed to create booking" });
  }
});

app.get("/api/meeting-room", verifyToken, async (req, res) => {
  try {
    // Ưu tiên đọc từ Google Sheets (nếu có)
    if (process.env.GOOGLE_SHEETS_ID) {
      try {
        const sheetsUrl = `https://sheets.googleapis.com/v4/spreadsheets/${process.env.GOOGLE_SHEETS_ID}/values/Trang%20tính1?key=${process.env.GOOGLE_SHEETS_API_KEY}`;
        const sheetsRes = await axios.get(sheetsUrl);
        const rows = sheetsRes.data.values || [];
        
        if (rows.length > 1) {
          const headers = rows[0];
          const email = req.user.email.toLowerCase();
          
          // Lọc bookings của user hiện tại
          const bookings = rows.slice(1)
            .filter(row => {
              const rowEmail = (row[1] || "").toLowerCase();
              return rowEmail === email;
            })
            .map(row => {
              const obj = {};
              headers.forEach((h, i) => { obj[h] = row[i] || ""; });
              return obj;
            });
          
          return res.json(bookings);
        }
      } catch (sheetsErr) {
        console.error("Google Sheets error, falling back to MongoDB:", sheetsErr.message);
      }
    }
    
    // Fallback: đọc từ MongoDB
    let query = {};
    if (req.user.role === "employee") {
      query = { requester_id: req.user.userId };
    } else if (req.user.role === "manager") {
      query = { department: req.user.department };
    }
    const bookings = await Booking.find(query).sort({ createdAt: -1 });
    res.json(bookings);
  } catch (error) {
    console.error("Get meeting room bookings error:", error);
    res.status(500).json({ message: "Error fetching bookings" });
  }
});

app.get("/api/meeting-room/token/:token", async (req, res) => {
  try {
    const booking = await Booking.findOne({ managerApprovalToken: req.params.token });
    if (!booking) return res.status(404).json({ message: "Invalid token" });

    res.json({
      booking_id: booking.booking_id,
      requester_name: booking.requester_name,
      requester_email: booking.requester_email,
      department: booking.department,
      room_name: booking.room_name,
      meeting_date: booking.meeting_date,
      start_time: booking.start_time,
      end_time: booking.end_time,
      purpose: booking.purpose,
      attendees: booking.attendees,
      priority: booking.priority || "normal",
      notes: booking.notes,
      equipment_needed: booking.equipment_needed || [],
      status: booking.status,
      manager_decided_at: booking.manager_decided_at,
    });
  } catch (error) {
    console.error("Get meeting room approval token error:", error);
    res.status(500).json({ message: "Error loading approval request" });
  }
});

app.post("/api/meeting-room/approve", async (req, res) => {
  try {
    const { token, booking_id, action } = req.body;
    if (!["approve", "reject"].includes(action)) {
      return res.status(400).json({ message: "Invalid action" });
    }
    if (!token && !booking_id) {
      return res.status(400).json({ message: "Token or booking_id is required" });
    }

    const booking = token
      ? await Booking.findOne({ managerApprovalToken: token })
      : await Booking.findOne({ booking_id });

    if (!booking) {
      return res.status(404).json({ message: "Booking not found" });
    }
    if (["approved", "rejected", "expired", "cancelled"].includes(booking.status)) {
      return res.status(400).json({ message: "Booking already processed" });
    }

    booking.manager_status = action === "approve" ? "approved" : "rejected";
    booking.status = action === "approve" ? "approved" : "rejected";
    booking.manager_decided_at = new Date();
    await booking.save();

    if (process.env.N8N_MEETING_APPROVAL_WEBHOOK) {
      try {
        await axios.get(process.env.N8N_MEETING_APPROVAL_WEBHOOK, {
          params: {
            booking_id: booking.booking_id,
            action,
          },
          timeout: 15000,
        });
      } catch (n8nErr) {
        console.error("Meeting approval n8n webhook error:", n8nErr.message);
      }
    }

    res.json({
      message: action === "approve" ? "Booking approved" : "Booking rejected",
      status: booking.status,
      booking_id: booking.booking_id,
    });
  } catch (error) {
    console.error("Meeting room approve error:", error);
    res.status(500).json({ message: "Approval failed" });
  }
});

app.get("/api/meeting-room/approve-link", async (req, res) => {
  try {
    const bookingId = req.query.booking_id;
    const action = req.query.action;

    if (!bookingId || !["approve", "reject"].includes(action)) {
      return res.status(400).send("Invalid approval link");
    }

    const booking = await Booking.findOne({ booking_id: bookingId });
    if (!booking) {
      return res.status(404).send("Booking not found");
    }

    if (["approved", "rejected", "expired", "cancelled"].includes(booking.status)) {
      return res
        .status(200)
        .send(`Booking ${booking.booking_id} was already processed with status: ${booking.status}`);
    }

    booking.manager_status = action === "approve" ? "approved" : "rejected";
    booking.status = action === "approve" ? "approved" : "rejected";
    booking.manager_decided_at = new Date();
    await booking.save();

    if (process.env.N8N_MEETING_APPROVAL_WEBHOOK) {
      try {
        await axios.get(process.env.N8N_MEETING_APPROVAL_WEBHOOK, {
          params: {
            booking_id: booking.booking_id,
            action,
          },
          timeout: 15000,
        });
      } catch (n8nErr) {
        console.error("Meeting approval n8n webhook error:", n8nErr.message);
      }
    }

    const text = action === "approve" ? "APPROVED" : "REJECTED";
    const color = action === "approve" ? "#16a34a" : "#dc2626";
    const redirectUrl = process.env.FRONTEND_URL 
      ? `${process.env.FRONTEND_URL}/booking-dashboard.html?approved=1`
      : null;
    return res.status(200).send(`
      <html>
        <head><title>Meeting Approval</title></head>
        <body style="font-family:Arial,sans-serif;padding:24px;text-align:center">
          <h2 style="color:${color}">Booking ${booking.booking_id} ${text}</h2>
          <p>Room: <b>${booking.room_name}</b></p>
          <p>Date: <b>${booking.meeting_date}</b></p>
          <p>Time: <b>${booking.start_time} - ${booking.end_time}</b></p>
          <p style="margin-top:20px;color:#666;">Page will redirect in 2 seconds...</p>
          <script>
            sessionStorage.setItem("justApproved", "1");
            setTimeout(() => {
              ${redirectUrl ? `window.location.href = "${redirectUrl}";` : `window.close();`}
            }, 2000);
          </script>
        </body>
      </html>
    `);
  } catch (error) {
    console.error("Approve link error:", error);
    return res.status(500).send("Approval failed");
  }
});

// Endpoint để n8n sync trạng thái về Mongo (optional nhưng hữu ích khi manager duyệt trực tiếp qua email)
app.post("/api/meeting-room/sync-status", async (req, res) => {
  try {
    const { booking_id, status, manager_note } = req.body;
    if (!booking_id || !status) {
      return res.status(400).json({ message: "booking_id and status are required" });
    }
    if (!["pending", "pending_urgent", "approved", "rejected", "cancelled", "expired"].includes(status)) {
      return res.status(400).json({ message: "Invalid status value" });
    }

    const update = {
      status,
      manager_status: status === "approved" ? "approved" : status === "rejected" ? "rejected" : "pending",
    };
    if (status === "approved" || status === "rejected") {
      update.manager_decided_at = new Date();
    }
    if (manager_note) {
      update.notes = manager_note;
    }

    const booking = await Booking.findOneAndUpdate({ booking_id }, update, { new: true });
    if (!booking) return res.status(404).json({ message: "Booking not found" });

    res.json({ message: "Booking synced", booking_id: booking.booking_id, status: booking.status });
  } catch (error) {
    console.error("Sync meeting room status error:", error);
    res.status(500).json({ message: "Sync failed" });
  }
});

// ═══════════════════════════════════════════
// CANCEL BOOKING
// ═══════════════════════════════════════════
app.post("/api/meeting-room/cancel", verifyToken, async (req, res) => {
  try {
    const { booking_id, reason } = req.body;
    const user = req.user;

    if (!booking_id) {
      return res.status(400).json({ message: "booking_id is required" });
    }

    // Tìm booking trong MongoDB
    let booking = await Booking.findOne({ booking_id });
    
    // Nếu không có trong MongoDB, gọi trực tiếp n8n webhook để cancel (n8n sẽ tìm trong Sheets)
    if (!booking) {
      console.log(`Booking ${booking_id} not in MongoDB, calling n8n cancel webhook...`);
      
      // Trigger n8n webhook để cancel trong Sheets
      if (process.env.N8N_CANCEL_BOOKING_WEBHOOK) {
        try {
          await axios.post(process.env.N8N_CANCEL_BOOKING_WEBHOOK, {
            booking_id,
            requester_email: user.email,
            reason: reason || "Không có lý do",
          });
          
          return res.json({ 
            message: "Đã gửi yêu cầu hủy booking", 
            booking_id,
            status: "cancelled" 
          });
        } catch (n8nErr) {
          console.error("N8N cancel webhook error:", n8nErr.message);
          return res.status(500).json({ message: "Lỗi gọi n8n webhook: " + n8nErr.message });
        }
      }
      
      return res.status(404).json({ message: "Booking not found in database" });
    }

    // Kiểm tra quyền: chỉ người tạo, HR hoặc Manager mới được hủy
    const requesterEmail = (booking.requester_email || "").toLowerCase();
    const userEmail = (user.email || "").toLowerCase();
    
    if (requesterEmail !== userEmail && user.role !== "hr" && user.role !== "manager") {
      return res.status(403).json({ message: "Bạn không có quyền hủy booking này" });
    }

    // Kiểm tra trạng thái có cho phép cancel
    if (["cancelled", "rejected", "expired"].includes(booking.status)) {
      return res.status(400).json({ message: "Booking đã được xử lý trước đó" });
    }

    // Cập nhật trạng thái
    booking.status = "cancelled";
    booking.cancel_reason = reason || "";
    booking.cancelled_at = new Date();
    await booking.save();

    // Gọi n8n webhook để sync với Sheets
    if (process.env.N8N_CANCEL_BOOKING_WEBHOOK) {
      try {
        await axios.post(process.env.N8N_CANCEL_BOOKING_WEBHOOK, {
          booking_id,
          requester_email: booking.requester_email,
          reason: reason || "Không có lý do",
        });
      } catch (n8nErr) {
        console.error("Cancel n8n webhook error:", n8nErr.message);
      }
    }

    res.json({ 
      message: "Booking đã được hủy thành công", 
      booking_id: booking.booking_id,
      status: "cancelled" 
    });
  } catch (error) {
    console.error("Cancel booking error:", error);
    res.status(500).json({ message: "Error cancelling booking" });
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
