require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const axios = require("axios");
const User = require("./models/User");
const LeaveRequest = require("./models/LeaveRequest");

const app = express();
const PORT = process.env.PORT || 3001;

// ═══════════════════════════════════════════
// CONFIG: Database + Email
// ═══════════════════════════════════════════

// MongoDB
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("✅ MongoDB Atlas connected");
  } catch (error) {
    console.error("❌ MongoDB error:", error.message);
    process.exit(1);
  }
};

// Email Transporter
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: process.env.SMTP_SECURE === "true",
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});

const sendEmail = async ({ to, subject, html }) => {
  try {
    await transporter.sendMail({
      from: `"Approval System" <${process.env.SMTP_USER}>`,
      to, subject, html,
    });
    console.log(`✅ Email sent to ${to}`);
  } catch (error) {
    console.error(`❌ Email error:`, error.message);
  }
};

const sendToManager = async ({ employeeName, leaveDate, leaveDays, managerEmail, approvalLink }) => {
  await sendEmail({
    to: managerEmail,
    subject: `📋 New Leave Request from ${employeeName}`,
    html: `<h2>New Leave Request</h2><p><strong>Employee:</strong> ${employeeName}</p><p><strong>Date:</strong> ${leaveDate}</p><p><strong>Days:</strong> ${leaveDays}</p><a href="${approvalLink}" style="background:#2563eb;color:white;padding:12px 24px;text-decoration:none;border-radius:8px;display:inline-block;">Review & Approve</a>`,
  });
};

const sendToHR = async ({ employeeName, leaveDate, leaveDays, hrEmail, approvalLink }) => {
  await sendEmail({
    to: hrEmail,
    subject: `📋 Approved by Manager - ${employeeName}`,
    html: `<h2>Manager Approved</h2><p><strong>Employee:</strong> ${employeeName}</p><p><strong>Date:</strong> ${leaveDate}</p><p><strong>Days:</strong> ${leaveDays} (HR approval needed)</p><a href="${approvalLink}" style="background:#059669;color:white;padding:12px 24px;text-decoration:none;border-radius:8px;display:inline-block;">HR Final Approve</a>`,
  });
};

const sendResultToEmployee = async ({ employeeEmail, status, employeeName }) => {
  const color = status === "approved" ? "#059669" : "#dc2626";
  const msg = status === "approved" ? "has been approved" : "has been rejected";
  await sendEmail({
    to: employeeEmail,
    subject: `Leave Request ${status === "approved" ? "Approved" : "Rejected"} - ${employeeName}`,
    html: `<h2>Leave Request Update</h2><p>Your leave request ${msg}.</p><p><strong>Status:</strong> <span style="color:${color};font-weight:bold;">${status.toUpperCase()}</span></p>`,
  });
};

// ═══════════════════════════════════════════
// N8N WEBHOOK CALLER
// ═══════════════════════════════════════════

// Gọi N8n webhook khi có sự kiện (tuỳ chọn - nếu có webhook URL)
const triggerN8n = async (webhookUrl, payload) => {
  if (!webhookUrl || webhookUrl.includes("yourdomain.com")) {
    console.log("⏭️ N8n webhook not configured, skipping...");
    return;
  }
  try {
    await axios.post(webhookUrl, payload, { timeout: 10000 });
    console.log(`✅ N8n webhook triggered: ${webhookUrl}`);
  } catch (error) {
    console.error(`⚠️ N8n webhook error:`, error.message);
  }
};

// ═══════════════════════════════════════════
// MIDDLEWARE: Auth
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

const requireRole = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({ message: "Access denied" });
  }
  next();
};

// Helper
const generateToken = () => crypto.randomBytes(32).toString("hex");
const buildLink = (token) => `${process.env.FRONTEND_URL}/approvals.html?token=${token}`;

// ═══════════════════════════════════════════
// ROUTES: Auth
// ═══════════════════════════════════════════

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password, department, role } = req.body;
    if (await User.findOne({ email })) {
      return res.status(400).json({ message: "Email already registered" });
    }
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashed, department, role: role || "employee" });
    await user.save();
    res.status(201).json({ message: "Registered", user: { id: user._id, name, email, department, role: user.role } });
  } catch (error) {
    res.status(500).json({ message: "Registration failed", error: error.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ message: "Invalid credentials" });
    }
    const token = jwt.sign({ userId: user._id, email: user.email, name: user.name, role: user.role, department: user.department }, process.env.JWT_SECRET, { expiresIn: "24h" });
    res.json({ message: "Login successful", token, user: { id: user._id, name: user.name, email, department: user.department, role: user.role } });
  } catch (error) {
    res.status(500).json({ message: "Login failed", error: error.message });
  }
});

app.get("/api/auth/me", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-password");
    res.json(user || {});
  } catch (error) {
    res.status(500).json({ message: "Error", error: error.message });
  }
});

// ═══════════════════════════════════════════
// ROUTES: Leave Request
// ═══════════════════════════════════════════

app.post("/api/leave", verifyToken, async (req, res) => {
  try {
    const { leave_date, leave_days, reason } = req.body;
    const user = await User.findById(req.user.userId);
    const managerApprovalToken = generateToken();
    const hrApprovalToken = leave_days > 3 ? generateToken() : null;

    const leave = new LeaveRequest({
      employeeId: user._id, employee_name: user.name, employee_email: user.email,
      department: user.department, leave_date, leave_days: Number(leave_days), reason,
      managerApprovalToken, hrApprovalToken,
      manager_status: "pending",
      hr_status: leave_days > 3 ? "pending" : "skipped",
      status: "pending",
    });
    await leave.save();

    // Gửi email cho Manager
    const manager = await User.findOne({ department: user.department, role: "manager" });
    const managerEmail = manager ? manager.email : process.env.Manager_EMAIL;
    await sendToManager({ employeeName: user.name, leaveDate: leave_date, leaveDays: leave_days, managerEmail, approvalLink: buildLink(managerApprovalToken) });

    // Trigger N8n Workflow (Slack/Calendar/Telegram)
    await triggerN8n(process.env.N8N_LEAVE_WEBHOOK, {
      event: "leave_request_created",
      employeeName: user.name,
      employeeEmail: user.email,
      department: user.department,
      leaveDate: leave_date,
      leaveDays: leave_days,
      reason,
    });

    res.status(201).json({ message: "Leave request submitted", leave });
  } catch (error) {
    res.status(500).json({ message: "Failed", error: error.message });
  }
});

app.get("/api/leave", verifyToken, async (req, res) => {
  try {
    let query = {};
    if (req.user.role === "employee") query = { employeeId: req.user.userId };
    else if (req.user.role === "manager") query = { department: req.user.department };
    const requests = await LeaveRequest.find(query).sort({ createdAt: -1 });
    res.json(requests);
  } catch (error) {
    res.status(500).json({ message: "Error", error: error.message });
  }
});

app.get("/api/leave/:id", verifyToken, async (req, res) => {
  try {
    const request = await LeaveRequest.findById(req.params.id);
    res.json(request || {});
  } catch (error) {
    res.status(500).json({ message: "Error", error: error.message });
  }
});

// ═══════════════════════════════════════════
// ROUTES: Approval
// ═══════════════════════════════════════════

app.post("/api/approval/manager", async (req, res) => {
  try {
    const { token, action } = req.body;
    if (!["approve", "reject"].includes(action)) {
      return res.status(400).json({ message: "Invalid action" });
    }

    const request = await LeaveRequest.findOne({ managerApprovalToken: token });
    if (!request) return res.status(404).json({ message: "Invalid token" });
    if (request.manager_status !== "pending") return res.status(400).json({ message: "Already processed" });

    if (action === "reject") {
      request.manager_status = "rejected";
      request.manager_decidedAt = new Date();
      request.status = "rejected";
      await request.save();
      await sendResultToEmployee({ employeeEmail: request.employee_email, status: "rejected", employeeName: request.employee_name });
      await triggerN8n(process.env.N8N_APPROVAL_WEBHOOK, { event: "manager_rejected", ...request.toObject() });
      return res.json({ message: "Rejected by manager", status: "rejected" });
    }

    // ✅ Manager approve
    request.manager_status = "approved";
    request.manager_decidedAt = new Date();

    if (request.leave_days > 3) {
      await sendToHR({ employeeName: request.employee_name, leaveDate: request.leave_date, leaveDays: request.leave_days, hrEmail: process.env.HR_EMAIL, approvalLink: buildLink(request.hrApprovalToken) });
      await triggerN8n(process.env.N8N_APPROVAL_WEBHOOK, { event: "manager_approved", ...request.toObject() });
      await request.save();
      return res.json({ message: "Sent to HR for final approval", status: "pending" });
    }

    request.status = "approved";
    await request.save();
    await sendResultToEmployee({ employeeEmail: request.employee_email, status: "approved", employeeName: request.employee_name });
    await triggerN8n(process.env.N8N_APPROVAL_WEBHOOK, { event: "leave_approved", ...request.toObject() });
    res.json({ message: "Fully approved", status: "approved" });
  } catch (error) {
    res.status(500).json({ message: "Error", error: error.message });
  }
});

app.post("/api/approval/hr", async (req, res) => {
  try {
    const { token, action } = req.body;
    if (!["approve", "reject"].includes(action)) {
      return res.status(400).json({ message: "Invalid action" });
    }

    const request = await LeaveRequest.findOne({ hrApprovalToken: token });
    if (!request) return res.status(404).json({ message: "Invalid token" });
    if (request.hr_status !== "pending") return res.status(400).json({ message: "Already processed" });
    if (request.manager_status !== "approved") return res.status(400).json({ message: "Not approved by manager" });

    request.hr_status = action === "approve" ? "approved" : "rejected";
    request.hr_decidedAt = new Date();
    request.status = request.hr_status;
    await request.save();
    await sendResultToEmployee({ employeeEmail: request.employee_email, status: request.status, employeeName: request.employee_name });
    await triggerN8n(process.env.N8N_APPROVAL_WEBHOOK, { event: "hr_decided", action: request.hr_status, ...request.toObject() });
    res.json({ message: `HR ${request.status}`, status: request.status });
  } catch (error) {
    res.status(500).json({ message: "Error", error: error.message });
  }
});

app.get("/api/approval/token/:token", async (req, res) => {
  try {
    let request = await LeaveRequest.findOne({ managerApprovalToken: req.params.token });
    let approvalType = "manager";
    if (!request) { request = await LeaveRequest.findOne({ hrApprovalToken: req.params.token }); approvalType = "hr"; }
    if (!request) return res.status(404).json({ message: "Invalid token" });
    res.json({
      employee_name: request.employee_name, employee_email: request.employee_email,
      department: request.department, leave_date: request.leave_date, leave_days: request.leave_days,
      reason: request.reason, status: approvalType === "manager" ? request.manager_status : request.hr_status,
      approvalType,
    });
  } catch (error) {
    res.status(500).json({ message: "Error", error: error.message });
  }
});

// ═══════════════════════════════════════════
// START
// ═══════════════════════════════════════════

app.use(cors({ origin: process.env.FRONTEND_URL || "http://localhost:3000", credentials: true }));
app.use(express.json());

app.get("/api/health", (req, res) => {
  res.json({ status: "OK", message: "Backend running" });
});

connectDB().then(() => {
  app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
});
