const express = require("express");
const mongoose = require("mongoose");
const LeaveRequest = require("../models/LeaveRequest");
const Booking = require("../models/Booking");
const Room = require("../models/Room");
const User = require("../models/User");
const { verifyN8nSecret } = require("../middleware/auth");
const { generateApprovalToken } = require("../middleware/n8n");
const { getEmailFromSettings } = require("../helpers/settings");
const { triggerN8NWorkflow } = require("../helpers/n8n");

const router = express.Router();

// All internal routes require N8N secret
router.use(verifyN8nSecret);

// ───────────────────────────────────────────
// LEAVE - Internal endpoints for N8N
// ───────────────────────────────────────────

// POST /api/internal/leave/notify - Backend triggers N8N to send notification emails
// Backend already created the leave; this tells N8N to email manager + employee
router.post("/leave/notify", async (req, res) => {
  try {
    const {
      leaveId, employeeName, employeeEmail, department,
      leave_date, leave_days, reason,
      managerEmail, hrEmail,
      managerApprovalToken, hrApprovalToken
    } = req.body;

    // Forward to N8N WF1 so it sends emails
    const startDate = new Date(leave_date + 'T12:00:00');
    const endDate = new Date(startDate);
    endDate.setDate(endDate.getDate() + parseInt(leave_days) - 1);
    const endDateStr = endDate.toISOString().split('T')[0];
    await triggerN8NWorkflow("webhook/leave-create", {
      leaveId,
      employee_name: employeeName,
      employee_email: employeeEmail,
      department,
      leave_date,
      end_date: endDateStr,
      leave_days,
      reason,
      managerEmail,
      hrEmail,
      managerApprovalToken,
      hrApprovalToken,
    });

    res.json({ success: true, message: "Notification workflow triggered" });
  } catch (error) {
    console.error("Internal notify error:", error.message);
    res.status(500).json({ message: "Failed to trigger notification" });
  }
});

// POST /api/internal/leave/create - N8N creates leave request
router.post("/leave/create", async (req, res) => {
  try {
    const {
      employeeId, employeeName, employeeEmail, department,
      leave_date, leave_days, reason, managerEmail, hrEmail,
      isAutoApproved, aiDecision, aiReason
    } = req.body;

    if (!leave_date || !leave_days || !reason || !employeeName || !employeeEmail) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    const tokenExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    const needsHr = parseInt(leave_days) > 3;

    const startDate = new Date(leave_date + 'T12:00:00');
    const endDate = new Date(startDate);
    endDate.setDate(endDate.getDate() + parseInt(leave_days) - 1);
    const endDateStr = endDate.toISOString().split('T')[0];

    let status = "pending";
    let manager_status = "pending";
    let hr_status = needsHr ? "pending" : "skipped";
    let autoApproved = false;
    let aiDecisionField = null;
    let aiReasonField = null;
    let approvedBy = null;

    if (isAutoApproved) {
      status = aiDecision === "approve" ? "approved" : "rejected";
      manager_status = aiDecision === "approve" ? "approved" : "rejected";
      hr_status = aiDecision === "approve" ? "approved" : "rejected";
      autoApproved = true;
      aiDecisionField = aiDecision;
      aiReasonField = aiReason;
      approvedBy = "AI_GEMINI_AUTO";
    }

    const managerApprovalToken = generateApprovalToken(managerEmail || "pending", "manager");
    const hrApprovalToken = needsHr ? generateApprovalToken(hrEmail || "pending", "hr") : null;

    const leave = new LeaveRequest({
      employeeId: employeeId ? new mongoose.Types.ObjectId(employeeId) : null,
      employee_name: employeeName,
      employee_email: employeeEmail,
      department: department || "Unknown",
      leave_date,
      end_date: endDateStr,
      leave_days: parseInt(leave_days),
      reason,
      managerApprovalToken,
      hrApprovalToken,
      managerTokenExpiresAt: tokenExpiresAt,
      hrTokenExpiresAt: needsHr ? tokenExpiresAt : null,
      manager_status,
      hr_status,
      status,
      manager_email: managerEmail || null,
      hr_email: needsHr ? (hrEmail || null) : null,
      managerApproverEmail: managerEmail || null,
      hrApproverEmail: needsHr ? (hrEmail || null) : null,
      autoApproved,
      aiDecision: aiDecisionField,
      aiReason: aiReasonField,
      approvedBy,
    });

    await leave.save();

    res.status(201).json({
      success: true,
      leaveId: leave._id.toString(),
      status: leave.status,
      managerApprovalToken,
      hrApprovalToken,
      managerEmail,
      hrEmail,
      requiresHrApproval: needsHr,
    });
  } catch (error) {
    console.error("Internal leave create error:", error.message);
    res.status(500).json({ message: "Failed to create leave", detail: error.message });
  }
});

// POST /api/internal/leave/update-status - N8N updates leave status
router.post("/leave/update-status", async (req, res) => {
  try {
    const { leaveId, field, value, decidedByEmail } = req.body;

    if (!leaveId || !field) {
      return res.status(400).json({ message: "leaveId and field are required" });
    }

    const updateData = {};
    updateData[field] = value;
    if (field === "manager_status" && decidedByEmail) {
      updateData.managerApproverEmail = decidedByEmail;
      updateData.manager_decidedAt = new Date();
    }
    if (field === "hr_status" && decidedByEmail) {
      updateData.hrApproverEmail = decidedByEmail;
      updateData.hr_decidedAt = new Date();
    }
    if (field === "status" && value === "approved") {
      updateData.approvedAt = new Date();
    }

    const leave = await LeaveRequest.findOneAndUpdate(
      { _id: leaveId },
      { $set: updateData },
      { new: true }
    );

    if (!leave) {
      return res.status(404).json({ message: "Leave request not found" });
    }

    res.json({ success: true, leaveId: leave._id.toString(), status: leave.status });
  } catch (error) {
    console.error("Internal leave update error:", error.message);
    res.status(500).json({ message: "Error updating leave", detail: error.message });
  }
});

// POST /api/internal/leave/generate-tokens - N8N generates approval tokens
router.post("/leave/generate-tokens", async (req, res) => {
  try {
    const { managerEmail, hrEmail, leave_days } = req.body;

    const tokenExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    const needsHr = parseInt(leave_days) > 3;

    const managerApprovalToken = generateApprovalToken(managerEmail || "pending", "manager");
    const hrApprovalToken = needsHr ? generateApprovalToken(hrEmail || "pending", "hr") : null;

    res.json({
      managerApprovalToken,
      hrApprovalToken,
      tokenExpiresAt,
      requiresHrApproval: needsHr,
    });
  } catch (error) {
    console.error("Generate tokens error:", error.message);
    res.status(500).json({ message: "Error generating tokens" });
  }
});

// GET /api/internal/leave/lookup-emails - N8N looks up manager/HR emails
router.get("/leave/lookup-emails", async (req, res) => {
  try {
    const { department } = req.query;
    if (!department) {
      return res.status(400).json({ message: "department query param required" });
    }

    const managerEmail = await getEmailFromSettings(department, "manager");
    const hrEmail = await getEmailFromSettings(null, "hr");

    res.json({ managerEmail, hrEmail, department });
  } catch (error) {
    res.status(404).json({ message: error.message });
  }
});

// GET /api/internal/leave/by-id/:id - Get leave by ID (for N8N)
router.get("/leave/by-id/:id", async (req, res) => {
  try {
    const leave = await LeaveRequest.findById(req.params.id);
    if (!leave) return res.status(404).json({ message: "Not found" });
    res.json(leave);
  } catch (error) {
    res.status(500).json({ message: "Error" });
  }
});

// ───────────────────────────────────────────
// BOOKING - Internal endpoints for N8N
// ───────────────────────────────────────────

// POST /api/internal/booking/create - N8N creates booking
router.post("/booking/create", async (req, res) => {
  try {
    const {
      requester_id, requester_name, requester_email, department,
      room_id, room_name, meeting_date, start_time, end_time,
      purpose, attendees, priority, equipment_needed, notes,
      managerEmail
    } = req.body;

    if (!requester_email || !room_id || !meeting_date || !start_time || !end_time || !purpose) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    const bookingId = `BK-${Date.now()}`;
    const managerApprovalToken = generateApprovalToken(managerEmail || "pending", "meeting_manager");
    const status = priority === "urgent" ? "pending_urgent" : "pending";

    const parseTimeToMinutes = (t) => {
      if (!t || !t.includes(":")) return 0;
      const [h, m] = t.split(":").map(Number);
      return (Number.isNaN(h) || Number.isNaN(m)) ? 0 : h * 60 + m;
    };
    const duration_minutes = parseTimeToMinutes(end_time) - parseTimeToMinutes(start_time);

    const booking = new Booking({
      booking_id: bookingId,
      requester_id: requester_id ? new mongoose.Types.ObjectId(requester_id) : null,
      requester_name: requester_name || "Unknown",
      requester_email,
      department: department || "Unknown",
      room_id: new mongoose.Types.ObjectId(room_id),
      room_name,
      meeting_date, start_time, end_time,
      duration_minutes,
      purpose,
      attendees: parseInt(attendees || 1),
      priority: priority || "normal",
      equipment_needed: Array.isArray(equipment_needed) ? equipment_needed : [],
      notes: notes || "",
      status,
      managerApprovalToken,
      manager_email: managerEmail || null,
      manager_status: "pending",
      approval_link: null,
    });

    await booking.save();

    res.status(201).json({
      success: true,
      booking_id: booking.booking_id,
      bookingId: booking.booking_id,
      status: booking.status,
      managerApprovalToken,
      managerEmail,
    });
  } catch (error) {
    console.error("Internal booking create error:", error.message);
    res.status(500).json({ message: "Failed to create booking", detail: error.message });
  }
});

// POST /api/internal/booking/update-status - N8N updates booking status
router.post("/booking/update-status", async (req, res) => {
  try {
    const { booking_id, status, manager_email, manager_note } = req.body;

    if (!booking_id || !status) {
      return res.status(400).json({ message: "booking_id and status are required" });
    }

    const update = { status };
    if (status === "approved" || status === "rejected") {
      update.manager_status = status === "approved" ? "approved" : "rejected";
      update.manager_decided_at = new Date();
    }
    if (manager_email) update.manager_email = manager_email;
    if (manager_note) update.notes = manager_note;

    const booking = await Booking.findOneAndUpdate({ booking_id }, { $set: update }, { new: true });
    if (!booking) return res.status(404).json({ message: "Booking not found" });

    res.json({ success: true, booking_id: booking.booking_id, status: booking.status });
  } catch (error) {
    console.error("Internal booking update error:", error.message);
    res.status(500).json({ message: "Error updating booking" });
  }
});

// GET /api/internal/booking/by-id/:id - Get booking by ID (for N8N)
router.get("/booking/by-id/:id", async (req, res) => {
  try {
    const booking = await Booking.findById(req.params.id);
    if (!booking) return res.status(404).json({ message: "Not found" });
    res.json(booking);
  } catch (error) {
    res.status(500).json({ message: "Error" });
  }
});

// ───────────────────────────────────────────
// ROOMS - For N8N to check availability
// ───────────────────────────────────────────

// GET /api/internal/rooms/available - Check room availability
router.get("/rooms/available", async (req, res) => {
  try {
    const { room_id, meeting_date, start_time, end_time } = req.query;

    if (!room_id || !meeting_date) {
      return res.status(400).json({ message: "room_id and meeting_date are required" });
    }

    const parseTimeToMinutes = (t) => {
      if (!t || !t.includes(":")) return null;
      const [h, m] = t.split(":").map(Number);
      return (Number.isNaN(h) || Number.isNaN(m)) ? null : h * 60 + m;
    };

    const startMins = parseTimeToMinutes(start_time);
    const endMins = parseTimeToMinutes(end_time);

    const query = {
      room_id: new mongoose.Types.ObjectId(room_id),
      meeting_date,
      status: { $in: ["pending", "pending_urgent", "approved"] },
    };

    if (startMins !== null && endMins !== null) {
      const conflicts = await Booking.find(query).select("start_time end_time");
      const hasConflict = conflicts.some((b) => {
        const exStart = parseTimeToMinutes(b.start_time);
        const exEnd = parseTimeToMinutes(b.end_time);
        if (exStart === null || exEnd === null) return false;
        return startMins < exEnd && endMins > exStart;
      });

      if (hasConflict) {
        return res.json({ available: false, message: "Room already booked in this timeslot" });
      }
    }

    res.json({ available: true, room_id, meeting_date });
  } catch (error) {
    console.error("Room availability error:", error.message);
    res.status(500).json({ message: "Error checking availability" });
  }
});

// GET /api/internal/rooms - List active rooms
router.get("/rooms", async (req, res) => {
  try {
    const rooms = await Room.find({ status: "active" }).sort({ floor: 1, name: 1 });
    res.json(rooms);
  } catch (error) {
    res.status(500).json({ message: "Error fetching rooms" });
  }
});

// ───────────────────────────────────────────
// USERS - For N8N to look up users
// ───────────────────────────────────────────

// GET /api/internal/users/by-email/:email - Look up user by email
router.get("/users/by-email/:email", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.params.email.toLowerCase() }).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: "Error" });
  }
});

// ───────────────────────────────────────────
// GMAIL — Access Token for N8N
// ───────────────────────────────────────────

// GET /api/internal/gmail/access-token?email=user@gmail.com
// N8N calls this to get a fresh Gmail access token for sending emails
router.get("/gmail/access-token", async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) {
      return res.status(400).json({ message: "email query param required" });
    }

    // Find user by their system email OR their connected Gmail email
    const user = await User.findOne({
      $or: [
        { email: email.toLowerCase() },
        { gmailEmail: email.toLowerCase() },
      ],
      gmailConnected: true,
      gmailRefreshToken: { $ne: null },
    });

    if (!user) {
      return res.status(404).json({
        message: `Không tìm thấy tài khoản Gmail đã kết nối cho email: ${email}`,
        connected: false,
      });
    }

    // Use refresh_token to get a fresh access_token
    const { google } = require("googleapis");
    const oauth2Client = new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET,
      process.env.GOOGLE_REDIRECT_URI
    );

    oauth2Client.setCredentials({
      refresh_token: user.gmailRefreshToken,
    });

    const { token: accessToken } = await oauth2Client.getAccessToken();

    if (!accessToken) {
      return res.status(500).json({
        message: "Không thể lấy access token từ Google. Nhân viên cần kết nối lại Gmail.",
        connected: false,
      });
    }

    res.json({
      accessToken,
      gmailEmail: user.gmailEmail,
      userEmail: user.email,
      userName: user.name,
    });
  } catch (error) {
    console.error("[Gmail] Access token error:", error.message);

    // Handle specific Google errors
    if (error.message?.includes("invalid_grant")) {
      return res.status(401).json({
        message: "Gmail token đã hết hạn. Nhân viên cần kết nối lại Gmail.",
        connected: false,
      });
    }

    res.status(500).json({ message: "Error getting Gmail access token" });
  }
});

module.exports = router;
