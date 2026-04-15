// routes/meetingRoom.js
// ─── Meeting Room Booking Route ───
// Tích hợp với n8n Workflow ApproveHub Meeting Room

const express = require("express");
const router = express.Router();
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { Booking, Room } = require("../models");

// Auth middleware (inline, không cần file riêng)
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "No token provided" });
  }
  const token = authHeader.split(" ")[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    // Đảm bảo req.user._id tương thích với cả userId và _id
    if (req.user.userId && !req.user._id) {
      req.user._id = req.user.userId;
    }
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
};

const N8N_WEBHOOK_URL =
  process.env.N8N_WEBHOOK_URL ||
  "https://n8n.internalautomation.io.vn/webhook/nhan-yeu-cau-dat-phong";

const N8N_CANCEL_URL =
  process.env.N8N_CANCEL_URL ||
  "https://n8n.internalautomation.io.vn/webhook/huy-dat-phong";

const FRONTEND_URL =
  process.env.FRONTEND_URL || "https://approvehub.internalautomation.io.vn";

// ─── Helper: generate booking_id ───
function genBookingId() {
  return "MTG-" + Date.now();
}

// ─── Helper: generate approval token ───
function genToken() {
  return crypto.randomBytes(32).toString("hex");
}

// ─── Helper: tính duration_minutes ───
function calcDuration(start, end) {
  const [sh, sm] = start.split(":").map(Number);
  const [eh, em] = end.split(":").map(Number);
  return (eh * 60 + em) - (sh * 60 + sm);
}

// ─────────────────────────────────────────────────
// POST /api/meeting-room/book
// Tạo booking mới → gửi webhook n8n
// ─────────────────────────────────────────────────
router.post("/book", authMiddleware, async (req, res) => {
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
      priority = "normal",
      equipment_needed = [],
    } = req.body;

    const user = req.user;

    // ── Validate required fields ──
    if (!room_id || !meeting_date || !start_time || !end_time || !purpose) {
      return res.status(400).json({ message: "Thiếu thông tin bắt buộc." });
    }

    // ── Tìm phòng ──
    const room = await Room.findById(room_id);
    if (!room) {
      return res.status(404).json({ message: "Phòng không tồn tại." });
    }

    // ── Kiểm tra sức chứa ──
    const numAttendees = parseInt(attendees) || 1;
    if (numAttendees > room.capacity) {
      return res.status(422).json({
        message: `Số người (${numAttendees}) vượt sức chứa phòng (${room.capacity}).`,
      });
    }

    // ── Kiểm tra thời gian hợp lệ ──
    const duration = calcDuration(start_time, end_time);
    if (duration <= 0) {
      return res.status(400).json({ message: "Giờ kết thúc phải sau giờ bắt đầu." });
    }
    if (duration > 480) {
      return res.status(400).json({ message: "Thời gian họp không được quá 8 giờ." });
    }

    // ── Kiểm tra xung đột lịch ──
    const conflictBooking = await Booking.findOne({
      room_id,
      meeting_date,
      status: { $in: ["pending", "approved"] },
      $or: [
        { start_time: { $lt: end_time }, end_time: { $gt: start_time } },
      ],
    });

    if (conflictBooking) {
      return res.status(409).json({
        message: `Phòng đã được đặt từ ${conflictBooking.start_time} - ${conflictBooking.end_time}. Vui lòng chọn khung giờ khác.`,
        conflict: {
          booking_id: conflictBooking.booking_id,
          start_time: conflictBooking.start_time,
          end_time: conflictBooking.end_time,
        },
      });
    }

    // ── Lấy manager email từ settings hoặc env ──
    const managerEmail =
      process.env.MANAGER_EMAIL || "quanganh.hs2005@gmail.com";

    // ── Tạo token phê duyệt ──
    const approvalToken = genToken();
    const bookingId = genBookingId();

    // ── Tạo approval link trỏ về frontend ──
    const approvalLink = `${FRONTEND_URL}/meeting-approvals.html?token=${approvalToken}`;

    // ── Lưu vào MongoDB ──
    const booking = await Booking.create({
      booking_id: bookingId,
      requester_id: user._id,
      requester_name: user.name,
      requester_email: user.email,
      department: user.department || "N/A",
      room_id: room._id,
      room_name: room.name,
      meeting_date,
      start_time,
      end_time,
      duration_minutes: duration,
      purpose,
      attendees: numAttendees,
      notes: notes || "",
      status: "pending",
      managerApprovalToken: approvalToken,
      manager_email: managerEmail,
      approval_link: approvalLink,
    });

    // ── Gửi webhook n8n (không block response) ──
    const n8nPayload = {
      bookingId: bookingId,
      requesterName: user.name,
      requesterEmail: user.email,
      department: user.department || "N/A",
      roomName: room.name,
      roomCapacity: room.capacity,
      meetingDate: meeting_date,
      startTime: start_time,
      endTime: end_time,
      purpose,
      attendees: numAttendees,
      priority,
      equipmentNeeded: Array.isArray(equipment_needed)
        ? equipment_needed
        : [equipment_needed].filter(Boolean),
      notes: notes || "",
      managerEmail: managerEmail,
      // Link phê duyệt trỏ về frontend ApproveHub (không phải n8n)
      approvalLink: approvalLink,
      rejectLink: `${FRONTEND_URL}/meeting-approvals.html?token=${approvalToken}&action=reject`,
    };

    // Fire-and-forget webhook
    fetch(N8N_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(n8nPayload),
    }).catch((err) => console.error("[n8n webhook error]", err.message));

    return res.status(201).json({
      message: "Đặt phòng thành công! Đang chờ quản lý phê duyệt.",
      booking_id: bookingId,
      status: "pending",
    });
  } catch (err) {
    console.error("[booking error]", err);
    return res.status(500).json({ message: "Lỗi server." });
  }
});

// ─────────────────────────────────────────────────
// POST /api/meeting-room/approve
// Manager phê duyệt/từ chối qua token (từ email link)
// ─────────────────────────────────────────────────
router.post("/approve", async (req, res) => {
  try {
    const { token, action } = req.body;

    if (!token || !["approve", "reject"].includes(action)) {
      return res.status(400).json({ message: "Token hoặc action không hợp lệ." });
    }

    const booking = await Booking.findOne({ managerApprovalToken: token });
    if (!booking) {
      return res.status(404).json({ message: "Booking không tồn tại." });
    }

    if (["approved", "rejected", "cancelled"].includes(booking.status)) {
      return res.status(409).json({
        message: `Booking này đã được xử lý (${booking.status}).`,
        status: booking.status,
      });
    }

    // ── Cập nhật status ──
    const newStatus = action === "approve" ? "approved" : "rejected";
    booking.status = newStatus;
    booking.manager_status = newStatus;
    booking.manager_decided_at = new Date();
    await booking.save();

    // ── Thông báo kết quả qua n8n (hoặc có thể gửi email trực tiếp) ──
    // n8n sẽ gửi email notify cho user
    const n8nApprovalPayload = {
      booking_id: booking.booking_id,
      action,
      requester_name: booking.requester_name,
      requester_email: booking.requester_email,
      room_name: booking.room_name,
      meeting_date: booking.meeting_date,
      start_time: booking.start_time,
      end_time: booking.end_time,
      attendees: booking.attendees,
      purpose: booking.purpose,
      status: newStatus,
    };

    fetch(
      `https://n8n.internalautomation.io.vn/webhook/mr-approval?booking_id=${booking.booking_id}&action=${action}`,
      { method: "GET" }
    ).catch((err) => console.error("[n8n approval webhook error]", err.message));

    return res.json({
      message:
        action === "approve"
          ? "Đã phê duyệt. Email thông báo đã gửi đến nhân viên."
          : "Đã từ chối. Email thông báo đã gửi đến nhân viên.",
      status: newStatus,
    });
  } catch (err) {
    console.error("[approve error]", err);
    return res.status(500).json({ message: "Lỗi server." });
  }
});

// ─────────────────────────────────────────────────
// GET /api/meeting-room/token/:token
// Lấy thông tin booking theo approval token (để hiển thị trên trang approval)
// ─────────────────────────────────────────────────
router.get("/token/:token", async (req, res) => {
  try {
    const booking = await Booking.findOne({
      managerApprovalToken: req.params.token,
    }).lean();

    if (!booking) {
      return res.status(404).json({ message: "Booking không tồn tại." });
    }

    return res.json(booking);
  } catch (err) {
    return res.status(500).json({ message: "Lỗi server." });
  }
});

// ─────────────────────────────────────────────────
// GET /api/meeting-room
// Lấy danh sách booking
// - Employee: chỉ lấy của mình
// - Manager/HR: lấy tất cả
// ─────────────────────────────────────────────────
router.get("/", authMiddleware, async (req, res) => {
  try {
    const user = req.user;
    const filter =
      user.role === "employee"
        ? { requester_id: user._id }
        : {};

    const bookings = await Booking.find(filter)
      .sort({ createdAt: -1 })
      .lean();

    return res.json(bookings);
  } catch (err) {
    return res.status(500).json({ message: "Lỗi server." });
  }
});

// ─────────────────────────────────────────────────
// GET /api/meeting-room/:id
// Lấy chi tiết 1 booking
// ─────────────────────────────────────────────────
router.get("/:id", authMiddleware, async (req, res) => {
  try {
    const booking = await Booking.findById(req.params.id).lean();
    if (!booking) return res.status(404).json({ message: "Không tìm thấy." });
    return res.json(booking);
  } catch (err) {
    return res.status(500).json({ message: "Lỗi server." });
  }
});

// ─────────────────────────────────────────────────
// POST /api/meeting-room/:id/cancel
// Người đặt tự hủy booking
// ─────────────────────────────────────────────────
router.post("/:id/cancel", authMiddleware, async (req, res) => {
  try {
    const user = req.user;
    const { reason } = req.body;

    const booking = await Booking.findById(req.params.id);
    if (!booking) return res.status(404).json({ message: "Không tìm thấy." });

    // Chỉ người đặt hoặc manager mới hủy được
    const isOwner = booking.requester_id.toString() === user._id.toString();
    const isManager = user.role === "manager";

    if (!isOwner && !isManager) {
      return res.status(403).json({ message: "Không có quyền hủy booking này." });
    }

    if (["cancelled", "rejected"].includes(booking.status)) {
      return res.status(409).json({ message: "Booking đã được hủy/từ chối rồi." });
    }

    booking.status = "cancelled";
    await booking.save();

    // Thông báo n8n để gửi email
    fetch(N8N_CANCEL_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        booking_id: booking.booking_id,
        requester_email: booking.requester_email,
        requester_name: booking.requester_name,
        room_name: booking.room_name,
        meeting_date: booking.meeting_date,
        start_time: booking.start_time,
        end_time: booking.end_time,
        reason: reason || "Không có lý do",
        manager_email: booking.manager_email,
      }),
    }).catch((err) => console.error("[n8n cancel error]", err.message));

    return res.json({ message: "Đã hủy booking thành công." });
  } catch (err) {
    return res.status(500).json({ message: "Lỗi server." });
  }
});

module.exports = router;