const express = require("express");
const axios = require("axios");
const Room = require("../models/Room");
const Booking = require("../models/Booking");
const User = require("../models/User");
const { verifyToken } = require("../middleware/auth");
const { generateApprovalToken } = require("../middleware/n8n");
const { triggerN8NWorkflow } = require("../helpers/n8n");

const router = express.Router();

// ───────────────────────────────────────────
// Data Layer: Rooms & Bookings
// N8N orchestrates the workflow. Backend only handles CRUD.
// ───────────────────────────────────────────

const parseTimeToMinutes = (timeString) => {
  if (!timeString || !timeString.includes(":")) return null;
  const [h, m] = timeString.split(":").map(Number);
  if (Number.isNaN(h) || Number.isNaN(m)) return null;
  return h * 60 + m;
};

// ───────────────────────────────────────────
// ROOMS
// ───────────────────────────────────────────

// GET /api/rooms or /api/meeting-room/rooms
router.get("/rooms", verifyToken, async (req, res) => {
  try {
    const rooms = await Room.find({ status: "active" }).sort({ floor: 1, name: 1 });
    res.json(rooms);
  } catch (error) {
    console.error("Get rooms error:", error);
    res.status(500).json({ message: "Error fetching rooms" });
  }
});

// GET /api/rooms/:id/slots or /api/meeting-room/rooms/:id/slots
router.get("/rooms/:id/slots", verifyToken, async (req, res) => {
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

// ───────────────────────────────────────────
// BOOKING (CRUD only — N8N handles email/workflow)
// ───────────────────────────────────────────

// POST /api/meeting-room/book - Tạo booking mới
router.post("/book", verifyToken, async (req, res) => {
  try {
    const {
      room_id, room_name, meeting_date, start_time, end_time,
      purpose, attendees, notes, priority, equipment_needed,
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

    // Check for slot conflicts
    const sameDayBookings = await Booking.find({
      room_id, meeting_date,
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

    // N8N will resolve manager email and send email
    // Backend just stores the booking data
    const bookingId = `BK-${Date.now()}`;
    const managerApprovalToken = generateApprovalToken(req.user.email, "meeting_manager");
    const status = priority === "urgent" ? "pending_urgent" : "pending";
    const safeRoomName = room_name || room.name;
    const duration_minutes = endMins - startMins;

    const booking = await Booking.create({
      booking_id: bookingId,
      requester_id: user._id,
      requester_name: user.name,
      requester_email: user.email,
      department: user.department,
      room_id, room_name: safeRoomName,
      meeting_date, start_time, end_time,
      duration_minutes, purpose,
      attendees: attendeesCount,
      priority: priority || "normal",
      equipment_needed: Array.isArray(equipment_needed) ? equipment_needed : [],
      notes: notes || "",
      status,
      managerApprovalToken,
      manager_email: null,  // N8N will update this
      manager_status: "pending",
      approval_link: null,   // N8N will generate this
    });

    // Trigger N8N workflow để gửi email duyệt
    const n8nPayload = {
      bookingId: booking.booking_id,
      requesterId: user._id.toString(),
      requesterName: user.name,
      requesterEmail: user.email,
      department: user.department,
      roomId: room._id.toString(),
      roomName: safeRoomName,
      roomCapacity: room.capacity,
      meetingDate: meeting_date,
      startTime: start_time,
      endTime: end_time,
      durationMinutes: duration_minutes,
      purpose,
      attendees: attendeesCount,
      priority: priority || "normal",
      equipmentNeeded: Array.isArray(equipment_needed) ? equipment_needed : [],
      notes: notes || "",
      managerApprovalToken,
      managerEmail: "",
    };
    triggerN8NWorkflow("webhook/nhan-yeu-cau-dat-phong", n8nPayload);

    res.status(201).json({
      success: true,
      message: "Booking submitted",
      booking_id: booking.booking_id,
      bookingId: booking.booking_id,
      status: booking.status,
      requester_name: booking.requester_name,
      requester_email: booking.requester_email,
      department: booking.department,
      room_name: booking.room_name,
      meeting_date: booking.meeting_date,
      start_time: booking.start_time,
      end_time: booking.end_time,
      purpose: booking.purpose,
      attendees: booking.attendees,
      priority: booking.priority,
    });
  } catch (error) {
    console.error("Meeting room booking error:", error.message || error);
    res.status(500).json({ message: "Failed to create booking" });
  }
});

// GET /api/meeting-room - Danh sách bookings
router.get("/", verifyToken, async (req, res) => {
  try {
    // Google Sheets fallback (existing behavior)
    if (process.env.GOOGLE_SHEETS_ID) {
      try {
        const sheetsUrl = `https://sheets.googleapis.com/v4/spreadsheets/${process.env.GOOGLE_SHEETS_ID}/values/Trang%20tính1?key=${process.env.GOOGLE_SHEETS_API_KEY}`;
        const sheetsRes = await axios.get(sheetsUrl);
        const rows = sheetsRes.data.values || [];

        if (rows.length > 1) {
          const headers = rows[0];
          const email = req.user.email.toLowerCase();
          const bookings = rows.slice(1)
            .filter(row => (row[1] || "").toLowerCase() === email)
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

// GET /api/meeting-room/token/:token - Chi tiết booking qua token
router.get("/token/:token", async (req, res) => {
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

// POST /api/meeting-room/approve - Phê duyệt booking (N8N or direct)
router.post("/approve", async (req, res) => {
  try {
    const { token, booking_id, action, manager_email } = req.body;
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
    if (manager_email) booking.manager_email = manager_email;
    await booking.save();

    res.json({
      success: true,
      message: action === "approve" ? "Booking approved" : "Booking rejected",
      status: booking.status,
      booking_id: booking.booking_id,
      requester_name: booking.requester_name,
      requester_email: booking.requester_email,
      room_name: booking.room_name,
      meeting_date: booking.meeting_date,
      start_time: booking.start_time,
      end_time: booking.end_time,
    });
  } catch (error) {
    console.error("Meeting room approve error:", error);
    res.status(500).json({ message: "Approval failed" });
  }
});

// GET /api/meeting-room/approve-link - Approval via GET link (for email buttons)
router.get("/approve-link", async (req, res) => {
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
      return res.status(200).send(`Booking ${booking.booking_id} was already processed with status: ${booking.status}`);
    }

    booking.manager_status = action === "approve" ? "approved" : "rejected";
    booking.status = action === "approve" ? "approved" : "rejected";
    booking.manager_decided_at = new Date();
    await booking.save();

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

// POST /api/meeting-room/sync-status - N8N sync booking status
router.post("/sync-status", async (req, res) => {
  try {
    const { booking_id, status, manager_email, manager_note } = req.body;
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
    if (manager_email) update.manager_email = manager_email;
    if (manager_note) update.notes = manager_note;

    const booking = await Booking.findOneAndUpdate({ booking_id }, update, { new: true });
    if (!booking) return res.status(404).json({ message: "Booking not found" });

    res.json({ success: true, message: "Booking synced", booking_id: booking.booking_id, status: booking.status });
  } catch (error) {
    console.error("Sync meeting room status error:", error);
    res.status(500).json({ message: "Sync failed" });
  }
});

// POST /api/meeting-room/cancel - Hủy booking
router.post("/cancel", verifyToken, async (req, res) => {
  try {
    const { booking_id, reason } = req.body;
    const user = req.user;

    if (!booking_id) {
      return res.status(400).json({ message: "booking_id is required" });
    }

    const booking = await Booking.findOne({ booking_id });
    if (!booking) {
      return res.status(404).json({ message: "Booking not found" });
    }

    const requesterEmail = (booking.requester_email || "").toLowerCase();
    const userEmail = (user.email || "").toLowerCase();

    if (requesterEmail !== userEmail && user.role !== "hr" && user.role !== "manager") {
      return res.status(403).json({ message: "Bạn không có quyền hủy booking này" });
    }

    if (["cancelled", "rejected", "expired"].includes(booking.status)) {
      return res.status(400).json({ message: "Booking đã được xử lý trước đó" });
    }

    booking.status = "cancelled";
    booking.cancel_reason = reason || "";
    booking.cancelled_at = new Date();
    await booking.save();

    res.json({
      success: true,
      message: "Booking đã được hủy thành công",
      booking_id: booking.booking_id,
      status: "cancelled"
    });
  } catch (error) {
    console.error("Cancel booking error:", error);
    res.status(500).json({ message: "Error cancelling booking" });
  }
});

module.exports = router;
