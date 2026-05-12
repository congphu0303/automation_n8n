const express = require("express");
const Booking = require("../models/Booking");
const Room = require("../models/Room");

const router = express.Router();

const parseTimeToMinutes = (timeString) => {
  if (!timeString || !timeString.includes(":")) return null;
  const [h, m] = timeString.split(":").map(Number);
  if (Number.isNaN(h) || Number.isNaN(m)) return null;
  return h * 60 + m;
};

const hasOverlap = (startA, endA, startB, endB) => {
  const aStart = parseTimeToMinutes(startA);
  const aEnd = parseTimeToMinutes(endA);
  const bStart = parseTimeToMinutes(startB);
  const bEnd = parseTimeToMinutes(endB);
  if (aStart === null || aEnd === null || bStart === null || bEnd === null) return false;
  return aStart < bEnd && aEnd > bStart;
};

router.get("/check-conflict", async (req, res) => {
  try {
    const { room_name, meeting_date, start_time, end_time } = req.query;
    if (!room_name || !meeting_date || !start_time || !end_time) {
      return res.json({ has_conflict: false, conflicts: [] });
    }
    const room = await Room.findOne({ name: room_name, status: "active" });
    if (!room) {
      return res.json({ has_conflict: false, conflicts: [] });
    }
    const existing = await Booking.find({
      room_id: room._id.toString(),
      meeting_date,
      status: { $in: ["pending", "pending_urgent", "approved"] },
    }).select("start_time end_time booking_id requester_name");
    const conflicts = existing.filter((b) => hasOverlap(start_time, end_time, b.start_time, b.end_time));
    res.json({ has_conflict: conflicts.length > 0, conflicts });
  } catch (error) {
    console.error("[MeetingRoomMongo] check-conflict error:", error.message);
    res.json({ has_conflict: false, conflicts: [] });
  }
});

router.post("/save", async (req, res) => {
  try {
    const {
      booking_id, requester_id, requester_name, requester_email, department,
      room_id, room_name, meeting_date, start_time, end_time, duration_minutes,
      purpose, attendees, priority, equipment_needed, notes,
      manager_email, managerApprovalToken, approval_link,
      status, manager_status, approval_deadline,
    } = req.body;
    if (!booking_id || !meeting_date || !start_time || !end_time) {
      return res.status(400).json({ status: "error", message: "Missing required fields" });
    }
    const existing = await Booking.findOne({ booking_id });
    if (existing) {
      return res.json(existing.toObject());
    }
    let roomObjId = room_id;
    if (room_id && !room_id.match(/^[0-9a-fA-F]{24}$/)) {
      const room = await Room.findOne({ name: room_name || room_id });
      if (room) roomObjId = room._id.toString();
    }
    const booking = await Booking.create({
      booking_id,
      requester_id: requester_id || null,
      requester_name: requester_name || "",
      requester_email: requester_email || "",
      department: department || "",
      room_id: roomObjId,
      room_name: room_name || "",
      meeting_date,
      start_time,
      end_time,
      duration_minutes: parseInt(duration_minutes) || 0,
      purpose: purpose || "",
      attendees: parseInt(attendees) || 1,
      priority: priority || "normal",
      equipment_needed: Array.isArray(equipment_needed) ? equipment_needed : [],
      notes: notes || "",
      manager_email: manager_email || null,
      managerApprovalToken: managerApprovalToken || null,
      approval_link: approval_link || null,
      status: status || "pending",
      manager_status: manager_status || "pending",
      manager_decided_at: null,
    });
    if (approval_deadline) {
      booking.approval_deadline = new Date(approval_deadline);
      await booking.save();
    }
    res.status(201).json(booking.toObject());
  } catch (error) {
    console.error("[MeetingRoomMongo] save error:", error.message);
    res.status(500).json({ status: "error", message: error.message });
  }
});

router.get("/get/:booking_id", async (req, res) => {
  try {
    const booking = await Booking.findOne({ booking_id: req.params.booking_id });
    if (!booking) {
      return res.status(404).json({ status: "error", message: "Booking not found" });
    }
    res.json(booking.toObject());
  } catch (error) {
    console.error("[MeetingRoomMongo] get error:", error.message);
    res.status(500).json({ status: "error", message: error.message });
  }
});

router.put("/update", async (req, res) => {
  try {
    const { booking_id, status, ...rest } = req.body;
    if (!booking_id || !status) {
      return res.status(400).json({ status: "error", message: "booking_id and status required" });
    }
    const update = { status, ...rest };
    if (["approved", "rejected"].includes(status)) {
      update.manager_decided_at = new Date();
    }
    const booking = await Booking.findOneAndUpdate(
      { booking_id },
      { $set: update },
      { new: true }
    );
    if (!booking) {
      return res.status(404).json({ status: "error", message: "Booking not found" });
    }
    res.json(booking.toObject());
  } catch (error) {
    console.error("[MeetingRoomMongo] update error:", error.message);
    res.status(500).json({ status: "error", message: error.message });
  }
});

router.get("/room-status", async (req, res) => {
  try {
    const rooms = await Room.find({ status: "active" }).sort({ floor: 1, name: 1 });
    const result = [];
    for (const room of rooms) {
      const today = new Date().toISOString().split("T")[0];
      const bookings = await Booking.find({
        room_id: room._id.toString(),
        meeting_date: today,
        status: { $in: ["pending", "pending_urgent", "approved"] },
      }).select("start_time end_time status");
      result.push({
        room_id: room.room_id,
        name: room.name,
        floor: room.floor,
        capacity: room.capacity,
        status: room.status,
        bookings,
      });
    }
    res.json(result);
  } catch (error) {
    console.error("[MeetingRoomMongo] room-status error:", error.message);
    res.status(500).json({ status: "error", message: error.message });
  }
});

router.get("/list", async (req, res) => {
  try {
    const { status, date } = req.query;
    const query = {};
    if (status) query.status = status;
    if (date) query.meeting_date = date;
    const bookings = await Booking.find(query).sort({ createdAt: -1 });
    res.json(bookings.map((b) => b.toObject()));
  } catch (error) {
    console.error("[MeetingRoomMongo] list error:", error.message);
    res.status(500).json({ status: "error", message: error.message });
  }
});

router.put("/remind", async (req, res) => {
  try {
    const { booking_id, manager_email, hours_left } = req.body;
    if (!booking_id) {
      return res.status(400).json({ status: "error", message: "booking_id required" });
    }
    const booking = await Booking.findOneAndUpdate(
      { booking_id },
      { $set: { last_reminder_sent_at: new Date(), reminder_hours_left: hours_left || null } },
      { new: true }
    );
    if (!booking) {
      return res.status(404).json({ status: "error", message: "Booking not found" });
    }
    res.json(booking.toObject());
  } catch (error) {
    console.error("[MeetingRoomMongo] remind error:", error.message);
    res.status(500).json({ status: "error", message: error.message });
  }
});

module.exports = router;
