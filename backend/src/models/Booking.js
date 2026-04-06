const mongoose = require("mongoose");

const bookingSchema = new mongoose.Schema(
  {
    // Mã booking hiển thị: MTG-{timestamp}
    booking_id: {
      type: String,
      required: [true, "Booking ID is required"],
      unique: true,
    },

    // Người đặt
    requester_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    requester_name: {
      type: String,
      required: true,
    },

    requester_email: {
      type: String,
      required: true,
    },

    department: {
      type: String,
      required: true,
    },

    // Phòng
    room_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Room",
      required: true,
    },

    room_name: {
      type: String,
      required: true,
    },

    // Thời gian họp
    meeting_date: {
      type: String, // "YYYY-MM-DD"
      required: [true, "Meeting date is required"],
    },

    start_time: {
      type: String, // "HH:MM"
      required: [true, "Start time is required"],
    },

    end_time: {
      type: String, // "HH:MM"
      required: [true, "End time is required"],
    },

    // Số phút = end - start (dùng để check > 4h)
    duration_minutes: {
      type: Number,
      default: 0,
    },

    // Mục đích & thông tin bổ sung
    purpose: {
      type: String,
      required: [true, "Meeting purpose is required"],
      maxlength: 500,
    },

    attendees: {
      type: Number,
      default: 1,
      min: 1,
    },

    notes: {
      type: String,
      default: "",
      maxlength: 500,
    },

    // Trạng thái phê duyệt
    // pending | approved | rejected | cancelled
    status: {
      type: String,
      enum: ["pending", "approved", "rejected", "cancelled"],
      default: "pending",
    },

    // Manager approval token (một lần duyệt)
    managerApprovalToken: {
      type: String,
      unique: true,
      sparse: true,
    },

    // Manager email (người nhận email)
    manager_email: {
      type: String,
      default: null,
    },

    manager_status: {
      type: String,
      enum: ["pending", "approved", "rejected"],
      default: "pending",
    },

    manager_decided_at: {
      type: Date,
      default: null,
    },

    // Lưu lại link phê duyệt để gửi email
    approval_link: {
      type: String,
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

// Index để query nhanh
bookingSchema.index({ requester_id: 1 });
bookingSchema.index({ room_id: 1, meeting_date: 1 });
bookingSchema.index({ status: 1 });
bookingSchema.index({ managerApprovalToken: 1 });
bookingSchema.index({ meeting_date: 1, start_time: 1, end_time: 1 });

module.exports = mongoose.model("Booking", bookingSchema);
