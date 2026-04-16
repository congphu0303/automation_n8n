const mongoose = require("mongoose");

const leaveRequestSchema = new mongoose.Schema(
  {
    employeeId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    employee_name: {
      type: String,
      required: true,
    },

    employee_email: {
      type: String,
      required: true,
    },

    department: {
      type: String,
      enum: ["IT", "Marketing", "Finance", "Sales"],
      required: true,
    },

    leave_date: {
      type: Date,
      required: [true, "Leave date is required"],
    },

    // Ngày kết thúc nghỉ = leave_date + leave_days - 1 (tự động tính khi tạo)
    end_date: {
      type: Date,
      default: null,
    },

    leave_days: {
      type: Number,
      required: [true, "Number of days is required"],
      min: 1,
      max: 365,
    },

    reason: {
      type: String,
      required: [true, "Reason is required"],
      maxlength: 1000,
    },

    // Token duyệt cho Manager
    managerApprovalToken: {
      type: String,
      unique: true,
      sparse: true,
    },

    // Token duyệt cho HR (chỉ khi leave_days > 3)
    hrApprovalToken: {
      type: String,
      sparse: true,
    },

    // Email người được gửi link duyệt — dùng để chặn tự duyệt đơn
    managerApproverEmail: {
      type: String,
      default: null,
    },
    hrApproverEmail: {
      type: String,
      default: null,
    },

    // ─── Cấp 1: Manager ───
    manager_status: {
      type: String,
      enum: ["pending", "approved", "rejected"],
      default: "pending",
    },

    manager_email: {
      type: String,
      default: null,
    },

    manager_decidedAt: {
      type: Date,
      default: null,
    },

    // ─── Cấp 2: HR ───
    hr_status: {
      type: String,
      enum: ["pending", "approved", "rejected", "skipped"],
      default: "pending",
    },

    hr_email: {
      type: String,
      default: null,
    },

    hr_decidedAt: {
      type: Date,
      default: null,
    },

    // ─── Trạng thái cuối cùng ───
    status: {
      type: String,
      enum: ["pending", "approved", "rejected", "cancelled"],
      default: "pending",
    },

    // ─── Cancel ───
    cancelledAt: {
      type: Date,
      default: null,
    },
    cancelledBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },

    // ─── Return Early ───
    actualReturnDate: {
      type: Date,
      default: null,
    },
    refundDays: {
      type: Number,
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("LeaveRequest", leaveRequestSchema);
