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
      enum: ["pending", "approved", "rejected"],
      default: "pending",
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("LeaveRequest", leaveRequestSchema);
