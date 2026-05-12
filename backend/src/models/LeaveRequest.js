const mongoose = require("mongoose");

const leaveRequestSchema = new mongoose.Schema(
  {
    employeeId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      // Optional: N8N không truyền employeeId (user chưa login)
      // Backend sẽ lookup bằng employeeEmail nếu cần
      default: null,
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

    // Token expiry (set when token is generated)
    managerTokenExpiresAt: {
      type: Date,
      default: null,
    },
    hrTokenExpiresAt: {
      type: Date,
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
    cancelReason: {
      type: String,
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

    // ─── AI Auto-Approve ───
    autoApproved: {
      type: Boolean,
      default: false,
    },
    aiDecision: {
      type: String,
      default: null,
    },
    aiReason: {
      type: String,
      default: null,
    },
    approvedBy: {
      type: String,
      default: null,
    },

    // ─── Final timestamps ───
    approvedAt: {
      type: Date,
      default: null,
    },
    rejectedAt: {
      type: Date,
      default: null,
    },
    rejectionReason: {
      type: String,
      default: null,
    },

    // ─── Reminder ───
    reminderCount: {
      type: Number,
      default: 0,
    },

    // ─── WF8 Resume Callback ───
    wf8ResumeCallback: {
      type: String,
      default: null,
    },
    wf8ResumeUrl: {
      type: String,
      default: null,
    },
    wf8ResumedAt: {
      type: Date,
      default: null,
    },

    // ─── Resubmit (WF8 flow) ───
    resubmittedAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("LeaveRequest", leaveRequestSchema);

// Compound indexes cho các truy vấn phổ biến
// NOTE: managerApprovalToken and hrApprovalToken already indexed via unique/sparse above
leaveRequestSchema.index({ employeeId: 1, createdAt: -1 });
leaveRequestSchema.index({ department: 1, manager_status: 1 });
leaveRequestSchema.index({ status: 1, manager_status: 1, hr_status: 1 });
