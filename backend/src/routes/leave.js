const express = require("express");
const mongoose = require("mongoose");
const LeaveRequest = require("../models/LeaveRequest");
const User = require("../models/User");
const { verifyToken, verifyN8nSecret } = require("../middleware/auth");
const { generateApprovalToken } = require("../middleware/n8n");
const { triggerN8NWorkflow } = require("../helpers/n8n");
const { getEmailFromSettings } = require("../helpers/settings");

const router = express.Router();

// ───────────────────────────────────────────
// N8N calls these endpoints to create/update
// leave records. N8N is the orchestrator.
// ───────────────────────────────────────────

// POST /api/leave - Tạo đơn nghỉ phép
// N8N sends: { employeeId, employeeName, employeeEmail, department, leave_date, leave_days, reason, managerEmail, hrEmail }
// Frontend (logged in user) sends: { leave_date, leave_days, reason }
router.post("/", verifyToken, async (req, res) => {
  try {
    const {
      leave_date, leave_days, reason,
      employeeName, employeeEmail, department,
      employeeId, managerEmail, hrEmail
    } = req.body;

    if (!leave_date || !leave_days || !reason) {
      return res.status(400).json({ message: "leave_date, leave_days, reason are required" });
    }

    // Resolve employee info
    let employeeNameVal = employeeName;
    let employeeEmailVal = employeeEmail;
    let employeeIdVal = req.user?.userId ? new mongoose.Types.ObjectId(req.user.userId) : null;

    if (employeeEmailVal) {
      const user = await User.findOne({ email: employeeEmailVal.toLowerCase() });
      if (user) {
        employeeNameVal = employeeNameVal || user.name;
        employeeEmailVal = user.email;
        employeeIdVal = user._id;
      }
    } else if (!employeeNameVal && !employeeEmailVal && req.user?.userId) {
      const user = await User.findById(req.user.userId);
      if (user) {
        employeeNameVal = user.name;
        employeeEmailVal = user.email;
        employeeIdVal = user._id;
      }
    }

    if (!employeeNameVal || !employeeEmailVal) {
      return res.status(400).json({ message: "Employee info required (name, email)" });
    }

    const resolvedDept = department || req.user?.department;

    // ─── RESOLVE MANAGER + HR EMAIL FROM SETTINGS (Bug #1 fix) ───
    // Frontend only sends department. Backend must resolve actual emails
    // so N8N workflows send emails to the correct people.
    let resolvedManagerEmail = managerEmail || null;
    let resolvedHrEmail = hrEmail || null;

    if (!resolvedManagerEmail || !resolvedHrEmail) {
      try {
        if (!resolvedManagerEmail && resolvedDept) {
          resolvedManagerEmail = await getEmailFromSettings(resolvedDept, "manager");
        }
        if (!resolvedHrEmail) {
          resolvedHrEmail = await getEmailFromSettings(null, "hr");
        }
      } catch (err) {
        console.warn("[Leave] Could not resolve emails from settings:", err.message);
      }
    }

    // ─── CHECK DATE CONFLICT BEFORE CREATING RECORD (Bug #4 fix) ───
    // Conflict check MUST happen before save, not after.
    const startDate = new Date(leave_date + 'T12:00:00');
    const endDate = new Date(startDate);
    endDate.setDate(endDate.getDate() + parseInt(leave_days) - 1);
    const endDateStr = endDate.toISOString().split('T')[0];

    const existingLeaves = await LeaveRequest.find({
      employeeId: employeeIdVal,
      status: { $in: ['pending', 'approved'] },
    });

    for (const existing of existingLeaves) {
      const existStart = new Date(existing.leave_date + 'T12:00:00');
      const existEnd = new Date(existStart);
      existEnd.setDate(existEnd.getDate() + (existing.leave_days || 1) - 1);
      if (startDate <= existEnd && endDate >= existStart) {
        return res.status(400).json({
          message: `Ngày nghỉ trùng với đơn đã có (từ ngày ${existStart.toLocaleDateString('vi-VN')} - ${existEnd.toLocaleDateString('vi-VN')}). Vui lòng chọn ngày khác.`,
          conflictDates: {
            existingStart: existing.leave_date,
            existingDays: existing.leave_days,
          },
        });
      }
    }

    const needsHr = parseInt(leave_days) > 3;
    const tokenExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    const managerApprovalToken = generateApprovalToken(resolvedManagerEmail || "pending", "manager");
    const hrApprovalToken = needsHr ? generateApprovalToken(resolvedHrEmail || "pending", "hr") : null;

    const leave = new LeaveRequest({
      employeeId: employeeIdVal,
      employee_name: employeeNameVal,
      employee_email: employeeEmailVal,
      department: resolvedDept,
      leave_date,
      end_date: endDateStr,
      leave_days: parseInt(leave_days),
      reason,
      managerApprovalToken,
      hrApprovalToken,
      managerTokenExpiresAt: tokenExpiresAt,
      hrTokenExpiresAt: needsHr ? tokenExpiresAt : null,
      manager_status: "pending",
      hr_status: needsHr ? "pending" : "skipped",
      status: "pending",
      manager_email: resolvedManagerEmail || null,
      hr_email: needsHr ? (resolvedHrEmail || null) : null,
      managerApproverEmail: resolvedManagerEmail || null,
      hrApproverEmail: needsHr ? (resolvedHrEmail || null) : null,
    });
    await leave.save();

    // Route to the correct N8N workflow based on leave duration
    // 1-day leaves → WF4 AI auto-approve
    // 2+ day leaves → WF1 manager email notification
    if (parseInt(leave_days) === 1) {
      triggerN8NWorkflow("webhook/auto-approve", {
        leaveId: leave._id.toString(),
        leave_date: leave.leave_date,
        end_date: endDateStr,
        leave_days: leave.leave_days,
        reason: leave.reason,
        employee_name: leave.employee_name,
        employee_email: leave.employee_email,
        department: leave.department,
        managerEmail: resolvedManagerEmail || null,
        hrEmail: resolvedHrEmail || null,
        managerApprovalToken: leave.managerApprovalToken,
        hrApprovalToken: leave.hrApprovalToken,
      });
    } else {
      triggerN8NWorkflow("webhook/leave-create", {
        leaveId: leave._id.toString(),
        leave_date: leave.leave_date,
        end_date: endDateStr,
        leave_days: leave.leave_days,
        reason: leave.reason,
        employee_name: leave.employee_name,
        employee_email: leave.employee_email,
        department: leave.department,
        managerEmail: resolvedManagerEmail || null,
        hrEmail: resolvedHrEmail || null,
        managerApprovalToken: leave.managerApprovalToken,
        hrApprovalToken: leave.hrApprovalToken,
      });
    }

    res.status(201).json({
      success: true,
      leaveId: leave._id.toString(),
      employeeName: leave.employee_name,
      employeeEmail: leave.employee_email,
      department: leave.department,
      leaveDate: leave.leave_date,
      endDate: endDateStr,
      leaveDays: parseInt(leave_days),
      reason: leave.reason,
      managerEmail: resolvedManagerEmail || null,
      hrEmail: resolvedHrEmail || null,
      requiresHrApproval: needsHr,
      status: leave.status,
    });
  } catch (error) {
    console.error("Leave error:", error.message || error);
    res.status(500).json({ message: "Failed to submit leave request", detail: error.message });
  }
});

// GET /api/leave - Lấy danh sách đơ (theo role), có phân trang
router.get("/", verifyToken, async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limitParam = parseInt(req.query.limit);
    // Only apply pagination when explicitly requested; return all records otherwise
    const limit = (limitParam > 0) ? Math.min(100, limitParam) : 0;
    const skip = limit > 0 ? (page - 1) * limit : 0;

    const query = { employeeId: req.user.userId };
    const [requests, total] = await Promise.all([
      limit > 0
        ? LeaveRequest.find(query).sort({ createdAt: -1 }).skip(skip).limit(limit)
        : LeaveRequest.find(query).sort({ createdAt: -1 }),
      LeaveRequest.countDocuments(query),
    ]);
    res.json({
      data: requests,
      pagination: { page, limit: limit || total, total, pages: limit > 0 ? Math.ceil(total / limit) : 1 },
    });
  } catch (error) {
    console.error("Get leave error:", error);
    res.status(500).json({ message: "Error fetching requests" });
  }
});

// GET /api/leave/for-approval - Đơn cần duyệt (manager/HR)
router.get("/for-approval", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "manager" && req.user.role !== "hr") {
      return res.status(403).json({ message: "Chỉ manager/HR mới có quyền xem" });
    }

    let query = {};
    if (req.user.role === "manager") {
      query = { department: req.user.department, manager_status: "pending" };
    } else if (req.user.role === "hr") {
      // HR chỉ thấy đơn ĐÃ được manager duyệt VÀ cần HR duyệt (4+ ngày)
      query = { manager_status: "approved", hr_status: "pending", leave_days: { $gt: 3 } };
    }

    const requests = await LeaveRequest.find(query).sort({ createdAt: -1 });
    res.json(requests);
  } catch (error) {
    console.error("Get for-approval error:", error);
    res.status(500).json({ message: "Error fetching approval requests" });
  }
});

// GET /api/leave/pending-approvals - Tất cả đơn pending (cho N8N reminder workflow)
router.get("/pending-approvals", async (req, res) => {
  try {
    const requests = await LeaveRequest.find({
      status: "pending",
    }).sort({ createdAt: -1 });
    res.json(requests);
  } catch (error) {
    console.error("Get pending approvals error:", error);
    res.status(500).json({ message: "Error fetching pending approvals" });
  }
});

// GET /api/leave/:id - Chi tiết đơ
router.get("/:id", verifyToken, async (req, res) => {
  try {
    const request = await LeaveRequest.findById(req.params.id);
    if (!request) {
      return res.status(404).json({ message: "Leave request not found" });
    }

    if (req.user.role === "employee" && request.employeeId?.toString() !== req.user.userId) {
      return res.status(403).json({ message: "Không có quyền xem đơn này" });
    }
    if (req.user.role === "manager" && request.department !== req.user.department) {
      return res.status(403).json({ message: "Không có quyền xem đơn này" });
    }

    res.json(request);
  } catch (error) {
    res.status(500).json({ message: "Error" });
  }
});

// PATCH /api/leave/:id/reminder-count - N8N updates reminder count
router.patch("/:id/reminder-count", verifyN8nSecret, async (req, res) => {
  try {
    const { reminderCount } = req.body;
    const leave = await LeaveRequest.findOneAndUpdate(
      { _id: req.params.id },
      { $set: { reminderCount: parseInt(reminderCount) } },
      { new: true }
    );
    if (!leave) return res.status(404).json({ message: "Leave request not found" });
    res.json({ success: true, leaveId: leave._id.toString(), reminderCount: leave.reminderCount });
  } catch (error) {
    console.error("Update reminder count error:", error);
    res.status(500).json({ message: "Error updating reminder count" });
  }
});

// POST /api/leave/:id/cancel - Hủy đơn nghỉ phép
router.post("/:id/cancel", verifyToken, async (req, res) => {
  try {
    const { reason } = req.body;
    const leaveId = req.params.id;

    const updated = await LeaveRequest.findOneAndUpdate(
      { _id: leaveId, status: "pending", employeeId: req.user.userId ? new mongoose.Types.ObjectId(req.user.userId) : null },
      {
        $set: {
          status: "cancelled",
          cancelledAt: new Date(),
          cancelledBy: req.user?.userId ? new mongoose.Types.ObjectId(req.user.userId) : null,
          cancelReason: reason || null,
        }
      },
      { new: true }
    );

    if (!updated) {
      const existing = await LeaveRequest.findById(leaveId);
      if (!existing) {
        return res.status(404).json({ message: "Leave request not found" });
      }
      if (existing.status === "cancelled") {
        return res.status(400).json({ message: "Đơn đã được hủy trước đó" });
      }
      if (existing.employeeId?.toString() !== req.user?.userId) {
        return res.status(403).json({ message: "Bạn không có quyền hủy đơn này" });
      }
      return res.status(400).json({ message: "Chỉ đơn đang chờ duyệt mới có thể hủy" });
    }

    res.json({
      success: true,
      message: "Đơn đã được hủy",
      status: "cancelled",
      leaveId: updated._id.toString(),
    });

    // Notify N8N to send cancellation email
    const needsHrNotify = updated.hr_status !== "skipped" && updated.hr_email;
    triggerN8NWorkflow("webhook/cancel-leave", {
      leaveId: updated._id.toString(),
      employee_name: updated.employee_name,
      employee_email: updated.employee_email,
      department: updated.department,
      leave_date: updated.leave_date,
      end_date: updated.end_date || null,
      leave_days: updated.leave_days,
      reason: reason || null,
      managerEmail: updated.manager_email || null,
      hrEmail: updated.hr_email || null,
      needsHrNotify: !!needsHrNotify,
      cancelledBy: updated.cancelledBy ? updated.cancelledBy.toString() : null,
      cancelReason: reason || null,
    });
  } catch (error) {
    console.error("Cancel leave error:", error);
    res.status(500).json({ message: "Error cancelling leave" });
  }
});

// POST /api/leave/:id/return-early - Về sớm
router.post("/:id/return-early", verifyToken, async (req, res) => {
  try {
    const { actualReturnDate } = req.body;

    const updated = await LeaveRequest.findOneAndUpdate(
      {
        _id: req.params.id,
        status: "approved",
        manager_status: "approved",
        employeeId: req.user?.userId ? new mongoose.Types.ObjectId(req.user.userId) : null,
      },
      { $set: { actualReturnDate: new Date(actualReturnDate || new Date()) } },
      { new: true }
    );

    if (!updated) {
      const existing = await LeaveRequest.findById(req.params.id);
      if (!existing) {
        return res.status(404).json({ message: "Leave request not found" });
      }
      if (existing.employeeId?.toString() !== req.user?.userId) {
        return res.status(403).json({ message: "Bạn không có quyền cập nhật đơn này" });
      }
      return res.status(400).json({ message: "Chỉ đơn đã duyệt mới có thể về sớm" });
    }

    // Tính end_date từ leave_date + leave_days (phòng trường hợp bản ghi cũ không có field end_date)
    const plannedEnd = new Date(updated.leave_date);
    plannedEnd.setDate(plannedEnd.getDate() + updated.leave_days - 1);
    const endDateIso = plannedEnd.toISOString();

    const actualReturn = new Date(actualReturnDate || new Date());
    const diffTime = plannedEnd - actualReturn;
    const refundDays = Math.max(0, Math.ceil(diffTime / (1000 * 60 * 60 * 24)));

    // Resolve manager/HR email từ DB hoặc từ settings (phòng trường hợp bản ghi cũ thiếu)
    let managerEmail = updated.manager_email || updated.managerApproverEmail || null;
    let hrEmail = updated.hr_email || updated.hrApproverEmail || null;
    if (!managerEmail || !hrEmail) {
      try {
        if (!managerEmail) managerEmail = await getEmailFromSettings(updated.department, "manager");
        if (!hrEmail) hrEmail = await getEmailFromSettings(null, "hr");
      } catch (_) { /* ignore — cứ gửi null */ }
    }

    updated.refundDays = refundDays;
    await updated.save();

    res.json({
      success: true,
      message: `Đã cập nhật ngày về. Hoàn lại ${refundDays} ngày phép.`,
      refundDays,
      actualReturnDate: actualReturn.toISOString().split('T')[0],
      leaveId: updated._id.toString(),
    });

    // Notify N8N of early return
    triggerN8NWorkflow("webhook/return-early", {
      leaveId: updated._id.toString(),
      employee_name: updated.employee_name,
      employee_email: updated.employee_email,
      department: updated.department,
      leave_date: updated.leave_date,
      end_date: plannedEnd.toISOString().split('T')[0],
      leave_days: updated.leave_days,
      actualReturnDate: actualReturn.toISOString().split('T')[0],
      refundDays,
      reason: updated.reason,
      managerEmail,
      hrEmail,
    });
  } catch (error) {
    console.error("Return early error:", error);
    res.status(500).json({ message: "Error processing return early" });
  }
});

// PUT /api/leave/:id - Cập nhật đơn nghỉ phép (chỉ khi pending, owner only)
// Khi update ngày/số ngày → sinh token DUYỆT MỚI + reset manager_status (Bug #6 fix)
router.put("/:id", verifyToken, async (req, res) => {
  try {
    const { leave_date, leave_days, reason, managerEmail, hrEmail, n8nResumeUrl } = req.body;
    const request = await LeaveRequest.findById(req.params.id);

    if (!request) {
      return res.status(404).json({ message: "Leave request not found" });
    }

    if (request.employeeId?.toString() !== req.user?.userId) {
      return res.status(403).json({ message: "Không có quyền cập nhật đơn này" });
    }

    const updateFields = { updatedAt: new Date() };

    if (leave_date) updateFields.leave_date = leave_date;
    if (leave_days) updateFields.leave_days = parseInt(leave_days);
    if (reason) updateFields.reason = reason;

    const dateOrDaysChanged = !!(leave_date || leave_days);
    let needsHr = request.leave_days > 3;
    if (leave_days) needsHr = parseInt(leave_days) > 3;

    // Re-check conflict if date/days changed
    const newStart = leave_date ? new Date(leave_date + 'T12:00:00') : new Date(request.leave_date + 'T12:00:00');
    const newDays = leave_days ? parseInt(leave_days) : request.leave_days;
    const newEnd = new Date(newStart);
    newEnd.setDate(newEnd.getDate() + newDays - 1);

    const existingLeaves = await LeaveRequest.find({
      employeeId: request.employeeId,
      status: { $in: ['pending', 'approved'] },
      _id: { $ne: request._id },
    });

    for (const existing of existingLeaves) {
      const existStart = new Date(existing.leave_date + 'T12:00:00');
      const existEnd = new Date(existStart);
      existEnd.setDate(existEnd.getDate() + (existing.leave_days || 1) - 1);
      if (newStart <= existEnd && newEnd >= existStart) {
        return res.status(400).json({
          message: `Ngày nghỉ trùng với đơn đã có (từ ngày ${existStart.toLocaleDateString('vi-VN')} - ${existEnd.toLocaleDateString('vi-VN')}). Vui lòng chọn ngày khác.`,
        });
      }
    }

    // ─── REGENERATE TOKENS if date/days changed (Bug #6 fix) ───
    // Old approval links may be expired or stale; new tokens ensure manager can still approve
    let newManagerApprovalToken = request.managerApprovalToken;
    let newHrApprovalToken = request.hrApprovalToken;
    let newTokenExpiresAt = request.managerTokenExpiresAt;
    let newHrTokenExpiresAt = request.hrTokenExpiresAt;

    if (dateOrDaysChanged) {
      const freshTokenExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
      const currentManagerEmail = managerEmail || request.manager_email || request.managerApproverEmail || "pending";
      newManagerApprovalToken = generateApprovalToken(currentManagerEmail, "manager");
      newTokenExpiresAt = freshTokenExpiresAt;
      if (needsHr) {
        const currentHrEmail = hrEmail || request.hr_email || request.hrApproverEmail || "pending";
        newHrApprovalToken = generateApprovalToken(currentHrEmail, "hr");
        newHrTokenExpiresAt = freshTokenExpiresAt;
      } else {
        newHrApprovalToken = null;
        newHrTokenExpiresAt = null;
      }
      updateFields.managerApprovalToken = newManagerApprovalToken;
      updateFields.hrApprovalToken = newHrApprovalToken;
      updateFields.managerTokenExpiresAt = newTokenExpiresAt;
      updateFields.hrTokenExpiresAt = newHrTokenExpiresAt;
      // Reset approval statuses so manager must re-approve after changes
      updateFields.manager_status = "pending";
      updateFields.hr_status = needsHr ? "pending" : "skipped";
      updateFields.resubmittedAt = new Date();
      updateFields.wf8ResumeUrl = n8nResumeUrl || null;
    }

    const updated = await LeaveRequest.findOneAndUpdate(
      { _id: req.params.id, status: "pending" },
      { $set: updateFields },
      { new: true }
    );

    if (!updated) {
      return res.status(400).json({ message: "Không thể cập nhật — đơn đã được xử lý" });
    }

    // Build fresh approval links for N8N email notification
    const frontendUrl = process.env.FRONTEND_URL || "http://localhost:3000";
    const newManagerApprovalLink = `${frontendUrl}/approval-page.html?token=${encodeURIComponent(newManagerApprovalToken)}`;
    const newHrApprovalLink = needsHr && newHrApprovalToken
      ? `${frontendUrl}/approval-page.html?token=${encodeURIComponent(newHrApprovalToken)}&hr=true`
      : null;

    res.json({
      success: true,
      message: "Đơn đã được cập nhật",
      leaveId: updated._id.toString(),
      status: updated.status,
    });

    // Notify N8N of leave update — with FRESH tokens so links are always valid
    triggerN8NWorkflow("webhook/update-leave", {
      leaveId: updated._id.toString(),
      employee_name: updated.employee_name,
      employee_email: updated.employee_email,
      department: updated.department,
      leave_date: updated.leave_date,
      end_date: updated.end_date || null,
      leave_days: updated.leave_days,
      reason: updated.reason,
      managerEmail: managerEmail || updated.manager_email || updated.managerApproverEmail || null,
      hrEmail: hrEmail || updated.hr_email || updated.hrApproverEmail || null,
      managerApprovalToken: newManagerApprovalToken,
      hrApprovalToken: newHrApprovalToken,
      managerApprovalLink: newManagerApprovalLink,
      hrApprovalLink: newHrApprovalLink,
      managerTokenExpiresAt: newTokenExpiresAt ? newTokenExpiresAt.toISOString() : null,
      hrTokenExpiresAt: newHrTokenExpiresAt ? newHrTokenExpiresAt.toISOString() : null,
      wasResubmitted: dateOrDaysChanged,
      resubmittedAt: updated.resubmittedAt ? updated.resubmittedAt.toISOString() : null,
      wf8ResumeCallback: `${process.env.N8N_URL || "http://n8n:5678"}/webhook/2fb9c5af-8318-48f3-9e43-d4fe49483d59`,
      wf8ResumeUrl: n8nResumeUrl || null,
    });
  } catch (error) {
    console.error("Update leave error:", error);
    res.status(500).json({ message: "Error updating leave" });
  }
});

module.exports = router;
