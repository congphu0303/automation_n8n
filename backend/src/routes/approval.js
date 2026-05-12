const express = require("express");
const LeaveRequest = require("../models/LeaveRequest");
const { verifyToken } = require("../middleware/auth");
const { decodeApprovalToken } = require("../middleware/n8n");
const { triggerN8NWorkflow } = require("../helpers/n8n");

const router = express.Router();

// ───────────────────────────────────────────
// N8N workflows call these endpoints after
// user clicks approve/reject in email.
// N8N sends the decision to update the DB.
// These endpoints are for: (1) N8N internal calls,
// (2) direct dashboard approval (JWT auth).
// ───────────────────────────────────────────

// POST /api/approval/manager - Manager approve/reject (via token from N8N email)
router.post("/manager", async (req, res) => {
  try {
    const { token, action, approverEmail, n8nResumeUrl } = req.body;

    if (!["approve", "reject"].includes(action)) {
      return res.status(400).json({ message: "Invalid action" });
    }

    const tokenInfo = decodeApprovalToken(token);
    const isNewToken = !!tokenInfo;

    let leave = await LeaveRequest.findOne({
      managerApprovalToken: token,
      manager_status: "pending",
    });

    if (isNewToken && !leave) {
      leave = await LeaveRequest.findOne({
        managerApprovalToken: { $regex: `^${tokenInfo.randomPart}` },
        manager_status: "pending",
      });
    }

    if (!leave) {
      const existing = await LeaveRequest.findOne({ managerApprovalToken: token });
      if (existing && existing.manager_status !== "pending") {
        return res.status(400).json({ message: "Đơn đã được xử lý trước đó" });
      }
      return res.status(404).json({ message: "Không tìm thấy đơn nghỉ phép" });
    }

    if (isNewToken && tokenInfo.type !== "manager" && tokenInfo.type !== "meeting_manager") {
      return res.status(400).json({ message: "Token không phải dành cho Manager" });
    }

    if (isNewToken && tokenInfo.isExpired) {
      return res.status(410).json({ message: "Link đã hết hạn. Vui lòng yêu cầu nhân viên gửi lại đơn." });
    }

    if (isNewToken && tokenInfo.approverEmail) {
      const expected = leave.managerApproverEmail || leave.manager_email;
      if (tokenInfo.approverEmail.toLowerCase() !== expected?.toLowerCase()) {
        return res.status(403).json({ message: "Bạn không có quyền duyệt đơn này" });
      }
    } else if (approverEmail) {
      const expected = leave.managerApproverEmail || leave.manager_email;
      if (approverEmail.toLowerCase() !== expected?.toLowerCase()) {
        return res.status(403).json({ message: "Bạn không có quyền duyệt đơn này" });
      }
    }

    const updateData = {
      manager_status: action === "approve" ? "approved" : "rejected",
      manager_decidedAt: new Date(),
      manager_email: approverEmail || tokenInfo?.approverEmail || null,
      wf8ResumeUrl: n8nResumeUrl || null,
    };

    if (action === "reject") {
      updateData.status = "rejected";
    } else if (leave.leave_days <= 3) {
      updateData.status = "approved";
    }

    const updated = await LeaveRequest.findOneAndUpdate(
      { _id: leave._id, manager_status: "pending" },
      { $set: updateData },
      { new: true }
    );

    if (!updated) {
      return res.status(400).json({ message: "Đơn đã được xử lý bởi người khác" });
    }

    const isApproved = action === "approve";
    let isWf8Resumed = false;

    // If this was a resubmitted leave (WF8 flow), call the resume URL to unblock the Wait node
    if (isApproved && updated.resubmittedAt && (updated.wf8ResumeUrl || updated.wf8ResumeCallback)) {
      try {
        const axios = require("axios");
        const resumeUrl = updated.wf8ResumeUrl || updated.wf8ResumeCallback;
        await axios.post(resumeUrl, {
          leaveId: updated._id.toString(),
          action: "approve",
          manager_status: updated.manager_status,
          hr_status: updated.hr_status,
          status: updated.status,
          managerEmail: updated.manager_email,
          hrEmail: updated.hr_email,
          employeeEmail: updated.employee_email,
          employeeName: updated.employee_name,
          department: updated.department,
          leaveDate: updated.leave_date,
          end_date: updated.end_date,
          leaveDays: updated.leave_days,
          reason: updated.reason,
          isWf8Resumed: true,
        }, { timeout: 10000 });
        await LeaveRequest.findByIdAndUpdate(updated._id, { wf8ResumedAt: new Date() });
        isWf8Resumed = true;
      } catch (e) {
        console.error("[WF8] Resume failed:", e.message);
      }
    }

    res.json({
      success: true,
      message: isApproved
        ? (updated.leave_days > 3 ? "Approved by manager. Sent to HR for final approval" : "Leave request fully approved")
        : "Leave request rejected",
      status: updated.status,
      leaveId: updated._id.toString(),
      requiresHrApproval: updated.leave_days > 3,
      employeeName: updated.employee_name,
      employeeEmail: updated.employee_email,
      department: updated.department,
      leaveDate: updated.leave_date,
      leaveDays: updated.leave_days,
      hrEmail: updated.hr_email,
      hrApprovalToken: updated.hrApprovalToken,
      managerApprovalToken: updated.managerApprovalToken,
    });

    // Trigger wf2 so it sends emails (approve/reject notification to employee, HR email for 4+ days)
    if (!isWf8Resumed) {
      triggerN8NWorkflow("webhook/manager-decision", {
        token: updated.managerApprovalToken,
        action: action,
        leaveId: updated._id.toString(),
        employeeName: updated.employee_name,
        employeeEmail: updated.employee_email,
        leaveDate: updated.leave_date,
        end_date: updated.end_date || computeEndDate(updated.leave_date, updated.leave_days),
        leaveDays: updated.leave_days,
        reason: updated.reason,
        department: updated.department,
        requiresHrApproval: updated.leave_days > 3,
        hrEmail: updated.hr_email,
        hrApprovalToken: updated.hrApprovalToken,
        managerApprovalLink: `${process.env.FRONTEND_URL || "http://localhost:3000"}/approval-page.html?token=${encodeURIComponent(updated.managerApprovalToken)}`,
        isInternalCall: true,
      });
    }
  } catch (error) {
    console.error("Manager approval error:", error);
    res.status(500).json({ message: "Error" });
  }
});

// POST /api/approval/hr - HR approve/reject (via token from N8N email)
router.post("/hr", async (req, res) => {
  try {
    const { token, action, approverEmail } = req.body;

    if (!["approve", "reject", "approved", "rejected"].includes(action)) {
      return res.status(400).json({ message: "Invalid action" });
    }

    const tokenInfo = decodeApprovalToken(token);
    const isNewToken = !!tokenInfo;

    let leave = await LeaveRequest.findOne({
      hrApprovalToken: token,
      hr_status: "pending",
      manager_status: "approved",
    });

    if (isNewToken && !leave) {
      leave = await LeaveRequest.findOne({
        hrApprovalToken: { $regex: `^${tokenInfo.randomPart}` },
        hr_status: "pending",
        manager_status: "approved",
      });
    }

    if (!leave) {
      const existing = await LeaveRequest.findOne({ hrApprovalToken: token });
      if (existing) {
        return res.status(400).json({ message: "Đơn đã được xử lý trước đó" });
      }
      return res.status(404).json({ message: "Không tìm thấy đơn hoặc chưa được Manager duyệt" });
    }

    if (isNewToken && tokenInfo.type !== "hr") {
      return res.status(400).json({ message: "Token không phải dành cho HR" });
    }

    if (isNewToken && tokenInfo.isExpired) {
      return res.status(410).json({ message: "Link đã hết hạn. Vui lòng yêu cầu nhân viên gửi lại đơn." });
    }

    if (isNewToken && tokenInfo.approverEmail) {
      const expected = leave.hrApproverEmail || leave.hr_email;
      if (tokenInfo.approverEmail.toLowerCase() !== expected?.toLowerCase()) {
        return res.status(403).json({ message: "Bạn không có quyền duyệt đơn này" });
      }
    } else if (approverEmail) {
      const expected = leave.hrApproverEmail || leave.hr_email;
      if (approverEmail.toLowerCase() !== expected?.toLowerCase()) {
        return res.status(403).json({ message: "Bạn không có quyền duyệt đơn này" });
      }
    }

    const isApprove = action === "approve" || action === "approved";
    const updated = await LeaveRequest.findOneAndUpdate(
      { _id: leave._id, hr_status: "pending", manager_status: "approved" },
      {
        $set: {
          hr_status: isApprove ? "approved" : "rejected",
          hr_decidedAt: new Date(),
          hr_email: approverEmail || tokenInfo?.approverEmail || null,
          status: isApprove ? "approved" : "rejected",
        }
      },
      { new: true }
    );

    if (!updated) {
      return res.status(400).json({ message: "Đơn đã được xử lý bởi người khác" });
    }

    res.json({
      success: true,
      message: `HR đã ${isApprove ? "duyệt" : "từ chối"} đơn`,
      status: updated.status,
      leaveId: updated._id.toString(),
      employeeName: updated.employee_name,
      employeeEmail: updated.employee_email,
      department: updated.department,
      leaveDate: updated.leave_date,
      leaveDays: updated.leave_days,
    });

    // Trigger wf3 to send final result email to employee
    triggerN8NWorkflow("webhook/hr-decision", {
      token: updated.hrApprovalToken,
      action: isApprove ? "approve" : "reject",
      leaveId: updated._id.toString(),
      employeeName: updated.employee_name,
      employeeEmail: updated.employee_email,
      leaveDate: updated.leave_date,
      end_date: updated.end_date || computeEndDate(updated.leave_date, updated.leave_days),
      leaveDays: updated.leave_days,
      reason: updated.reason,
      department: updated.department,
      isInternalCall: true,
    });
  } catch (error) {
    console.error("HR approval error:", error);
    res.status(500).json({ message: "Error" });
  }
});

// POST /api/approval/approve-by-id - Manager/HR approve from dashboard (JWT auth)
router.post("/approve-by-id", verifyToken, async (req, res) => {
  try {
    const { leaveId, action, n8nResumeUrl } = req.body;
    const user = req.user;

    if (!["approve", "reject"].includes(action)) {
      return res.status(400).json({ message: "Invalid action" });
    }

    const request = await LeaveRequest.findById(leaveId);
    if (!request) {
      return res.status(404).json({ message: "Leave request not found" });
    }

    const isManager = user.role === "manager" && user.department === request.department;
    const isHR = user.role === "hr";

    if (isManager) {
      if (request.manager_status !== "pending") {
        return res.status(400).json({ message: "Đơn đã được xử lý bởi Manager" });
      }

      const updateData = {
        manager_status: action === "approve" ? "approved" : "rejected",
        manager_decidedAt: new Date(),
        managerApproverEmail: user.email,
        wf8ResumeUrl: n8nResumeUrl || null,
      };

      if (action === "reject") {
        updateData.status = "rejected";
        updateData.rejectedAt = new Date();
      } else if (request.leave_days <= 3) {
        updateData.status = "approved";
        updateData.approvedAt = new Date();
      }

      const updated = await LeaveRequest.findOneAndUpdate(
        { _id: leaveId, manager_status: "pending" },
        { $set: updateData },
        { new: true }
      );

      if (!updated) {
        return res.status(400).json({ message: "Đơn đã được xử lý bởi người khác" });
      }

      let isWf8Resumed = false;
      // If this was a resubmitted leave (WF8 flow), call the resume URL to unblock the Wait node
      if (action === "approve" && updated.resubmittedAt && (updated.wf8ResumeUrl || updated.wf8ResumeCallback)) {
        try {
          const axios = require("axios");
          const resumeUrl = updated.wf8ResumeUrl || updated.wf8ResumeCallback;
          await axios.post(resumeUrl, {
            leaveId: updated._id.toString(),
            action: "approve",
            manager_status: updated.manager_status,
            hr_status: updated.hr_status,
            status: updated.status,
            managerEmail: updated.manager_email,
            hrEmail: updated.hr_email,
            employeeEmail: updated.employee_email,
            employeeName: updated.employee_name,
            department: updated.department,
            leaveDate: updated.leave_date,
            end_date: updated.end_date,
            leaveDays: updated.leave_days,
            reason: updated.reason,
            isWf8Resumed: true,
          }, { timeout: 10000 });
          await LeaveRequest.findByIdAndUpdate(updated._id, { wf8ResumedAt: new Date() });
          isWf8Resumed = true;
        } catch (e) {
          console.error("[WF8] Resume failed:", e.message);
        }
      }

      // Trigger wf2 to send email notifications (approve/reject + HR email for 4+ days)
      if (!isWf8Resumed) {
        triggerN8NWorkflow("webhook/manager-decision", {
          token: updated.managerApprovalToken,
          action: action,
          leaveId: updated._id.toString(),
          employeeName: updated.employee_name,
          employeeEmail: updated.employee_email,
          leaveDate: updated.leave_date,
          end_date: updated.end_date || computeEndDate(updated.leave_date, updated.leave_days),
          leaveDays: updated.leave_days,
          reason: updated.reason,
          department: updated.department,
          requiresHrApproval: updated.leave_days > 3,
          hrEmail: updated.hr_email,
          hrApprovalToken: updated.hrApprovalToken,
          isInternalCall: true,
        });
      }

      return res.json({
        success: true,
        message: action === "approve"
          ? (updated.leave_days > 3 ? "Approved by manager. Sent to HR for final approval." : "Leave request fully approved.")
          : "Leave request rejected.",
        status: updated.status,
        requiresHrApproval: updated.leave_days > 3 && action === "approve",
        manager_status: updated.manager_status,
        hr_status: updated.hr_status,
        hrApprovalToken: updated.hrApprovalToken,
      });
    }

    if (isHR) {
      if (request.manager_status !== "approved") {
        return res.status(400).json({ message: "Đơn chưa được Manager duyệt" });
      }
      if (request.hr_status !== "pending") {
        return res.status(400).json({ message: "Đơn đã được HR xử lý" });
      }

      const updated = await LeaveRequest.findOneAndUpdate(
        { _id: leaveId, hr_status: "pending", manager_status: "approved" },
        {
          $set: {
            hr_status: action === "approve" ? "approved" : "rejected",
            hr_decidedAt: new Date(),
            hrApproverEmail: user.email,
            status: action === "approve" ? "approved" : "rejected",
          }
        },
        { new: true }
      );

      if (!updated) {
        return res.status(400).json({ message: "Đơn đã được xử lý bởi người khác" });
      }

      // Trigger wf3 to send final email to employee
      triggerN8NWorkflow("webhook/hr-decision", {
        token: updated.hrApprovalToken,
        action: action,
        leaveId: updated._id.toString(),
        employeeName: updated.employee_name,
        employeeEmail: updated.employee_email,
        leaveDate: updated.leave_date,
        end_date: updated.end_date || computeEndDate(updated.leave_date, updated.leave_days),
        leaveDays: updated.leave_days,
        reason: updated.reason,
        department: updated.department,
      });

      return res.json({
        success: true,
        message: `HR đã ${action === "approve" ? "duyệt" : "từ chối"} đơn.`,
        status: updated.status,
        manager_status: updated.manager_status,
        hr_status: updated.hr_status,
      });
    }

    return res.status(403).json({ message: "Bạn không có quyền duyệt đơn này" });
  } catch (error) {
    console.error("Approve by ID error:", error);
    res.status(500).json({ message: "Error approving leave" });
  }
});

// POST /api/approval/auto-approve - N8N AI auto-approve callback (verified by secret)
router.post("/auto-approve", async (req, res) => {
  const secret = req.headers["x-n8n-secret"];
  const validSecret = process.env.N8N_SECRET_KEY;
  if (!validSecret) {
    return res.status(500).json({ message: "Server misconfigured: N8N_SECRET_KEY not set" });
  }
  if (secret !== validSecret) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const { leaveId, aiDecision, aiReason, approvedBy } = req.body;

    if (!leaveId) {
      return res.status(400).json({ message: "leaveId is required" });
    }

    const updateData = {
      autoApproved: true,
      aiDecision: aiDecision,
      aiReason: aiReason,
      approvedBy: approvedBy || "AI_GEMINI_AUTO",
    };

    if (aiDecision === "approve") {
      updateData.manager_status = "approved";
      updateData.hr_status = "approved";
      updateData.status = "approved";
      updateData.approvedAt = new Date();
      updateData.manager_decidedAt = new Date();
      updateData.hr_decidedAt = new Date();
    } else {
      updateData.manager_status = "rejected";
      updateData.hr_status = "rejected";
      updateData.status = "rejected";
      updateData.rejectedAt = new Date();
      updateData.rejectionReason = aiReason;
    }

    const request = await LeaveRequest.findOneAndUpdate(
      { _id: leaveId, status: "pending" },
      { $set: updateData },
      { new: true }
    );

    if (!request) {
      const existing = await LeaveRequest.findById(leaveId);
      if (!existing) {
        return res.status(404).json({ message: "Leave request not found" });
      }
      return res.status(400).json({
        success: false,
        message: `Leave already processed: ${existing.status}`,
        currentStatus: existing.status
      });
    }

    console.log(`${aiDecision === "approve" ? "Auto-approved" : "Auto-rejected"} 1-day leave: ${request.employee_name} - ${request.leave_date}`);

    res.json({
      success: true,
      status: aiDecision === "approve" ? "approved" : "rejected",
      leaveId: request._id.toString(),
    });
  } catch (error) {
    console.error("Auto approve error:", error);
    res.status(500).json({ message: "Error auto approving leave" });
  }
});

// GET /api/approval/token/:token - Validate approval token
router.get("/token/:token", async (req, res) => {
  try {
    const { token } = req.params;

    let request = await LeaveRequest.findOne({ managerApprovalToken: token });
    let approvalType = "manager";
    let expiresAt = request?.managerTokenExpiresAt || null;

    if (!request) {
      request = await LeaveRequest.findOne({ hrApprovalToken: token });
      approvalType = "hr";
      expiresAt = request?.hrTokenExpiresAt || null;
    }

    if (!request) {
      const tokenInfo = decodeApprovalToken(token);
      if (tokenInfo) {
        request = await LeaveRequest.findOne({ managerApprovalToken: { $regex: `^${tokenInfo.randomPart}` } });
        if (request) {
          approvalType = "manager";
          expiresAt = tokenInfo.expiresAt;
        } else {
          request = await LeaveRequest.findOne({ hrApprovalToken: { $regex: `^${tokenInfo.randomPart}` } });
          if (request) {
            approvalType = "hr";
            expiresAt = tokenInfo.expiresAt;
          }
        }
      }
    }

    if (!request) {
      return res.status(404).json({ message: "Invalid or expired token" });
    }

    const expired = expiresAt ? new Date() > new Date(expiresAt) : false;
    const expiresAtFormatted = expiresAt ? new Date(expiresAt).toLocaleString("vi-VN") : null;

    res.json({
      employee_name: request.employee_name,
      employee_email: request.employee_email,
      department: request.department,
      leave_date: request.leave_date,
      end_date: request.end_date,
      leave_days: request.leave_days,
      reason: request.reason,
      approvalType,
      status: approvalType === "manager" ? request.manager_status : request.hr_status,
      finalStatus: request.status,
      manager_status: request.manager_status,
      hr_status: request.hr_status,
      managerApproverEmail: request.managerApproverEmail,
      hrApproverEmail: request.hrApproverEmail,
      tokenExpired: expired,
      tokenExpiresAt: expiresAtFormatted,
    });
  } catch (error) {
    res.status(500).json({ message: "Error" });
  }
});


// Helper: compute end_date from a Date object and leave_days
function computeEndDate(leave_date, leave_days) {
  if (!leave_date || !leave_days) return null;
  const d = new Date(leave_date);
  d.setDate(d.getDate() + parseInt(leave_days) - 1);
  return d.toISOString().split('T')[0];
}

module.exports = router;
