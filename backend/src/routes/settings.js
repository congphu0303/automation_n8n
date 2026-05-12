const express = require("express");
const Settings = require("../models/Settings");
const { verifyToken } = require("../middleware/auth");
const { getEmailFromSettings, getAllManagerEmails } = require("../helpers/settings");

const router = express.Router();

// GET /api/settings/manager-emails - Lấy cấu hình email (HR only)
router.get("/manager-emails", verifyToken, async (req, res) => {
  if (req.user.role !== "hr") {
    return res.status(403).json({ message: "Chỉ HR mới có quyền xem" });
  }
  try {
    const value = await getAllManagerEmails();
    res.json(value);
  } catch (error) {
    res.status(500).json({ message: "Error fetching settings" });
  }
});

// PUT /api/settings/manager-emails - Cập nhật email manager (HR only)
router.put("/manager-emails", verifyToken, async (req, res) => {
  if (req.user.role !== "hr") {
    return res.status(403).json({ message: "Chỉ HR mới có quyền cập nhật" });
  }
  try {
    const { IT, Marketing, Finance, Sales, hrEmail } = req.body;
    const value = { IT, Marketing, Finance, Sales, hrEmail };
    await Settings.findOneAndUpdate(
      { key: "manager_emails" },
      { $set: { value } },
      { upsert: true, new: true }
    );
    res.json({ message: "Cập nhật thành công", value });
  } catch (error) {
    res.status(500).json({ message: "Error saving settings" });
  }
});

// GET /api/settings/lookup?department=IT - Lookup manager email (public, for N8N)
// N8N calls this to resolve manager email before creating records
router.get("/lookup", async (req, res) => {
  try {
    const { department, type } = req.query;
    if (!department && !type) {
      return res.status(400).json({ message: "department or type query param required" });
    }
    const email = await getEmailFromSettings(department, type);
    res.json({ email, department, type });
  } catch (error) {
    res.status(404).json({ message: error.message });
  }
});

// GET /api/settings/all - Get all settings (for N8N internal use)
router.get("/all", async (req, res) => {
  try {
    const settings = await Settings.find();
    const result = {};
    settings.forEach(s => { result[s.key] = s.value; });
    res.json(result);
  } catch (error) {
    res.status(500).json({ message: "Error fetching settings" });
  }
});

module.exports = router;
