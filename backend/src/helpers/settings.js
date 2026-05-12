const Settings = require("../models/Settings");

const isTokenExpired = (expiresAt) => {
  if (!expiresAt) return false;
  return new Date() > new Date(expiresAt);
};

// Returns manager email for a department OR hr email
const getEmailFromSettings = async (department, type) => {
  try {
    const settings = await Settings.findOne({ key: "manager_emails" });
    if (!settings || !settings.value) {
      throw new Error("Chưa cấu hình email Manager. Vui lòng liên hệ HR để cài đặt.");
    }
    if (type === "hr") {
      const hrEmail = settings.value.hrEmail;
      if (!hrEmail) throw new Error("Chưa cấu hình email HR. Vui lòng liên hệ admin.");
      return hrEmail;
    }
    const deptEmail = settings.value[department];
    if (!deptEmail) {
      throw new Error(`Chưa cấu hình email Manager cho phòng ban "${department}". Vui lòng liên hệ HR.`);
    }
    return deptEmail;
  } catch (error) {
    if (error.message.includes("Chưa cấu hình")) {
      throw error;
    }
    console.error("Error fetching settings:", error.message);
    throw new Error("Không thể lấy cấu hình email. Vui lòng thử lại sau.");
  }
};

// Get all manager emails config (for N8N)
const getAllManagerEmails = async () => {
  const settings = await Settings.findOne({ key: "manager_emails" });
  return settings ? settings.value : {};
};

module.exports = { getEmailFromSettings, getAllManagerEmails, isTokenExpired };
