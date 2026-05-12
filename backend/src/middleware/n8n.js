const crypto = require("crypto");

// Generate a random token for approvals/bookings
const generateToken = () => crypto.randomBytes(32).toString("hex");

// Generate base64url-encoded approval token with expiry
const generateApprovalToken = (approverEmail, type) => {
  const randomPart = crypto.randomBytes(24).toString("hex");
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  const payload = {
    r: randomPart,
    e: approverEmail,
    t: type,
    exp: expiresAt.getTime(),
  };
  return Buffer.from(JSON.stringify(payload)).toString("base64url");
};

// Decode base64url approval token
const decodeApprovalToken = (token) => {
  if (!token || typeof token !== "string") return null;
  try {
    const decoded = Buffer.from(token, "base64url").toString("utf8");
    const payload = JSON.parse(decoded);
    if (!payload.r || !payload.t) return null;
    return {
      randomPart: payload.r,
      approverEmail: payload.e,
      type: payload.t,
      expiresAt: new Date(payload.exp),
      isExpired: new Date() > new Date(payload.exp),
    };
  } catch {
    return null;
  }
};

module.exports = { generateToken, generateApprovalToken, decodeApprovalToken };
