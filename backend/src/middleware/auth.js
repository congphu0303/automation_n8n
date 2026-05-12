const jwt = require("jsonwebtoken");

const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "No token provided" });
  }
  const token = authHeader.split(" ")[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
};

const verifyN8nSecret = (req, res, next) => {
  const configuredSecret = process.env.N8N_SECRET_KEY;
  if (!configuredSecret) {
    // Refuse access if secret is not configured — never silently skip
    return res.status(500).json({ message: "Server misconfigured: N8N_SECRET_KEY not set" });
  }
  const n8nSecret = req.headers["x-n8n-secret"];
  if (!n8nSecret || n8nSecret !== configuredSecret) {
    return res.status(401).json({ message: "Unauthorized: Invalid secret key" });
  }
  next();
};

module.exports = { verifyToken, verifyN8nSecret };
