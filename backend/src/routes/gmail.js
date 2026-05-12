const express = require("express");
const { google } = require("googleapis");
const User = require("../models/User");
const { verifyToken } = require("../middleware/auth");

const router = express.Router();

// ───────────────────────────────────────────
// Gmail OAuth2 — Per-user Gmail connection
// Allows each employee to connect their Gmail
// so N8N can send emails from their account.
// ───────────────────────────────────────────

/**
 * Create a new OAuth2 client from env vars.
 * Called per-request so redirect URI is always fresh.
 */
function createOAuth2Client() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
  );
}

// GET /api/gmail/auth-url — Generate Google OAuth consent URL
// Frontend calls this, then redirects user to the returned URL.
router.get("/auth-url", verifyToken, async (req, res) => {
  try {
    const oauth2Client = createOAuth2Client();

    // state = JWT userId so callback knows who to save the token for
    const state = Buffer.from(
      JSON.stringify({ userId: req.user.userId })
    ).toString("base64url");

    const authUrl = oauth2Client.generateAuthUrl({
      access_type: "offline", // Required to get refresh_token
      prompt: "consent",      // Force consent screen every time (ensures refresh_token)
      scope: [
        "https://www.googleapis.com/auth/gmail.send",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid"
      ],
      state,
    });

    res.json({ authUrl });
  } catch (error) {
    console.error("[Gmail] Auth URL error:", error.message);
    res.status(500).json({ message: "Không thể tạo liên kết xác thực Google" });
  }
});

// GET /api/gmail/callback — Google redirects here after user grants permission
// This endpoint is NOT behind verifyToken because it's called by Google's redirect.
// We use the `state` param to identify the user.
router.get("/callback", async (req, res) => {
  const frontendUrl = process.env.FRONTEND_URL || "http://localhost:3000";

  try {
    const { code, state, error: oauthError } = req.query;

    // User denied permission
    if (oauthError) {
      console.warn("[Gmail] OAuth denied:", oauthError);
      return res.redirect(`${frontendUrl}/profile?gmail=denied`);
    }

    if (!code || !state) {
      return res.redirect(`${frontendUrl}/profile?gmail=error&reason=missing_params`);
    }

    // Decode state to get userId
    let userId;
    try {
      const decoded = JSON.parse(Buffer.from(state, "base64url").toString("utf8"));
      userId = decoded.userId;
    } catch {
      return res.redirect(`${frontendUrl}/profile?gmail=error&reason=invalid_state`);
    }

    if (!userId) {
      return res.redirect(`${frontendUrl}/profile?gmail=error&reason=no_user`);
    }

    // Exchange authorization code for tokens
    const oauth2Client = createOAuth2Client();
    const { tokens } = await oauth2Client.getToken(code);

    if (!tokens.refresh_token) {
      console.error("[Gmail] No refresh_token received. User may have already granted access.");
      // Still try to proceed — sometimes Google doesn't return refresh_token
      // if user already authorized the app before. prompt: "consent" should prevent this.
      return res.redirect(`${frontendUrl}/profile?gmail=error&reason=no_refresh_token`);
    }

    // Verify that the user actually granted the gmail.send scope
    const grantedScopes = tokens.scope || "";
    if (!grantedScopes.includes("https://www.googleapis.com/auth/gmail.send")) {
      console.error("[Gmail] User did not grant gmail.send scope.");
      // Revoke the token since it's useless without the scope
      try {
        oauth2Client.setCredentials(tokens);
        await oauth2Client.revokeToken(tokens.access_token);
      } catch (e) {}
      return res.redirect(`${frontendUrl}/profile?gmail=error&reason=missing_send_scope`);
    }

    // Get user's Google email address
    oauth2Client.setCredentials(tokens);
    const oauth2 = google.oauth2({ version: "v2", auth: oauth2Client });
    const profile = await oauth2.userinfo.get();
    const gmailEmail = profile.data.email;

    // Save refresh token to user record
    await User.findByIdAndUpdate(userId, {
      gmailRefreshToken: tokens.refresh_token,
      gmailConnected: true,
      gmailEmail: gmailEmail,
    });

    console.log(`[Gmail] Connected for user ${userId} (${gmailEmail})`);
    res.redirect(`${frontendUrl}/profile?gmail=connected`);
  } catch (error) {
    console.error("[Gmail] Callback error:", error.message);
    res.redirect(`${frontendUrl}/profile?gmail=error&reason=exchange_failed`);
  }
});

// GET /api/gmail/status — Check if current user has Gmail connected
router.get("/status", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select(
      "gmailConnected gmailEmail"
    );
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({
      connected: !!user.gmailConnected,
      gmailEmail: user.gmailEmail || null,
    });
  } catch (error) {
    console.error("[Gmail] Status error:", error.message);
    res.status(500).json({ message: "Error checking Gmail status" });
  }
});

// POST /api/gmail/disconnect — Remove Gmail connection for current user
router.post("/disconnect", verifyToken, async (req, res) => {
  try {
    // Optionally revoke the token at Google
    const user = await User.findById(req.user.userId);
    if (user?.gmailRefreshToken) {
      try {
        const oauth2Client = createOAuth2Client();
        await oauth2Client.revokeToken(user.gmailRefreshToken);
      } catch (revokeErr) {
        // Log but don't fail — token may already be invalid
        console.warn("[Gmail] Revoke failed (non-critical):", revokeErr.message);
      }
    }

    await User.findByIdAndUpdate(req.user.userId, {
      gmailRefreshToken: null,
      gmailConnected: false,
      gmailEmail: null,
    });

    console.log(`[Gmail] Disconnected for user ${req.user.userId}`);
    res.json({ success: true, message: "Gmail đã được ngắt kết nối" });
  } catch (error) {
    console.error("[Gmail] Disconnect error:", error.message);
    res.status(500).json({ message: "Error disconnecting Gmail" });
  }
});

module.exports = router;
