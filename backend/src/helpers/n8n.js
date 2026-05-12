const axios = require("axios");

/**
 * Trigger an N8N workflow by calling its webhook URL.
 * Non-blocking: catches errors and logs, never throws.
 * @param {string} webhookPath - e.g. "webhook/leave-create"
 * @param {object} payload - data to send in the request body
 */
async function triggerN8NWorkflow(webhookPath, payload) {
  const baseUrl = process.env.N8N_URL || "http://n8n:5678";
  const url = `${baseUrl}/${webhookPath}`;

  try {
    await axios.post(url, payload, {
      headers: { "Content-Type": "application/json" },
      timeout: 30000,
    });
    console.log(`[N8N] Triggered workflow: ${webhookPath}`);
  } catch (error) {
    // Log but never throw — N8N failure should not break the API response
    console.error(`[N8N] Failed to trigger ${webhookPath}:`, error.message);
  }
}

module.exports = { triggerN8NWorkflow };
