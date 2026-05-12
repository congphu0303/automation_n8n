const https = require("https");
const http = require("http");

const WEBHOOK_URL = "https://n8n.internalautomation.io.vn/webhook/nhan-yeu-cau-dat-phong";
const N8N_API = "http://n8n.internalautomation.io.vn";
const N8N_EMAIL = process.env.N8N_EMAIL || "";
const N8N_PASS = process.env.N8N_PASS || "";

function callWebhook() {
  return new Promise((resolve, reject) => {
    const payload = {
      bookingId: "TEST-WF-" + Date.now(),
      requesterName: "Nguyễn Văn A",
      requesterEmail: "quanganh.hs2005@gmail.com",
      department: "IT",
      roomName: "Phòng họp 101",
      roomCapacity: 10,
      meetingDate: "2026-05-27",
      startTime: "10:00",
      endTime: "11:00",
      purpose: "Họp test workflow",
      attendees: 3,
      priority: "normal",
      managerEmail: "quanganh.hs2005@gmail.com",
      notes: "Test từ script",
    };

    const body = JSON.stringify(payload);
    const url = new URL(WEBHOOK_URL);
    const opts = {
      hostname: url.hostname, port: 443, path: url.pathname,
      method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) },
      rejectUnauthorized: false,
    };
    const req = https.request(opts, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve({ status: res.statusCode, body: data }));
    });
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

function login() {
  return new Promise((resolve, reject) => {
    if (!N8N_EMAIL) return resolve("");
    const data = JSON.stringify({ email: N8N_EMAIL, password: N8N_PASS });
    const url = new URL(N8N_API);
    const opts = {
      hostname: url.hostname, port: 80, path: "/rest/login",
      method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) },
    };
    const req = http.request(opts, (res) => {
      let body = "";
      res.on("data", (c) => (body += c));
      res.on("end", () => {
        const cookie = res.headers["set-cookie"];
        resolve(cookie ? cookie.join("; ") : "");
      });
    });
    req.on("error", reject);
    req.write(data);
    req.end();
  });
}

function getExecutions(cookie) {
  return new Promise((resolve, reject) => {
    const url = new URL(N8N_API);
    const opts = {
      hostname: url.hostname, port: 80,
      path: "/rest/executions?limit=5&includeData=true",
      headers: cookie ? { Cookie: cookie } : {},
    };
    http.get(opts, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve(JSON.parse(data)));
    }).on("error", reject);
  });
}

(async () => {
  console.log("1. Gửi webhook...");
  const wh = await callWebhook();
  console.log(`   HTTP ${wh.status}: ${wh.body.slice(0, 200)}`);

  if (!N8N_EMAIL) {
    console.log("\n2. Bỏ qua kiểm tra execution (set N8N_EMAIL để xem log)");
    console.log("\nVí dụ: N8N_EMAIL=admin@example.com N8N_PASS=admin123 node scripts/test-n8n-workflow.js");
    return;
  }

  console.log("\n2. Đăng nhập n8n API...");
  const cookie = await login();
  if (!cookie) { console.log("   Login thất bại"); return; }
  console.log("   OK");

  await new Promise(r => setTimeout(r, 3000));

  console.log("\n3. Executions gần nhất:");
  const execs = await getExecutions(cookie);
  const results = execs.data?.results || execs.data || [];
  for (const ex of results.slice(0, 3)) {
    const id = ex.id;
    const status = ex.status || "?";
    const createdAt = ex.createdAt ? new Date(ex.createdAt).toLocaleString("vi-VN") : "?";
    const workflow = ex.workflowId || "?";
    console.log(`   #${id} | ${status} | ${workflow} | ${createdAt}`);
    if (ex.data?.resultData?.error) {
      console.log(`   LỖI: ${ex.data.resultData.error.message}`);
    }
  }
})();
