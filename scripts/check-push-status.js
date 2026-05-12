const { execSync } = require("child_process");

try {
  console.log("=== KIỂM TRA PUSH CODE ===\n");

  // Local commit
  const local = execSync("git rev-parse HEAD").toString().trim();
  const localMsg = execSync("git log -1 --pretty=%s").toString().trim();
  const localBranch = execSync("git rev-parse --abbrev-ref HEAD").toString().trim();
  console.log(`Local:  ${localBranch} | ${local.slice(0,8)} | "${localMsg}"`);

  // Remote commit
  try {
    execSync("git fetch origin", { stdio: "pipe" });
    const remote = execSync("git rev-parse origin/main").toString().trim();
    const remoteMsg = execSync("git log -1 --pretty=%s origin/main").toString().trim();
    console.log(`Remote: main    | ${remote.slice(0,8)} | "${remoteMsg}"`);

    if (local === remote) {
      console.log("\n✅ ĐÃ push — Local và remote giống nhau");
    } else {
      console.log("\n❌ CHƯA push — Local khác remote");
    }
  } catch {
    console.log("\n❌ Remote chưa có branch main hoặc chưa fetch được");
  }
} catch (e) {
  console.log("Lỗi:", e.message);
}
