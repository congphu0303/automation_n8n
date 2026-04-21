/**
 * Script tạo tài khoản Manager và HR
 * Chạy: node scripts/create-admin-users.js
 */
require("dotenv").config({ path: require("path").resolve(__dirname, "../.env") });
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const User = require("../src/models/User");

const users = [
  {
    name: "HR Admin",
    email: "phupc.23ite@vku.udn.vn",
    password: "Manager@123",
    department: "HR",
    role: "hr",
  },
  {
    name: "IT Manager",
    email: "tjpeter020@gmail.com",
    password: "Manager@123",
    department: "IT",
    role: "manager",
  },
];

async function createUsers() {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("✅ Connected to MongoDB");

    for (const u of users) {
      const exists = await User.findOne({ email: u.email });
      if (exists) {
        // Update role nếu user đã tồn tại
        exists.role = u.role;
        exists.department = u.department;
        exists.name = u.name;
        await exists.save();
        console.log(`♻️  Updated: ${u.email} → role: ${u.role}`);
      } else {
        const hashed = await bcrypt.hash(u.password, 10);
        const user = new User({ ...u, password: hashed });
        await user.save();
        console.log(`✅ Created: ${u.email} → role: ${u.role}`);
      }
    }

    console.log("\n🎉 Done! Thông tin đăng nhập:");
    console.log("   HR: phupc.23ite@vku.udn.vn / Manager@123");
    console.log("   Manager: tjpeter020@gmail.com / Manager@123");
  } catch (err) {
    console.error("❌ Error:", err.message);
  } finally {
    await mongoose.disconnect();
  }
}

createUsers();
