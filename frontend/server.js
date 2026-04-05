const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Serve static files
app.use(express.static(__dirname));

// Routes
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "login.html")));
app.get("/leave", (req, res) => res.sendFile(path.join(__dirname, "leave.html")));
app.get("/approvals", (req, res) => res.sendFile(path.join(__dirname, "approvals.html")));

app.listen(PORT, () => {
  console.log(`🚀 Frontend running at http://localhost:${PORT}`);
});
