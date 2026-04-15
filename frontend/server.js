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

// Meeting Room routes
app.get("/rooms", (req, res) => res.sendFile(path.join(__dirname, "rooms.html")));
app.get("/book-room", (req, res) => res.sendFile(path.join(__dirname, "book-room.html")));
app.get("/booking-dashboard", (req, res) => res.sendFile(path.join(__dirname, "booking-dashboard.html")));
app.get("/meeting-approvals", (req, res) => res.sendFile(path.join(__dirname, "meeting-approvals.html")));

app.listen(PORT, () => {
  console.log(`🚀 Frontend running at http://localhost:${PORT}`);
});
