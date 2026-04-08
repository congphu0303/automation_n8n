// ─── Models Index ───
// Export all models in one place for easy imports

const User = require("./User");
const LeaveRequest = require("./LeaveRequest");
const Room = require("./Room");
const Booking = require("./Booking");
const Settings = require("./Settings");

module.exports = {
  User,
  LeaveRequest,
  Room,
  Booking,
  Settings,
};
