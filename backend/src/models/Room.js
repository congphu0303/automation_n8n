const mongoose = require("mongoose");

const roomSchema = new mongoose.Schema(
  {
    room_id: {
      type: String,
      required: [true, "Room ID is required"],
      unique: true,
      uppercase: true,
      trim: true,
    },

    name: {
      type: String,
      required: [true, "Room name is required"],
      trim: true,
      maxlength: 100,
    },

    capacity: {
      type: Number,
      required: [true, "Capacity is required"],
      min: 1,
      max: 500,
    },

    floor: {
      type: String,
      required: [true, "Floor is required"],
      trim: true,
    },

    facilities: {
      type: [String],
      default: [],
    },

    // active = có thể đặt, maintenance = đang bảo trì
    status: {
      type: String,
      enum: ["active", "maintenance"],
      default: "active",
    },

    // Các khung giờ mặc định làm việc: ["08:00-12:00", "13:00-17:00"]
    working_hours: {
      type: [String],
      default: ["08:00-17:00"],
    },
  },
  {
    timestamps: true,
  }
);

// Index để query nhanh
roomSchema.index({ status: 1 });
roomSchema.index({ floor: 1 });
roomSchema.index({ capacity: 1 });

module.exports = mongoose.model("Room", roomSchema);
