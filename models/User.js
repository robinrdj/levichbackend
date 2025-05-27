const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: {
    type: String,
    enum: ["guest", "user", "admin"],
    default: "guest",
  },
  permissions: [String], // We'll keep this in sync with role
  refreshToken: String,
});

module.exports = mongoose.model("User", userSchema);
