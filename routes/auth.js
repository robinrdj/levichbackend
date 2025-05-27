const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const router = express.Router();

const ROLE_PERMISSIONS = {
  guest: ["read"],
  user: ["read", "write"],
  admin: ["read", "write", "deleteAny"],
};

function getPermissionsByRole(role) {
  return ROLE_PERMISSIONS[role] || ROLE_PERMISSIONS.guest;
}

const generateTokens = (user) => {
  user.permissions = getPermissionsByRole(user.role);
  const payload = {
    id: user._id,
    name: user.name,
    email: user.email,
    role: user.role,
    permissions: user.permissions,
  };
  const accessToken = jwt.sign(payload, process.env.ACCESS_SECRET, {
    expiresIn: "1d",
  });
  const refreshToken = jwt.sign({ id: user._id }, process.env.REFRESH_SECRET, {
    expiresIn: "30d",
  });
  return { accessToken, refreshToken };
};

// Signup
router.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({
      name,
      email,
      password: hashed,
      role: "user",
      permissions: ["read", "write"],
    });
    res.status(201).json({ message: "User created" });
  } catch (err) {
    console.error("Signup Error:", err);
    res.status(500).json({ error: "Signup failed" });
  }
});

// Login
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ error: "Invalid credentials" });
    if (!user.permissions || user.permissions.length === 0) {
      user.permissions = ["read", "write"];
    }
    const { accessToken, refreshToken } = generateTokens(user);
    user.refreshToken = refreshToken;
    await user.save();
    res.cookie("refreshToken", refreshToken, { httpOnly: true });
    res.json({ accessToken, user });
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

// Refresh Token
router.post("/refresh", async (req, res) => {
  try {
    const token = req.cookies.refreshToken;
    if (!token) return res.sendStatus(401);
    const payload = jwt.verify(token, process.env.REFRESH_SECRET);
    const user = await User.findById(payload.id);
    if (!user || user.refreshToken !== token) return res.sendStatus(403);
    const { accessToken, refreshToken } = generateTokens(user);
    user.refreshToken = refreshToken;
    await user.save();
    res.cookie("refreshToken", refreshToken, { httpOnly: true });
    res.json({ accessToken });
  } catch (err) {
    console.error("Refresh Token Error:", err);
    res.sendStatus(403);
  }
});

// Logout
router.post("/logout", async (req, res) => {
  try {
    const token = req.cookies.refreshToken;
    if (token) {
      const user = await User.findOne({ refreshToken: token });
      if (user) {
        user.refreshToken = null;
        await user.save();
      }
    }
    res.clearCookie("refreshToken");
    res.sendStatus(204);
  } catch (err) {
    console.error("Logout Error:", err);
    res.status(500).json({ error: "Logout failed" });
  }
});

// Admin: Update Role/Permissions
router.post("/permissions", async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });
    user.permissions = ["read", "write", "deleteAny"];
    user.role = "admin";
    await user.save();
    res.json({
      message: "Role & permissions updated",
      permissions: user.permissions,
    });
  } catch (err) {
    console.error("Permission Update Error:", err);
    res.status(500).json({ error: "Failed to update permissions" });
  }
});

// Forgot Password
router.post("/forgot", async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });
    const token = jwt.sign(
      { id: user._id },
      process.env.RESET_PASSWORD_SECRET,
      {
        expiresIn: "15m",
      }
    );
    const resetLink = `${process.env.FRONTEND_URL}/reset-password/${token}`;
    console.log("Reset Link:", resetLink); 
    res.json({ message: "Reset link generated", token });
  } catch (err) {
    console.error("Forgot Password Error:", err);
    res.status(500).json({ message: "Failed to process password reset" });
  }
});

// Reset Password
router.post("/reset/:token", async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    const decoded = jwt.verify(token, process.env.RESET_PASSWORD_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) return res.status(404).json({ message: "User not found" });

    const hashed = await bcrypt.hash(password, 10);
    user.password = hashed;
    await user.save();

    res.json({ message: "Password reset successful" });
  } catch (err) {
    console.error("Reset Password Error:", err);
    res.status(400).json({ message: "Invalid or expired token" });
  }
});

module.exports = router;
