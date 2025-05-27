const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const router = express.Router();

// Map roles → permissions
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

  const token = jwt.sign(payload, process.env.ACCESS_SECRET, {
    expiresIn: "1h",
  });

  const accessToken = jwt.sign(payload, process.env.ACCESS_SECRET, {
    expiresIn: "300m",
  });
  const refreshToken = jwt.sign({ id: user._id }, process.env.REFRESH_SECRET, {
    expiresIn: "7d",
  });
  return { accessToken, refreshToken };
};

router.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  // default role = user
  const user = await User.create({
    name,
    email,
    password: hashed,
    role: "user",
    permissions: ["read", "write", "delete"],
  });
  res.status(201).json({ message: "User created" });
});

router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: "Invalid credentials" });

  // Fallback in case permissions were empty
  if (!user.permissions || user.permissions.length === 0) {
    user.permissions = ["read", "write"];
  }

  const { accessToken, refreshToken } = generateTokens(user);
  user.refreshToken = refreshToken;
  await user.save();

  res.cookie("refreshToken", refreshToken, { httpOnly: true });
  res.json({ accessToken, user });
});

router.post("/refresh", async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.sendStatus(401);

  try {
    const payload = jwt.verify(token, process.env.REFRESH_SECRET);
    const user = await User.findById(payload.id);
    if (!user || user.refreshToken !== token) return res.sendStatus(403);

    const { accessToken, refreshToken } = generateTokens(user);
    user.refreshToken = refreshToken;
    await user.save();

    res.cookie("refreshToken", refreshToken, { httpOnly: true });
    res.json({ accessToken });
  } catch {
    res.sendStatus(403);
  }
});

router.post("/logout", async (req, res) => {
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
});

// (Optional) Admin-only: change user role/permissions
router.post("/permissions", async (req, res) => {
  console.log(req.body);
  const { email, permissions } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ error: "User not found" });

  user.permissions = permissions;
  await user.save();
  res.json({
    message: "Role & permissions updated",
    permissions: user.permissions,
  });
});

module.exports = router;
