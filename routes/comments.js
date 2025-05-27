const express = require("express");
const jwt = require("jsonwebtoken");
const Comment = require("../models/Comment");
const router = express.Router();
const User = require("../models/User");

// authMiddleware now also provides req.user.role
const authMiddleware = (requiredPermission) => async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);

  try {
    const payload = jwt.verify(token, process.env.ACCESS_SECRET);
    req.user = payload;
    const { email, permissions } = payload;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });
    if (!user.permissions.includes(requiredPermission)) {
      return res.sendStatus(403);
    }
    next();
  } catch (err) {
    console.error(err);
    res.sendStatus(403);
  }
};

// READ all comments - anyone with 'read'
router.get("/", async (req, res) => {
  try {
    const comments = await Comment.find().populate("userId", "name");
    res.json(comments);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch comments" });
  }
});

// WRITE a new comment - 'user' or 'admin'
router.post("/", authMiddleware("write"), async (req, res) => {
  try {
    const comment = await Comment.create({
      text: req.body.text,
      userId: req.user.id,
    });
    res.status(201).json(comment);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to post comment" });
  }
});

// helper functions
const getToken = async (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);
  return token;
};

const getUserByToken = async (token) => {
  const payload = jwt.verify(token, process.env.ACCESS_SECRET);
  const { email } = payload;
  const user = await User.findOne({ email });
  if (!user) throw new Error("User not found");
  return user;
};

// DELETE a comment - admin can delete any
router.delete("/:id", authMiddleware("deleteAny"), async (req, res) => {
  try {
    const comment = await Comment.findById(req.params.id);
    if (!comment) return res.status(404).json({ error: "Comment not found" });

    const token = await getToken(req, res);
    const user = await getUserByToken(token);

    // if not admin, ensure owner
    if (user.role !== "admin" && comment.userId.toString() !== req.user.id) {
      return res
        .status(403)
        .json({ error: "Not allowed to delete this comment" });
    }
    await comment.deleteOne();
    res.status(204).json({ msg: "Successfully deleted the comment" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to delete comment" });
  }
});

module.exports = router;
