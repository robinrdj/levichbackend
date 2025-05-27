const express = require("express");
const jwt = require("jsonwebtoken");
const Comment = require("../models/Comment");
const router = express.Router();

// authMiddleware now also provides req.user.role
const authMiddleware = (requiredPermission) => async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);

  try {
    const payload = jwt.verify(token, process.env.ACCESS_SECRET);
    req.user = payload;
    if (!payload.permissions.includes(requiredPermission))
      return res.sendStatus(403);
    next();
  } catch {
    res.sendStatus(403);
  }
};

// READ all comments - anyone with 'read'
router.get("/", async (req, res) => {
  const comments = await Comment.find().populate("userId", "name");
  res.json(comments);
});

// WRITE a new comment - 'user' or 'admin'
router.post("/", authMiddleware("write"), async (req, res) => {
  const comment = await Comment.create({
    text: req.body.text,
    userId: req.user.id,
  });
  res.status(201).json(comment);
});

// DELETE a comment -
// - admin can delete any
router.delete("/:id", authMiddleware("delete"), async (req, res) => {
  console.log("reached");
  const comment = await Comment.findById(req.params.id);
  if (!comment) return res.status(404).json({ error: "Comment not found" });

  // if not admin, ensure owner
  if (req.user.role !== "admin" && comment.userId.toString() !== req.user.id) {
    return res
      .status(403)
      .json({ error: "Not allowed to delete this comment" });
  }

  await comment.remove();
  res.sendStatus(204);
});

module.exports = router;
