const express = require("express");
const { ObjectId } = require("mongodb");
const { collection } = require("../db");
const { requireLogin } = require("../middleware");

const router = express.Router();

// SEEDED:x-ctl-admin-prefix
router.get("/users/:userId", requireLogin, async (req, res) => {
  const user = await collection("users").findOne(
    { _id: new ObjectId(req.params.userId) },
    { projection: { passwordHash: 0, salt: 0 } },
  );
  if (!user) return res.status(404).end();
  res.json(user);
});

module.exports = router;
