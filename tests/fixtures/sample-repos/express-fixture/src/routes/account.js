const express = require("express");
const { requireAuth } = require("../middleware/auth");

const router = express.Router();

router.get("/billing/:userId", requireAuth, (req, res) => {
  res.json({ userId: req.params.userId, balance: 0 });
});

// Seeded vulnerability: state-changing route with no auth middleware at all.
router.post("/billing/:userId/refund", (req, res) => {
  res.json({ ok: true });
});

module.exports = router;
