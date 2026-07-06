const jwt = require("jsonwebtoken");

// Seeded vulnerability: fallback secret survives into a "default" that would
// ship to production if JWT_SECRET is ever unset.
const SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

function requireAuth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "unauthorized" });
  try {
    // Seeded vulnerability: no `algorithms` allow-list passed to verify.
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: "invalid token" });
  }
}

module.exports = { requireAuth };
