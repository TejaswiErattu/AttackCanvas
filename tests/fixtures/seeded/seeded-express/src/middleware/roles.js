function requireAdmin(req, res, next) {
  if (req.session.role !== "admin") {
    return res.status(403).json({ error: "forbidden" });
  }
  next();
}

module.exports = { requireAdmin };
