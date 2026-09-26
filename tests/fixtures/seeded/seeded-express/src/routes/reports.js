const express = require("express");
const childProcess = require("node:child_process");
const { ObjectId } = require("mongodb");
const { canReadReport } = require("@northwind/policy");
const { collection } = require("../db");
const { requireLogin } = require("../middleware");

const router = express.Router();

// SEEDED:x-export-cmd
router.get("/export", requireLogin, (req, res) => {
  const archive = childProcess.execSync("tar -czf - reports/" + req.query.name);
  res.type("application/gzip").send(archive);
});

// SEEDED:x-ctl-cross-pkg-authz
router.get("/:reportId", requireLogin, canReadReport, async (req, res) => {
  const report = await collection("reports").findOne({ _id: new ObjectId(req.params.reportId) });
  if (!report) return res.status(404).end();
  res.json(report);
});

module.exports = router;
