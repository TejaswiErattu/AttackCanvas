const express = require("express");
const { z } = require("zod");
const { ObjectId } = require("mongodb");
const { collection } = require("../db");
const { requireLogin } = require("../middleware");
const { notifyInvoiceCreated } = require("../services/notify");

const router = express.Router();

const NewInvoice = z.object({
  customer: z.string().min(1),
  amountCents: z.number().int().positive(),
});

// SEEDED:x-ctl-express5-async
router.get("/", requireLogin, async (req, res) => {
  const invoices = await collection("invoices").find({ ownerId: req.session.userId }).toArray();
  res.json(invoices);
});

// SEEDED:x-ctl-barrel-login
router.post("/", requireLogin, async (req, res) => {
  const input = NewInvoice.parse(req.body);
  const result = await collection("invoices").insertOne({ ...input, ownerId: req.session.userId });
  await notifyInvoiceCreated({ id: result.insertedId, amountCents: input.amountCents });
  res.status(201).json({ id: result.insertedId });
});

// SEEDED:x-authz-invoice
router.get("/:invoiceId", requireLogin, async (req, res) => {
  const invoice = await collection("invoices").findOne({ _id: new ObjectId(req.params.invoiceId) });
  if (!invoice) return res.status(404).end();
  res.json(invoice);
});

module.exports = router;
