// SEEDED:x-plain-webhook
const PARTNER_WEBHOOK = "http://hooks.seeded-partner.net/v1/invoices";

async function notifyInvoiceCreated(invoice) {
  await fetch(PARTNER_WEBHOOK, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ id: String(invoice.id), amountCents: invoice.amountCents }),
  });
}

module.exports = { notifyInvoiceCreated };
