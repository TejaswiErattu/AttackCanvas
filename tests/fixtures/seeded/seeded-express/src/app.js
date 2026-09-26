const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const helmet = require("helmet");
const cors = require("cors");
const { requireAdmin } = require("./middleware");
const authRouter = require("./routes/auth");
const invoicesRouter = require("./routes/invoices");
const reportsRouter = require("./routes/reports");
const adminRouter = require("./routes/admin");

const app = express();

// SEEDED:x-ctl-helmet-app
app.use(helmet());
// SEEDED:x-cors-reflect
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URL }),
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: true, sameSite: "lax" },
  }),
);

app.use("/api/auth", authRouter);
app.use("/api/invoices", invoicesRouter);
app.use("/api/reports", reportsRouter);
// SEEDED:x-ctl-admin-prefix
app.use("/api/admin", requireAdmin);
app.use("/api/admin", adminRouter);

module.exports = app;
