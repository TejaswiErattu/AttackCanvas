import express from "express";
import cookieSession from "cookie-session";
import { errorHandler } from "./errors";
import { requestLogger } from "./logging";
import accountRouter from "./routes/account";
import authRouter from "./routes/auth";
import documentsRouter from "./routes/documents";
import projectsRouter from "./routes/projects";
import reportsRouter from "./routes/reports";

export const app = express();

// SEEDED:m-ctl-request-logger
app.use(requestLogger);
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(
  cookieSession({
    name: "acme.sid",
    keys: [process.env.SESSION_KEY ?? ""],
    httpOnly: true,
    secure: true,
    sameSite: "lax",
  }),
);

app.use("/account", accountRouter);
app.use("/api/auth", authRouter);
app.use("/api/documents", documentsRouter);
app.use("/api/projects", projectsRouter);
app.use("/api/reports", reportsRouter);

// SEEDED:m-ctl-error-mw
app.use(errorHandler({ log: true }));
