// Route handlers import their guards from "@/lib/auth", never from ./session directly.
// SEEDED:n-ctl-with-auth-barrel
export { withAuth, withRole } from "./session";
