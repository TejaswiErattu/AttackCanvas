import { NextResponse } from "next/server";
import { verifyAccessToken, type TokenClaims } from "@/lib/tokens";

type Handler<C> = (request: Request, user: TokenClaims, context: C) => Promise<Response>;

export function withAuth<C>(handler: Handler<C>) {
  return async (request: Request, context: C): Promise<Response> => {
    const header = request.headers.get("authorization") ?? "";
    const user = header.startsWith("Bearer ") ? verifyAccessToken(header.slice(7)) : null;
    if (!user) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
    return handler(request, user, context);
  };
}

export function withRole<C>(role: TokenClaims["role"], handler: Handler<C>) {
  return withAuth<C>(async (request, user, context) => {
    if (user.role !== role) return NextResponse.json({ error: "forbidden" }, { status: 403 });
    return handler(request, user, context);
  });
}
