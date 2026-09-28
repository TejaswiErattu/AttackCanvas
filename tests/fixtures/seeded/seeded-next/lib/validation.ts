import { z } from "zod";

export const LoginInput = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

export const OrderInput = z.object({
  sku: z.string().min(1),
  quantity: z.number().int().positive(),
});

export const ExportRange = z.object({
  from: z.string().datetime(),
  to: z.string().datetime(),
});
