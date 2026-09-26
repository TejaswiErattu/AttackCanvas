import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback) as (
  password: string,
  salt: Buffer,
  keylen: number,
) => Promise<Buffer>;

// SEEDED:m-ctl-cross-pkg-kdf
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await scrypt(password, salt, 64);
  return `${salt.toString("hex")}:${key.toString("hex")}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [saltHex, keyHex] = stored.split(":");
  const expected = Buffer.from(keyHex ?? "", "hex");
  const actual = await scrypt(password, Buffer.from(saltHex ?? "", "hex"), expected.length);
  return expected.length > 0 && timingSafeEqual(expected, actual);
}
