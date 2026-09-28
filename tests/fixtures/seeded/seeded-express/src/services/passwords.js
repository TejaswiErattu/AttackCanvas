const crypto = require("node:crypto");

function newSalt() {
  return crypto.randomBytes(16).toString("hex");
}

function hashPassword(password, salt) {
  // SEEDED:x-md5-password
  return crypto.createHash("md5").update(salt + password).digest("hex");
}

module.exports = { newSalt, hashPassword };
