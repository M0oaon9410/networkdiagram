// Time-based one-time codes (RFC 6238, the 6-digit codes of Google / Microsoft Authenticator),
// recovery codes, and the QR code shown when a user sets up an authenticator app.
"use strict";
const crypto = require("crypto");
const qrcode = require("./vendor/qrcode");

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const STEP_MS = 30e3;

function base32(buf) {
  let bits = 0, val = 0, out = "";
  for (const b of buf) {
    val = ((val << 8) | b) & 0xffff; bits += 8;
    while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(val << (5 - bits)) & 31];
  return out;
}
function unbase32(s) {
  let bits = 0, val = 0;
  const out = [];
  for (const c of String(s).toUpperCase().replace(/[\s=]/g, "")) {
    const i = B32.indexOf(c);
    if (i < 0) throw new Error("bad base32");
    val = ((val << 5) | i) & 0xffff; bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}

const newSecret = () => base32(crypto.randomBytes(20));

function hotp(key, counter, digits = 6) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac("sha1", key).update(msg).digest();
  const o = h[h.length - 1] & 15;
  const n = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 10 ** digits).padStart(digits, "0");
}

// The time step a code belongs to, or null. One step either side allows for clock drift;
// steps at or before lastStep were already used, so a code works only once.
function checkCode(secret, code, lastStep = 0, at = Date.now()) {
  code = String(code || "").replace(/\s/g, "");
  if (!/^\d{6}$/.test(code)) return null;
  const key = unbase32(secret), step = Math.floor(at / STEP_MS);
  for (const s of [step - 1, step, step + 1]) {
    if (s <= lastStep) continue;
    if (crypto.timingSafeEqual(Buffer.from(hotp(key, s)), Buffer.from(code))) return s;
  }
  return null;
}

// Recovery codes look like "k7rm-q2xe"; only their hashes are stored.
const RC_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789";
const normRecovery = (c) => String(c || "").toLowerCase().replace(/[^a-z0-9]/g, "");
const hashRecovery = (c) => crypto.createHash("sha256").update("aon-recovery:" + normRecovery(c)).digest("hex");
function newRecoveryCodes(n = 10) {
  return Array.from({ length: n }, () => {
    const b = crypto.randomBytes(8);
    const s = [...b].map((x) => RC_ALPHABET[x % RC_ALPHABET.length]).join("");
    return s.slice(0, 4) + "-" + s.slice(4);
  });
}

const otpauthUri = (issuer, account, secret) =>
  `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;

// QR code as a small SVG (black squares on white, 4-module quiet zone).
function qrSvg(text) {
  const q = qrcode(0, "M");
  q.addData(text);
  q.make();
  const n = q.getModuleCount(), m = 4, size = n + m * 2;
  let d = "";
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (q.isDark(r, c)) d += `M${c + m} ${r + m}h1v1h-1z`;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges"><rect width="${size}" height="${size}" fill="#fff"/><path d="${d}" fill="#000"/></svg>`;
}

module.exports = { base32, unbase32, newSecret, hotp, checkCode, newRecoveryCodes, hashRecovery, normRecovery, otpauthUri, qrSvg, STEP_MS };
