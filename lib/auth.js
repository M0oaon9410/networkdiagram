// Accounts, sessions, roles and e-mail verification for NetPlan.
// Everything lives in DATA_DIR/auth/*.json; tokens are stored only as SHA-256 hashes.
"use strict";
const fs = require("fs");
const fsp = fs.promises;
const path = require("path");
const crypto = require("crypto");
const { sendMail } = require("./mailer");

const ROLES = ["admin", "editor", "viewer"];
const SESSION_DAYS = 30;
const VERIFY_HOURS = 48;
const RESET_HOURS = 1;
const COOKIE = "np_sid";
const EMAIL_RE = /^[^\s@<>"']+@[^\s@<>"']+\.[^\s@<>"']+$/;

const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const token = () => crypto.randomBytes(32).toString("hex");
const now = () => Date.now();

function scrypt(password, salt) {
  return new Promise((resolve, reject) => crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (e, k) => (e ? reject(e) : resolve(k))));
}

class JsonStore {
  constructor(file, init) {
    this.file = file;
    try { this.data = JSON.parse(fs.readFileSync(file, "utf8")); } catch (e) { this.data = init; }
    this.queue = Promise.resolve();
  }
  save() {
    const snapshot = JSON.stringify(this.data, null, 2);
    this.queue = this.queue.then(async () => {
      const tmp = this.file + "." + process.pid + ".tmp";
      await fsp.writeFile(tmp, snapshot, { mode: 0o600 });
      await fsp.rename(tmp, this.file);
    }).catch((e) => console.error("auth store write failed:", e.message));
    return this.queue;
  }
}

function createAuth({ dataDir, env = process.env }) {
  const dir = path.join(dataDir, "auth");
  fs.mkdirSync(dir, { recursive: true });
  const users = new JsonStore(path.join(dir, "users.json"), { users: [] });
  const sessions = new JsonStore(path.join(dir, "sessions.json"), {});
  const settings = new JsonStore(path.join(dir, "settings.json"), {});

  // SMTP from the admin's settings page, falling back to environment variables.
  function smtp() {
    const s = settings.data.smtp || {};
    return {
      host: s.host || env.SMTP_HOST || "",
      port: +(s.port || env.SMTP_PORT || 0) || undefined,
      secure: s.host ? !!s.secure : /^(1|true|yes)$/i.test(env.SMTP_SECURE || ""),
      user: s.host ? s.user || "" : env.SMTP_USER || "",
      pass: s.host ? s.pass || "" : env.SMTP_PASS || "",
      from: (s.host ? s.from : env.SMTP_FROM) || "",
    };
  }
  const mailReady = () => !!smtp().host;
  const appUrl = (req) => (settings.data.appUrl || env.APP_URL || originOf(req)).replace(/\/+$/, "");

  function originOf(req) {
    const proto = (req.headers["x-forwarded-proto"] || "").split(",")[0].trim() || (req.socket.encrypted ? "https" : "http");
    return `${proto}://${req.headers.host || "localhost"}`;
  }

  const findByEmail = (email) => users.data.users.find((u) => u.email === email);
  const findById = (id) => users.data.users.find((u) => u.id === id);
  const publicUser = (u) => ({ id: u.id, email: u.email, name: u.name, role: u.role, verified: !!u.verified, createdAt: u.createdAt, lastLogin: u.lastLogin || null });
  const admins = () => users.data.users.filter((u) => u.role === "admin" && u.verified);

  // ---- e-mail ----
  const mailShell = (title, body, link, cta) => ({
    html: `<div style="font-family:Tahoma,Arial,sans-serif;max-width:520px;margin:auto;color:#1c2430"><h2 style="font-size:18px">${title}</h2><p style="line-height:1.6">${body}</p><p><a href="${link}" style="display:inline-block;background:#2652c4;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none">${cta}</a></p><p style="color:#6b7684;font-size:12px;line-height:1.6">หากกดปุ่มไม่ได้ ให้คัดลอกลิงก์นี้ไปเปิดในเบราว์เซอร์ / If the button does not work, open this link:<br>${link}</p></div>`,
    text: `${title}\n\n${body.replace(/<br>/g, "\n")}\n\n${link}\n`,
  });
  async function deliver(to, subject, parts, linkForLog) {
    if (!mailReady()) {
      console.log(`[netplan] SMTP not configured. ${subject} for ${to}: ${linkForLog}`);
      return false;
    }
    try { await sendMail(smtp(), { to, subject, ...parts }); return true; }
    catch (e) { console.error(`[netplan] mail to ${to} failed: ${e.message}. Link: ${linkForLog}`); return false; }
  }
  function sendVerify(req, u) {
    const t = token();
    u.verifyHash = sha(t); u.verifyExp = now() + VERIFY_HOURS * 3600e3;
    const link = `${appUrl(req)}/verify?token=${t}`;
    return deliver(u.email, "ยืนยันอีเมลสำหรับ NetPlan / Verify your NetPlan e-mail",
      mailShell("ยืนยันอีเมลของคุณ / Verify your e-mail", `สวัสดีคุณ ${escapeHtml(u.name)}<br>กดปุ่มด้านล่างเพื่อยืนยันอีเมลและเปิดใช้บัญชี NetPlan ลิงก์ใช้ได้ ${VERIFY_HOURS} ชั่วโมง<br>Click the button to verify your e-mail and activate your account.`, link, "ยืนยันอีเมล / Verify"), link);
  }
  function sendReset(req, u) {
    const t = token();
    u.resetHash = sha(t); u.resetExp = now() + RESET_HOURS * 3600e3;
    const link = `${appUrl(req)}/?reset=${t}`;
    return deliver(u.email, "ตั้งรหัสผ่านใหม่ NetPlan / Reset your NetPlan password",
      mailShell("ตั้งรหัสผ่านใหม่ / Reset password", `มีการขอตั้งรหัสผ่านใหม่สำหรับบัญชี ${escapeHtml(u.email)} ลิงก์ใช้ได้ ${RESET_HOURS} ชั่วโมง ถ้าคุณไม่ได้ขอ ไม่ต้องทำอะไร<br>Someone asked to reset this account's password. Ignore this if it was not you.`, link, "ตั้งรหัสผ่านใหม่ / Reset password"), link);
  }

  // ---- sessions ----
  function parseCookies(req) {
    const out = {};
    for (const part of (req.headers.cookie || "").split(";")) {
      const i = part.indexOf("="); if (i < 0) continue;
      out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
    }
    return out;
  }
  function currentUser(req) {
    const t = parseCookies(req)[COOKIE];
    if (!t) return null;
    const s = sessions.data[sha(t)];
    if (!s || s.exp < now()) return null;
    const u = findById(s.uid);
    return u && u.verified ? u : null;
  }
  function cookieHeader(req, value, maxAge) {
    const secure = originOf(req).startsWith("https") ? "; Secure" : "";
    return `${COOKIE}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`;
  }
  function startSession(req, res, u) {
    const t = token();
    for (const [k, s] of Object.entries(sessions.data)) if (s.exp < now()) delete sessions.data[k];
    sessions.data[sha(t)] = { uid: u.id, exp: now() + SESSION_DAYS * 864e5 };
    sessions.save();
    res.setHeader("Set-Cookie", cookieHeader(req, t, SESSION_DAYS * 86400));
  }
  function dropSessions(uid, keepReq) {
    const keep = keepReq && parseCookies(keepReq)[COOKIE];
    for (const [k, s] of Object.entries(sessions.data)) if (s.uid === uid && (!keep || k !== sha(keep))) delete sessions.data[k];
    sessions.save();
  }

  // ---- brute-force guard: 10 failures per IP+email in 15 minutes ----
  const fails = new Map();
  const failKey = (req, email) => (req.socket.remoteAddress || "") + "|" + email;
  function tooMany(req, email) {
    const f = fails.get(failKey(req, email));
    return f && f.n >= 10 && f.until > now();
  }
  function noteFail(req, email) {
    const k = failKey(req, email), f = fails.get(k);
    if (!f || f.until < now()) fails.set(k, { n: 1, until: now() + 15 * 60e3 }); else f.n++;
    if (fails.size > 5000) fails.clear();
  }

  function checkPassword(p) {
    return typeof p === "string" && p.length >= 8 && p.length <= 200;
  }
  async function setPassword(u, p) {
    u.salt = crypto.randomBytes(16).toString("hex");
    u.hash = (await scrypt(p, u.salt)).toString("hex");
  }
  async function passwordOk(u, p) {
    if (!u || !u.hash || typeof p !== "string") { await scrypt("x", "dummy-salt-value"); return false; }
    const k = await scrypt(p, u.salt);
    return crypto.timingSafeEqual(k, Buffer.from(u.hash, "hex"));
  }

  // ---- HTTP handlers; each returns [status, body] ----
  async function register(req, b) {
    const email = String(b.email || "").trim().toLowerCase();
    const name = String(b.name || "").trim().slice(0, 80);
    if (!EMAIL_RE.test(email) || email.length > 200) return [400, { error: "bad_email" }];
    if (!name) return [400, { error: "bad_name" }];
    if (!checkPassword(b.password)) return [400, { error: "weak_password" }];
    const existing = findByEmail(email);
    if (existing && existing.verified) return [409, { error: "exists" }];
    // A pending account keeps its first password; only the inbox owner can change it (via reset).
    if (existing) { const mailed = await sendVerify(req, existing); await users.save(); return [201, { ok: true, mailed }]; }
    const first = !users.data.users.some((x) => x.verified);
    const u = { id: crypto.randomBytes(8).toString("hex"), email, name, createdAt: new Date().toISOString() };
    users.data.users.push(u);
    await setPassword(u, b.password);
    // The very first account becomes the administrator and is active at once,
    // because nobody can have set up e-mail sending yet.
    if (first) {
      u.role = "admin"; u.verified = true;
      if (!settings.data.appUrl && !env.APP_URL) { settings.data.appUrl = originOf(req); settings.save(); }
      await users.save();
      return [201, { ok: true, first: true }];
    }
    u.role = ROLES.includes(env.DEFAULT_ROLE) && env.DEFAULT_ROLE !== "admin" ? env.DEFAULT_ROLE : "viewer";
    u.verified = false;
    const mailed = await sendVerify(req, u);
    await users.save();
    return [201, { ok: true, mailed }];
  }

  async function login(req, res, b) {
    const email = String(b.email || "").trim().toLowerCase();
    if (tooMany(req, email)) return [429, { error: "too_many" }];
    const u = findByEmail(email);
    if (!(await passwordOk(u, b.password))) { noteFail(req, email); return [401, { error: "bad_login" }]; }
    if (!u.verified) return [403, { error: "unverified" }];
    fails.delete(failKey(req, email));
    u.lastLogin = new Date().toISOString(); users.save();
    startSession(req, res, u);
    return [200, publicUser(u)];
  }

  function logout(req, res) {
    const t = parseCookies(req)[COOKIE];
    if (t) { delete sessions.data[sha(t)]; sessions.save(); }
    res.setHeader("Set-Cookie", cookieHeader(req, "", 0));
    return [200, { ok: true }];
  }

  async function resend(req, b) {
    const u = findByEmail(String(b.email || "").trim().toLowerCase());
    if (u && !u.verified) { await sendVerify(req, u); await users.save(); }
    return [200, { ok: true, mailReady: mailReady() }];
  }

  async function forgot(req, b) {
    const u = findByEmail(String(b.email || "").trim().toLowerCase());
    if (u) { await sendReset(req, u); await users.save(); }
    return [200, { ok: true, mailReady: mailReady() }];
  }

  async function reset(req, b) {
    const t = String(b.token || "");
    const u = t && users.data.users.find((x) => x.resetHash === sha(t) && x.resetExp > now());
    if (!u) return [400, { error: "bad_token" }];
    if (!checkPassword(b.password)) return [400, { error: "weak_password" }];
    await setPassword(u, b.password);
    delete u.resetHash; delete u.resetExp;
    // the link reached the inbox, so it also proves the address
    if (!u.verified) { u.verified = true; delete u.verifyHash; delete u.verifyExp; }
    dropSessions(u.id);
    await users.save();
    return [200, { ok: true }];
  }

  async function verify(t) {
    const u = t && users.data.users.find((x) => x.verifyHash === sha(String(t)) && x.verifyExp > now());
    if (!u) return false;
    u.verified = true; delete u.verifyHash; delete u.verifyExp;
    await users.save();
    return true;
  }

  async function changePassword(req, me, b) {
    if (!(await passwordOk(me, b.current))) return [400, { error: "bad_current" }];
    if (!checkPassword(b.password)) return [400, { error: "weak_password" }];
    await setPassword(me, b.password);
    dropSessions(me.id, req);
    await users.save();
    return [200, { ok: true }];
  }

  // ---- admin ----
  const listUsers = () => [200, users.data.users.map(publicUser)];
  async function updateUser(me, id, b) {
    const u = findById(id);
    if (!u) return [404, { error: "not_found" }];
    if (b.role !== undefined) {
      if (!ROLES.includes(b.role)) return [400, { error: "bad_role" }];
      if (u.role === "admin" && b.role !== "admin" && admins().length <= 1 && u.verified) return [400, { error: "last_admin" }];
      u.role = b.role;
    }
    if (b.verified === true && !u.verified) { u.verified = true; delete u.verifyHash; delete u.verifyExp; }
    await users.save();
    return [200, publicUser(u)];
  }
  async function deleteUser(me, id) {
    const u = findById(id);
    if (!u) return [404, { error: "not_found" }];
    if (u.id === me.id) return [400, { error: "self" }];
    if (u.role === "admin" && u.verified && admins().length <= 1) return [400, { error: "last_admin" }];
    users.data.users = users.data.users.filter((x) => x !== u);
    dropSessions(u.id);
    await users.save();
    return [204, ""];
  }
  function getSettings(req) {
    const s = smtp();
    return [200, { appUrl: appUrl(req), smtp: { host: s.host, port: s.port || "", secure: s.secure, user: s.user, from: s.from, hasPass: !!s.pass }, mailReady: mailReady() }];
  }
  async function putSettings(req, b) {
    if (b.appUrl !== undefined) {
      const v = String(b.appUrl || "").trim();
      if (v && !/^https?:\/\/[^\s/]+(\/[^\s]*)?$/i.test(v)) return [400, { error: "bad_url" }];
      settings.data.appUrl = v;
    }
    if (b.smtp) {
      const old = settings.data.smtp || {}, s = b.smtp;
      settings.data.smtp = {
        host: String(s.host || "").trim(), port: +s.port || "", secure: !!s.secure,
        user: String(s.user || "").trim(), from: String(s.from || "").trim(),
        // a blank password field keeps the saved one
        pass: s.pass ? String(s.pass) : old.pass || "",
      };
    }
    await settings.save();
    return getSettings(req);
  }
  async function testMail(me) {
    try {
      await sendMail(smtp(), { to: me.email, subject: "NetPlan: ทดสอบการส่งอีเมล / Test e-mail", html: "<p>ระบบส่งอีเมลของ NetPlan ใช้งานได้แล้ว<br>NetPlan can send e-mail.</p>", text: "ระบบส่งอีเมลของ NetPlan ใช้งานได้แล้ว\nNetPlan can send e-mail.\n" });
      return [200, { ok: true }];
    } catch (e) { return [502, { error: "mail_failed", detail: e.message }]; }
  }

  return {
    ROLES, currentUser, publicUser, register, login, logout, resend, forgot, reset, verify, changePassword,
    listUsers, updateUser, deleteUser, getSettings, putSettings, testMail,
    hasUsers: () => users.data.users.some((u) => u.verified), mailReady,
  };
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

module.exports = { createAuth };
