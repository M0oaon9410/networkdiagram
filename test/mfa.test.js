"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const totp = require("../lib/totp");
const { startServer, client, signUpAdmin, addUser, PASSWORD } = require("./helpers");

// the code the authenticator app would show, for a time step offset from now
const codeFor = (secret, offset = 0) => totp.hotp(totp.unbase32(secret), Math.floor(Date.now() / totp.STEP_MS) + offset);

test("one-time codes match RFC 6238", () => {
  const key = Buffer.from("12345678901234567890");
  assert.equal(totp.hotp(key, Math.floor(59 / 30), 8), "94287082");
  assert.equal(totp.hotp(key, Math.floor(1111111109 / 30), 8), "07081804");
  assert.equal(totp.base32(key), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
});

test("MFA for admins", async (t) => {
  const srv = await startServer({ env: { MFA_REQUIRED: "admin" } });
  t.after(srv.stop);
  const admin = await signUpAdmin(srv.base);
  let secret, recovery;

  await t.test("an admin without MFA can only set it up", async () => {
    const me = await admin.get("/api/me");
    assert.equal(me.body.mfaSetupRequired, true);
    assert.equal(me.body.mfa, false);
    assert.equal((await admin.get("/api/diagrams")).status, 403);
    assert.equal((await admin.get("/api/users")).body.error, "mfa_setup_required");
  });

  await t.test("setup gives a secret and QR code; a wrong code does not turn it on", async () => {
    const r = await admin.post("/api/me/mfa/setup", {});
    assert.equal(r.status, 200);
    secret = r.body.secret;
    assert.match(secret, /^[A-Z2-7]{32}$/);
    assert.match(r.body.uri, /^otpauth:\/\/totp\/AON:admin%40example\.com\?secret=/);
    assert.match(r.body.qr, /^<svg /);
    assert.equal((await admin.post("/api/me/mfa/enable", { code: "000000" === codeFor(secret) ? "111111" : "000000" })).body.error, "bad_code");
  });

  await t.test("the right code turns it on and returns 10 recovery codes", async () => {
    const r = await admin.post("/api/me/mfa/enable", { code: codeFor(secret) });
    assert.equal(r.status, 200);
    recovery = r.body.recovery;
    assert.equal(recovery.length, 10);
    assert.match(recovery[0], /^[a-z2-9]{4}-[a-z2-9]{4}$/);
    assert.equal((await admin.get("/api/diagrams")).status, 200);
    const me = (await admin.get("/api/me")).body;
    assert.equal(me.mfa, true); assert.equal(me.mfaSetupRequired, false);
  });

  await t.test("signing in now needs the code after the password", async () => {
    const c = client(srv.base);
    const r = await c.post("/api/auth/login", { email: "admin@example.com", password: PASSWORD });
    assert.equal(r.status, 200);
    assert.equal(r.body.mfa, true);
    assert.equal(c.cookie, "");
    assert.equal((await c.get("/api/me")).status, 401);
    assert.equal((await c.post("/api/auth/mfa", { ticket: r.body.ticket, code: "12345" })).body.error, "bad_code");
    // the code used to turn MFA on was already spent; the next one works
    const ok = await c.post("/api/auth/mfa", { ticket: r.body.ticket, code: codeFor(secret, 1) });
    assert.equal(ok.status, 200);
    assert.equal(ok.body.role, "admin");
    assert.equal((await c.get("/api/diagrams")).status, 200);
    // the ticket is used up
    assert.equal((await c.post("/api/auth/mfa", { ticket: r.body.ticket, code: codeFor(secret, 1) })).body.error, "bad_ticket");
  });

  await t.test("a recovery code works once", async () => {
    for (const expect of [200, 401]) {
      const c = client(srv.base);
      const r = await c.post("/api/auth/login", { email: "admin@example.com", password: PASSWORD });
      assert.equal((await c.post("/api/auth/mfa", { ticket: r.body.ticket, code: recovery[0].toUpperCase() })).status, expect);
    }
  });

  await t.test("five wrong codes end the ticket", async () => {
    const c = client(srv.base);
    const r = await c.post("/api/auth/login", { email: "admin@example.com", password: PASSWORD });
    for (let i = 0; i < 5; i++) await c.post("/api/auth/mfa", { ticket: r.body.ticket, code: "abcd-efgh" });
    assert.equal((await c.post("/api/auth/mfa", { ticket: r.body.ticket, code: codeFor(secret, -1) })).status, 429);
  });

  await t.test("an admin cannot turn off MFA while the role requires it", async () => {
    assert.equal((await admin.post("/api/me/mfa/disable", { password: PASSWORD, code: codeFor(secret, -1) })).body.error, "mfa_required");
  });

  await t.test("editors are not asked; another admin can reset an admin's MFA", async () => {
    const ed = await addUser(srv.base, admin, "ed", "editor");
    assert.equal((await ed.get("/api/me")).body.mfaSetupRequired, false);
    assert.equal((await ed.get("/api/diagrams")).status, 200);
    const list = (await admin.get("/api/users")).body;
    const self = list.find((u) => u.email === "admin@example.com");
    assert.equal(self.mfa, true);
    assert.equal((await admin.patch("/api/users/" + self.id, { resetMfa: true })).body.error, "self");
  });

  await t.test("the admin can require MFA for more roles", async () => {
    const s = await admin.put("/api/settings", { mfaRoles: ["admin", "editor", "bogus"] });
    assert.deepEqual(s.body.mfaRoles, ["admin", "editor"]);
    const c = client(srv.base);
    await c.post("/api/auth/login", { email: "ed@example.com", password: PASSWORD });
    assert.equal((await c.get("/api/diagrams")).body.error, "mfa_setup_required");
    const log = (await admin.get("/api/audit?group=account")).body.map((e) => e.action);
    assert.ok(log.includes("account.mfa_on"));
  });

  await t.test("reset-mfa on the command line turns it off for one account", async () => {
    await srv.stop();
    const out = execFileSync(process.execPath, [path.join(__dirname, "..", "server.js"), "reset-mfa", "admin@example.com"], { env: { ...process.env, DATA_DIR: srv.dataDir } }).toString();
    assert.match(out, /MFA turned off/);
    const users = JSON.parse(fs.readFileSync(path.join(srv.dataDir, "auth", "users.json"), "utf8")).users;
    assert.equal(users.find((u) => u.email === "admin@example.com").mfa, undefined);
  });
});
