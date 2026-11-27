"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { startServer, client, signUpAdmin, addUser, sampleDiagram, tempDir, PASSWORD } = require("./helpers");

test("an audit.log from before the database is imported once and kept", async (t) => {
  const dataDir = tempDir();
  const auth = path.join(dataDir, "auth");
  fs.mkdirSync(auth, { recursive: true });
  const line = (t, action, extra = {}) => JSON.stringify({ t, user: { id: "u-old", name: "Old Admin", email: "old@example.com" }, ip: "10.1.1.1", action, ...extra });
  fs.writeFileSync(path.join(auth, "audit.log.1"), line("2026-01-01T00:00:00.000Z", "auth.login") + "\n" + line("2026-01-02T00:00:00.000Z", "diagram.create", { diagram: { id: "d-old", title: "Old" } }) + "\n");
  fs.writeFileSync(path.join(auth, "audit.log"), line("2026-02-01T00:00:00.000Z", "auth.logout") + "\nnot json\n\n");

  let srv = await startServer({ dataDir });
  t.after(() => srv.stop());
  let admin = await signUpAdmin(srv.base);
  const old = (await admin.get("/api/audit?user=u-old")).body;
  assert.deepEqual(old.map((e) => e.action), ["auth.logout", "diagram.create", "auth.login"]);
  assert.equal(old[1].diagram.id, "d-old");
  assert.equal((await admin.get("/api/audit?diagram=d-old")).body.length, 1);
  assert.equal((await admin.get("/api/audit?to=2026-01-15T00:00:00.000Z")).body.length, 2);
  assert.ok(fs.existsSync(path.join(auth, "audit.log.imported")));
  assert.ok(fs.existsSync(path.join(auth, "audit.log.1.imported")));
  assert.ok(!fs.existsSync(path.join(auth, "audit.log")));
  assert.equal(fs.statSync(path.join(auth, "audit.db")).mode & 0o777, 0o600);

  await srv.stop();
  srv = await startServer({ dataDir });
  admin = client(srv.base);
  await admin.post("/api/auth/login", { email: "admin@example.com", password: PASSWORD });
  assert.equal((await admin.get("/api/audit?user=u-old")).body.length, 3);
});

test("activity log", async (t) => {
  const srv = await startServer();
  t.after(srv.stop);
  const admin = await signUpAdmin(srv.base);
  const editor = await addUser(srv.base, admin, "editor", "editor");
  await client(srv.base).post("/api/auth/login", { email: "editor@example.com", password: "wrong-password" });
  const audit = async (params = {}) => {
    const r = await admin.get("/api/audit?" + new URLSearchParams(params));
    assert.equal(r.status, 200);
    return r.body;
  };

  await t.test("sign-ins, failures and admin actions are recorded, newest first", async () => {
    const all = await audit();
    const actions = all.map((e) => e.action);
    assert.deepEqual(actions, ["auth.login_failed", "auth.login", "admin.verify", "admin.role", "account.register", "mail.not_configured", "auth.login", "account.register"]);
    const failed = all[0];
    assert.equal(failed.email, "editor@example.com");
    assert.equal(failed.user.name, "editor");
    assert.ok(failed.ip);
    for (let i = 1; i < all.length; i++) assert.ok(all[i - 1].t >= all[i].t);
  });

  await t.test("filter by group, user, text and limit", async () => {
    assert.deepEqual((await audit({ group: "auth" })).map((e) => e.action), ["auth.login_failed", "auth.login", "auth.login"]);
    assert.ok((await audit({ group: "admin" })).every((e) => e.action.startsWith("admin.")));
    const mine = await audit({ user: admin.user.id });
    assert.ok(mine.length >= 3 && mine.every((e) => e.user.id === admin.user.id));
    assert.deepEqual((await audit({ q: "LOGIN_FAILED" })).map((e) => e.action), ["auth.login_failed"]);
    assert.equal((await audit({ q: "EDITOR@EXAMPLE" })).length, 6);
    const mail = await audit({ group: "mail" });
    assert.deepEqual(mail.map((e) => [e.action, e.to, e.kind]), [["mail.not_configured", "editor@example.com", "verify"]]);
    assert.equal((await admin.get("/api/settings")).body.lastMail.ok, false);
    const one = await audit({ limit: "1" });
    assert.equal(one.length, 1);
    assert.equal(one[0].action, "auth.login_failed");
  });

  await t.test("filter by date", async () => {
    const all = await audit();
    assert.equal((await audit({ from: "2999-01-01T00:00:00.000Z" })).length, 0);
    assert.equal((await audit({ to: "2000-01-01T00:00:00.000Z" })).length, 0);
    assert.equal((await audit({ from: "not a date" })).length, all.length);
    const mid = all[2].t;
    assert.ok((await audit({ from: mid })).every((e) => e.t >= mid));
    assert.ok((await audit({ to: mid })).every((e) => e.t <= mid));
  });

  let id;
  await t.test("diagram create, edits and delete are recorded with what changed", async () => {
    id = (await editor.post("/api/diagrams", sampleDiagram())).body.id;
    const changed = sampleDiagram();
    changed.nodes[0].ip = "10.0.0.2";
    await editor.put("/api/diagrams/" + id, changed, { headers: { "X-NetPlan-Rev": "1" } });
    changed.nodes.push({ id: "n2", type: "router", name: "Edge", x: 100, y: 0 });
    await editor.put("/api/diagrams/" + id, changed, { headers: { "X-NetPlan-Rev": "2" } });
    const entries = await audit({ diagram: id });
    assert.deepEqual(entries.map((e) => e.action), ["diagram.edit", "diagram.create"]);
    assert.deepEqual(entries[1].count, { nodes: 1, links: 0, zones: 0 });
    const edit = entries[0];
    assert.equal(edit.user.name, "editor");
    assert.equal(edit.diagram.title, "Test diagram");
    assert.deepEqual(edit.changes, [
      { op: "edit", kind: "node", name: "Core", field: "ip", from: "10.0.0.1", to: "10.0.0.2" },
      { op: "add", kind: "node", name: "Edge", type: "router" },
    ]);
    assert.equal(edit.more, 0);
    assert.ok(edit.t0 <= edit.t);
  });

  await t.test("deleting a diagram is recorded", async () => {
    await editor.del("/api/diagrams/" + id);
    assert.deepEqual((await audit({ diagram: id })).map((e) => e.action), ["diagram.delete", "diagram.edit", "diagram.create"]);
  });

  await t.test("the log survives a restart, including edits still being gathered", async () => {
    const before = (await audit()).length;
    const id2 = (await editor.post("/api/diagrams", sampleDiagram())).body.id;
    await editor.put("/api/diagrams/" + id2, sampleDiagram({ title: "renamed" }), { headers: { "X-NetPlan-Rev": "1" } });
    await srv.stop();
    const again = await startServer({ dataDir: srv.dataDir });
    t.after(again.stop);
    const a = client(again.base);
    await a.post("/api/auth/login", { email: "admin@example.com", password: PASSWORD });
    const after = (await a.get("/api/audit")).body;
    assert.equal(after.length, before + 3);
    assert.deepEqual(after.slice(0, 3).map((e) => e.action), ["auth.login", "diagram.edit", "diagram.create"]);
    assert.deepEqual(after[1].changes, [{ op: "edit", kind: "title", field: "title", from: "Test diagram", to: "renamed" }]);
  });
});

test("development languages: an old single language and the same list read the same, changes show as one line", () => {
  const { diffDiagrams } = require("../lib/audit");
  const node = (f) => ({ id: "n1", type: "server", name: "WEB-01", x: 0, y: 0, ...f });
  const doc = (f) => ({ nodes: [node(f)], links: [], zones: [] });
  assert.deepEqual(diffDiagrams(doc({ lang: "PHP", langVer: "8.3" }), doc({ langs: [{ lang: "PHP", ver: "8.3" }] })), []);
  assert.deepEqual(diffDiagrams(doc({ langs: [{ lang: "PHP", ver: "8.3" }] }), doc({ langs: [{ lang: "PHP", ver: "8.3" }, { lang: "Node.js", ver: "20" }, { lang: "", ver: "" }] })),
    [{ op: "edit", kind: "node", name: "WEB-01", field: "langs", from: "PHP 8.3", to: "PHP 8.3, Node.js 20" }]);
});

test("a long Thai email subject is split into short encoded words", () => {
  const { encodeWord } = require("../lib/mailer");
  const subject = "รีเซ็ตรหัสผ่านสำหรับ AON (Asset and Operational Network)";
  const out = encodeWord(subject);
  const words = out.split("\r\n ");
  assert.ok(words.length > 1);
  for (const w of words) assert.ok(w.length <= 75, w);
  const back = words.map((w) => Buffer.from(w.match(/^=\?UTF-8\?B\?(.*)\?=$/)[1], "base64")).reduce((a, b) => Buffer.concat([a, b]));
  assert.equal(back.toString("utf8"), subject);
  assert.equal(encodeWord("Hello"), "Hello");
});
