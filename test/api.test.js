"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { startServer, client, signUpAdmin, addUser, sampleDiagram, PASSWORD } = require("./helpers");

test("sign-in and roles", async (t) => {
  const srv = await startServer();
  t.after(srv.stop);
  const anon = client(srv.base);

  await t.test("health reports login on", async () => {
    const r = await anon.get("/api/health");
    assert.equal(r.status, 200);
    assert.deepEqual(r.body, { app: "netplan", ok: true, auth: true });
  });

  await t.test("nothing is readable before signing in", async () => {
    const r = await anon.get("/api/diagrams");
    assert.equal(r.status, 401);
    assert.deepEqual(r.body, { error: "login_required", hasUsers: false });
  });

  await t.test("writes without the X-NetPlan header are refused", async () => {
    const r = await anon.post("/api/auth/login", { email: "x@example.com", password: PASSWORD }, { headers: { "X-NetPlan": null } });
    assert.equal(r.status, 403);
  });

  let admin;
  await t.test("the first account becomes an active admin", async () => {
    const reg = await anon.post("/api/auth/register", { email: "admin@example.com", name: "Admin", password: PASSWORD });
    assert.equal(reg.status, 201);
    assert.equal(reg.body.first, true);
    admin = client(srv.base);
    const r = await admin.post("/api/auth/login", { email: "admin@example.com", password: PASSWORD });
    assert.equal(r.status, 200);
    assert.equal(r.body.role, "admin");
    admin.user = r.body;
    const cookie = r.headers.get("set-cookie");
    assert.match(cookie, /np_sid=[0-9a-f]{64}/);
    assert.match(cookie, /HttpOnly/);
    assert.match(cookie, /SameSite=Lax/);
    assert.equal((await admin.get("/api/me")).body.role, "admin");
  });

  await t.test("a wrong password is refused", async () => {
    const r = await client(srv.base).post("/api/auth/login", { email: "admin@example.com", password: "wrong-password" });
    assert.equal(r.status, 401);
    assert.equal(r.body.error, "bad_login");
  });

  await t.test("later accounts wait for verification", async () => {
    const c = client(srv.base);
    const reg = await c.post("/api/auth/register", { email: "late@example.com", name: "Late", password: PASSWORD });
    assert.equal(reg.status, 201);
    assert.equal(reg.body.first, undefined);
    const r = await c.post("/api/auth/login", { email: "late@example.com", password: PASSWORD });
    assert.equal(r.status, 403);
    assert.equal(r.body.error, "unverified");
  });

  const editor = await addUser(srv.base, admin, "editor", "editor");
  const viewer = await addUser(srv.base, admin, "viewer", "viewer");
  const pending = await addUser(srv.base, admin, "pending", "pending");

  await t.test("pending accounts see nothing", async () => {
    const r = await pending.get("/api/diagrams");
    assert.equal(r.status, 403);
    assert.equal(r.body.error, "pending");
  });

  await t.test("viewers read but cannot write", async () => {
    assert.equal((await viewer.get("/api/diagrams")).status, 200);
    const r = await viewer.post("/api/diagrams", sampleDiagram());
    assert.equal(r.status, 403);
    assert.equal(r.body.error, "read_only");
  });

  await t.test("viewers may still share their selection", async () => {
    const id = (await editor.post("/api/diagrams", sampleDiagram())).body.id;
    const r = await viewer.post(`/api/diagrams/${id}/presence`, { client: "viewer-tab-1", sel: "" });
    assert.equal(r.status, 404);
    assert.equal(r.body.error, "not connected");
  });

  await t.test("editors write diagrams but cannot manage users or read the log", async () => {
    assert.equal((await editor.post("/api/diagrams", sampleDiagram())).status, 201);
    for (const url of ["/api/users", "/api/settings", "/api/audit"]) {
      const r = await editor.get(url);
      assert.equal(r.status, 403, url);
      assert.equal(r.body.error, "admin_only", url);
    }
  });

  await t.test("admins list users", async () => {
    const r = await admin.get("/api/users");
    assert.equal(r.status, 200);
    assert.equal(r.body.length, 5);
    for (const u of r.body) { assert.equal(u.hash, undefined); assert.equal(u.salt, undefined); }
  });

  await t.test("the last admin cannot be demoted or delete itself", async () => {
    const demote = await admin.patch("/api/users/" + admin.user.id, { role: "editor" });
    assert.equal(demote.status, 400);
    assert.equal(demote.body.error, "last_admin");
    const del = await admin.del("/api/users/" + admin.user.id);
    assert.equal(del.status, 400);
    assert.equal(del.body.error, "self");
  });

  await t.test("a new role takes effect on the next request", async () => {
    await admin.patch("/api/users/" + viewer.user.id, { role: "editor" });
    assert.equal((await viewer.post("/api/diagrams", sampleDiagram())).status, 201);
    await admin.patch("/api/users/" + viewer.user.id, { role: "viewer" });
    assert.equal((await viewer.post("/api/diagrams", sampleDiagram())).status, 403);
  });

  await t.test("changing the password signs out other sessions only", async () => {
    const other = client(srv.base);
    await other.post("/api/auth/login", { email: "editor@example.com", password: PASSWORD });
    assert.equal((await other.get("/api/me")).status, 200);
    const r = await editor.post("/api/me/password", { current: PASSWORD, password: "another-pass-2" });
    assert.equal(r.status, 200);
    assert.equal((await editor.get("/api/me")).status, 200);
    assert.equal((await other.get("/api/me")).status, 401);
  });

  await t.test("deleting a user ends their sessions", async () => {
    assert.equal((await admin.del("/api/users/" + pending.user.id)).status, 204);
    assert.equal((await pending.get("/api/me")).status, 401);
  });

  await t.test("logging out ends the session", async () => {
    assert.equal((await viewer.post("/api/auth/logout", {})).status, 200);
    assert.equal((await viewer.get("/api/diagrams")).status, 401);
  });

  await t.test("a broken JSON body is a 400", async () => {
    const r = await editor.post("/api/diagrams", "{not json");
    assert.equal(r.status, 400);
  });
});

test("diagram revisions", async (t) => {
  const srv = await startServer();
  t.after(srv.stop);
  const admin = await signUpAdmin(srv.base);
  const editor = await addUser(srv.base, admin, "editor", "editor");
  const rev = (n) => ({ headers: { "X-NetPlan-Rev": String(n) } });
  let id;

  await t.test("a new diagram starts at revision 1", async () => {
    const r = await editor.post("/api/diagrams", sampleDiagram());
    assert.equal(r.status, 201);
    assert.equal(r.body.rev, 1);
    id = r.body.id;
    const d = (await editor.get("/api/diagrams/" + id)).body;
    assert.equal(d.rev, 1);
    assert.equal(d.updatedBy, "editor");
    assert.equal(d.nodes[0].ip, "10.0.0.1");
  });

  await t.test("saving from the current revision moves it forward", async () => {
    const r = await editor.put("/api/diagrams/" + id, sampleDiagram({ title: "v2" }), rev(1));
    assert.equal(r.status, 200);
    assert.equal(r.body.rev, 2);
  });

  await t.test("saving from an old revision is a conflict that returns the newer copy", async () => {
    const r = await admin.put("/api/diagrams/" + id, sampleDiagram({ title: "stale" }), rev(1));
    assert.equal(r.status, 409);
    assert.equal(r.body.error, "conflict");
    assert.equal(r.body.rev, 2);
    assert.equal(r.body.updatedBy, "editor");
    assert.equal(r.body.diagram.title, "v2");
    assert.equal((await editor.get("/api/diagrams/" + id)).body.title, "v2");
  });

  await t.test("saving without a revision overwrites", async () => {
    const r = await admin.put("/api/diagrams/" + id, sampleDiagram({ title: "forced" }));
    assert.equal(r.status, 200);
    assert.equal(r.body.rev, 3);
  });

  await t.test("two saves from the same revision: exactly one wins", async () => {
    const [a, b] = await Promise.all([
      editor.put("/api/diagrams/" + id, sampleDiagram({ title: "A" }), rev(3)),
      admin.put("/api/diagrams/" + id, sampleDiagram({ title: "B" }), rev(3)),
    ]);
    assert.deepEqual([a.status, b.status].sort(), [200, 409]);
    const winner = a.status === 200 ? "A" : "B";
    const d = (await editor.get("/api/diagrams/" + id)).body;
    assert.equal(d.rev, 4);
    assert.equal(d.title, winner);
  });

  await t.test("bad input is refused", async () => {
    assert.equal((await editor.put("/api/diagrams/" + id, sampleDiagram(), { headers: { "X-NetPlan-Rev": "abc" } })).status, 400);
    assert.equal((await editor.put("/api/diagrams/" + id, { title: "no nodes" }, rev(4))).status, 400);
    assert.equal((await editor.post("/api/diagrams", { nodes: "x" })).status, 400);
    assert.equal((await editor.get("/api/diagrams/BAD_ID")).status, 400);
    assert.equal((await editor.get("/api/diagrams/does-not-exist")).status, 404);
  });

  await t.test("the list shows the diagram", async () => {
    const list = (await editor.get("/api/diagrams")).body;
    const row = list.find((x) => x.id === id);
    assert.equal(row.nodes, 1);
    assert.equal(row.updatedBy, "editor");
  });

  await t.test("deleting: reads are 404 and saves from a revision are 410", async () => {
    assert.equal((await editor.del("/api/diagrams/" + id)).status, 204);
    assert.equal((await editor.get("/api/diagrams/" + id)).status, 404);
    const r = await editor.put("/api/diagrams/" + id, sampleDiagram(), rev(4));
    assert.equal(r.status, 410);
    assert.equal(r.body.error, "deleted");
  });

  await t.test("saving without a revision brings a deleted diagram back at revision 1", async () => {
    const r = await editor.put("/api/diagrams/" + id, sampleDiagram({ title: "back" }));
    assert.equal(r.status, 200);
    assert.equal(r.body.rev, 1);
  });

  await t.test("diagrams survive a restart", async () => {
    await srv.stop();
    const again = await startServer({ dataDir: srv.dataDir });
    t.after(again.stop);
    const c = client(again.base);
    await c.post("/api/auth/login", { email: "editor@example.com", password: PASSWORD });
    const d = (await c.get("/api/diagrams/" + id)).body;
    assert.equal(d.title, "back");
    assert.equal(d.rev, 1);
  });
});

test("live updates", async (t) => {
  const srv = await startServer();
  t.after(srv.stop);
  const admin = await signUpAdmin(srv.base);
  const editor = await addUser(srv.base, admin, "editor", "editor");
  const id = (await editor.post("/api/diagrams", sampleDiagram())).body.id;

  const ctl = new AbortController();
  t.after(() => ctl.abort());
  const r = await fetch(`${srv.base}/api/diagrams/${id}/events?client=admin-tab-1`, { headers: { Cookie: admin.cookie }, signal: ctl.signal });
  assert.equal(r.status, 200);
  assert.match(r.headers.get("content-type"), /text\/event-stream/);
  const reader = r.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  async function nextEvent(name) {
    for (;;) {
      const m = buf.match(new RegExp(`event: ${name}\\ndata: (.*)\\n\\n`));
      if (m) { buf = buf.slice(m.index + m[0].length); return JSON.parse(m[1]); }
      const { value, done } = await reader.read();
      if (done) throw new Error("stream ended before " + name);
      buf += decoder.decode(value);
    }
  }

  assert.deepEqual(await nextEvent("hello"), { rev: 1 });
  const presence = await nextEvent("presence");
  assert.equal(presence.people[0].user.name, "Admin");

  await editor.put("/api/diagrams/" + id, sampleDiagram({ title: "v2" }), { headers: { "X-NetPlan-Rev": "1", "X-NetPlan-Client": "editor-tab-1" } });
  const saved = await nextEvent("saved");
  assert.equal(saved.rev, 2);
  assert.equal(saved.by.name, "editor");
  assert.equal(saved.client, "editor-tab-1");

  await editor.del("/api/diagrams/" + id);
  assert.equal((await nextEvent("deleted")).by.name, "editor");
});
