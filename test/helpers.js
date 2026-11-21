// Starts a real NetPlan server on a free port with its own data folder, and talks to it like the page does.
"use strict";
const { spawn } = require("node:child_process");
const net = require("node:net");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.on("error", reject);
    s.listen(0, "127.0.0.1", () => { const { port } = s.address(); s.close(() => resolve(port)); });
  });
}

const tempDir = () => fs.mkdtempSync(path.join(os.tmpdir(), "netplan-test-"));

async function startServer({ dataDir = tempDir(), env = {} } = {}) {
  const port = await freePort();
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], {
    env: { ...process.env, PORT: String(port), DATA_DIR: dataDir, AUTH: "on", DEFAULT_ROLE: "", APP_URL: "", SMTP_HOST: "", ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (c) => { output += c; });
  child.stderr.on("data", (c) => { output += c; });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("server did not start:\n" + output)), 10000);
    child.stdout.on("data", () => { if (output.includes("NetPlan running")) { clearTimeout(timer); resolve(); } });
    child.on("exit", (code) => { clearTimeout(timer); reject(new Error(`server exited (${code}):\n${output}`)); });
  });
  const stop = () => new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) return resolve();
    child.on("exit", () => resolve());
    child.kill("SIGTERM");
  });
  return { base: `http://127.0.0.1:${port}`, dataDir, stop, output: () => output };
}

// One signed-in browser: keeps its own session cookie.
function client(base) {
  let cookie = "";
  async function req(method, url, { body, headers = {} } = {}) {
    const h = { "X-NetPlan": "1", ...headers };
    if (method === "GET") delete h["X-NetPlan"];
    for (const k of Object.keys(h)) if (h[k] === null) delete h[k];
    if (cookie) h.Cookie = cookie;
    if (body !== undefined) h["Content-Type"] = "application/json";
    const r = await fetch(base + url, { method, headers: h, body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body) });
    const set = r.headers.get("set-cookie");
    if (set) { const v = set.split(";")[0]; cookie = v.endsWith("=") ? "" : v; }
    const text = await r.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch (e) { /* not JSON */ }
    return { status: r.status, body: json, text, headers: r.headers };
  }
  return {
    req,
    get: (url, o) => req("GET", url, o),
    post: (url, body, o) => req("POST", url, { ...o, body }),
    put: (url, body, o) => req("PUT", url, { ...o, body }),
    patch: (url, body, o) => req("PATCH", url, { ...o, body }),
    del: (url, o) => req("DELETE", url, o),
    get cookie() { return cookie; },
  };
}

const PASSWORD = "correct-horse-1";

// Registers the first account (which becomes admin) and signs it in.
async function signUpAdmin(base) {
  const admin = client(base);
  await admin.post("/api/auth/register", { email: "admin@example.com", name: "Admin", password: PASSWORD });
  const r = await admin.post("/api/auth/login", { email: "admin@example.com", password: PASSWORD });
  if (r.status !== 200) throw new Error("admin login failed: " + r.text);
  admin.user = r.body;
  return admin;
}

// Registers another account, lets the admin verify it and give it a role, then signs it in.
async function addUser(base, admin, name, role) {
  const email = `${name}@example.com`;
  const c = client(base);
  await c.post("/api/auth/register", { email, name, password: PASSWORD });
  const u = (await admin.get("/api/users")).body.find((x) => x.email === email);
  await admin.patch("/api/users/" + u.id, { role, verified: true });
  const r = await c.post("/api/auth/login", { email, password: PASSWORD });
  if (r.status !== 200) throw new Error(`${name} login failed: ` + r.text);
  c.user = r.body;
  return c;
}

const sampleDiagram = (extra = {}) => ({
  title: "Test diagram",
  nodes: [{ id: "n1", type: "switch", name: "Core", ip: "10.0.0.1", x: 0, y: 0 }],
  links: [],
  zones: [],
  ...extra,
});

module.exports = { startServer, client, signUpAdmin, addUser, sampleDiagram, tempDir, PASSWORD };
