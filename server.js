// NetPlan server: serves the diagram editor and stores diagrams as JSON files.
// No external dependencies, Node.js 18+.
"use strict";
const http = require("http");
const fs = require("fs");
const fsp = fs.promises;
const path = require("path");
const crypto = require("crypto");
const { createAuth } = require("./lib/auth");

const PORT = parseInt(process.env.PORT || "8080", 10);
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, "data"));
const PUBLIC_DIR = path.join(__dirname, "public");
const MAX_BODY = 5 * 1024 * 1024;
const ID_RE = /^[a-z0-9-]{1,64}$/;
const FONT_RE = /^[a-z0-9-]+\.(woff2|txt)$/;
// Login is on unless AUTH=off (then anyone who can reach the port may edit, as before).
const AUTH_ON = !/^(0|off|false|no)$/i.test(process.env.AUTH || "");
const CAN_EDIT = ["admin", "editor"];

fs.mkdirSync(DATA_DIR, { recursive: true });
const auth = AUTH_ON ? createAuth({ dataDir: DATA_DIR }) : null;

// app.html holds the page content only; wrap it in a document skeleton once at startup.
const APP_HTML =
  '<!doctype html><html lang="th"><head><meta charset="utf-8">' +
  '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">' +
  "<style>:root{padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}" +
  "body{margin:0;font-size:14px}img{max-width:100%}[hidden]{display:none!important}</style></head><body>" +
  fs.readFileSync(path.join(PUBLIC_DIR, "app.html"), "utf8") +
  "</body></html>";

function send(res, status, body, type = "application/json; charset=utf-8") {
  if (status === 204) { res.writeHead(204, { "Cache-Control": "no-store" }); return res.end(); }
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === "string" ? body : JSON.stringify(body));
  res.writeHead(status, { "Content-Type": type, "Content-Length": buf.length, "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" });
  res.end(buf);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject(Object.assign(new Error("too large"), { status: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function validDiagram(d) {
  return d && typeof d === "object" && Array.isArray(d.nodes) && Array.isArray(d.links || []) && Array.isArray(d.zones || []);
}

const fileFor = (id) => path.join(DATA_DIR, id + ".json");

async function writeDiagram(id, d, me) {
  const rec = { ...d, updatedAt: new Date().toISOString(), updatedBy: me ? me.name : undefined };
  const tmp = fileFor(id) + "." + process.pid + ".tmp";
  await fsp.writeFile(tmp, JSON.stringify(rec, null, 2));
  await fsp.rename(tmp, fileFor(id));
  return rec;
}

async function listDiagrams() {
  const files = (await fsp.readdir(DATA_DIR)).filter((f) => f.endsWith(".json"));
  const out = [];
  for (const f of files) {
    try {
      const d = JSON.parse(await fsp.readFile(path.join(DATA_DIR, f), "utf8"));
      out.push({ id: f.slice(0, -5), title: d.title || "(ไม่มีชื่อ)", nodes: (d.nodes || []).length, updatedAt: d.updatedAt || null, updatedBy: d.updatedBy || null });
    } catch (e) { /* skip unreadable file */ }
  }
  return out.sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)));
}

const readJson = async (req) => { const t = await readBody(req); return t ? JSON.parse(t) : {}; };

async function api(req, res, parts) {
  // parts: ["api", "diagrams", id?] and the account routes below
  if (parts[1] === "health" && req.method === "GET") return send(res, 200, { app: "netplan", ok: true, auth: AUTH_ON });
  // Writes must carry a header that a cross-site form or image cannot add.
  if (req.method !== "GET" && req.headers["x-netplan"] !== "1") return send(res, 403, { error: "missing X-NetPlan header" });
  let me = null;
  if (AUTH_ON) {
    const reply = ([status, body]) => send(res, status, body);
    if (parts[1] === "auth" && parts.length === 3 && req.method === "POST") {
      const b = await readJson(req);
      switch (parts[2]) {
        case "register": return reply(await auth.register(req, b));
        case "login": return reply(await auth.login(req, res, b));
        case "logout": return reply(auth.logout(req, res));
        case "resend": return reply(await auth.resend(req, b));
        case "forgot": return reply(await auth.forgot(req, b));
        case "reset": return reply(await auth.reset(req, b));
      }
      return send(res, 404, { error: "not found" });
    }
    me = auth.currentUser(req);
    if (!me) return send(res, 401, { error: "login_required", hasUsers: auth.hasUsers() });
    if (parts[1] === "me") {
      if (parts.length === 2 && req.method === "GET") return send(res, 200, auth.publicUser(me));
      if (parts[2] === "password" && req.method === "POST") return reply(await auth.changePassword(req, me, await readJson(req)));
      return send(res, 404, { error: "not found" });
    }
    if (parts[1] === "users" || parts[1] === "settings") {
      if (me.role !== "admin") return send(res, 403, { error: "admin_only" });
      if (parts[1] === "users" && parts.length === 2 && req.method === "GET") return reply(auth.listUsers());
      if (parts[1] === "users" && parts.length === 3 && ID_RE.test(parts[2])) {
        if (req.method === "PATCH") return reply(await auth.updateUser(me, parts[2], await readJson(req)));
        if (req.method === "DELETE") return reply(await auth.deleteUser(me, parts[2]));
      }
      if (parts[1] === "settings" && parts.length === 2 && req.method === "GET") return reply(auth.getSettings(req));
      if (parts[1] === "settings" && parts.length === 2 && req.method === "PUT") return reply(await auth.putSettings(req, await readJson(req)));
      if (parts[1] === "settings" && parts[2] === "test" && req.method === "POST") return reply(await auth.testMail(me));
      return send(res, 404, { error: "not found" });
    }
    if (req.method !== "GET" && !CAN_EDIT.includes(me.role)) return send(res, 403, { error: "read_only" });
  }
  if (parts[1] !== "diagrams" || parts.length > 3) return send(res, 404, { error: "not found" });
  const id = parts[2];

  if (!id) {
    if (req.method === "GET") return send(res, 200, await listDiagrams());
    if (req.method === "POST") {
      const d = JSON.parse(await readBody(req));
      if (!validDiagram(d)) return send(res, 400, { error: "invalid diagram" });
      const newId = crypto.randomBytes(6).toString("hex");
      await writeDiagram(newId, d, me);
      return send(res, 201, { id: newId });
    }
    return send(res, 405, { error: "method not allowed" });
  }

  if (!ID_RE.test(id)) return send(res, 400, { error: "invalid id" });
  if (req.method === "GET") {
    try { return send(res, 200, await fsp.readFile(fileFor(id))); }
    catch (e) { return send(res, 404, { error: "not found" }); }
  }
  if (req.method === "PUT") {
    const d = JSON.parse(await readBody(req));
    if (!validDiagram(d)) return send(res, 400, { error: "invalid diagram" });
    const rec = await writeDiagram(id, d, me);
    return send(res, 200, { id, updatedAt: rec.updatedAt });
  }
  if (req.method === "DELETE") {
    await fsp.rm(fileFor(id), { force: true });
    return send(res, 204, "");
  }
  return send(res, 405, { error: "method not allowed" });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://localhost");
    const parts = url.pathname.split("/").filter(Boolean).map(decodeURIComponent);
    if (parts[0] === "api") return await api(req, res, parts);
    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) return send(res, 200, APP_HTML, "text/html; charset=utf-8");
    if (req.method === "GET" && url.pathname === "/verify" && AUTH_ON) {
      const ok = await auth.verify(url.searchParams.get("token") || "");
      res.writeHead(302, { Location: "/?verified=" + (ok ? "1" : "0"), "Cache-Control": "no-store" });
      return res.end();
    }
    if (req.method === "GET" && parts[0] === "fonts" && parts.length === 2 && FONT_RE.test(parts[1])) {
      try {
        const buf = await fsp.readFile(path.join(PUBLIC_DIR, "fonts", parts[1]));
        res.writeHead(200, { "Content-Type": parts[1].endsWith(".woff2") ? "font/woff2" : "text/plain; charset=utf-8", "Content-Length": buf.length, "Cache-Control": "public, max-age=604800" });
        return res.end(buf);
      } catch (e) { return send(res, 404, "Not found", "text/plain; charset=utf-8"); }
    }
    return send(res, 404, "Not found", "text/plain; charset=utf-8");
  } catch (e) {
    const status = e.status || (e instanceof SyntaxError ? 400 : 500);
    if (status === 500) console.error(e);
    if (!res.headersSent) send(res, status, { error: status === 400 ? "invalid JSON" : e.message });
  }
});

server.listen(PORT, () => console.log(`NetPlan running on http://localhost:${PORT} (data: ${DATA_DIR}, login ${AUTH_ON ? "on" : "off"})`));
for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => server.close(() => process.exit(0)));
