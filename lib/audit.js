// Audit log: one row per entry in the SQLite database DATA_DIR/auth/audit.db; each row keeps the entry as JSON.
// Diagram saves arrive every few seconds while someone edits, so saves by the same person
// to the same diagram are gathered into one entry that lists what changed overall.
"use strict";
const fs = require("fs");
const path = require("path");
const { DatabaseSync } = require("node:sqlite");

const IDLE_MS = 2 * 60e3;        // write the gathered changes after 2 minutes without a save
const MAX_SPAN_MS = 15 * 60e3;   // and never gather more than 15 minutes into one entry
const MAX_DETAILS = 300;

const NODE_FIELDS = ["name", "type", "ip", "mask", "gateway", "vlan", "mac", "servicePort", "vendor", "model", "serial", "platform", "os", "antivirus", "location", "status", "notes", "color"];
const LINK_FIELDS = ["kind", "label", "fromPort", "toPort", "notes", "route"];
const ZONE_FIELDS = ["name", "notes", "color"];

const str = (v) => (v == null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v));
const clip = (v) => { const s = str(v); return s.length > 200 ? s.slice(0, 200) + "…" : s; };

// What changed from diagram a to diagram b, as small records the page turns into sentences.
function diffDiagrams(a, b) {
  a = a || { nodes: [], links: [], zones: [] }; b = b || { nodes: [], links: [], zones: [] };
  const out = [];
  const byId = (list) => new Map((list || []).filter((x) => x && x.id).map((x) => [x.id, x]));
  const an = byId(a.nodes), bn = byId(b.nodes), az = byId(a.zones), bz = byId(b.zones), al = byId(a.links), bl = byId(b.links);
  const nodeName = (n) => n.name || n.type || n.id;
  const endName = (id) => { const n = bn.get(id) || an.get(id); if (n) return nodeName(n); const z = bz.get(id) || az.get(id); return z ? z.name || "zone" : id; };
  const linkName = (l) => `${endName(l.from)} ↔ ${endName(l.to)}`;
  if (str(a.title) !== str(b.title)) out.push({ op: "edit", kind: "title", field: "title", from: clip(a.title), to: clip(b.title) });
  if (str(a.area) !== str(b.area)) out.push({ op: "edit", kind: "area", field: "area", from: clip(a.area), to: clip(b.area) });

  for (const [id, n] of bn) {
    const o = an.get(id);
    if (!o) { out.push({ op: "add", kind: "node", name: nodeName(n), type: n.type }); continue; }
    for (const f of NODE_FIELDS) if (str(o[f]) !== str(n[f])) out.push({ op: "edit", kind: "node", name: nodeName(n), field: f, from: clip(o[f]), to: clip(n[f]) });
    const keys = new Set([...Object.keys(o.extra || {}), ...Object.keys(n.extra || {})]);
    for (const k of keys) if (str((o.extra || {})[k]) !== str((n.extra || {})[k])) out.push({ op: "edit", kind: "node", name: nodeName(n), field: k, from: clip((o.extra || {})[k]), to: clip((n.extra || {})[k]) });
    if (str(o.custom) !== str(n.custom)) out.push({ op: "edit", kind: "node", name: nodeName(n), field: "custom", from: clip((o.custom || []).map((c) => `${c.k}: ${c.v}`).join("; ")), to: clip((n.custom || []).map((c) => `${c.k}: ${c.v}`).join("; ")) });
    if (o.x !== n.x || o.y !== n.y) out.push({ op: "move", kind: "node", name: nodeName(n) });
  }
  for (const [id, n] of an) if (!bn.has(id)) out.push({ op: "del", kind: "node", name: nodeName(n), type: n.type });

  for (const [id, z] of bz) {
    const o = az.get(id);
    if (!o) { out.push({ op: "add", kind: "zone", name: z.name || "" }); continue; }
    for (const f of ZONE_FIELDS) if (str(o[f]) !== str(z[f])) out.push({ op: "edit", kind: "zone", name: z.name || "", field: f, from: clip(o[f]), to: clip(z[f]) });
    if (o.x !== z.x || o.y !== z.y || o.w !== z.w || o.h !== z.h) out.push({ op: "move", kind: "zone", name: z.name || "" });
  }
  for (const [id, z] of az) if (!bz.has(id)) out.push({ op: "del", kind: "zone", name: z.name || "" });

  for (const [id, l] of bl) {
    const o = al.get(id);
    if (!o) { out.push({ op: "add", kind: "link", name: linkName(l), type: l.kind }); continue; }
    if (o.from !== l.from || o.to !== l.to) out.push({ op: "edit", kind: "link", name: linkName(l), field: "ends", from: linkName(o), to: linkName(l) });
    for (const f of LINK_FIELDS) if (str(o[f]) !== str(l[f])) out.push({ op: "edit", kind: "link", name: linkName(l), field: f, from: clip(o[f]), to: clip(l[f]) });
    if (str(o.bends) !== str(l.bends)) out.push({ op: "path", kind: "link", name: linkName(l) });
  }
  for (const [id, l] of al) if (!bl.has(id)) out.push({ op: "del", kind: "link", name: linkName(l), type: l.kind });

  // collapse repeated "moved" records for the same thing
  const seen = new Set(), res = [];
  for (const r of out) {
    if (r.op === "move" || r.op === "path") { const k = r.op + r.kind + r.name; if (seen.has(k)) continue; seen.add(k); }
    res.push(r);
  }
  return res;
}

function openDb(file) {
  // created empty first so the database and its -wal/-shm files are readable by this user only
  fs.closeSync(fs.openSync(file, "a", 0o600));
  const db = new DatabaseSync(file);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA busy_timeout = 5000;
    CREATE TABLE IF NOT EXISTS audit (
      id INTEGER PRIMARY KEY,
      t TEXT NOT NULL,
      action TEXT NOT NULL,
      user_id TEXT,
      diagram_id TEXT,
      entry TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS audit_t ON audit (t);
    CREATE INDEX IF NOT EXISTS audit_user ON audit (user_id);
    CREATE INDEX IF NOT EXISTS audit_diagram ON audit (diagram_id);
    CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
  `);
  return db;
}

function createAudit({ dataDir }) {
  const dir = path.join(dataDir, "auth");
  fs.mkdirSync(dir, { recursive: true });
  const db = openDb(path.join(dir, "audit.db"));
  const insert = db.prepare("INSERT INTO audit (t, action, user_id, diagram_id, entry) VALUES (?, ?, ?, ?, ?)");
  const store = (e, json) => insert.run(String(e.t || ""), String(e.action || ""), e.user?.id ?? null, e.diagram?.id ?? null, json);
  importLegacy(db, path.join(dir, "audit.log"), store);

  function append(entry) {
    const e = { t: new Date().toISOString(), ...entry };
    try { store(e, JSON.stringify(e)); } catch (err) { console.error("audit write failed:", err.message); }
    return Promise.resolve();
  }
  const who = (u) => (u ? { id: u.id, name: u.name, email: u.email } : null);
  const ipOf = (req) => (req ? String(req.headers["cf-connecting-ip"] || "").trim() || req.socket.remoteAddress || "" : "");

  // account and sign-in events
  function log(req, user, action, extra = {}) {
    return append({ user: who(user), ip: ipOf(req), action, ...extra });
  }

  // diagram saves, gathered per person and diagram
  const pending = new Map();
  function flush(key) {
    const p = pending.get(key);
    if (!p) return Promise.resolve();
    pending.delete(key); clearTimeout(p.timer);
    const changes = diffDiagrams(p.base, p.latest);
    if (!changes.length) return Promise.resolve();
    return append({ t0: new Date(p.first).toISOString(), user: p.user, ip: p.ip, action: "diagram.edit", diagram: { id: p.id, title: str(p.latest.title) }, changes: changes.slice(0, MAX_DETAILS), more: Math.max(0, changes.length - MAX_DETAILS) });
  }
  function flushAll() { for (const k of [...pending.keys()]) flush(k); return Promise.resolve(); }
  function diagramSaved(req, user, id, before, after) {
    // someone else's unsaved run on this diagram is closed first, so entries stay in order
    for (const [k, p] of pending) if (p.id === id && (!user || p.user?.id !== user.id)) flush(k);
    const key = (user ? user.id : "-") + "|" + id;
    let p = pending.get(key);
    if (p && Date.now() - p.first > MAX_SPAN_MS) { flush(key); p = null; }
    if (!p) { p = { id, user: who(user), ip: ipOf(req), base: before, first: Date.now() }; pending.set(key, p); }
    p.latest = after; p.ip = ipOf(req);
    clearTimeout(p.timer);
    p.timer = setTimeout(() => flush(key), IDLE_MS);
    p.timer.unref?.();
  }
  function diagramCreated(req, user, id, d) {
    return log(req, user, "diagram.create", { diagram: { id, title: str(d.title), area: str(d.area) }, count: { nodes: (d.nodes || []).length, links: (d.links || []).length, zones: (d.zones || []).length } });
  }
  function diagramDeleted(req, user, id, d) {
    for (const [k, p] of pending) if (p.id === id) { pending.delete(k); clearTimeout(p.timer); }
    return log(req, user, "diagram.delete", { diagram: { id, title: str(d && d.title) } });
  }

  // newest first, filtered
  async function query(f = {}) {
    await flushAll();
    const where = [], args = [];
    const from = isoOf(f.from), to = isoOf(f.to);
    if (from) { where.push("t >= ?"); args.push(from); }
    if (to) { where.push("t <= ?"); args.push(to); }
    if (f.user) { where.push("user_id = ?"); args.push(String(f.user)); }
    if (f.diagram) { where.push("diagram_id = ?"); args.push(String(f.diagram)); }
    if (f.group) { const g = String(f.group) + "."; where.push("substr(action, 1, ?) = ?"); args.push(g.length, g); }
    const q = String(f.q || "").toLowerCase(), limit = Math.min(2000, Math.max(1, +f.limit || 500));
    // text search runs here rather than in SQL because SQLite's lower() only folds ASCII
    const sql = `SELECT entry FROM audit ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY id DESC${q ? "" : " LIMIT ?"}`;
    if (!q) args.push(limit);
    const out = [];
    for (const row of db.prepare(sql).iterate(...args)) {
      if (q && !row.entry.toLowerCase().includes(q)) continue;
      out.push(JSON.parse(row.entry));
      if (out.length >= limit) break;
    }
    return out;
  }

  function close() { flushAll(); if (db.isOpen) db.close(); }

  return { log, diagramSaved, diagramCreated, diagramDeleted, flushAll, query, close };
}

function isoOf(v) {
  const n = v ? Date.parse(v) : NaN;
  return Number.isFinite(n) && Math.abs(n) <= 8.64e15 ? new Date(n).toISOString() : null;
}

// audit.log (and its rotated audit.log.1) from before the database are copied in once, oldest first,
// then renamed to *.imported so they are kept but never read again.
function importLegacy(db, file, store) {
  const files = [file + ".1", file].filter((f) => fs.existsSync(f));
  if (!files.length) return;
  const done = db.prepare("SELECT v FROM meta WHERE k = 'legacy_log_imported'").get();
  if (!done) {
    let n = 0;
    db.exec("BEGIN");
    try {
      for (const f of files) {
        for (const line of fs.readFileSync(f, "utf8").split("\n")) {
          if (!line.trim()) continue;
          let e; try { e = JSON.parse(line); } catch (err) { continue; }
          store(e, line); n++;
        }
      }
      db.prepare("INSERT INTO meta (k, v) VALUES ('legacy_log_imported', ?)").run(new Date().toISOString());
      db.exec("COMMIT");
    } catch (err) { db.exec("ROLLBACK"); throw err; }
    console.log(`[netplan] audit: imported ${n} entries from ${files.map((f) => path.basename(f)).join(", ")}`);
  }
  for (const f of files) fs.renameSync(f, f + ".imported");
}

module.exports = { createAudit, diffDiagrams };
