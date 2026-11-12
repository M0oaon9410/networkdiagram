// Audit log: one JSON object per line in DATA_DIR/auth/audit.log.
// Diagram saves arrive every few seconds while someone edits, so saves by the same person
// to the same diagram are gathered into one entry that lists what changed overall.
"use strict";
const fs = require("fs");
const fsp = fs.promises;
const path = require("path");

const IDLE_MS = 2 * 60e3;        // write the gathered changes after 2 minutes without a save
const MAX_SPAN_MS = 15 * 60e3;   // and never gather more than 15 minutes into one entry
const MAX_BYTES = 20 * 1024 * 1024;
const MAX_DETAILS = 300;

const NODE_FIELDS = ["name", "type", "ip", "mask", "gateway", "vlan", "mac", "vendor", "model", "serial", "platform", "os", "location", "status", "notes", "color"];
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

function createAudit({ dataDir }) {
  const dir = path.join(dataDir, "auth");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, "audit.log");
  let queue = Promise.resolve();

  function append(entry) {
    const line = JSON.stringify({ t: new Date().toISOString(), ...entry }) + "\n";
    queue = queue.then(async () => {
      try { if ((await fsp.stat(file)).size > MAX_BYTES) await fsp.rename(file, file + ".1"); } catch (e) {}
      await fsp.appendFile(file, line, { mode: 0o600 });
    }).catch((e) => console.error("audit write failed:", e.message));
    return queue;
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
    if (!p) return queue;
    pending.delete(key); clearTimeout(p.timer);
    const changes = diffDiagrams(p.base, p.latest);
    if (!changes.length) return queue;
    return append({ t0: new Date(p.first).toISOString(), user: p.user, ip: p.ip, action: "diagram.edit", diagram: { id: p.id, title: str(p.latest.title) }, changes: changes.slice(0, MAX_DETAILS), more: Math.max(0, changes.length - MAX_DETAILS) });
  }
  function flushAll() { for (const k of [...pending.keys()]) flush(k); return queue; }
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

  // newest first, filtered; reads the current file and the rotated one
  async function query(f = {}) {
    await flushAll();
    let text = "";
    for (const fn of [file + ".1", file]) { try { text += await fsp.readFile(fn, "utf8"); } catch (e) {} }
    const from = f.from ? Date.parse(f.from) : -Infinity, to = f.to ? Date.parse(f.to) : Infinity;
    const q = String(f.q || "").toLowerCase(), limit = Math.min(2000, Math.max(1, +f.limit || 500));
    const out = [];
    const lines = text.split("\n");
    for (let i = lines.length - 1; i >= 0 && out.length < limit; i--) {
      if (!lines[i]) continue;
      let e; try { e = JSON.parse(lines[i]); } catch (err) { continue; }
      const t = Date.parse(e.t);
      if (t < from || t > to) continue;
      if (f.user && (!e.user || e.user.id !== f.user)) continue;
      if (f.diagram && (!e.diagram || e.diagram.id !== f.diagram)) continue;
      if (f.group && !String(e.action).startsWith(f.group + ".")) continue;
      if (q && !lines[i].toLowerCase().includes(q)) continue;
      out.push(e);
    }
    return out;
  }

  return { log, diagramSaved, diagramCreated, diagramDeleted, flushAll, query };
}

module.exports = { createAudit, diffDiagrams };
