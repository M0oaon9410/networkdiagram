// Live updates for open diagrams over Server-Sent Events: who has each diagram open,
// what each of them has selected, and a ping whenever someone saves or deletes it.
"use strict";

const HEARTBEAT_MS = 25e3;   // keeps proxies (nginx, Cloudflare) from closing an idle stream
const CLIENT_RE = /^[A-Za-z0-9_-]{8,40}$/;
const SEL_RE = /^([nlz]:[A-Za-z0-9_-]{1,64})?$/;

function createLive() {
  const rooms = new Map();   // diagram id -> Map(client id -> { res, user, sel })

  const write = (res, event, data) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  function broadcast(id, event, data) {
    const room = rooms.get(id);
    if (room) for (const c of room.values()) write(c.res, event, data);
  }
  function sendPresence(id) {
    const room = rooms.get(id);
    if (room) broadcast(id, "presence", { people: [...room].map(([client, c]) => ({ client, user: c.user, sel: c.sel })) });
  }

  // `res` already has its event-stream headers written
  function join(id, client, user, res, rev) {
    let room = rooms.get(id);
    if (!room) rooms.set(id, (room = new Map()));
    // the same tab reconnecting replaces its old stream
    const old = room.get(client);
    if (old) old.res.end();
    const c = { res, user, sel: "" };
    room.set(client, c);
    const beat = setInterval(() => res.write(": ping\n\n"), HEARTBEAT_MS);
    beat.unref?.();
    res.on("close", () => {
      clearInterval(beat);
      if (room.get(client) !== c) return;
      room.delete(client);
      if (room.size) sendPresence(id); else rooms.delete(id);
    });
    res.write("retry: 3000\n\n");
    write(res, "hello", { rev });
    sendPresence(id);
  }

  // only the account that opened the stream may move its selection
  function select(id, client, userId, sel) {
    const c = rooms.get(id)?.get(client);
    if (!c || c.user.id !== userId) return false;
    if (c.sel !== sel) { c.sel = sel; sendPresence(id); }
    return true;
  }

  const saved = (id, rev, user, client) => broadcast(id, "saved", { rev, by: user, client });
  function deleted(id, user, client) {
    broadcast(id, "deleted", { by: user, client });
    const room = rooms.get(id);
    if (room) { rooms.delete(id); for (const c of room.values()) c.res.end(); }
  }
  function closeAll() {
    for (const room of rooms.values()) for (const c of room.values()) c.res.end();
    rooms.clear();
  }

  return { join, select, saved, deleted, closeAll };
}

module.exports = { createLive, CLIENT_RE, SEL_RE };
