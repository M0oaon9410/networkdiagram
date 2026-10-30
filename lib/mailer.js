// Minimal SMTP client (no dependencies): implicit TLS (port 465) or STARTTLS (587/25),
// AUTH PLAIN or LOGIN, one HTML message per call.
"use strict";
const net = require("net");
const tls = require("tls");
const os = require("os");
const crypto = require("crypto");

const b64 = (s) => Buffer.from(s, "utf8").toString("base64");
const encodeWord = (s) => (/^[\x20-\x7e]*$/.test(s) ? s : `=?UTF-8?B?${b64(s)}?=`);
const addrOf = (s) => { const m = /<([^>]+)>/.exec(s); return (m ? m[1] : s).trim(); };
function formatAddress(s) {
  const m = /^\s*(.*?)\s*<([^>]+)>\s*$/.exec(s);
  if (!m || !m[1]) return addrOf(s);
  return `${encodeWord(m[1].replace(/^"|"$/g, ""))} <${m[2]}>`;
}

function buildMessage({ from, to, subject, html, text }) {
  const boundary = "np-" + crypto.randomBytes(12).toString("hex");
  const wrap = (s) => b64(s).replace(/.{1,76}/g, "$&\r\n");
  const domain = addrOf(from).split("@")[1] || "localhost";
  return [
    `From: ${formatAddress(from)}`,
    `To: ${to}`,
    `Subject: ${encodeWord(subject)}`,
    `Date: ${new Date().toUTCString().replace("GMT", "+0000")}`,
    `Message-ID: <${crypto.randomBytes(16).toString("hex")}@${domain}>`,
    "MIME-Version: 1.0",
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    "",
    `--${boundary}`,
    "Content-Type: text/plain; charset=UTF-8",
    "Content-Transfer-Encoding: base64",
    "",
    wrap(text),
    `--${boundary}`,
    "Content-Type: text/html; charset=UTF-8",
    "Content-Transfer-Encoding: base64",
    "",
    wrap(html),
    `--${boundary}--`,
    "",
  ].join("\r\n");
}

// Reads SMTP replies (possibly multi-line) from a socket that can be swapped for its TLS upgrade.
class Conn {
  constructor(sock) { this.buf = ""; this.waiters = []; this.replies = []; this.err = null; this.attach(sock); }
  attach(sock) {
    this.sock = sock;
    sock.setTimeout(20000, () => sock.destroy(new Error("SMTP timeout")));
    sock.on("data", (d) => this.onData(d));
    sock.on("error", (e) => this.fail(e));
    sock.on("close", () => this.fail(new Error("SMTP connection closed")));
  }
  detach() { this.sock.removeAllListeners("data"); this.sock.removeAllListeners("error"); this.sock.removeAllListeners("close"); this.sock.setTimeout(0); }
  fail(e) { if (this.err) return; this.err = e; for (const w of this.waiters.splice(0)) w.reject(e); }
  onData(d) {
    this.buf += d.toString("utf8");
    let i, lines = [];
    while ((i = this.buf.indexOf("\n")) >= 0) {
      const line = this.buf.slice(0, i).replace(/\r$/, ""); this.buf = this.buf.slice(i + 1);
      lines.push(line);
      if (/^\d{3}(?: |$)/.test(line)) { this.push({ code: +line.slice(0, 3), text: lines.join("\n") }); lines = []; }
    }
    if (lines.length) this.buf = lines.join("\n") + "\n" + this.buf;
  }
  push(r) { const w = this.waiters.shift(); if (w) w.resolve(r); else this.replies.push(r); }
  read() {
    if (this.replies.length) return Promise.resolve(this.replies.shift());
    if (this.err) return Promise.reject(this.err);
    return new Promise((resolve, reject) => this.waiters.push({ resolve, reject }));
  }
  async cmd(line, expect, hide) {
    if (line != null) this.sock.write(line + "\r\n");
    const r = await this.read();
    if (!expect.includes(r.code)) throw new Error(`SMTP ${hide ? "AUTH" : (line || "greeting").split(" ")[0]} failed: ${r.text}`);
    return r;
  }
}

function connect(cfg) {
  return new Promise((resolve, reject) => {
    const opts = { host: cfg.host, port: cfg.port, servername: cfg.host };
    const s = cfg.secure ? tls.connect(opts) : net.connect(opts);
    s.once(cfg.secure ? "secureConnect" : "connect", () => { s.removeListener("error", reject); resolve(s); });
    s.once("error", reject);
  });
}

async function sendMail(cfg, msg) {
  if (!cfg || !cfg.host) throw new Error("SMTP is not configured");
  const port = +cfg.port || (cfg.secure ? 465 : 587);
  const c = new Conn(await connect({ ...cfg, port }));
  try {
    const helo = "EHLO " + (os.hostname() || "netplan");
    await c.cmd(null, [220]);
    let ehlo = await c.cmd(helo, [250]);
    if (!cfg.secure && /STARTTLS/i.test(ehlo.text)) {
      await c.cmd("STARTTLS", [220]);
      c.detach();
      const raw = c.sock;
      const t = await new Promise((resolve, reject) => {
        const t = tls.connect({ socket: raw, servername: cfg.host }, () => resolve(t));
        t.once("error", reject);
      });
      c.attach(t);
      ehlo = await c.cmd(helo, [250]);
    }
    if (cfg.user) {
      if (/AUTH[ =][^\n]*PLAIN/i.test(ehlo.text) || !/AUTH[ =][^\n]*LOGIN/i.test(ehlo.text)) {
        await c.cmd("AUTH PLAIN " + b64("\0" + cfg.user + "\0" + (cfg.pass || "")), [235], true);
      } else {
        await c.cmd("AUTH LOGIN", [334], true);
        await c.cmd(b64(cfg.user), [334], true);
        await c.cmd(b64(cfg.pass || ""), [235], true);
      }
    }
    const from = cfg.from || cfg.user;
    await c.cmd(`MAIL FROM:<${addrOf(from)}>`, [250]);
    await c.cmd(`RCPT TO:<${addrOf(msg.to)}>`, [250, 251]);
    await c.cmd("DATA", [354]);
    const body = buildMessage({ ...msg, from }).replace(/\r\n\./g, "\r\n..");
    await c.cmd(body + "\r\n.", [250]);
    c.sock.write("QUIT\r\n");
  } finally {
    setTimeout(() => c.sock.destroy(), 500);
  }
}

module.exports = { sendMail };
