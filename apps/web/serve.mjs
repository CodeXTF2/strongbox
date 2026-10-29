#!/usr/bin/env node
// Serves the web client (ui/) as static files. No dependencies.
//
//   node serve.mjs [--listen 127.0.0.1:8090] [--api http://127.0.0.1:8080]
//
// With --api, requests to /v1/ and /v2/ are passed through to a Strongbox server, so the page
// and the API share one origin (as behind the Caddy config in this folder) and the browser
// needs no cross-origin access. For local development: in production put both behind a TLS
// proxy instead (see Caddyfile). The page never sends this server anything but file requests.

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const args = process.argv.slice(2);
const opt = (name, def) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : def; };
const [host, port] = opt("--listen", "127.0.0.1:8090").split(/:(?=\d+$)/);
const api = opt("--api", null);
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "ui");

const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".png": "image/png" };
const HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Content-Security-Policy": "frame-ancestors 'none'",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), publickey-credentials-get=(self), publickey-credentials-create=(self)",
  "Cache-Control": "no-cache",
};

function proxy(req, res) {
  const target = new URL(req.url, api);
  const out = http.request(target, { method: req.method, headers: { ...req.headers, host: target.host } }, (r) => {
    res.writeHead(r.statusCode, r.headers);
    r.pipe(res);
  });
  out.on("error", () => { res.writeHead(502); res.end(); });
  req.pipe(out);
}

http.createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  if (api && /^\/v[12]\//.test(url.pathname)) return proxy(req, res);
  if (req.method !== "GET" && req.method !== "HEAD") { res.writeHead(405); return res.end(); }
  const rel = url.pathname === "/" ? "index.html" : decodeURIComponent(url.pathname).replace(/^\/+/, "");
  const file = path.join(root, rel);
  if (!file.startsWith(root + path.sep) || !TYPES[path.extname(file)]) { res.writeHead(404, HEADERS); return res.end(); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404, HEADERS); return res.end(); }
    res.writeHead(200, { ...HEADERS, "Content-Type": TYPES[path.extname(file)] });
    res.end(req.method === "HEAD" ? undefined : data);
  });
}).listen(Number(port), host, () => {
  console.log(`Strongbox web client on http://${host}:${port}/${api ? `  (API: ${api})` : ""}`);
});
