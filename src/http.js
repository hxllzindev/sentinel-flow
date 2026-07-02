import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";

const contentTypes = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8" };

export function applySecurityHeaders(res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
}

export function sendJson(res, status, payload, headers = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers });
  res.end(body);
}

export async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 2 * 1024 * 1024) throw Object.assign(new Error("Payload too large."), { statusCode: 413 });
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch { throw Object.assign(new Error("Invalid JSON."), { statusCode: 400 }); }
}

export async function serveStatic(res, pathname, publicDir) {
  const relative = pathname === "/" ? "index.html" : pathname.slice(1);
  const safe = normalize(relative).replace(/^(\.\.(\/|\\|$))+/, "");
  try {
    const file = await readFile(join(publicDir, safe));
    res.writeHead(200, { "Content-Type": contentTypes[extname(safe)] ?? "application/octet-stream", "Cache-Control": "no-cache" });
    res.end(file);
  } catch {
    sendJson(res, 404, { error: "Not found." });
  }
}
