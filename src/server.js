import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { createStore } from "./data.js";
import { handleApi } from "./api.js";
import { applySecurityHeaders, sendJson, serveStatic } from "./http.js";

const PUBLIC_DIR = fileURLToPath(new URL("./public", import.meta.url));

export function createApp(options = {}) {
  const store = options.store ?? createStore();
  const server = createServer(async (req, res) => {
    applySecurityHeaders(res);
    try {
      const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
      if (url.pathname.startsWith("/api/")) await handleApi(req, res, url, store);
      else await serveStatic(res, url.pathname, PUBLIC_DIR);
    } catch (error) {
      sendJson(res, error.statusCode ?? 500, { error: error.statusCode ? error.message : "Internal server error." });
    }
  });
  return { server, store };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT ?? 4000);
  createApp().server.listen(port, "0.0.0.0", () => console.log(`Sentinel Flow: http://127.0.0.1:${port}`));
}
