/**
 * APIProxy realtime notification relay (Node/TypeScript pillar).
 *
 * Why this exists (multi-language split):
 *   - Python (Quart) owns business logic, auth, DB, billing, security.
 *   - Node owns the high-concurrency realtime fan-out: WebSocket clients
 *     subscribe per user, and the Python app publishes events to this sidecar
 *     over a local HTTP POST. This keeps long-lived socket I/O off the
 *     async Python event loop.
 *
 * Wire format:
 *   POST http://127.0.0.1:8765/publish
 *   { "user": "<id>", "event": "<name>", "payload": { ... } }
 *
 * Client:
 *   ws://127.0.0.1:8765/?user=<id>
 *
 * The Python app is the ONLY publisher (shared localhost, no auth needed
 * because it is bound to loopback). Tune PORT below if needed.
 */
import express from "express";
import { WebSocketServer, WebSocket } from "ws";

const PORT = Number(process.env.SIDECAR_PORT || 8765);
const PUBLISH_TOKEN = process.env.SIDECAR_PUBLISH_TOKEN || "";

type Subscriber = WebSocket;
const subscribers = new Map<string, Set<Subscriber>>();

function send(ws: Subscriber, msg: unknown): void {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(msg));
  }
}

const app = express();
app.use(express.json({ limit: "256kb" }));

app.post("/publish", (req, res) => {
  const { user, event, payload } = req.body || {};
  if (!user || !event) {
    res.status(400).json({ ok: false, error: "user and event required" });
    return;
  }
  if (PUBLISH_TOKEN && req.header("x-publish-token") !== PUBLISH_TOKEN) {
    res.status(401).json({ ok: false, error: "unauthorized" });
    return;
  }
  const set = subscribers.get(String(user));
  let delivered = 0;
  if (set) {
    for (const ws of set) {
      send(ws, { event, payload, ts: Date.now() });
      delivered += 1;
    }
  }
  res.json({ ok: true, delivered });
});

app.get("/health", (_req, res) => {
  res.json({ ok: true, subscribers: subscribers.size });
});

const server = app.listen(PORT, "127.0.0.1", () => {
  // eslint-disable-next-line no-console
  console.log(`[sidecar] publish HTTP + WS listening on 127.0.0.1:${PORT}`);
});

const wss = new WebSocketServer({ server, path: "/" });

wss.on("connection", (ws, req) => {
  const url = new URL(req.url || "", "http://localhost");
  const user = url.searchParams.get("user");
  if (!user) {
    ws.close(1008, "user query param required");
    return;
  }
  const key = String(user);
  if (!subscribers.has(key)) subscribers.set(key, new Set());
  const set = subscribers.get(key)!;
  set.add(ws);
  ws.on("close", () => set.delete(ws));
  ws.on("error", () => set.delete(ws));
  send(ws, { event: "connected", payload: { user: key }, ts: Date.now() });
});

process.on("SIGINT", () => {
  server.close();
  process.exit(0);
});
