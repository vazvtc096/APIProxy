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
 *
 * Monitoring endpoints (this file):
 *   GET /            -> small HTML dashboard (live connection / broadcast stats)
 *   GET /health      -> JSON { ok, version, uptime_sec, connections_total,
 *                             subscribers, broadcasts_total, publish_errors,
 *                             per_user: { "<id>": <conn_count>, ... } }
 *   GET /metrics     -> Prometheus text exposition format
 */
import express from "express";
import { WebSocketServer, WebSocket } from "ws";

const PORT = Number(process.env.SIDECAR_PORT || 8765);
const PUBLISH_TOKEN = process.env.SIDECAR_PUBLISH_TOKEN || "";
const VERSION = "1.1.0";

const STARTED = Date.now();

type Subscriber = WebSocket;
const subscribers = new Map<string, Set<Subscriber>>();

// live counters for the health/monitoring page
const stats = {
  connections_total: 0,
  broadcasts_total: 0,
  publish_errors: 0,
  delivered_total: 0,
};

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
    stats.publish_errors += 1;
    res.status(400).json({ ok: false, error: "user and event required" });
    return;
  }
  if (PUBLISH_TOKEN && req.header("x-publish-token") !== PUBLISH_TOKEN) {
    stats.publish_errors += 1;
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
  stats.broadcasts_total += 1;
  stats.delivered_total += delivered;
  res.json({ ok: true, delivered });
});

// ---- per-user connection distribution (for /health + /metrics + dashboard) ----
function perUserCounts(): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [u, set] of subscribers.entries()) {
    out[u] = set.size;
  }
  return out;
}

function uptimeSec(): number {
  return Math.floor((Date.now() - STARTED) / 1000);
}

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    version: VERSION,
    uptime_sec: uptimeSec(),
    connections_total: stats.connections_total,
    subscribers: subscribers.size,
    broadcasts_total: stats.broadcasts_total,
    delivered_total: stats.delivered_total,
    publish_errors: stats.publish_errors,
    per_user: perUserCounts(),
  });
});

app.get("/metrics", (_req, res) => {
  const lines: string[] = [];
  lines.push("# HELP sidecar_up Whether the sidecar is alive");
  lines.push("# TYPE sidecar_up gauge");
  lines.push("sidecar_up 1");
  lines.push("# HELP sidecar_connections_total Total WebSocket connections ever opened");
  lines.push("# TYPE sidecar_connections_total counter");
  lines.push(`sidecar_connections_total ${stats.connections_total}`);
  lines.push("# HELP sidecar_subscribers Current distinct subscribed users");
  lines.push("# TYPE sidecar_subscribers gauge");
  lines.push(`sidecar_subscribers ${subscribers.size}`);
  lines.push("# HELP sidecar_broadcasts_total Total publish calls received");
  lines.push("# TYPE sidecar_broadcasts_total counter");
  lines.push(`sidecar_broadcasts_total ${stats.broadcasts_total}`);
  lines.push("# HELP sidecar_delivered_total Total messages delivered to clients");
  lines.push("# TYPE sidecar_delivered_total counter");
  lines.push(`sidecar_delivered_total ${stats.delivered_total}`);
  lines.push("# HELP sidecar_publish_errors_total Failed publish calls");
  lines.push("# TYPE sidecar_publish_errors_total counter");
  lines.push(`sidecar_publish_errors_total ${stats.publish_errors}`);
  lines.push("# HELP sidecar_subscriber_conns Connections for a given user");
  lines.push("# TYPE sidecar_subscriber_conns gauge");
  for (const [u, n] of Object.entries(perUserCounts())) {
    lines.push(`sidecar_subscriber_conns{user="${u}"} ${n}`);
  }
  res.set("Content-Type", "text/plain; version=0.0.4; charset=utf-8");
  res.send(lines.join("\n") + "\n");
});

// ---- tiny HTML dashboard (dark theme) ----
const DASHBOARD = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>APIProxy sidecar — health</title>
<style>
  :root { color-scheme: dark; }
  body { margin:0; background:#0f1115; color:#e6e6e6; font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
  .wrap { max-width:880px; margin:0 auto; padding:24px; }
  h1 { font-size:18px; margin:0 0 4px; }
  .sub { color:#8b95a5; margin:0 0 20px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; }
  .card { background:#171a21; border:1px solid #232833; border-radius:10px; padding:14px; }
  .k { color:#8b95a5; font-size:12px; }
  .v { font-size:22px; margin-top:4px; }
  .ok { color:#46d369; }
  table { width:100%; border-collapse:collapse; margin-top:20px; }
  th,td { text-align:left; padding:6px 10px; border-bottom:1px solid #232833; }
  th { color:#8b95a5; font-weight:600; }
  .row td:last-child { text-align:right; }
  .foot { color:#8b95a5; margin-top:18px; font-size:12px; }
</style></head>
<body><div class="wrap">
  <h1>APIProxy realtime sidecar</h1>
  <p class="sub">WebSocket notification relay — health &amp; connections</p>
  <div class="grid" id="cards"></div>
  <table><thead><tr><th>user</th><th>connections</th></tr></thead>
    <tbody id="rows"></tbody></table>
  <p class="foot" id="foot"></p>
</div>
<script>
async function load(){
  try {
    const r = await fetch('/health'); const d = await r.json();
    const cards = [
      ['status', d.ok ? '<span class="ok">up</span>' : 'down', ''],
      ['version', d.version, ''],
      ['uptime', d.uptime_sec + 's', ''],
      ['connections', d.connections_total, 'total opened'],
      ['subscribers', d.subscribers, 'distinct users'],
      ['broadcasts', d.broadcasts_total, 'published'],
      ['delivered', d.delivered_total, 'to clients'],
      ['errors', d.publish_errors, ''],
    ];
    document.getElementById('cards').innerHTML = cards.map(([k,v,h])=>
      '<div class="card"><div class="k">'+k+'</div><div class="v">'+v+'</div>'+
      (h?'<div class="k">'+h+'</div>':'')).join('');
    const rows = Object.entries(d.per_user).sort((a,b)=>b[1]-a[1]);
    document.getElementById('rows').innerHTML = rows.length
      ? rows.map(([u,n])=>'<tr class="row"><td>'+u+'</td><td>'+n+'</td></tr>').join('')
      : '<tr><td colspan="2">no subscribers</td></tr>';
    document.getElementById('foot').textContent = 'auto-refresh every 2s';
  } catch(e) {
    document.getElementById('foot').textContent = 'health fetch failed: '+e;
  }
}
load(); setInterval(load, 2000);
</script></body></html>`;

app.get("/", (_req, res) => {
  res.set("Content-Type", "text/html; charset=utf-8");
  res.send(DASHBOARD);
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
  stats.connections_total += 1;
  ws.on("close", () => set.delete(ws));
  ws.on("error", () => set.delete(ws));
  send(ws, { event: "connected", payload: { user: key }, ts: Date.now() });
});

process.on("SIGINT", () => {
  server.close();
  process.exit(0);
});
