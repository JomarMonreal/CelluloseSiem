import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { BlockList, isIP } from "node:net";
import type Auth from "./auth.js";
import { MAX_DB_MB, PORT } from "./config.js";
import type Disk from "./disk.js";
import type Probe from "./probe.js";
import { RULES } from "./rules.js";
import type Store from "./store.js";

const DAY = 24 * 60 * 60_000;
const PUBLIC = new URL("../public/", import.meta.url);
const STATIC: Record<string, { file: string; type: string; open?: boolean }> = {
  "/": { file: "index.html", type: "text/html; charset=utf-8" },
  "/app.js": { file: "app.js", type: "text/javascript; charset=utf-8" },
  // the sign-in page uses it too
  "/style.css": { file: "style.css", type: "text/css; charset=utf-8", open: true },
};
const files = new Map(Object.entries(STATIC).map(([path, s]) => [path, readFileSync(new URL(s.file, PUBLIC))]));
const loginPage = readFileSync(new URL("login.html", PUBLIC), "utf8");

// Everything shown is attacker-controlled text (usernames, reasons, event names), so the page never runs anything
// but its own script, and builds the page with textContent only.
const SECURITY_HEADERS = {
  "content-security-policy":
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  // not no-referrer: under that, browsers send `Origin: null` with form posts, and sign-in looks cross-site
  "referrer-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
};

const json = (res: ServerResponse, status: number, body: unknown) => {
  res.writeHead(status, { ...SECURITY_HEADERS, "content-type": "application/json", "cache-control": "no-store" });
  res.end(JSON.stringify(body));
};
const redirect = (res: ServerResponse, to: string, cookie?: string) => {
  res.writeHead(303, { ...SECURITY_HEADERS, location: to, "cache-control": "no-store", ...(cookie ? { "set-cookie": cookie } : {}) });
  res.end();
};
const int = (v: string | null, fallback: number, max: number) => {
  const n = Number(v);
  return Number.isInteger(n) && n > 0 ? Math.min(n, max) : fallback;
};

/** Addresses that may connect: this machine, plus each address or subnet in `allow`. */
function allowList(allow: string[]): BlockList {
  const list = new BlockList();
  list.addSubnet("127.0.0.0", 8, "ipv4");
  list.addAddress("::1", "ipv6");
  for (const entry of allow) {
    const [addr, bits] = entry.split("/");
    const type = isIP(addr) === 6 ? "ipv6" : isIP(addr) === 4 ? "ipv4" : null;
    if (!type) throw new Error(`SIEM_ALLOW: '${entry}' isn't an address or subnet`);
    if (bits === undefined) list.addAddress(addr, type);
    else list.addSubnet(addr, Number(bits), type);
  }
  return list;
}

/**
 * A page on another site can point a hostname of its own at this machine (DNS rebinding) and then read the API as
 * if it were us. Its requests still carry that hostname, so only bare addresses and localhost are answered.
 */
function hostAllowed(host: string | undefined): boolean {
  const m = (host ?? "").match(/^(\[[^\]]+\]|[^:]+):(\d+)$/);
  if (!m || Number(m[2]) !== PORT) return false;
  const name = m[1].replace(/^\[|\]$/g, "");
  return name === "localhost" || isIP(name) !== 0;
}

function readBody(req: IncomingMessage, max: number): Promise<string | null> {
  return new Promise((resolve) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk: string) => {
      body += chunk;
      if (body.length > max) {
        resolve(null);
        req.destroy();
      }
    });
    req.on("end", () => resolve(body));
    req.on("error", () => resolve(null));
  });
}

/** The dashboard and its JSON API. Read-only, except acknowledging alerts. */
export function startWeb(store: Store, probe: Probe, disk: Disk, auth: Auth, host: string, allow: string[], laptop: () => Record<string, unknown>) {
  const allowed = allowList(allow);

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const ip = (req.socket.remoteAddress ?? "").replace(/^::ffff:/, "");
    if (!allowed.check(ip, isIP(ip) === 6 ? "ipv6" : "ipv4")) return void res.writeHead(403).end();
    if (!hostAllowed(req.headers.host)) return void res.writeHead(421).end();
    const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
    // other sites' pages can send a POST here blind; the browser always says where it came from
    if (req.method === "POST" && req.headers.origin !== `http://${req.headers.host}`) return json(res, 403, { error: "cross-origin" });

    // signing in

    if (url.pathname === "/login") {
      if (req.method === "GET") {
        const note = url.searchParams.has("failed") ? "Wrong password." : url.searchParams.has("wait") ? "Too many wrong passwords. Try again in a few minutes." : "";
        res.writeHead(200, { ...SECURITY_HEADERS, "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
        return void res.end(loginPage.replace("{{note}}", note));
      }
      if (req.method !== "POST" || !auth.enabled) return redirect(res, "/");
      if (!auth.mayTry(ip)) return redirect(res, "/login?wait");
      const body = await readBody(req, 1024);
      const token = body === null ? null : auth.signIn(ip, new URLSearchParams(body).get("password") ?? "");
      if (!token) {
        console.log(JSON.stringify({ dashboard: "login_fail", srcip: ip }));
        return redirect(res, "/login?failed");
      }
      console.log(JSON.stringify({ dashboard: "login_ok", srcip: ip }));
      return redirect(res, "/", auth.cookie(token));
    }
    if (url.pathname === "/logout" && req.method === "POST") {
      auth.signOut(req.headers.cookie);
      return redirect(res, "/login", auth.cookie(null));
    }

    const file = files.get(url.pathname);
    if (auth.enabled && !auth.signedIn(req.headers.cookie) && !(file && STATIC[url.pathname].open)) {
      return url.pathname.startsWith("/api/") ? json(res, 401, { error: "sign in" }) : redirect(res, "/login");
    }

    if (req.method === "POST") {
      const m = url.pathname.match(/^\/api\/alerts\/(\d+|all)\/ack$/);
      if (!m) return json(res, 404, { error: "not found" });
      return json(res, 200, { acked: store.ack(m[1] === "all" ? "all" : Number(m[1])) });
    }
    if (req.method !== "GET") return json(res, 405, { error: "method" });

    if (file) {
      res.writeHead(200, { ...SECURITY_HEADERS, "content-type": STATIC[url.pathname].type, "cache-control": "no-cache" });
      return void res.end(file);
    }

    const q = url.searchParams;
    const since = Date.now() - DAY;
    switch (url.pathname) {
      case "/api/summary":
        return json(res, 200, {
          ...store.summary(since),
          probes: Object.fromEntries(probe.status),
          storage: { dbMb: store.bytes() / 2 ** 20, maxDbMb: MAX_DB_MB, diskFreeMb: disk.status.freeMb, diskTotalMb: disk.status.totalMb, diskLow: disk.status.low },
          laptop: laptop(),
          rules: Object.fromEntries(RULES.map((r) => [r.id, { name: r.name, explain: r.explain, todo: r.todo, level: r.level, mitre: r.mitre ?? [] }])),
          signOut: auth.enabled,
          now: Date.now(),
        });
      case "/api/alerts":
        return json(res, 200, store.alerts({ all: q.get("all") === "1", limit: int(q.get("limit"), 200, 1000) }));
      case "/api/digests":
        return json(res, 200, store.digests(int(q.get("limit"), 7, 60)));
      case "/api/timeline":
        return json(res, 200, { since, hours: store.timeline(since) });
      case "/api/ips":
        return json(res, 200, store.topIps(since, int(q.get("limit"), 15, 100)));
      case "/api/events":
        return json(
          res,
          200,
          store.events({
            evt: q.get("evt")?.split(",").filter(Boolean),
            srcip: q.get("ip") || undefined,
            username: q.get("user") || undefined,
            q: q.get("q") || undefined,
            before: int(q.get("before"), 0, Number.MAX_SAFE_INTEGER) || undefined,
            limit: int(q.get("limit"), 100, 500),
          }),
        );
    }
    const related = url.pathname.match(/^\/api\/alerts\/(\d+)\/related$/);
    const alert = related && store.alert(Number(related[1]));
    if (alert) return json(res, 200, store.related(alert, 50));
    json(res, 404, { error: "not found" });
  });
  server.listen(PORT, host, () => console.log(`dashboard on http://${host}:${PORT}${allow.length ? `, open to ${allow.join(", ")}` : ""}`));
  return server;
}
