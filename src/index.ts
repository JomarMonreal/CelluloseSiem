import { mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import Auth from "./auth.js";
import {
  ALERT_DAYS,
  ALLOW,
  DATA_DIR,
  DIGEST_HOUR,
  DISK_CHECK_MS,
  DISK_MIN_FREE_MB,
  EVENT_DAYS,
  FAIRPLAY_CHECK_MS,
  FILES_CHECK_MS,
  HOST,
  LOCAL_HEALTH_URL,
  MAX_DB_MB,
  NOTIFY_MIN_LEVEL,
  PASSWORD,
  PORTS_CHECK_MS,
  PROBE_FAILS,
  PROBE_MS,
  PUBLIC_HEALTH_URL,
  SERVER_DIR,
  UNIT,
  WATCH,
} from "./config.js";
import { buildDigest } from "./digest.js";
import Disk from "./disk.js";
import { Engine } from "./engine.js";
import { diskEvent, fromHost, fromJournal, HOST_SOURCES, hostEvent, type NewEvent, probeEvent } from "./events.js";
import { findings, fresh } from "./fairplay.js";
import { diff, type Snapshot, snapshot, type Watched } from "./files.js";
import Journal from "./journal.js";
import { notify, push } from "./notify.js";
import { networkListeners } from "./ports.js";
import Probe from "./probe.js";
import { RULES } from "./rules.js";
import Store, { type Alert } from "./store.js";
import { startWeb } from "./web.js";

const DAY = 24 * 60 * 60_000;
// an alert raised from a line this old is history being read in, not news: it's stored but not pushed
const LIVE_MS = 5 * 60_000;
// longer than any rule's window, so replaying it on start restores every threshold's count
const REPLAY_MS = 2 * 60 * 60_000;
// the laptop's logs, the first time: recent history is useful, years of it isn't
const HOST_FIRST_RUN = ["--since=-7d"];
// the daily summary waits this long after a start, so it counts history read in, not an empty database
const SETTLE_MS = 2 * 60_000;
const startedAt = Date.now();

// the dashboard shows players' IPs and usernames: anything beyond this machine has to sign in
const LOOPBACK = new Set(["127.0.0.1", "::1", "localhost"]);
if ((!LOOPBACK.has(HOST) || ALLOW.length) && !PASSWORD) {
  console.error(`SIEM_HOST=${HOST}${ALLOW.length ? ` and SIEM_ALLOW=${ALLOW.join(",")}` : ""} open the dashboard to other machines: set SIEM_PASSWORD too`);
  process.exit(1);
}

mkdirSync(DATA_DIR, { recursive: true });
const store = new Store(join(DATA_DIR, "siem.db"));
const engine = new Engine(RULES);

// pick up the thresholds where the last run left them; what fires again folds into the alerts already open
for (const e of store.eventsSince(Date.now() - REPLAY_MS)) engine.process(e);

/** Stores events, runs them past the rules and records what fires, all in one transaction with the saved state. */
function ingest(events: NewEvent[], state: Record<string, string> = {}) {
  const news: Alert[] = [];
  store.transaction(() => {
    for (const ne of events) {
      const e = store.addEvent(ne);
      for (const fired of engine.process(e)) {
        const { alert, fresh } = store.raise(fired);
        if (fresh && Date.now() - e.ts < LIVE_MS) news.push(alert);
      }
    }
    for (const [key, value] of Object.entries(state)) store.setState(key, value);
  });
  for (const a of news) {
    console.log(JSON.stringify({ alert: a.rule, level: a.level, title: a.title, srcip: a.srcip, user: a.username }));
    if (a.level >= NOTIFY_MIN_LEVEL) void notify(a);
  }
}

/** Events from the SIEM's own checks. Unlike journal lines these can't be read again, so a failed save is only logged. */
function ingestNow(events: NewEvent[], state: Record<string, string> = {}) {
  try {
    ingest(events, state);
  } catch (err) {
    console.error(`couldn't save ${events.map((e) => e.evt).join(", ") || "state"}:`, (err as Error).message);
  }
}

/** Runs `task` now and every `ms`, logging (not throwing) what goes wrong. */
function every(ms: number, name: string, task: () => unknown): NodeJS.Timeout {
  const run = async () => {
    try {
      await task();
    } catch (err) {
      console.error(`${name}:`, (err as Error).message);
    }
  };
  void run();
  return setInterval(() => void run(), ms);
}

// the game server's journal, and the laptop's own (sudo, logins, users, the tunnel, sleep), each with its own cursor

const journal = new Journal(["--unit", UNIT], store.getState("cursor"), ["--lines=all"], (entries, cursor) => {
  ingest(
    entries.map((en) => fromJournal(en, UNIT)).filter((e): e is NewEvent => !!e),
    { cursor },
  );
});
const hostJournal = new Journal(HOST_SOURCES, store.getState("host_cursor"), HOST_FIRST_RUN, (entries, cursor) => {
  ingest(
    entries.map(fromHost).filter((e): e is NewEvent => !!e),
    { host_cursor: cursor },
  );
});

// health and disk

const probe = new Probe(
  { local: LOCAL_HEALTH_URL, ...(PUBLIC_HEALTH_URL ? { public: PUBLIC_HEALTH_URL } : {}) },
  PROBE_MS,
  PROBE_FAILS,
  (target, up, s) => ingestNow([probeEvent(target, up, s.url, s.detail)]),
);
const disk = new Disk(DATA_DIR, DISK_MIN_FREE_MB, DISK_CHECK_MS, (low, s) => ingestNow([diskEvent(low, s.freeMb, s.totalMb, s.path)]));

// ports open to the network: each one is news the first time it's ever seen

let ports: string[] = [];
const portsTimer = every(PORTS_CHECK_MS, "ports", async () => {
  ports = await networkListeners();
  const saved = store.getState("ports_known");
  const known = new Set<string>(saved ? JSON.parse(saved) : []);
  const opened = ports.filter((p) => !known.has(p));
  if (!opened.length) return;
  for (const p of opened) known.add(p);
  // the first run only learns what's already open
  ingestNow(saved ? opened.map((listen) => hostEvent("port_opened", { listen })) : [], { ports_known: JSON.stringify([...known].sort()) });
});

// watched files: the server's and the SIEM's code, secrets, services, users, admins, scheduled tasks, the tunnel

const ownDist = fileURLToPath(new URL(".", import.meta.url));
const serverDir = resolve(SERVER_DIR);
const watched: Watched[] = [
  ...[join(serverDir, "dist"), join(serverDir, "package.json"), join(serverDir, "package-lock.json"), ownDist].map((path) => ({ path, kind: "code" as const })),
  ...[
    join(serverDir, ".env"),
    "/etc/systemd/system",
    "/etc/cellulose-siem.env",
    "/etc/cloudflared",
    "/etc/passwd",
    "/etc/group",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/ssh/sshd_config",
    "/etc/systemd/logind.conf",
  ].map((path) => ({ path, kind: "config" as const })),
  ...WATCH.map((w) => {
    const [kind, ...path] = w.split(":");
    return { path: path.join(":"), kind: kind === "code" ? ("code" as const) : ("config" as const) };
  }),
];
let filesCheckedAt = 0;
let filesChangedAt = 0;
const filesTimer = every(FILES_CHECK_MS, "files", async () => {
  const now = await snapshot(watched);
  const saved = store.getState("files");
  const before: Snapshot = saved ? JSON.parse(saved) : {};
  const events = diff(before, now, watched).map((c) => {
    const parts = [c.changed.length && `${c.changed.length} changed`, c.added.length && `${c.added.length} added`, c.removed.length && `${c.removed.length} removed`].filter(Boolean);
    const names = [...c.changed, ...c.added, ...c.removed].map((n) => n || "(itself)");
    const summary = `${parts.join(", ")}${names.length ? `: ${names.slice(0, 4).join(", ")}${names.length > 4 ? ", …" : ""}` : ""}`;
    return hostEvent("file_changed", { path: c.path, kind: c.kind, summary, changed: c.changed.slice(0, 20), added: c.added.slice(0, 20), removed: c.removed.slice(0, 20) });
  });
  ingestNow(events, { files: JSON.stringify(now) });
  filesCheckedAt = Date.now();
  if (events.length) filesChangedAt = filesCheckedAt;
});

// fair play: patterns across a week of ranked games

const fairplayTimer = every(FAIRPLAY_CHECK_MS, "fair play", () => {
  const seen: Record<string, number> = JSON.parse(store.getState("fairplay_seen") ?? "{}");
  const events = fresh(findings(store, Date.now()), seen, Date.now());
  if (events.length) ingestNow(events, { fairplay_seen: JSON.stringify(seen) });
});

// the daily summary, once a day from DIGEST_HOUR

const digestTimer = every(60_000, "daily summary", () => {
  const now = new Date();
  const day = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}`;
  if (now.getHours() < DIGEST_HOUR || store.getState("digest_day") === day) return;
  if (Date.now() - startedAt < SETTLE_MS || !disk.status.checkedAt) return;
  const { text, data } = buildDigest(store, now.getTime(), { diskFreeMb: disk.status.freeMb, dbMb: store.bytes() / 2 ** 20 });
  store.transaction(() => {
    store.addDigest(day, text, data);
    store.setState("digest_day", day);
  });
  console.log(`daily summary for ${day}`);
  void push(`Cellulose: daily summary`, text, data.open.critical ? "high" : "low");
});

const prune = () => {
  try {
    const { aged, overSize } = store.prune(Date.now() - EVENT_DAYS * DAY, Date.now() - ALERT_DAYS * DAY, MAX_DB_MB * 2 ** 20);
    if (aged) console.log(`retention: dropped ${aged} events older than ${EVENT_DAYS} days`);
    if (overSize) console.log(`retention: dropped the ${overSize} oldest events to stay under ${MAX_DB_MB} MB`);
  } catch (err) {
    console.error("retention:", (err as Error).message);
  }
};
prune();
const pruneTimer = setInterval(prune, 60 * 60_000);

journal.start();
hostJournal.start();
probe.start();
disk.start();
const web = startWeb(store, probe, disk, new Auth(PASSWORD), HOST, ALLOW, () => ({
  ports,
  files: { watched: watched.length, checkedAt: filesCheckedAt, changedAt: filesChangedAt },
}));
console.log(`watching ${UNIT} and the laptop; data in ${join(DATA_DIR, "siem.db")}`);

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    console.log(`${signal}: shutting down`);
    journal.stop();
    hostJournal.stop();
    probe.stop();
    disk.stop();
    for (const t of [pruneTimer, portsTimer, filesTimer, fairplayTimer, digestTimer]) clearInterval(t);
    web.close();
    store.close();
    process.exit(0);
  });
}
