// Everything is overridable from the environment (the systemd unit sets the few that differ from these).
const env = (name: string, fallback: number) => {
  const v = Number(process.env[name]);
  return Number.isFinite(v) && v > 0 ? v : fallback;
};

/** The dashboard. It shows players' IPs and usernames, so keep it to this machine or your own network. */
export const PORT = env("SIEM_PORT", 4100);
export const HOST = process.env.SIEM_HOST ?? "127.0.0.1";
/** Who else may connect: comma-separated addresses or subnets, e.g. 192.168.18.0/24. This machine always may. */
export const ALLOW = (process.env.SIEM_ALLOW ?? "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
/** The dashboard's password. Required when it listens on more than this machine. */
export const PASSWORD = process.env.SIEM_PASSWORD ?? "";
/** Where the database lives. systemd's StateDirectory= sets STATE_DIRECTORY. */
export const DATA_DIR = process.env.STATE_DIRECTORY ?? process.env.SIEM_DATA_DIR ?? "data";

/** The unit whose journal is read, both the server's own lines and systemd's lines about it. */
export const UNIT = process.env.SIEM_UNIT ?? "cellulose-server.service";

/** Health checks: the server itself, and (optional) the public address, which also covers the tunnel. */
export const LOCAL_HEALTH_URL = process.env.LOCAL_HEALTH_URL ?? "http://127.0.0.1:3000/health";
export const PUBLIC_HEALTH_URL = process.env.PUBLIC_HEALTH_URL ?? "";
export const PROBE_MS = env("PROBE_MS", 30_000);
/** Failed checks in a row before a target counts as down, so one slow reply isn't an outage. */
export const PROBE_FAILS = env("PROBE_FAILS", 2);

/** Days events and alerts are kept. */
export const EVENT_DAYS = env("EVENT_DAYS", 90);
export const ALERT_DAYS = env("ALERT_DAYS", 365);
/** The most the database may take; past it the oldest events go first (alerts stay). */
export const MAX_DB_MB = env("MAX_DB_MB", 15 * 1024);
/** Free space on the laptop's disk below which a "disk almost full" alert fires. */
export const DISK_MIN_FREE_MB = env("DISK_MIN_FREE_MB", 2 * 1024);
export const DISK_CHECK_MS = env("DISK_CHECK_MS", 10 * 60_000);

/** The game server's folder: its code and .env are watched for changes. */
export const SERVER_DIR = process.env.SERVER_DIR ?? "../CelluloseServer";
/**
 * Extra files or folders to watch, comma-separated, each `code:path` (changes on every rebuild) or `config:path`
 * (should rarely change). Added to the defaults in index.ts.
 */
export const WATCH = (process.env.WATCH ?? "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
export const FILES_CHECK_MS = env("FILES_CHECK_MS", 5 * 60_000);
export const PORTS_CHECK_MS = env("PORTS_CHECK_MS", 60_000);
export const FAIRPLAY_CHECK_MS = env("FAIRPLAY_CHECK_MS", 60 * 60_000);
/** The local hour (0-23) the daily summary is made; 0 counts as midnight. */
export const DIGEST_HOUR = Number.isInteger(Number(process.env.DIGEST_HOUR)) && process.env.DIGEST_HOUR ? Number(process.env.DIGEST_HOUR) : 8;

/**
 * Optional push for serious alerts: an ntfy topic URL (plain text) or a Discord webhook. Empty sends nothing.
 * Alerts carry IPs and usernames, so only point this at a service you trust.
 */
export const NOTIFY_URL = process.env.NOTIFY_URL ?? "";
export const NOTIFY_MIN_LEVEL = env("NOTIFY_MIN_LEVEL", 10);
