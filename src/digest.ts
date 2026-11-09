import type Store from "./store.js";

const DAY = 24 * 60 * 60_000;

export type DigestData = {
  from: number;
  to: number;
  open: { total: number; critical: number; high: number };
  newAlerts: { level: number; title: string; count: number }[];
  players: { signedIn: number; newAccounts: number; signIns: number; games: number; ranked: number; guests: number };
  security: { failedSignIns: number; blocked: number; probing: number; topIp: string | null; topIpEvents: number };
  fairPlay: { scripted: number; modified: number; findings: number };
  server: { starts: number; crashes: number; outages: number; publicOutages: number };
  laptop: { sleeps: number; sudo: number; wrongPasswords: number; logins: number; tunnelDrops: number; ports: number; fileChanges: number };
  storage: { diskFreeMb: number; dbMb: number };
};

/** Counts the last 24 hours (or `from`..`to`) into a summary, and words it for a phone notification. */
export function buildDigest(store: Store, to: number, storage: DigestData["storage"], from = to - DAY): { text: string; data: DigestData } {
  const n = (sql: string, ...args: (string | number)[]) => Number(store.query(sql, ...args)[0]?.n ?? 0);
  const count = (evts: string[]) => n(`SELECT count(*) n FROM events WHERE ts >= ? AND ts < ? AND evt IN (${evts.map(() => "?").join()})`, from, to, ...evts);
  const games = (extra = "") => n(`SELECT count(DISTINCT json_extract(data, '$.game')) n FROM events WHERE evt = 'game_player' AND ts >= ? AND ts < ? ${extra}`, from, to);
  const top = store.query("SELECT srcip, count(*) n FROM events WHERE ts >= ? AND ts < ? AND source = 'audit' AND srcip IS NOT NULL GROUP BY srcip ORDER BY n DESC LIMIT 1", from, to)[0];
  const openRows = store.query("SELECT level, count(*) n FROM alerts WHERE acked = 0 GROUP BY level");
  const open = (min: number, max = 99) => openRows.filter((r) => Number(r.level) >= min && Number(r.level) <= max).reduce((s, r) => s + Number(r.n), 0);

  const data: DigestData = {
    from,
    to,
    open: { total: open(0), critical: open(12), high: open(10, 11) },
    newAlerts: store
      .query("SELECT level, title, count FROM alerts WHERE first_ts >= ? AND first_ts < ? ORDER BY level DESC, last_ts DESC LIMIT 5", from, to)
      .map((r) => ({ level: Number(r.level), title: String(r.title), count: Number(r.count) })),
    players: {
      signedIn: n("SELECT count(DISTINCT username) n FROM events WHERE evt = 'auth_ok' AND ts >= ? AND ts < ?", from, to),
      newAccounts: count(["signup_ok"]),
      signIns: count(["auth_ok"]),
      games: games(),
      ranked: games("AND json_extract(data, '$.kind') = 'ranked'"),
      guests: n("SELECT count(DISTINCT json_extract(data, '$.name') || srcip) n FROM events WHERE evt = 'game_player' AND username IS NULL AND ts >= ? AND ts < ?", from, to),
    },
    security: {
      failedSignIns: count(["auth_fail"]),
      blocked: count(["rate_limit", "conn_refused", "origin_refused"]),
      probing: count(["bad_request", "unknown_event", "server_error"]),
      topIp: top ? String(top.srcip) : null,
      topIpEvents: top ? Number(top.n) : 0,
    },
    fairPlay: {
      scripted: n("SELECT count(*) n FROM alerts WHERE rule IN ('scripted-speed', 'scripted-rhythm') AND last_ts >= ? AND last_ts < ?", from, to),
      modified: count(["game_rejected"]),
      findings: n("SELECT count(*) n FROM events WHERE source = 'analysis' AND ts >= ? AND ts < ?", from, to),
    },
    server: {
      starts: count(["server_start"]),
      crashes: count(["server_crash", "unit_failed"]),
      outages: n("SELECT count(*) n FROM events WHERE evt = 'probe_down' AND json_extract(data, '$.target') = 'local' AND ts >= ? AND ts < ?", from, to),
      publicOutages: n("SELECT count(*) n FROM events WHERE evt = 'probe_down' AND json_extract(data, '$.target') = 'public' AND ts >= ? AND ts < ?", from, to),
    },
    laptop: {
      sleeps: count(["laptop_sleep"]),
      sudo: count(["sudo_command"]),
      wrongPasswords: count(["local_auth_fail", "sudo_denied"]),
      logins: count(["login_session", "ssh_login"]),
      tunnelDrops: count(["tunnel_drop"]),
      ports: count(["port_opened"]),
      fileChanges: count(["file_changed"]),
    },
    storage,
  };
  return { text: wordDigest(data), data };
}

const plural = (n: number, one: string, many = `${one}s`) => `${n.toLocaleString()} ${n === 1 ? one : many}`;
const gb = (mb: number) => (mb >= 1024 ? `${(mb / 1024).toFixed(1)} GB` : `${Math.round(mb)} MB`);

/** The summary as a few short lines, for a phone notification. */
export function wordDigest(d: DigestData): string {
  const lines: string[] = [];
  lines.push(
    d.open.total === 0
      ? "All clear: no open alerts."
      : `${plural(d.open.total, "open alert")}${d.open.critical ? `, ${d.open.critical} critical` : d.open.high ? `, ${d.open.high} high` : ""}.`,
  );
  for (const a of d.newAlerts.slice(0, 3)) lines.push(`• ${a.title}${a.count > 1 ? ` (×${a.count})` : ""}`);
  const p = d.players;
  lines.push(`Players: ${plural(p.signedIn, "account")} signed in, ${plural(p.newAccounts, "new account")}, ${plural(p.games, "game")} (${p.ranked} ranked).`);
  const s = d.security;
  lines.push(
    s.failedSignIns || s.blocked || s.probing
      ? `Security: ${plural(s.failedSignIns, "failed sign-in")}, ${s.blocked} blocked, ${plural(s.probing, "odd request")}${s.topIp ? `; busiest IP ${s.topIp}` : ""}.`
      : "Security: nothing suspicious.",
  );
  const f = d.fairPlay;
  if (f.scripted || f.modified || f.findings) lines.push(`Fair play: ${plural(f.scripted, "scripted-play alert")}, ${plural(f.modified, "impossible move")}, ${plural(f.findings, "pattern")} found.`);
  const v = d.server;
  lines.push(
    v.outages || v.crashes || v.publicOutages
      ? `Server: ${plural(v.outages, "outage")}, ${plural(v.crashes, "crash", "crashes")}, unreachable from the internet ${plural(v.publicOutages, "time")}.`
      : `Server: up all day${v.starts ? ` (${plural(v.starts, "restart")})` : ""}.`,
  );
  const l = d.laptop;
  const laptop = [
    l.sleeps && `slept ${plural(l.sleeps, "time")} (game offline)`,
    l.wrongPasswords && plural(l.wrongPasswords, "wrong password"),
    l.sudo && plural(l.sudo, "sudo command"),
    l.ports && plural(l.ports, "new open port"),
    l.fileChanges && plural(l.fileChanges, "watched file change"),
    l.tunnelDrops >= 20 && `tunnel dropped ${l.tunnelDrops} times`,
  ].filter(Boolean);
  lines.push(`Laptop: ${laptop.length ? laptop.join(", ") : "nothing unusual"}. ${gb(d.storage.diskFreeMb)} disk free.`);
  return lines.join("\n");
}
