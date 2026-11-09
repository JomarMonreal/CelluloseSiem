import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import { foldMs, type Fired } from "./engine.js";
import type { Event, NewEvent } from "./events.js";

export type Alert = {
  id: number;
  rule: string;
  level: number;
  title: string;
  /** What repeats fold under: the rule's key for the event that raised it. */
  akey: string;
  srcip: string | null;
  username: string | null;
  mitre: string;
  /** How many times it fired before anyone looked: repeats within the rule's fold time add here. */
  count: number;
  first_ts: number;
  last_ts: number;
  event_id: number;
  acked: number;
};

type EventRow = { id: number; ts: number; source: NewEvent["source"]; evt: string; srcip: string | null; username: string | null; data: string };
const toEvent = (r: EventRow): Event => ({ id: r.id, ts: r.ts, source: r.source, evt: r.evt, srcip: r.srcip, username: r.username, fields: JSON.parse(r.data) });

/** Every event and alert, in one SQLite file. One writer (this process); reads come from the dashboard. */
export default class Store {
  private db: DatabaseSync;

  constructor(path: string) {
    this.db = new DatabaseSync(path);
    // deleting rows leaves the file its old size unless pages are handed back; switching an existing database over
    // takes one full VACUUM, after that prune() returns the space a little at a time
    if (Number((this.db.prepare("PRAGMA auto_vacuum").get() as { auto_vacuum: number }).auto_vacuum) !== 2) {
      this.db.exec("PRAGMA auto_vacuum = INCREMENTAL; VACUUM;");
    }
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = NORMAL;
      CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, source TEXT NOT NULL, evt TEXT NOT NULL,
        srcip TEXT, username TEXT, data TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
      CREATE INDEX IF NOT EXISTS events_evt ON events (evt, ts);
      CREATE INDEX IF NOT EXISTS events_srcip ON events (srcip, ts);
      CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY, rule TEXT NOT NULL, level INTEGER NOT NULL, title TEXT NOT NULL, akey TEXT NOT NULL,
        srcip TEXT, username TEXT, mitre TEXT NOT NULL, count INTEGER NOT NULL, first_ts INTEGER NOT NULL,
        last_ts INTEGER NOT NULL, event_id INTEGER NOT NULL, acked INTEGER NOT NULL DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS alerts_last ON alerts (last_ts);
      CREATE INDEX IF NOT EXISTS alerts_fold ON alerts (rule, akey, last_ts);
      CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS digests (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, day TEXT NOT NULL, text TEXT NOT NULL, data TEXT NOT NULL);
    `);
  }

  /** Runs `fn` as one transaction: a batch of journal lines and the cursor after them land together or not at all. */
  transaction<T>(fn: () => T): T {
    this.db.exec("BEGIN");
    try {
      const out = fn();
      this.db.exec("COMMIT");
      return out;
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }

  // prepared once: the first run inserts the whole journal history through it
  private insertEvent?: ReturnType<DatabaseSync["prepare"]>;

  addEvent(e: NewEvent): Event {
    this.insertEvent ??= this.db.prepare("INSERT INTO events (ts, source, evt, srcip, username, data) VALUES (?, ?, ?, ?, ?, ?)");
    const r = this.insertEvent.run(e.ts, e.source, e.evt, e.srcip, e.username, JSON.stringify(e.fields));
    return { ...e, id: Number(r.lastInsertRowid) };
  }

  /** Records a fired rule: a new alert, or one more on the open alert it folds into. */
  raise({ rule, event, key }: Fired): { alert: Alert; fresh: boolean } {
    const open = this.db
      .prepare("SELECT id FROM alerts WHERE rule = ? AND akey = ? AND acked = 0 AND last_ts > ? ORDER BY id DESC LIMIT 1")
      .get(rule.id, key, event.ts - foldMs(rule)) as { id: number } | undefined;
    if (open) {
      this.db
        .prepare("UPDATE alerts SET count = count + 1, last_ts = ?, event_id = ?, title = ?, srcip = coalesce(?, srcip) WHERE id = ?")
        .run(event.ts, event.id, rule.title(event), event.srcip, open.id);
      return { alert: this.alert(open.id)!, fresh: false };
    }
    const r = this.db
      .prepare(
        `INSERT INTO alerts (rule, level, title, akey, srcip, username, mitre, count, first_ts, last_ts, event_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)`,
      )
      .run(rule.id, rule.level, rule.title(event), key, event.srcip, event.username, (rule.mitre ?? []).join(","), event.ts, event.ts, event.id);
    return { alert: this.alert(Number(r.lastInsertRowid))!, fresh: true };
  }

  alert(id: number): Alert | undefined {
    return this.db.prepare("SELECT * FROM alerts WHERE id = ?").get(id) as Alert | undefined;
  }

  alerts(opts: { all: boolean; limit: number }): Alert[] {
    return this.db
      // open before handled, then the most serious, then the most recent
      .prepare(`SELECT * FROM alerts ${opts.all ? "" : "WHERE acked = 0"} ORDER BY acked, level DESC, last_ts DESC LIMIT ?`)
      .all(opts.limit) as Alert[];
  }

  ack(id: number | "all"): number {
    const r = id === "all" ? this.db.prepare("UPDATE alerts SET acked = 1 WHERE acked = 0").run() : this.db.prepare("UPDATE alerts SET acked = 1 WHERE id = ?").run(id);
    return Number(r.changes);
  }

  /** Newest first. `before` is an event id, for paging back. `q` searches the event's fields as text. */
  /** Events and alerts per hour since `since`, split the way the dashboard's activity chart shows them. */
  timeline(since: number) {
    return this.db
      .prepare(
        `SELECT ts / 3600000 hour,
           sum(evt = 'auth_fail') failed,
           sum(evt IN ('rate_limit', 'conn_refused', 'origin_refused', 'bad_request', 'unknown_event', 'server_error', 'avatar_rejected')) blocked,
           sum(evt NOT IN ('auth_fail', 'rate_limit', 'conn_refused', 'origin_refused', 'bad_request', 'unknown_event', 'server_error', 'avatar_rejected')) other
         FROM events WHERE ts >= ? AND source = 'audit' GROUP BY hour ORDER BY hour`,
      )
      .all(since) as { hour: number; failed: number; blocked: number; other: number }[];
  }

  /** What happened around an alert: the same IP or account, from a little before it began to just after its last. */
  related(a: Alert, limit: number): Event[] {
    const keys = [a.srcip, a.username].filter((k): k is string => !!k);
    if (!keys.length) {
      return (this.db.prepare("SELECT * FROM events WHERE ts BETWEEN ? AND ? AND source != 'log' ORDER BY id DESC LIMIT ?").all(a.first_ts - 5 * 60_000, a.last_ts + 60_000, limit) as EventRow[]).map(toEvent);
    }
    return (
      this.db
        .prepare(`SELECT * FROM events WHERE ts BETWEEN ? AND ? AND (srcip IN (${keys.map(() => "?").join()}) OR username IN (${keys.map(() => "?").join()})) ORDER BY id DESC LIMIT ?`)
        .all(a.first_ts - 15 * 60_000, a.last_ts + 5 * 60_000, ...keys, ...keys, limit) as EventRow[]
    ).map(toEvent);
  }

  events(opts: { evt?: string[]; srcip?: string; username?: string; q?: string; before?: number; limit: number }): Event[] {
    const where: string[] = [];
    const args: SQLInputValue[] = [];
    const filter = (sql: string, arg: SQLInputValue) => {
      where.push(sql);
      args.push(arg);
    };
    if (opts.evt?.length) {
      where.push(`evt IN (${opts.evt.map(() => "?").join()})`);
      args.push(...opts.evt);
    }
    if (opts.srcip) filter("srcip = ?", opts.srcip);
    if (opts.username) filter("username = ?", opts.username);
    if (opts.q) filter("data LIKE ? ESCAPE '\\'", `%${opts.q.replace(/[\\%_]/g, "\\$&")}%`);
    if (opts.before) filter("id < ?", opts.before);
    const sql = `SELECT * FROM events ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY id DESC LIMIT ?`;
    return (this.db.prepare(sql).all(...args, opts.limit) as EventRow[]).map(toEvent);
  }

  /** Oldest first: what the engine replays on start, so thresholds and `after` rules pick up where they left off. */
  eventsSince(ts: number): Event[] {
    return (this.db.prepare("SELECT * FROM events WHERE ts >= ? ORDER BY id").all(ts) as EventRow[]).map(toEvent);
  }

  summary(since: number) {
    const count = (sql: string, ...args: SQLInputValue[]) => Number((this.db.prepare(sql).get(...args) as { n: number }).n);
    return {
      events: count("SELECT count(*) n FROM events"),
      eventsSince: count("SELECT count(*) n FROM events WHERE ts >= ?", since),
      lastEventTs: count("SELECT coalesce(max(ts), 0) n FROM events WHERE source != 'probe'"),
      byEvt: this.db.prepare("SELECT evt, count(*) n FROM events WHERE ts >= ? GROUP BY evt ORDER BY n DESC").all(since) as { evt: string; n: number }[],
      openAlerts: this.db.prepare("SELECT level, count(*) n FROM alerts WHERE acked = 0 GROUP BY level ORDER BY level DESC").all() as { level: number; n: number }[],
    };
  }

  /** The IPs behind the most security events since `since`, with what they did. */
  topIps(since: number, limit: number) {
    return this.db
      .prepare(
        `SELECT srcip, count(*) n, sum(evt = 'auth_fail') auth_fail, sum(evt = 'auth_ok') auth_ok, sum(evt = 'signup_ok') signups,
           sum(evt IN ('rate_limit', 'conn_refused')) limited, sum(evt IN ('bad_request', 'unknown_event', 'server_error')) probing,
           max(ts) last_ts
         FROM events WHERE ts >= ? AND srcip IS NOT NULL GROUP BY srcip ORDER BY n DESC LIMIT ?`,
      )
      .all(since, limit);
  }

  /** A read-only query for the analyses (fairplay.ts, digest.ts), which know the events' shapes. */
  query(sql: string, ...args: SQLInputValue[]): Record<string, unknown>[] {
    return this.db.prepare(sql).all(...args) as Record<string, unknown>[];
  }

  addDigest(day: string, text: string, data: unknown) {
    this.db.prepare("INSERT INTO digests (ts, day, text, data) VALUES (?, ?, ?, ?)").run(Date.now(), day, text, JSON.stringify(data));
  }

  digests(limit: number) {
    return (this.db.prepare("SELECT * FROM digests ORDER BY id DESC LIMIT ?").all(limit) as { id: number; ts: number; day: string; text: string; data: string }[]).map((d) => ({
      ...d,
      data: JSON.parse(d.data),
    }));
  }

  getState(key: string): string | undefined {
    return (this.db.prepare("SELECT value FROM state WHERE key = ?").get(key) as { value: string } | undefined)?.value;
  }

  setState(key: string, value: string) {
    this.db.prepare("INSERT INTO state (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value").run(key, value);
  }

  /** Drops events and alerts past their retention, then the oldest events until the file fits in `maxBytes`. */
  prune(eventsBefore: number, alertsBefore: number, maxBytes: number): { aged: number; overSize: number } {
    const aged = Number(this.db.prepare("DELETE FROM events WHERE ts < ?").run(eventsBefore).changes);
    this.db.prepare("DELETE FROM alerts WHERE last_ts < ?").run(alertsBefore);
    this.reclaim();
    // alerts stay: they're small, and they're the part worth keeping longest
    let overSize = 0;
    for (let i = 0; i < 20 && this.bytes() > maxBytes; i++) {
      const total = Number((this.db.prepare("SELECT count(*) n FROM events").get() as { n: number }).n);
      if (!total) break;
      // the oldest tenth each round, so a small overshoot doesn't cost much history
      const row = this.db.prepare("SELECT id FROM events ORDER BY id LIMIT 1 OFFSET ?").get(Math.ceil(total / 10)) as { id: number } | undefined;
      overSize += Number(this.db.prepare("DELETE FROM events WHERE id < ?").run(row?.id ?? Number.MAX_SAFE_INTEGER).changes);
      this.reclaim();
    }
    return { aged, overSize };
  }

  /** Hands the pages freed by deletes back to the disk, and folds the write-ahead log into the file. */
  private reclaim() {
    this.db.exec("PRAGMA incremental_vacuum; PRAGMA wal_checkpoint(TRUNCATE);");
  }

  /** The database's size on disk, in bytes (pages in use and free, not counting the write-ahead log). */
  bytes(): number {
    const pages = Number((this.db.prepare("PRAGMA page_count").get() as { page_count: number }).page_count);
    const size = Number((this.db.prepare("PRAGMA page_size").get() as { page_size: number }).page_size);
    return pages * size;
  }

  close() {
    this.db.close();
  }
}
