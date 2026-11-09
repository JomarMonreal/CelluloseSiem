import assert from "node:assert/strict";
import { test } from "node:test";
import { Engine } from "../src/engine.js";
import { type Event, fromJournal, type NewEvent } from "../src/events.js";
import { RULES } from "../src/rules.js";
import Store from "../src/store.js";

const UNIT = "cellulose-server.service";
const MIN = 60_000;
const T0 = Date.UTC(2026, 10, 9, 12);

/** A journal entry as `journalctl -o json` prints it. */
const entry = (message: string, ts: number, unit = UNIT) => ({
  MESSAGE: message,
  __REALTIME_TIMESTAMP: String(ts * 1000),
  __CURSOR: `c${ts}`,
  ...(unit === UNIT ? { _SYSTEMD_UNIT: UNIT } : { _SYSTEMD_UNIT: "init.scope", UNIT }),
});
const audit = (fields: Record<string, unknown>, ts: number) => entry(JSON.stringify({ app: "cellulose", ...fields }), ts);

/** Runs entries through parsing, the store and the engine, like index.ts does, and returns the alerts. */
function run(entries: Record<string, unknown>[]) {
  const store = new Store(":memory:");
  const engine = new Engine(RULES);
  for (const en of entries) {
    const ne = fromJournal(en, UNIT);
    if (!ne) continue;
    const e = store.addEvent(ne);
    for (const fired of engine.process(e)) store.raise(fired);
  }
  return store.alerts({ all: true, limit: 100 });
}

const fail = (target: string, srcip: string, ts: number) =>
  audit({ evt: "auth_fail", method: "password", srcip, sid: "s", target, reason: "wrong username or password" }, ts);

test("parses the server's audit lines, its other output, and systemd's lines about it", () => {
  const a = fromJournal(fail("victim", "203.0.113.7", T0), UNIT)!;
  assert.equal(a.source, "audit");
  assert.equal(a.evt, "auth_fail");
  assert.equal(a.srcip, "203.0.113.7");
  assert.equal(a.username, "victim");
  assert.equal(a.ts, T0);

  const log = fromJournal(entry("Cellulose server listening on http://127.0.0.1:3000", T0), UNIT)!;
  assert.equal(log.evt, "log");

  const failed = fromJournal(entry("cellulose-server.service: Failed with result 'exit-code'.", T0, "other"), UNIT)!;
  assert.deepEqual([failed.source, failed.evt, failed.fields.result], ["systemd", "unit_failed", "exit-code"]);
  const restart = fromJournal(entry("cellulose-server.service: Scheduled restart job, restart counter is at 4.", T0, "other"), UNIT)!;
  assert.equal(restart.fields.counter, 4);

  // journald hands over non-UTF-8 messages as byte arrays
  const bytes = fromJournal({ ...entry("", T0), MESSAGE: [...Buffer.from("hello")] }, UNIT)!;
  assert.equal(bytes.fields.message, "hello");
});

test("a line that only looks like an audit event stays a plain log line", () => {
  for (const text of ['{"app":"cellulose","evt":"made_up"}', '{"app":"cellulose","evt":"auth_ok"', '{"app":"cellulose","evt":3}']) {
    assert.equal(fromJournal(entry(text, T0), UNIT)!.evt, "log", text);
  }
});

test("password guessing fires on the 8th failure for one account in 10 minutes, not before", () => {
  const seven = Array.from({ length: 7 }, (_, i) => fail("victim", `198.51.100.${i}`, T0 + i * MIN));
  assert.deepEqual(run(seven).map((a) => a.rule), []);
  const alerts = run([...seven, fail("victim", "198.51.100.9", T0 + 8 * MIN)]);
  assert.deepEqual(alerts.map((a) => a.rule), ["password-guessing"]);
  assert.equal(alerts[0].level, 10);
});

test("failures spread wider than the window don't add up", () => {
  const slow = Array.from({ length: 12 }, (_, i) => fail("victim", "198.51.100.1", T0 + i * 2 * MIN));
  assert.deepEqual(run(slow).map((a) => a.rule), []);
});

test("credential stuffing needs 10 different usernames from one IP", () => {
  const same = Array.from({ length: 10 }, (_, i) => fail(`user${i % 3}`, "203.0.113.7", T0 + i * 1000));
  assert.ok(!run(same).some((a) => a.rule === "credential-stuffing"));
  const many = Array.from({ length: 10 }, (_, i) => fail(`user${i}`, "203.0.113.7", T0 + i * 1000));
  const alerts = run(many);
  assert.deepEqual(alerts.map((a) => [a.rule, a.srcip]), [["credential-stuffing", "203.0.113.7"]]);
});

test("a sign-in right after an attack on that account is flagged as a possible compromise", () => {
  const guessing = Array.from({ length: 8 }, (_, i) => fail("victim", "203.0.113.7", T0 + i * 1000));
  const ok = audit({ evt: "auth_ok", method: "password", srcip: "192.0.2.50", sid: "s", user: "victim" }, T0 + 2 * MIN);
  assert.ok(run([...guessing, ok]).some((a) => a.rule === "signin-after-attack" && a.level === 13));

  // the same sign-in an hour later is just a sign-in
  const later = audit({ evt: "auth_ok", method: "password", srcip: "192.0.2.50", sid: "s", user: "victim" }, T0 + 60 * MIN);
  assert.ok(!run([...guessing, later]).some((a) => a.rule === "signin-after-attack"));
});

test("a sustained attack folds into one open alert instead of a new one each time", () => {
  const flood = Array.from({ length: 24 }, (_, i) => fail("victim", "203.0.113.7", T0 + i * 1000));
  const alerts = run(flood).filter((a) => a.rule === "password-guessing");
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].count, 3);
});

test("server rules: crash loop, a failed unit, errors in its output", () => {
  // you restarting it is not a crash loop; systemd restarting it after it died is
  const starts = [0, 1, 2].map((i) => audit({ evt: "server_start", port: 3000, production: true, cors_any: false }, T0 + i * MIN));
  assert.ok(!run(starts).some((a) => a.rule === "crash-loop"));
  const restarts = [1, 2, 3].map((n) => entry(`cellulose-server.service: Scheduled restart job, restart counter is at ${n}.`, T0 + n * 2000, "other"));
  assert.ok(run(restarts).some((a) => a.rule === "crash-loop" && a.level === 12));

  assert.ok(run([entry("cellulose-server.service: Failed with result 'exit-code'.", T0, "other")]).some((a) => a.rule === "unit-failed"));

  // stack frames under an error line don't count as more errors
  const trace = [entry("unhandled rejection: Error: boom", T0), ...Array.from({ length: 8 }, (_, i) => entry(`    at frame${i} (file.js:1:1)`, T0 + i))];
  assert.ok(!run(trace).some((a) => a.rule === "error-output"));
  const errors = Array.from({ length: 5 }, (_, i) => entry(`signup: Error: database unavailable ${i}`, T0 + i * 1000));
  assert.ok(run(errors).some((a) => a.rule === "error-output"));
});

test("health checks going down raise outages", () => {
  const store = new Store(":memory:");
  const engine = new Engine(RULES);
  const probe = (target: string): NewEvent => ({ ts: T0, source: "probe", evt: "probe_down", srcip: null, username: null, fields: { target, url: "u", detail: "ECONNREFUSED" } });
  const rules = [probe("local"), probe("public")].flatMap((ne) => engine.process(store.addEvent(ne)).map((f) => f.rule.id));
  assert.deepEqual(rules, ["server-down", "public-down"]);
});

test("the store pages events newest first and searches their fields literally", () => {
  const store = new Store(":memory:");
  const add = (evt: string, data: Record<string, unknown>) =>
    store.addEvent({ ts: T0, source: "audit", evt, srcip: "203.0.113.7", username: null, fields: data });
  const ids: Event[] = [add("bad_request", { reason: "100% junk" }), add("bad_request", { reason: "plain" }), add("auth_ok", {})];
  assert.deepEqual(store.events({ limit: 2 }).map((e) => e.id), [ids[2].id, ids[1].id]);
  assert.deepEqual(store.events({ limit: 10, before: ids[1].id }).map((e) => e.id), [ids[0].id]);
  // % is a LIKE wildcard; searching for it should only find the line that contains it
  assert.deepEqual(store.events({ limit: 10, q: "0%" }).map((e) => e.id), [ids[0].id]);
  assert.equal(store.events({ limit: 10, evt: ["auth_ok"] }).length, 1);
});

test("the size cap drops the oldest events first, keeps alerts, and hands the space back", () => {
  const store = new Store(":memory:");
  const engine = new Engine(RULES);
  const filler = "x".repeat(2000);
  for (let i = 0; i < 2000; i++) {
    const e = store.addEvent({ ts: T0 + i * 1000, source: "audit", evt: "auth_fail", srcip: "203.0.113.7", username: `u${i}`, fields: { target: `u${i}`, pad: filler } });
    for (const fired of engine.process(e)) store.raise(fired);
  }
  const alertsBefore = store.alerts({ all: true, limit: 100 }).length;
  assert.ok(alertsBefore > 0);
  const before = store.bytes();
  const cap = Math.floor(before / 3);
  const { overSize } = store.prune(0, 0, cap);
  assert.ok(overSize > 0);
  assert.ok(store.bytes() <= cap, `${store.bytes()} > ${cap}`);
  // what's left is the newest
  const left = store.events({ limit: 500 });
  assert.equal(left[0].username, "u1999");
  assert.equal(store.alerts({ all: true, limit: 100 }).length, alertsBefore);
});

test("the activity timeline splits each hour into normal, failed and blocked", () => {
  const store = new Store(":memory:");
  const add = (evt: string, ts: number) => store.addEvent({ ts, source: "audit", evt, srcip: "203.0.113.7", username: null, fields: {} });
  add("auth_fail", T0);
  add("auth_fail", T0 + 1000);
  add("rate_limit", T0 + 2000);
  add("auth_ok", T0 + 3000);
  add("auth_ok", T0 + 3_600_000);
  // rows come back without a prototype; spread them to compare as plain objects
  assert.deepEqual(store.timeline(T0 - 1).map((r) => ({ ...r })), [
    { hour: T0 / 3_600_000, failed: 2, blocked: 1, other: 1 },
    { hour: T0 / 3_600_000 + 1, failed: 0, blocked: 0, other: 1 },
  ]);
});
