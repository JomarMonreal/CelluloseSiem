import assert from "node:assert/strict";
import { test } from "node:test";
import { buildDigest } from "../src/digest.js";
import { Engine } from "../src/engine.js";
import { fromHost, type NewEvent } from "../src/events.js";
import { findings, fresh } from "../src/fairplay.js";
import { diff } from "../src/files.js";
import { RULES } from "../src/rules.js";
import Store from "../src/store.js";

const T0 = Date.UTC(2026, 10, 9, 12);
const MIN = 60_000;
const host = (id: string, message: string, ts = T0) => ({ SYSLOG_IDENTIFIER: id, MESSAGE: message, __REALTIME_TIMESTAMP: String(ts * 1000) });

/** Events through the store and the engine, like index.ts; the alerts that come out. */
function run(events: NewEvent[]) {
  const store = new Store(":memory:");
  const engine = new Engine(RULES);
  for (const ne of events) for (const fired of engine.process(store.addEvent(ne))) store.raise(fired);
  return { store, alerts: store.alerts({ all: true, limit: 100 }) };
}
const rules = (events: NewEvent[]) => run(events).alerts.map((a) => a.rule);

// the laptop, from lines as this laptop's journal has them

test("reads the laptop's log lines that matter, and drops the rest", () => {
  const sudo = fromHost(host("sudo", "alice : TTY=/dev/pts/8 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart cellulose-siem"))!;
  assert.deepEqual([sudo.evt, sudo.username, sudo.fields.as, sudo.fields.command], ["sudo_command", "alice", "root", "/usr/bin/systemctl restart cellulose-siem"]);
  const streak = fromHost(host("sudo", "alice : 3 incorrect password attempts ; TTY=/dev/pts/6 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/ls"))!;
  assert.deepEqual([streak.evt, streak.fields.attempts], ["sudo_denied", 3]);
  assert.equal(fromHost(host("sudo", "pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)")), null);
  assert.equal(fromHost(host("sudo", "pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/6 ruser=alice rhost=  user=alice")), null);
  assert.equal(fromHost(host("unix_chkpwd", "password check failed for user (alice)"))!.evt, "local_auth_fail");
  const user = fromHost(host("useradd", "new user: name=wazuh, UID=106, GID=127, home=/var/ossec, shell=/sbin/nologin, from=none"))!;
  assert.deepEqual([user.evt, user.username, user.fields.uid], ["user_added", "wazuh", 106]);
  assert.equal(fromHost(host("usermod", "add 'mallory' to group 'sudo'"))!.fields.group, "sudo");
  assert.equal(fromHost(host("usermod", "add 'mallory' to shadow group 'sudo'")), null);
  assert.equal(fromHost(host("systemd-logind", "The system will suspend now!"))!.evt, "laptop_sleep");
  assert.equal(fromHost(host("systemd-logind", "New session '3' of user 'alice' with class 'user' and type 'wayland'."))!.username, "alice");
  assert.equal(fromHost(host("systemd-logind", "New session '1' of user 'sddm' with class 'greeter' and type 'wayland'.")), null);
  assert.equal(fromHost(host("cloudflared", '2026-11-02T12:51:25Z ERR Connection terminated error="failed to dial to edge with quic: timeout" connIndex=1'))!.evt, "tunnel_drop");
  assert.equal(fromHost(host("cloudflared", "2026-11-02T12:51:25Z INF Registered tunnel connection connIndex=3 location=hk"))!.fields.location, "hk");
  const ssh = fromHost(host("sshd-session", "Accepted publickey for alice from 192.168.1.20 port 51234 ssh2: ED25519 SHA256:x"))!;
  assert.deepEqual([ssh.evt, ssh.username, ssh.srcip], ["ssh_login", "alice", "192.168.1.20"]);
  assert.equal(fromHost(host("sshd", "Failed password for invalid user admin from 203.0.113.9 port 4444 ssh2"))!.username, "admin");
  assert.equal(fromHost(host("kernel", "Out of memory: Killed process 4242 (node) total-vm:1234kB"))!.fields.process, "node");
  assert.equal(fromHost(host("kernel", "wlp3s0: associated")), null);
});

test("laptop rules: wrong passwords, new users, admin rights, sleep", () => {
  const wrong = (i: number) => fromHost(host("unix_chkpwd", "password check failed for user (alice)", T0 + i * MIN))!;
  assert.deepEqual(rules([wrong(0), wrong(1)]), []);
  assert.deepEqual(rules([wrong(0), wrong(1), wrong(2)]), ["laptop-password-guessing"]);
  // a typo streak's summary line doesn't raise a second alert
  const streak = fromHost(host("sudo", "alice : 3 incorrect password attempts ; TTY=/dev/pts/6 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/ls", T0 + 3 * MIN))!;
  assert.deepEqual(rules([wrong(0), wrong(1), wrong(2), streak]), ["laptop-password-guessing"]);
  assert.deepEqual(rules([fromHost(host("useradd", "new user: name=x, UID=1001, GID=1001, home=/home/x, shell=/bin/bash, from=none"))!]), ["new-system-user"]);
  assert.deepEqual(rules([fromHost(host("usermod", "add 'x' to group 'sudo'"))!]), ["admin-group"]);
  assert.deepEqual(rules([fromHost(host("usermod", "add 'x' to group 'video'"))!]), []);
  assert.deepEqual(rules([fromHost(host("systemd-logind", "The system will suspend now!"))!]), ["laptop-slept"]);
});

// the game

const audit = (evt: string, fields: Record<string, unknown>, ts = T0): NewEvent => ({
  ts,
  source: "audit",
  evt,
  srcip: (fields.srcip as string) ?? null,
  username: (fields.user as string) ?? null,
  fields,
});
const played = (user: string | undefined, stats: Record<string, unknown>, extra: Record<string, unknown> = {}) =>
  audit("game_player", { game: "R#1", kind: "friends", mode: "strongest500", srcip: "203.0.113.7", user, name: user ?? "guesty", place: 1, actions: 30, after_setup: 10, burst: 1, fast: 0, gaps: 29, median_ms: 600, spread: 0.45, impossible: 0, ...stats, ...extra });

test("scripted play: inhuman speed and a metronome beat; people pass", () => {
  assert.deepEqual(rules([played("alice", {})]), []);
  assert.deepEqual(rules([played("bot", { burst: 8, fast: 8 })]), ["scripted-speed"]);
  assert.deepEqual(rules([played("tick", { gaps: 29, spread: 0.01, median_ms: 161 })]), ["scripted-rhythm"]);
  // too few moves to tell a rhythm from luck
  assert.deepEqual(rules([played("short", { gaps: 8, spread: 0.02 })]), []);
  const guest = run([played(undefined, { burst: 6, fast: 6 })]).alerts[0];
  assert.match(guest.title, /guest 'guesty' \(203\.0\.113\.7\)/);
  assert.deepEqual(rules([audit("game_rejected", { srcip: "203.0.113.7", user: "eve", name: "eve", kind: "ranked", reason: "not your territory" })]), ["modified-client"]);
});

/** Ranked games where `winner` beats `loser` `n` times, `loserIdle` of them without moving after setup. */
function rankedSeries(winner: string, loser: string, n: number, opts: { loserIdle?: number; winnerIp?: string; loserIp?: string } = {}): NewEvent[] {
  return Array.from({ length: n }, (_, i) => [
    played(winner, {}, { game: `G${i}`, kind: "ranked", place: 1, srcip: opts.winnerIp ?? "198.51.100.1" }),
    played(loser, { after_setup: i < (opts.loserIdle ?? 0) ? 0 : 5 }, { game: `G${i}`, kind: "ranked", place: 2, srcip: opts.loserIp ?? "198.51.100.2" }),
  ]).flat().map((e, i) => ({ ...e, ts: T0 + i * MIN }));
}

test("fair play across games: win trading, throwing, smurfs, linked accounts", () => {
  const now = T0 + 60 * MIN;
  const checks = (events: NewEvent[]) => findings(run(events).store, now).map((f) => `${f.check} ${f.key}`).sort();

  assert.deepEqual(checks(rankedSeries("ace", "feeder", 4)), []);
  assert.ok(checks(rankedSeries("ace", "feeder", 5)).includes("win_trading ace > feeder"));
  assert.ok(checks(rankedSeries("ace", "feeder", 5, { loserIdle: 3 })).includes("throwing feeder"));
  // new this week and won all 5
  assert.ok(checks(rankedSeries("ace", "feeder", 5)).includes("smurf ace"));

  const signIn = (user: string, srcip: string) => audit("auth_ok", { method: "password", srcip, user });
  const linked = checks([signIn("ace", "192.0.2.50"), signIn("feeder", "192.0.2.50"), ...rankedSeries("ace", "feeder", 2)]);
  assert.ok(linked.includes("linked_accounts ace + feeder"));
  const shared = checks([signIn("a", "192.0.2.9"), signIn("b", "192.0.2.9"), signIn("c", "192.0.2.9")]);
  assert.ok(shared.includes("shared_ip 192.0.2.9"));
});

test("a finding is reported once, and again only when it grows", () => {
  const { store } = run(rankedSeries("ace", "feeder", 5));
  const seen: Record<string, number> = {};
  const first = fresh(findings(store, T0 + 60 * MIN), seen, T0);
  assert.ok(first.some((e) => e.evt === "win_trading"));
  assert.deepEqual(fresh(findings(store, T0 + 60 * MIN), seen, T0), []);
  // the findings raise their alerts like any event
  assert.ok(rules(first).includes("win-trading-pattern"));
});

test("file changes: changed, added, removed; a newly watched path isn't a change", () => {
  const watched = [
    { path: "/srv/app", kind: "code" as const },
    { path: "/etc/new", kind: "config" as const },
  ];
  const before = { "/srv/app": { "index.js": "1", "old.js": "1" } };
  const after = { "/srv/app": { "index.js": "2", "new.js": "1" }, "/etc/new": { "": "x" } };
  assert.deepEqual(diff(before, after, watched), [{ path: "/srv/app", kind: "code", changed: ["index.js"], added: ["new.js"], removed: ["old.js"] }]);
});

test("the daily summary counts the day and words it", () => {
  const { store } = run([
    audit("auth_ok", { srcip: "203.0.113.7", user: "alice", method: "password" }, T0),
    audit("signup_ok", { srcip: "203.0.113.7", user: "bob" }, T0),
    ...Array.from({ length: 8 }, (_, i) => audit("auth_fail", { srcip: "203.0.113.9", target: "alice", reason: "wrong" }, T0 + i * 1000)),
    played("alice", {}, { game: "G1", kind: "ranked" }),
    fromHost(host("systemd-logind", "The system will suspend now!"))!,
  ]);
  const { text, data } = buildDigest(store, T0 + 60 * MIN, { diskFreeMb: 60_000, dbMb: 1 });
  assert.equal(data.players.newAccounts, 1);
  assert.equal(data.players.ranked, 1);
  assert.equal(data.security.failedSignIns, 8);
  assert.equal(data.laptop.sleeps, 1);
  assert.equal(data.open.total, 2);
  assert.match(text, /2 open alerts, 1 high/);
  assert.match(text, /Laptop: slept 1 time \(game offline\)/);
});
