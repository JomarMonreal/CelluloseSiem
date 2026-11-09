import type { NewEvent } from "./events.js";
import type Store from "./store.js";

const DAY = 24 * 60 * 60_000;
// ranked games looked at; IPs shared between accounts are remembered a while longer
const GAMES_DAYS = 7;
const IPS_DAYS = 30;

// win trading: two accounts that met at least this often, with one ahead at least this share of the time
const PAIR_MIN_GAMES = 5;
const PAIR_WIN_SHARE = 0.8;
// throwing: games where an account did nothing after setup, and that share of their games
const IDLE_MIN_GAMES = 3;
const IDLE_SHARE = 0.5;
// smurfs: an account new to ranked this week, winning this share of at least this many games
const SMURF_MIN_GAMES = 5;
const SMURF_WIN_SHARE = 0.8;
// one IP signing in to this many accounts
const IP_MIN_ACCOUNTS = 3;

type Row = Record<string, unknown>;
export type Finding = { check: string; key: string; size: number; fields: Record<string, unknown>; username: string | null; srcip: string | null };

// one row per signed-in player per finished ranked game, from the server's game_player lines
const RANKED = `
  SELECT json_extract(data, '$.game') game, username, srcip, ts,
         json_extract(data, '$.place') place, json_extract(data, '$.after_setup') after_setup
  FROM events
  WHERE evt = 'game_player' AND json_extract(data, '$.kind') = 'ranked' AND username IS NOT NULL AND ts >= ?`;

/**
 * Patterns across many ranked games that no single game shows: win trading, throwing, smurfs and alt accounts.
 * Run now and then over the stored events; what it finds goes through the rules like any other event.
 */
export function findings(store: Store, now: number): Finding[] {
  const since = now - GAMES_DAYS * DAY;
  const out: Finding[] = [];

  // the same two accounts in many ranked games, one nearly always ahead
  for (const r of store.query(
    `WITH g AS (${RANKED})
     SELECT a.username winner, b.username loser, count(*) games, sum(a.place < b.place) ahead,
            group_concat(DISTINCT a.srcip) winner_ips, group_concat(DISTINCT b.srcip) loser_ips
     FROM g a JOIN g b ON a.game = b.game AND a.username != b.username
     GROUP BY a.username, b.username HAVING count(*) >= ? AND sum(a.place < b.place) >= ? * count(*)`,
    since,
    PAIR_MIN_GAMES,
    PAIR_WIN_SHARE,
  )) {
    out.push({
      check: "win_trading",
      key: `${r.winner} > ${r.loser}`,
      size: Number(r.games),
      username: String(r.winner),
      srcip: null,
      fields: { winner: r.winner, loser: r.loser, games: r.games, ahead: r.ahead, winner_ips: r.winner_ips, loser_ips: r.loser_ips, days: GAMES_DAYS },
    });
  }

  // accounts that keep sitting out ranked games, and who won those games
  for (const r of store.query(
    `WITH g AS (${RANKED})
     SELECT username, count(*) games, sum(after_setup = 0) idle,
            (SELECT w.username FROM g idle JOIN g w ON w.game = idle.game AND w.place = 1 AND w.username != idle.username
              WHERE idle.username = g.username AND idle.after_setup = 0 GROUP BY w.username ORDER BY count(*) DESC LIMIT 1) top_winner
     FROM g GROUP BY username HAVING sum(after_setup = 0) >= ? AND sum(after_setup = 0) >= ? * count(*)`,
    since,
    IDLE_MIN_GAMES,
    IDLE_SHARE,
  )) {
    out.push({
      check: "throwing",
      key: String(r.username),
      size: Number(r.idle),
      username: String(r.username),
      srcip: null,
      fields: { user: r.username, games: r.games, idle: r.idle, top_winner: r.top_winner, days: GAMES_DAYS },
    });
  }

  // new to ranked this week and winning nearly everything
  for (const r of store.query(
    `WITH g AS (${RANKED})
     SELECT username, count(*) games, sum(place = 1) wins FROM g
     WHERE username NOT IN (SELECT username FROM events WHERE evt = 'game_player' AND json_extract(data, '$.kind') = 'ranked' AND ts < ? AND username IS NOT NULL)
     GROUP BY username HAVING count(*) >= ? AND sum(place = 1) >= ? * count(*)`,
    since,
    since,
    SMURF_MIN_GAMES,
    SMURF_WIN_SHARE,
  )) {
    out.push({ check: "smurf", key: String(r.username), size: Number(r.games), username: String(r.username), srcip: null, fields: { user: r.username, games: r.games, wins: r.wins, days: GAMES_DAYS } });
  }

  // accounts seen on one IP: a family or a school, or one person with several accounts
  const ipSince = now - IPS_DAYS * DAY;
  const accountsByIp = new Map<string, string[]>();
  for (const r of store.query(
    "SELECT srcip, group_concat(DISTINCT username) users FROM events WHERE evt IN ('auth_ok', 'signup_ok') AND ts >= ? AND srcip IS NOT NULL AND username IS NOT NULL GROUP BY srcip",
    ipSince,
  )) {
    const users = String(r.users).split(",").sort();
    accountsByIp.set(String(r.srcip), users);
    if (users.length >= IP_MIN_ACCOUNTS) {
      out.push({ check: "shared_ip", key: String(r.srcip), size: users.length, username: null, srcip: String(r.srcip), fields: { users: users.join(", "), accounts: users.length, days: IPS_DAYS } });
    }
  }

  // and the serious version: two accounts that shared an IP, then met in a ranked game (from different IPs, since
  // the server never seats one IP twice in a match: one of them was on a VPN or another network)
  const linked = new Map<string, string>();
  for (const [ip, users] of accountsByIp) for (let i = 0; i < users.length; i++) for (let j = i + 1; j < users.length; j++) linked.set(`${users[i]} ${users[j]}`, ip);
  if (linked.size) {
    for (const r of store.query(
      `WITH g AS (${RANKED}) SELECT a.username a, b.username b, count(*) games FROM g a JOIN g b ON a.game = b.game AND a.username < b.username GROUP BY a.username, b.username`,
      since,
    )) {
      const ip = linked.get(`${r.a} ${r.b}`);
      if (!ip) continue;
      out.push({ check: "linked_accounts", key: `${r.a} + ${r.b}`, size: Number(r.games), username: String(r.a), srcip: ip, fields: { a: r.a, b: r.b, games: r.games, shared_ip: ip, days: GAMES_DAYS } });
    }
  }
  return out;
}

/**
 * The findings worth an event: new ones, and ones that grew since they were last reported. `seen` maps each
 * finding to the size last reported, and is updated in place (the caller stores it).
 */
export function fresh(found: Finding[], seen: Record<string, number>, now: number): NewEvent[] {
  const events: NewEvent[] = [];
  for (const f of found) {
    const id = `${f.check} ${f.key}`;
    if ((seen[id] ?? 0) >= f.size) continue;
    seen[id] = f.size;
    events.push({ ts: now, source: "analysis", evt: f.check, srcip: f.srcip, username: f.username, fields: { key: f.key, ...f.fields } });
  }
  return events;
}
