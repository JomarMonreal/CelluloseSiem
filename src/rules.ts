import type { Rule } from "./engine.js";
import type { Event } from "./events.js";

// The thresholds assume the server's default limits (AUTH_PER_IP_PER_MINUTE=20, LOGINS_PER_USERNAME=10 per
// 10 minutes, SIGNUPS_PER_IP_PER_HOUR=5); retune them together.

const MIN = 60_000;
const f = (e: Event, name: string) => String(e.fields[name] ?? "");
const is = (...evts: string[]) => (e: Event) => evts.includes(e.evt);
const ip = (e: Event) => e.srcip ?? "an unknown IP";
// one key for the whole server, for rules about the server itself
const whole = () => "server";

// a line of the server's own output that reports a problem; stack frames ("    at ...") belong to the line above
const ERROR_LINE = /\b(error|exception|rejection|failed|ECONNREFUSED|ETIMEDOUT)\b/i;

// the advice that recurs
const BLOCK =
  "If it keeps going, block the IP in Cloudflare: dash.cloudflare.com → cellulose.lol → Security → WAF → Tools → IP Access Rules, add the IP with action Block.";
const LIMITS_HOLD = "The server's limits already refused the extra attempts, so nothing got through because of this alone.";
const SERVER_LOG = "See what the server said: run `journalctl -u cellulose-server -n 100` on the laptop.";

export const RULES: Rule[] = [
  // the server itself

  {
    id: "server-crash",
    name: "Server crashed",
    explain: "The game server hit an error it couldn't recover from and stopped. systemd starts it again by itself within seconds.",
    todo: [SERVER_LOG, "If it keeps happening, the error message says what to fix in the code or setup."],
    level: 10,
    match: is("server_crash"),
    key: whole,
    title: (e) => `Server crashed: ${f(e, "error")}`,
  },
  {
    // systemd schedules a restart only when the process died on its own; `systemctl restart` doesn't count
    id: "crash-loop",
    name: "Server keeps crashing",
    explain: "The server died and was restarted 3 times in 5 minutes. Players can't stay connected while this goes on.",
    todo: [
      SERVER_LOG,
      "Common causes: missing packages (run `npm ci && npm run build` in CelluloseServer), a bad .env, or the port already in use.",
    ],
    level: 12,
    match: is("unit_restart"),
    key: whole,
    threshold: { count: 3, windowMs: 5 * MIN },
    title: (e) => `Server died and was restarted 3 times in 5 minutes (restart counter ${f(e, "counter")})`,
    mitre: ["T1499"],
  },
  {
    id: "unit-failed",
    name: "Server stopped with an error",
    explain: "systemd reports the server process exited with an error.",
    todo: [SERVER_LOG, "Check it's back: `systemctl status cellulose-server`."],
    level: 10,
    match: is("unit_failed"),
    key: whole,
    title: (e) => `systemd: the server failed (${f(e, "result")})`,
  },
  {
    id: "cors-any",
    name: "Any website can connect",
    explain: "The server started in production with CORS_ORIGIN=*, so pages on any website can open connections to it.",
    todo: ["Set CORS_ORIGIN to https://cellulose.lol,https://www.cellulose.lol in the server's unit, then restart it."],
    level: 7,
    match: (e) => e.evt === "server_start" && e.fields.production === true && e.fields.cors_any === true,
    key: whole,
    title: () => "Production server started with CORS_ORIGIN=*",
  },
  {
    id: "error-output",
    name: "Server reporting errors",
    explain: "The server wrote 5 error messages in 5 minutes. Often harmless (a database hiccup), sometimes a sign something is broken.",
    todo: [SERVER_LOG, "If it's Supabase errors, check status.supabase.com and your keys in .env."],
    level: 7,
    match: (e) => e.evt === "log" && !/^\s/.test(f(e, "message")) && ERROR_LINE.test(f(e, "message")),
    key: whole,
    threshold: { count: 5, windowMs: 5 * MIN },
    title: (e) => `5 errors in 5 minutes, latest: ${f(e, "message").slice(0, 160)}`,
  },
  {
    id: "server-down",
    name: "Server not responding",
    explain: "The SIEM couldn't reach the game server's health check twice in a row. Players can't play right now.",
    todo: ["Check it: `systemctl status cellulose-server`.", SERVER_LOG, "Restart it if needed: `sudo systemctl restart cellulose-server`."],
    level: 12,
    match: (e) => e.evt === "probe_down" && e.fields.target === "local",
    key: whole,
    title: (e) => `Health check failing: ${f(e, "detail")}`,
    mitre: ["T1499"],
  },
  {
    id: "public-down",
    name: "Game unreachable from the internet",
    explain:
      "api.cellulose.lol didn't answer twice in a row. If the server itself is up, the problem is the Cloudflare Tunnel or Cloudflare, or the laptop lost internet.",
    todo: [
      "Check the tunnel: `systemctl status cloudflared` and `journalctl -u cloudflared -n 50`.",
      "Check the laptop is online, and the Cloudflare dashboard (Zero Trust → Networks → Tunnels).",
    ],
    level: 10,
    match: (e) => e.evt === "probe_down" && e.fields.target === "public",
    key: whole,
    title: (e) => `${f(e, "url")} unreachable (${f(e, "detail")})`,
  },

  {
    id: "disk-low",
    name: "Disk almost full",
    explain:
      "The laptop is running out of disk space. When it's full, the game server, the system journal and this SIEM can't save anything new. The SIEM pauses rather than lose events, and catches up once there's room.",
    todo: [
      "See what's big: `sudo du -xh --max-depth=2 / | sort -h | tail -20`.",
      "Usual suspects: the system journal (`journalctl --disk-usage`, shrink it with `sudo journalctl --vacuum-size=500M`), old downloads, ~/.cache, and the apt cache (`sudo apt clean`).",
      "The SIEM's own database is capped at MAX_DB_MB (15 GB); the dashboard shows its current size.",
    ],
    level: 10,
    match: is("disk_low"),
    key: whole,
    title: (e) => `Only ${(Number(e.fields.free_mb) / 1024).toFixed(1)} GB free of ${(Number(e.fields.total_mb) / 1024).toFixed(0)} GB`,
  },

  // sign-in

  {
    id: "password-guessing",
    name: "Password guessing",
    explain: "Someone tried 8 wrong passwords for one account in 10 minutes. They may be trying to break into it.",
    todo: [
      LIMITS_HOLD,
      "If a real player owns the account, they may want a stronger password.",
      "Watch for a \"Sign-in right after an attack\" alert: that would mean a guess worked.",
      BLOCK,
    ],
    level: 10,
    match: (e) => e.evt === "auth_fail" && !!e.fields.target,
    key: (e) => `user:${f(e, "target")}`,
    threshold: { count: 8, windowMs: 10 * MIN },
    title: (e) => `8 failed sign-ins for '${f(e, "target")}' in 10 minutes (latest from ${ip(e)})`,
    mitre: ["T1110.001"],
    groups: ["auth-attack"],
  },
  {
    id: "credential-stuffing",
    name: "Many accounts tried",
    explain:
      "One IP tried to sign in to 10 different accounts in 5 minutes. This is usually a bot trying leaked username and password lists from other sites.",
    todo: [LIMITS_HOLD, BLOCK, "Watch for a \"Sign-in right after an attack\" alert."],
    level: 12,
    match: (e) => e.evt === "auth_fail" && !!e.fields.target,
    threshold: { count: 10, windowMs: 5 * MIN, distinct: (e) => f(e, "target") },
    title: (e) => `${ip(e)} failed sign-ins for 10 different usernames in 5 minutes`,
    mitre: ["T1110.004"],
    groups: ["auth-attack"],
  },
  {
    id: "signin-held-back",
    name: "Sign-ins blocked by limits",
    explain: "An IP made so many sign-in attempts that the server's limits started refusing it.",
    todo: [LIMITS_HOLD, "It's often a player who forgot their password. Many alerts from the same IP are not.", BLOCK],
    level: 8,
    match: (e) => e.evt === "rate_limit" && ["login_user", "auth_ip"].includes(f(e, "limit")),
    title: (e) => `${ip(e)} is being held back from signing in${e.fields.target ? ` (target '${f(e, "target")}')` : ""}`,
    mitre: ["T1110"],
    groups: ["auth-attack"],
  },
  {
    id: "signin-after-attack",
    name: "Sign-in right after an attack",
    explain:
      "An account signed in successfully within 10 minutes of password guessing against it, or from an IP that was attacking. A guess may have worked.",
    todo: [
      "Look at the related activity below: same IP as the attack is a strong sign.",
      "If it looks wrong, reset that account's password in Supabase (Authentication → Users) and sign it out everywhere.",
      BLOCK,
    ],
    level: 13,
    match: is("auth_ok"),
    key: (e) => `user:${e.username}`,
    after: { group: "auth-attack", windowMs: 10 * MIN, keys: (e) => [`ip:${e.srcip}`, `user:${e.username}`] },
    title: (e) => `'${e.username}' signed in from ${ip(e)} right after a sign-in attack on that IP or account`,
    mitre: ["T1110", "T1078"],
    foldMs: 0,
  },

  // accounts

  {
    id: "account-farming",
    name: "Many new accounts",
    explain: "One IP made 4 accounts in an hour. Could be a family or school on one connection, or someone making extra accounts to cheat in ranked.",
    todo: ["Check the related activity for the usernames.", "If they play ranked against each other, see the win trading alerts."],
    level: 8,
    match: is("signup_ok"),
    threshold: { count: 4, windowMs: 60 * MIN },
    title: (e) => `${ip(e)} made 4 accounts in an hour`,
    mitre: ["T1136"],
  },
  {
    id: "signup-held-back",
    name: "Sign-ups blocked by limits",
    explain: "An IP hit the limit on new accounts, so the server refused more.",
    todo: [LIMITS_HOLD, BLOCK],
    level: 8,
    match: (e) => e.evt === "rate_limit" && f(e, "limit") === "signup_ip",
    title: (e) => `${ip(e)} is being held back from making more accounts`,
    mitre: ["T1136"],
  },

  // abuse: the server already refused these; the alerts show who keeps pushing

  {
    id: "too-many-connections",
    name: "Too many connections",
    explain: "An IP tried to hold more connections open than one player needs. Often a bot, sometimes many tabs.",
    todo: [LIMITS_HOLD, BLOCK],
    level: 6,
    match: is("conn_refused"),
    title: (e) => `${ip(e)} refused: already has ${f(e, "open")} connections open`,
    mitre: ["T1499"],
  },
  {
    // the server logs a refusal at most once per 10 seconds per IP, so 6 in 2 minutes is a client that kept going
    id: "sustained-abuse",
    name: "Flooding the server",
    explain: "An IP kept hitting the server's limits for 2 minutes straight. That's a script, not a person playing.",
    todo: [LIMITS_HOLD, BLOCK],
    level: 10,
    match: is("rate_limit", "conn_refused"),
    threshold: { count: 6, windowMs: 2 * MIN },
    title: (e) => `${ip(e)} kept hitting rate limits for 2 minutes`,
    mitre: ["T1499"],
  },

  // protocol abuse: the real client never sends these

  {
    id: "protocol-probing",
    name: "Malformed requests",
    explain: "An IP keeps sending requests the real game never sends. Someone is poking at the server, probably with a script, looking for weaknesses.",
    todo: ["The server rejected them, so nothing broke.", BLOCK],
    level: 8,
    match: is("bad_request"),
    threshold: { count: 5, windowMs: 5 * MIN },
    title: (e) => `${ip(e)} keeps sending malformed requests (${f(e, "reason")})`,
    mitre: ["T1190"],
  },
  {
    id: "unknown-event",
    name: "Unknown request",
    explain: "An IP sent a request type the server doesn't have. The real game never does this: someone is exploring the server.",
    todo: ["The server ignored it.", BLOCK],
    level: 8,
    match: is("unknown_event"),
    title: (e) => `${ip(e)} sent '${f(e, "event")}', which the server doesn't handle`,
    mitre: ["T1190"],
  },
  {
    id: "error-hunting",
    name: "Hunting for crashes",
    explain: "One IP's requests keep causing errors in the server. Someone may be looking for a bug that crashes it.",
    todo: [SERVER_LOG + " The errors show which request breaks it, which is a bug worth fixing.", BLOCK],
    level: 10,
    match: is("server_error"),
    threshold: { count: 5, windowMs: 2 * MIN },
    title: (e) => `${ip(e)} keeps causing server errors ('${f(e, "event")}')`,
    mitre: ["T1190"],
  },

  // fair play

  {
    id: "win-trading",
    name: "Possible win trading",
    explain: "Two players were matched against each other unusually often in ranked within a day. They may be throwing games to boost one account.",
    todo: ["Compare their IPs (shown in the alert): the same IP for both suggests one person with two accounts.", "Look at their match history in Supabase."],
    level: 9,
    match: is("ranked_pair"),
    key: (e) => [f(e, "user"), f(e, "other")].sort().join(" + "),
    title: (e) => `'${f(e, "user")}' and '${f(e, "other")}' met ${f(e, "times")} times in ranked in 24h (IPs ${f(e, "ips")})`,
    foldMs: 24 * 60 * MIN,
  },

  // fair play: one game at a time (the server reports each player's moves when a game ends)

  {
    // the client places one cell per click, so several landing in one 40 ms tick, or many under 50 ms apart, is a script
    id: "scripted-speed",
    name: "Moves faster than a person",
    explain:
      "In one game this player placed cells faster than anyone can click: several in the same 40 ms, or many less than 50 ms apart. The real game needs a separate click per cell, so this is a script or a modified client.",
    todo: [
      "Look at the related activity: one game is a strong sign, several is near certain.",
      "Ranked: consider resetting or banning the account in Supabase. Guests: block the IP in Cloudflare if it keeps happening.",
    ],
    level: 10,
    match: (e) => e.evt === "game_player" && (Number(e.fields.burst) >= 4 || Number(e.fields.fast) >= 5),
    key: player,
    title: (e) => `${who(e)} placed ${f(e, "burst")} cells in one tick and ${f(e, "fast")} under 50 ms apart in a ${f(e, "kind")} game`,
    mitre: ["T1059"],
    groups: ["cheat"],
    foldMs: 24 * 60 * MIN,
  },
  {
    id: "scripted-rhythm",
    name: "Robot-like timing",
    explain:
      "This player's moves came on an almost perfectly even beat. People click at uneven speeds; a script on a timer doesn't. One game could be a fluke, a pattern across games isn't.",
    todo: ["Check whether it repeats: the alert counts each game it happens in.", "If it does, treat it like \"Moves faster than a person\"."],
    level: 9,
    match: (e) => e.evt === "game_player" && Number(e.fields.gaps) >= 20 && e.fields.spread !== null && Number(e.fields.spread) < 0.1,
    key: player,
    title: (e) => `${who(e)} moved every ${f(e, "median_ms")} ms give or take ${Math.round(Number(e.fields.spread) * 100)}%, over ${f(e, "gaps")} moves`,
    mitre: ["T1059"],
    groups: ["cheat"],
    foldMs: 24 * 60 * MIN,
  },
  {
    id: "modified-client",
    name: "Impossible move",
    explain:
      "This player tried to place in someone else's land or remove a cell that isn't theirs. The real game never sends those moves, so they're using a modified client or a script. The server refused the move.",
    todo: ["The server already blocked it; nothing on the board changed.", "Watch this account or IP. Repeat offenders: ban the account or block the IP."],
    level: 9,
    match: is("game_rejected"),
    key: player,
    title: (e) => `${who(e)} sent an impossible move (${f(e, "reason")}) in a ${f(e, "kind")} game`,
    mitre: ["T1565"],
    groups: ["cheat"],
    foldMs: 24 * 60 * MIN,
  },

  // fair play: patterns across a week of ranked games (fairplay.ts looks for them hourly)

  {
    id: "win-trading-pattern",
    name: "One account keeps beating another",
    explain:
      "Two accounts met often in ranked this week and the same one finished ahead nearly every time. That's how win trading looks: one account throwing games to pump up the other.",
    todo: [
      "Compare their IPs in the alert: the same or similar IPs suggest one person with two accounts.",
      "If it's trading, reset both accounts' ratings or ban the losing account in Supabase.",
    ],
    level: 10,
    match: is("win_trading"),
    key: (e) => f(e, "key"),
    title: (e) => `'${f(e, "winner")}' finished ahead of '${f(e, "loser")}' in ${f(e, "ahead")} of their ${f(e, "games")} ranked games this week (IPs ${f(e, "winner_ips")} / ${f(e, "loser_ips")})`,
    foldMs: 7 * 24 * 60 * MIN,
  },
  {
    id: "throwing",
    name: "Throwing ranked games",
    explain:
      "This account joined ranked games and then did nothing after the opening round, again and again. It might be someone with a bad connection, or someone losing on purpose to feed rating to another account.",
    todo: [
      "If one account keeps winning those games (shown in the alert), it's feeding: treat it like win trading.",
      "Otherwise it's probably a connection problem, or someone leaving their games idle.",
    ],
    level: 8,
    match: is("throwing"),
    key: (e) => f(e, "key"),
    title: (e) =>
      `'${f(e, "user")}' sat out ${f(e, "idle")} of ${f(e, "games")} ranked games this week${e.fields.top_winner ? `; '${f(e, "top_winner")}' won most of them` : ""}`,
    foldMs: 7 * 24 * 60 * MIN,
  },
  {
    id: "smurf",
    name: "New account winning everything",
    explain: "An account new to ranked this week is winning nearly every game. Often an experienced player on a second account (a smurf), which spoils matches for real newcomers.",
    todo: ["Usually not worth acting on alone.", "If it shares an IP with an established account (see \"Linked accounts\"), it's a smurf."],
    level: 7,
    match: is("smurf"),
    key: (e) => f(e, "key"),
    title: (e) => `'${f(e, "user")}' won ${f(e, "wins")} of their first ${f(e, "games")} ranked games`,
    foldMs: 7 * 24 * 60 * MIN,
  },
  {
    id: "linked-accounts",
    name: "Linked accounts met in ranked",
    explain:
      "Two accounts that signed in from the same IP were matched against each other in ranked. The server never puts one IP twice in a match, so one of them was on a VPN or another network: a classic way to trade wins with yourself.",
    todo: ["Check whether the pair also appears in \"One account keeps beating another\".", "If it does, ban the second account and reset the first's rating."],
    level: 10,
    match: is("linked_accounts"),
    key: (e) => f(e, "key"),
    title: (e) => `'${f(e, "a")}' and '${f(e, "b")}' both signed in from ${f(e, "shared_ip")}, then met in ${f(e, "games")} ranked games`,
    foldMs: 7 * 24 * 60 * MIN,
  },
  {
    id: "shared-ip",
    name: "Several accounts on one IP",
    explain: "Three or more accounts signed in from the same IP this month. Usually a family, a school or a shared network; sometimes one person with alt accounts.",
    todo: ["Nothing to do on its own.", "It matters if those accounts show up in other fair-play alerts."],
    level: 6,
    match: is("shared_ip"),
    key: (e) => f(e, "key"),
    title: (e) => `${f(e, "accounts")} accounts from ${e.srcip}: ${f(e, "users")}`,
    foldMs: 7 * 24 * 60 * MIN,
  },

  // the laptop

  {
    id: "laptop-password-guessing",
    name: "Wrong laptop password",
    explain: "Someone typed the wrong password on the laptop 3 times in 10 minutes: at the lock screen, for sudo, or a system prompt. Usually you mistyping; otherwise someone is trying to get in.",
    todo: ["If it wasn't you, check who had access to the laptop, and change your password (`passwd`)."],
    level: 10,
    match: is("local_auth_fail"),
    key: (e) => `user:${e.username}`,
    threshold: { count: 3, windowMs: 10 * MIN },
    title: (e) => `3 wrong passwords for '${e.username}' in 10 minutes`,
    mitre: ["T1110"],
  },
  {
    id: "sudo-denied",
    name: "Admin access refused",
    explain: "An account that isn't allowed to use sudo tried to run something as administrator, and was refused.",
    todo: ["If it wasn't you, something on the laptop is trying to get admin rights. See the related activity for the command."],
    level: 10,
    // "3 incorrect password attempts" is a typo streak, already counted by laptop-password-guessing
    match: (e) => e.evt === "sudo_denied" && !e.fields.attempts,
    key: (e) => `user:${e.username}`,
    title: (e) => `sudo refused for '${e.username}'${e.fields.command ? `: ${f(e, "command").slice(0, 120)}` : ` (${f(e, "reason")})`}`,
    mitre: ["T1548.003"],
  },
  {
    id: "ssh-login",
    name: "Remote login over SSH",
    explain: "Someone logged in to the laptop over SSH. SSH isn't normally installed on this laptop, so this should only ever be you.",
    todo: ["If it wasn't you: disconnect the laptop from the network, then change your password.", "Remove SSH if you don't use it: `sudo apt remove openssh-server`."],
    level: 12,
    match: is("ssh_login"),
    title: (e) => `'${e.username}' logged in over SSH from ${ip(e)} (${f(e, "method")})`,
    mitre: ["T1021.004"],
    foldMs: 0,
  },
  {
    id: "ssh-guessing",
    name: "SSH password guessing",
    explain: "An IP tried 5 SSH logins in 10 minutes. Bots scan the whole internet for SSH; it only matters if SSH is reachable.",
    todo: ["Remove SSH if you don't use it: `sudo apt remove openssh-server`.", "If you do, allow keys only: `PasswordAuthentication no` in /etc/ssh/sshd_config."],
    level: 10,
    match: is("ssh_fail"),
    threshold: { count: 5, windowMs: 10 * MIN },
    title: (e) => `${ip(e)} failed 5 SSH logins in 10 minutes (latest as '${e.username}')`,
    mitre: ["T1110.001"],
  },
  {
    id: "new-system-user",
    name: "New user on the laptop",
    explain:
      "A new user account was created on the laptop. Installing some software does this (Wazuh, databases, Docker); an attacker does it too, to keep a way back in.",
    todo: ["If you just installed something, this is it.", "Otherwise: `getent passwd <name>` to see it, and `sudo userdel <name>` to remove it."],
    level: 10,
    match: is("user_added"),
    key: (e) => `user:${e.username}`,
    title: (e) => `User '${e.username}' created (uid ${f(e, "uid")}, shell ${f(e, "shell")})`,
    mitre: ["T1136.001"],
  },
  {
    id: "admin-group",
    name: "Account given admin rights",
    explain: "An account was added to an administrator group on the laptop. That gives it full control.",
    todo: ["If it wasn't you, remove it at once: `sudo gpasswd -d <user> <group>`, then look for what else changed."],
    level: 12,
    match: (e) => e.evt === "group_member_added" && ["sudo", "adm", "root", "wheel", "admin"].includes(f(e, "group")),
    key: (e) => `user:${e.username}`,
    title: (e) => `'${e.username}' added to the '${f(e, "group")}' group`,
    mitre: ["T1098"],
  },
  {
    id: "port-opened",
    name: "New port open to the network",
    explain:
      "Something on the laptop started accepting connections from other devices on a port it never used before. Fine if you just started a program that needs it; otherwise it's something to find.",
    todo: ["See what owns it: `sudo ss -tlnp | grep <port>`.", "Stop that program, or block the port: `sudo ufw deny <port>`."],
    level: 8,
    match: is("port_opened"),
    key: (e) => f(e, "listen"),
    title: (e) => `Listening on ${f(e, "listen")}`,
    mitre: ["T1571"],
  },
  {
    id: "config-changed",
    name: "Important file changed",
    explain:
      "A watched file changed: the server's .env, a service's settings, the user or admin lists, scheduled tasks, or the tunnel's settings. You changing them is expected; anyone else changing them is serious.",
    todo: ["If it wasn't you, find what changed (the alert lists the files) and restore it.", "Then look for how they got in: other laptop alerts around the same time."],
    level: 10,
    match: (e) => e.evt === "file_changed" && e.fields.kind === "config",
    key: (e) => f(e, "path"),
    title: (e) => `${f(e, "path")}: ${f(e, "summary")}`,
    mitre: ["T1565.001"],
    foldMs: 60 * MIN,
  },
  {
    id: "code-changed",
    name: "Server code changed",
    explain: "The game server's or the SIEM's built code changed. That's what `npm run build` does; if you didn't rebuild, someone may have tampered with the code.",
    todo: ["If you just rebuilt, mark it handled.", "If not, rebuild from your source (`npm run build`) and restart, then look for other laptop alerts."],
    level: 6,
    match: (e) => e.evt === "file_changed" && e.fields.kind === "code",
    key: (e) => f(e, "path"),
    title: (e) => `${f(e, "path")}: ${f(e, "summary")}`,
    foldMs: 60 * MIN,
  },
  {
    id: "out-of-memory",
    name: "Laptop ran out of memory",
    explain: "The laptop ran so low on memory that the system killed a program to recover. If it killed the game server, players were dropped.",
    todo: ["See what uses memory: `ps aux --sort=-rss | head`.", "Close heavy programs (browsers, editors) while hosting."],
    level: 8,
    match: is("oom_kill"),
    key: whole,
    title: (e) => `Killed ${f(e, "process")} to free memory (${f(e, "by")})`,
    foldMs: 60 * MIN,
  },
  {
    id: "laptop-slept",
    name: "Laptop went to sleep",
    explain: "The laptop suspended (often the lid closing), which takes the game offline until it wakes.",
    todo: [
      "To keep hosting with the lid closed: set `HandleLidSwitch=ignore` (and `HandleLidSwitchExternalPower=ignore`) in /etc/systemd/logind.conf, then `sudo systemctl restart systemd-logind`.",
    ],
    level: 7,
    match: is("laptop_sleep"),
    key: whole,
    title: () => "Laptop suspended: the game was offline until it woke",
    foldMs: 6 * 60 * MIN,
  },
  {
    id: "tunnel-unstable",
    name: "Tunnel keeps dropping",
    explain: "The Cloudflare tunnel lost its connections over and over. Players notice lag or disconnects. Usually weak Wi-Fi.",
    todo: ["Use a wired connection or move closer to the router.", "Check `journalctl -u cloudflared -n 50` for the errors."],
    level: 7,
    match: is("tunnel_drop"),
    key: whole,
    threshold: { count: 12, windowMs: 10 * MIN },
    title: () => "The tunnel dropped 12 connections in 10 minutes",
    foldMs: 24 * 60 * MIN,
  },
];

/** Who played: the account for signed-in players, else the name typed and the IP (a guest name is anyone's). */
function who(e: Event): string {
  return e.username ? `'${e.username}'` : `guest '${f(e, "name")}' (${ip(e)})`;
}
function player(e: Event): string {
  return e.username ? `user:${e.username}` : `guest:${e.srcip}`;
}
