# Cellulose SIEM

A small security monitor for the Cellulose server. It runs beside the server as its own
service, reads the server's security events from journald, raises alerts on attacks and outages, and keeps every
event in a local SQLite database. A dashboard on port 4100 shows it all, to this machine and, with a password, to
your other devices on the home network.

No runtime dependencies: Node 22's built-in `node:sqlite`, `node:http` and `journalctl`.

## What it watches

- **The server's security events.** The lines `src/audit.ts` writes, one JSON object each: sign-ins, sign-ups,
  rate limits, refused connections, malformed requests and so on (the server's README lists them).
- **Its other output**, stored as `log` events. A burst of error lines raises an alert.
- **systemd's lines about it**: starts, stops, crashes and automatic restarts.
- **The laptop itself**, from its system journal: sudo commands and wrong passwords, desktop and SSH logins, new
  users and admin-group changes, out-of-memory kills, the laptop going to sleep, and the Cloudflare tunnel dropping.
  Plus its own checks: ports newly open to the network (every minute) and changes to important files (every 5
  minutes: the server's code and `.env`, service units, `/etc/passwd`, sudoers, cron, the tunnel's settings).
- **Fair play.** The server reports how each person played every game (moves, how fast, how evenly spaced, moves the
  real client can't make). Single games are checked as they end; every hour the last week of ranked games is
  checked for win trading, throwing, smurfs and alt accounts meeting in ranked.
- **Health checks** every 30 seconds: the server's `/health` on 127.0.0.1, and the public address through
  Cloudflare. Telling the two apart shows whether an outage is the server or the tunnel.

## Daily summary

Every morning (`DIGEST_HOUR`, 8 by default) it sums up the last 24 hours: open and new alerts, players, sign-ins,
games, attacks, fair play, outages and the laptop. It's on the dashboard (with earlier days), and pushed to
`NOTIFY_URL` when that's set.

## Rules

| Rule | Level | Fires on |
|---|---|---|
| `signin-after-attack` | 13 | A successful sign-in within 10 minutes of a sign-in attack on that IP or account |
| `credential-stuffing` | 12 | One IP failing sign-ins for 10 different usernames in 5 minutes |
| `crash-loop` | 12 | systemd restarting the server after it died, 3 times in 5 minutes |
| `server-down` | 12 | The server's own health check failing twice in a row |
| `password-guessing` | 10 | 8 failed sign-ins for one account in 10 minutes, from any IPs |
| `sustained-abuse` | 10 | One IP refused by rate limits 6 times in 2 minutes |
| `error-hunting` | 10 | One IP causing 5 server errors in 2 minutes |
| `server-crash`, `unit-failed` | 10 | The server crashing, or systemd marking it failed |
| `disk-low` | 10 | The laptop's free disk space dropping under `DISK_MIN_FREE_MB` |
| `public-down` | 10 | The public address failing twice in a row (the tunnel or Cloudflare, if the server is up) |
| `ssh-login`, `admin-group`, `new-system-user` | 12, 12, 10 | Someone logged in over SSH; an account given admin rights; a new user on the laptop |
| `laptop-password-guessing`, `sudo-denied` | 10 | 3 wrong laptop passwords in 10 minutes; sudo refused to an account not allowed it |
| `config-changed` | 10 | A watched secret, service, user list, sudoers, cron or tunnel file changed |
| `scripted-speed` | 10 | A player placing several cells in one 40 ms tick, or many under 50 ms apart (one cell per click is the limit) |
| `win-trading-pattern`, `linked-accounts` | 10 | One account ahead of another in 80% of 5+ ranked games this week; two accounts that shared an IP meeting in ranked |
| `scripted-rhythm`, `modified-client` | 9 | Moves on a near-perfect beat (20+ moves, spread under 10%); a move the real client never sends |
| `win-trading` | 9 | Two players meeting too often in ranked |
| `port-opened`, `out-of-memory`, `throwing` | 8 | A port newly open to the network; the system killing a program for memory; an account sitting out most of its ranked games |
| `smurf`, `laptop-slept`, `tunnel-unstable` | 7 | New to ranked and winning 80%+; the laptop suspending (game offline); 12 tunnel drops in 10 minutes |
| `code-changed`, `shared-ip` | 6 | The server's or SIEM's built code changed (expected after a build); 3+ accounts signing in from one IP |
| `signin-held-back`, `signup-held-back` | 8 | An IP stopped by the sign-in or sign-up limits |
| `account-farming` | 8 | One IP making 4 accounts in an hour |
| `protocol-probing`, `unknown-event` | 8 | Malformed requests, or events the real client never sends |
| `error-output`, `cors-any` | 7 | 5 error lines in 5 minutes; a production server started with `CORS_ORIGIN=*` |
| `too-many-connections` | 6 | An IP refused for holding too many connections |

The rules are in [src/rules.ts](src/rules.ts). A repeat within 10 minutes (24 hours for win trading) adds to the
open alert's count instead of making a new one. Time is the events' own, so reading old history fires the same
alerts reading it live would have. Thresholds assume the server's default limits; retune them together.

## Running it

```bash
npm install && npm run build
npm test
```

As a service, next to the server:

```bash
sudo mkdir -p /opt/cellulose-siem /opt/cellulose-siem-node
# the dashboard's password, readable by root only
sudo install -m 600 /dev/null /etc/cellulose-siem.env
echo 'SIEM_PASSWORD=pick-a-long-password' | sudo tee /etc/cellulose-siem.env >/dev/null
sudo cp deploy/cellulose-siem.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now cellulose-siem
journalctl -fu cellulose-siem    # its own log: one JSON line per new alert
```

The unit runs it as a throwaway user (`DynamicUser`), so the game server, which runs as you, can't stop it or
change its records even if someone takes it over. The code and Node are mounted read-only from your home, so after
`npm run build` a `sudo systemctl restart cellulose-siem` picks up the new version. If you upgrade Node, change its
path in the unit.

On its first start it reads the server's whole journal history. After that it remembers where it got to (the
journal cursor, saved with each batch of events), so a restart or reboot neither misses lines nor reads any twice,
as long as journald still has them.

For development, `npm run dev` runs it as you, with the database in `./data`. Your user needs to be able to read
the system journal (the `adm` or `systemd-journal` group). Stop the service first, or set `SIEM_PORT`.

## Settings

Environment variables, set in the unit or in `/etc/cellulose-siem.env`:

| Variable | Default | |
|---|---|---|
| `SIEM_PORT`, `SIEM_HOST` | `4100`, `127.0.0.1` | The dashboard. The unit uses `0.0.0.0` (every address), so it keeps working when the router hands out a new one |
| `SIEM_ALLOW` | none (the unit sets your home subnet, e.g. `192.168.1.0/24`) | Other addresses or subnets that may connect, comma-separated. This machine always may |
| `SIEM_PASSWORD` | none | The dashboard's password. Required when `SIEM_HOST` or `SIEM_ALLOW` let other machines in; it won't start without one |
| `SIEM_UNIT` | `cellulose-server.service` | The unit to watch |
| `LOCAL_HEALTH_URL` | `http://127.0.0.1:3000/health` | |
| `PUBLIC_HEALTH_URL` | none (the unit sets `https://api.cellulose.lol/health`) | Empty skips the public check |
| `PROBE_MS`, `PROBE_FAILS` | `30000`, `2` | How often to check, and failures in a row before it counts as down |
| `EVENT_DAYS`, `ALERT_DAYS` | `90`, `365` | How long events and alerts are kept |
| `MAX_DB_MB` | `15360` (15 GB) | The most the database may take. Past it, the oldest events go first; alerts stay |
| `DISK_MIN_FREE_MB` | `2048` | Free space on the laptop's disk below which "Disk almost full" fires |
| `SERVER_DIR` | `../CelluloseServer` (the unit sets the full path) | The game server's folder, for the file watch |
| `WATCH` | none | More files or folders to watch, comma-separated: `config:/path` or `code:/path` |
| `DIGEST_HOUR` | `8` | The local hour the daily summary is made |
| `NOTIFY_URL` | none | Push alerts to an [ntfy](https://ntfy.sh) topic URL or a Discord webhook |
| `NOTIFY_MIN_LEVEL` | `10` | The lowest level pushed |

Only alerts from lines less than 5 minutes old are pushed, so reading history doesn't flood your phone. Pushed
alerts include IPs and usernames: use a private ntfy topic or a server you trust.

## The data

Everything is in `/var/lib/cellulose-siem/siem.db` (for the service). To query it directly (`sudo apt install sqlite3`
for the command):

```bash
sudo sqlite3 /var/lib/cellulose-siem/siem.db "SELECT datetime(ts/1000, 'unixepoch', 'localtime'), evt, srcip, username, data FROM events ORDER BY id DESC LIMIT 20"
```

Tables: `events` (every line, with its fields as JSON in `data`), `alerts`, and `state` (the journal cursor).

**Space.** Events older than `EVENT_DAYS` are deleted hourly, and if the file still passes `MAX_DB_MB` the oldest
events go until it fits. Freed space is handed back to the disk (incremental vacuum), so the file really shrinks.
The dashboard's Health panel shows the database size and the laptop's free space, and an alert fires below
`DISK_MIN_FREE_MB`. If the disk does fill up, the SIEM doesn't drop anything: the batch it couldn't save is read
again from the journal a minute later, until there's room. It never deletes records to free space for other
programs, so filling the disk can't be used to erase what it recorded.

## Limits

- **Same machine.** If the laptop itself is taken over with root, the records can be too. The separate user keeps
  out a compromised game server, not root.
- **No blocking.** It records and alerts. Players arrive through the Cloudflare Tunnel, so the place to ban an IP is
  Cloudflare (Security → WAF → Tools → IP Access Rules).
- **The dashboard is plain HTTP.** Anyone on your Wi-Fi who can watch its traffic could read the password and the
  pages. It only answers addresses in `SIEM_ALLOW`, makes an address wait after 10 wrong passwords in 10 minutes,
  refuses requests by hostname (DNS rebinding) and cross-site writes, and sessions last 30 days (or until the SIEM
  restarts). Without `SIEM_PASSWORD` it stays on 127.0.0.1, where any program on this machine can read it.

## License

All rights reserved; see [LICENSE](LICENSE). The source is here to read, not to reuse. Ask if you'd like to use any of it.
