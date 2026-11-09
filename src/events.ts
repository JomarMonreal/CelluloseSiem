/** What the SIEM stores and the rules look at: one journal line (or one health-check change), made uniform. */
export type NewEvent = {
  /** Milliseconds since the epoch, from the journal (when the line was written), not when it was read. */
  ts: number;
  /**
   * audit: the server's security events; log: its other output; systemd: lines about the unit; probe: health and
   * disk checks; host: the laptop itself (logins, sudo, users, ports, files); analysis: fair-play findings
   */
  source: "audit" | "log" | "systemd" | "probe" | "host" | "analysis";
  evt: string;
  srcip: string | null;
  /** The account involved: `user` when signed in, else the `target` someone tried. */
  username: string | null;
  fields: Record<string, unknown>;
};
export type Event = NewEvent & { id: number };

/** The events the server's src/audit.ts writes. Anything else on a {"app":"cellulose" line is kept as plain log. */
const AUDIT_EVENTS = new Set([
  "server_start",
  "server_stop",
  "server_crash",
  "auth_ok",
  "auth_fail",
  "signup_ok",
  "signup_fail",
  "logout_all",
  "password_changed",
  "session_kicked",
  "rate_limit",
  "conn_refused",
  "origin_refused",
  "bad_request",
  "unknown_event",
  "server_error",
  "avatar_rejected",
  "ranked_pair",
  "game_player",
  "game_rejected",
]);

const MAX_MESSAGE = 2000;
const str = (v: unknown) => (typeof v === "string" && v ? v : null);

/** journald gives MESSAGE as a string, or as an array of bytes when it isn't valid UTF-8. */
function message(m: unknown): string | null {
  if (typeof m === "string") return m;
  if (Array.isArray(m)) return Buffer.from(m as number[]).toString("utf8");
  return null;
}

/** One `journalctl -o json` entry as an event, or null for one with nothing to say. */
export function fromJournal(entry: Record<string, unknown>, unit: string): NewEvent | null {
  const text = message(entry.MESSAGE);
  if (!text) return null;
  const ts = Math.floor(Number(entry.__REALTIME_TIMESTAMP) / 1000) || Date.now();

  // systemd's own lines about the unit carry UNIT=; the server's carry _SYSTEMD_UNIT=
  if (entry._SYSTEMD_UNIT !== unit) return fromSystemd(text, ts);

  if (text.startsWith('{"app":"cellulose"')) {
    try {
      const j = JSON.parse(text) as Record<string, unknown>;
      if (j.app === "cellulose" && typeof j.evt === "string" && AUDIT_EVENTS.has(j.evt)) {
        const { app: _app, evt, ...fields } = j;
        return { ts, source: "audit", evt, srcip: str(j.srcip), username: str(j.user) ?? str(j.target), fields };
      }
    } catch {
      // not JSON after all: falls through to a plain line
    }
  }
  return { ts, source: "log", evt: "log", srcip: null, username: null, fields: { message: text.slice(0, MAX_MESSAGE) } };
}

function fromSystemd(text: string, ts: number): NewEvent {
  const ev = (evt: string, fields: Record<string, unknown> = {}): NewEvent => ({
    ts,
    source: "systemd",
    evt,
    srcip: null,
    username: null,
    fields: { message: text.slice(0, MAX_MESSAGE), ...fields },
  });
  let m: RegExpMatchArray | null;
  if ((m = text.match(/Main process exited, code=(\w+), status=(\S+)/))) return ev("unit_exit", { code: m[1], status: m[2] });
  if ((m = text.match(/Failed with result '([^']+)'/))) return ev("unit_failed", { result: m[1] });
  if ((m = text.match(/Scheduled restart job, restart counter is at (\d+)/))) return ev("unit_restart", { counter: Number(m[1]) });
  if (/^Started /.test(text)) return ev("unit_started");
  if (/^Stopped /.test(text)) return ev("unit_stopped");
  return ev("systemd");
}

/**
 * The programs whose lines say something about the laptop's security, as journalctl matches (one field repeated
 * is an OR). Everything else they write is dropped by fromHost().
 */
export const HOST_SOURCES = [
  "sudo",
  "su",
  "unix_chkpwd",
  "sshd",
  "sshd-session",
  "useradd",
  "userdel",
  "usermod",
  "groupadd",
  "passwd",
  "chpasswd",
  "systemd-logind",
  "cloudflared",
  "systemd-oomd",
  "kernel",
].map((id) => `SYSLOG_IDENTIFIER=${id}`);

/** One line from the laptop's own logs as an event, or null for the many that don't matter. */
export function fromHost(entry: Record<string, unknown>): NewEvent | null {
  const text = message(entry.MESSAGE);
  if (!text) return null;
  const ts = Math.floor(Number(entry.__REALTIME_TIMESTAMP) / 1000) || Date.now();
  const ev = (evt: string, fields: Record<string, unknown> = {}, who: { srcip?: string; user?: string } = {}): NewEvent => ({
    ts,
    source: "host",
    evt,
    srcip: who.srcip ?? null,
    username: who.user ?? null,
    fields: { ...fields, message: text.slice(0, 500) },
  });
  let m: RegExpMatchArray | null;
  switch (entry.SYSLOG_IDENTIFIER) {
    case "sudo":
      // the pam_unix failure line has a unix_chkpwd twin; only the latter is counted
      if ((m = text.match(/^\s*(\S+) : .*?(?:(\d+) incorrect password attempts? ; )?.*?USER=(\S+) ; COMMAND=(.*)$/))) {
        return m[2] ? ev("sudo_denied", { attempts: Number(m[2]), as: m[3], command: m[4] }, { user: m[1] }) : ev("sudo_command", { as: m[3], command: m[4] }, { user: m[1] });
      }
      if ((m = text.match(/^\s*(\S+) : .*?(not in the sudoers file|user NOT in sudoers|command not allowed)/))) return ev("sudo_denied", { reason: m[2] }, { user: m[1] });
      return null;
    case "su":
      if ((m = text.match(/^\(to (\S+)\) (\S+) on/))) return ev("su_session", { as: m[1] }, { user: m[2] });
      return null;
    case "unix_chkpwd":
      if ((m = text.match(/password check failed for user \((\S+)\)/))) return ev("local_auth_fail", {}, { user: m[1] });
      return null;
    case "sshd":
    case "sshd-session":
      if ((m = text.match(/^Accepted (\S+) for (\S+) from (\S+) port/))) return ev("ssh_login", { method: m[1] }, { user: m[2], srcip: m[3] });
      if ((m = text.match(/^Failed (\S+) for (?:invalid user )?(\S+) from (\S+) port/))) return ev("ssh_fail", { method: m[1] }, { user: m[2], srcip: m[3] });
      if ((m = text.match(/^Invalid user (\S*) from (\S+)/))) return ev("ssh_fail", { method: "invalid user" }, { user: m[1], srcip: m[2] });
      return null;
    case "useradd":
      if ((m = text.match(/^new user: name=([^,]+), UID=(\d+).*?home=([^,]*), shell=([^,]*)/))) return ev("user_added", { uid: Number(m[2]), home: m[3], shell: m[4] }, { user: m[1] });
      return null;
    case "userdel":
      if ((m = text.match(/^delete user '([^']+)'/))) return ev("user_removed", {}, { user: m[1] });
      return null;
    case "usermod":
    case "groupadd":
      if ((m = text.match(/^add '([^']+)' to (?:shadow )?group '([^']+)'/))) return text.includes("shadow") ? null : ev("group_member_added", { group: m[2] }, { user: m[1] });
      return null;
    case "passwd":
    case "chpasswd":
      if ((m = text.match(/password changed for (\S+)/))) return ev("local_password_changed", {}, { user: m[1] });
      return null;
    case "systemd-logind":
      if (/^The system will suspend now|^Lid closed/.test(text)) return text.startsWith("Lid") ? ev("lid_closed") : ev("laptop_sleep");
      if (/^Operation 'suspend' finished/.test(text)) return ev("laptop_wake");
      if (/^System is (powering down|rebooting)/.test(text)) return ev("laptop_shutdown");
      if ((m = text.match(/^New session '?(\S+?)'? of user '?([^' ]+)'? with class '(user)'/))) return ev("login_session", { session: m[1] }, { user: m[2] });
      return null;
    case "cloudflared":
      if (/Registered tunnel connection/.test(text)) return ev("tunnel_up", { location: text.match(/location=(\S+)/)?.[1] ?? null });
      if (/Connection terminated|Unregistered tunnel connection/.test(text)) return ev("tunnel_drop", { error: text.match(/error="([^"]*)"/)?.[1]?.slice(0, 200) ?? null });
      return null;
    case "systemd-oomd":
      if ((m = text.match(/^Killed (\S+) due to/))) return ev("oom_kill", { process: m[1], by: "systemd-oomd" });
      return null;
    case "kernel":
      if ((m = text.match(/Out of memory: Killed process (\d+) \(([^)]+)\)/))) return ev("oom_kill", { pid: Number(m[1]), process: m[2], by: "kernel" });
      return null;
  }
  return null;
}

/** Something the SIEM noticed itself on the laptop: a new open port, a watched file changing. */
export function hostEvent(evt: string, fields: Record<string, unknown>): NewEvent {
  return { ts: Date.now(), source: "host", evt, srcip: null, username: null, fields };
}

/** Free disk space dropping below the minimum, or recovering. */
export function diskEvent(low: boolean, freeMb: number, totalMb: number, path: string): NewEvent {
  return { ts: Date.now(), source: "probe", evt: low ? "disk_low" : "disk_ok", srcip: null, username: null, fields: { free_mb: freeMb, total_mb: totalMb, path } };
}

/** A health-check target going down or coming back. */
export function probeEvent(target: "local" | "public", up: boolean, url: string, detail: string): NewEvent {
  return { ts: Date.now(), source: "probe", evt: up ? "probe_up" : "probe_down", srcip: null, username: null, fields: { target, url, detail } };
}
