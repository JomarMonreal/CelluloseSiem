import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

const COOKIE = "siem_session";
const SESSION_MS = 30 * 24 * 60 * 60_000;
// wrong passwords one address may try before it's made to wait
const MAX_FAILURES = 10;
const FAILURE_WINDOW_MS = 10 * 60_000;

const sha256 = (s: string) => createHash("sha256").update(s).digest();

/**
 * The dashboard's password and its sign-in sessions. Sessions live in memory, so restarting the SIEM signs
 * everyone out.
 */
export default class Auth {
  private sessions = new Map<string, number>();
  private failures = new Map<string, number[]>();

  constructor(private password: string) {}

  get enabled() {
    return this.password !== "";
  }

  /** Whether `ip` may try a password now (it hasn't failed too often lately). */
  mayTry(ip: string): boolean {
    const now = Date.now();
    const recent = (this.failures.get(ip) ?? []).filter((t) => now - t < FAILURE_WINDOW_MS);
    this.failures.set(ip, recent);
    return recent.length < MAX_FAILURES;
  }

  /** Checks a password, counting it against `ip` when it's wrong; a new session's token when it's right. */
  signIn(ip: string, password: string): string | null {
    // hashing both first makes them equal length, so the comparison takes the same time whatever was typed
    if (!timingSafeEqual(sha256(password), sha256(this.password))) {
      this.failures.set(ip, [...(this.failures.get(ip) ?? []), Date.now()]);
      return null;
    }
    this.failures.delete(ip);
    const now = Date.now();
    for (const [t, expires] of this.sessions) if (expires <= now) this.sessions.delete(t);
    const token = randomBytes(32).toString("base64url");
    this.sessions.set(token, now + SESSION_MS);
    return token;
  }

  signedIn(cookieHeader: string | undefined): boolean {
    const expires = this.sessions.get(this.token(cookieHeader) ?? "");
    return expires !== undefined && expires > Date.now();
  }

  signOut(cookieHeader: string | undefined) {
    this.sessions.delete(this.token(cookieHeader) ?? "");
  }

  /** The Set-Cookie value for a session; HttpOnly keeps it from scripts, SameSite=Strict from other sites. */
  cookie(token: string | null): string {
    const age = token ? Math.floor(SESSION_MS / 1000) : 0;
    return `${COOKIE}=${token ?? ""}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${age}`;
  }

  private token(cookieHeader: string | undefined): string | undefined {
    for (const part of (cookieHeader ?? "").split(";")) {
      const [name, value] = part.trim().split("=");
      if (name === COOKIE) return value;
    }
    return undefined;
  }
}
