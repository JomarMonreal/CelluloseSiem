export type Target = "local" | "public";
export type Status = { url: string; up: boolean | null; since: number; detail: string; checkedAt: number };

const TIMEOUT_MS = 10_000;

/**
 * Checks the server's /health now and then. A target only counts as down after `fails` failures in a row, and
 * `onChange` hears each flip (and the first result, if that's down).
 */
export default class Probe {
  readonly status = new Map<Target, Status>();
  private failures = new Map<Target, number>();
  private timer?: NodeJS.Timeout;

  constructor(
    private targets: Partial<Record<Target, string>>,
    private everyMs: number,
    private fails: number,
    private onChange: (target: Target, up: boolean, s: Status) => void,
  ) {
    for (const [t, url] of Object.entries(targets) as [Target, string][]) this.status.set(t, { url, up: null, since: Date.now(), detail: "not checked yet", checkedAt: 0 });
  }

  start() {
    void this.checkAll();
    this.timer = setInterval(() => void this.checkAll(), this.everyMs);
  }

  stop() {
    clearInterval(this.timer);
  }

  private async checkAll() {
    await Promise.all((Object.entries(this.targets) as [Target, string][]).map(([t, url]) => this.check(t, url)));
  }

  private async check(target: Target, url: string) {
    let detail: string;
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(TIMEOUT_MS), headers: { "user-agent": "cellulose-siem" } });
      detail = res.ok ? "ok" : `HTTP ${res.status}`;
    } catch (err) {
      const cause = (err as { cause?: { code?: string } }).cause?.code;
      detail = (err as Error).name === "TimeoutError" ? `no reply in ${TIMEOUT_MS / 1000}s` : cause ?? (err as Error).message;
    }
    const s = this.status.get(target)!;
    s.checkedAt = Date.now();
    const ok = detail === "ok";
    const failures = ok ? 0 : (this.failures.get(target) ?? 0) + 1;
    this.failures.set(target, failures);
    const up = ok ? true : failures >= this.fails ? false : s.up;
    // unchanged (or one failure short of down): the detail stays the one from the last flip
    if (up === s.up) return;
    const first = s.up === null;
    Object.assign(s, { up, since: Date.now(), detail });
    if (!first || up === false) this.onChange(target, up!, s);
  }
}
