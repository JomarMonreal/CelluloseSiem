import type { Event } from "./events.js";

export type Rule = {
  id: string;
  /** What the dashboard calls it, in a few plain words. */
  name: string;
  /** What it means, for someone who isn't a security person. */
  explain: string;
  /** What to do about it, in order. */
  todo: string[];
  /** 6 to 9 are worth a look, 10 and up are attacks or outages, 12 and up need you now. */
  level: number;
  title: (e: Event) => string;
  mitre?: string[];
  /** Alerts from this rule count toward `after` rules that name one of these. */
  groups?: string[];
  match: (e: Event) => boolean;
  /** What thresholds count per and repeats fold under. Defaults to the IP, else the account, else one for all. */
  key?: (e: Event) => string;
  /** Fire on the `count`th matching event within `windowMs` for one key, or the `count`th different `distinct`. */
  threshold?: { count: number; windowMs: number; distinct?: (e: Event) => string };
  /** Fire only when an alert in `group` came first, within `windowMs`, for one of these keys (see alertKeys). */
  after?: { group: string; windowMs: number; keys: (e: Event) => string[] };
  /** A repeat for the same key within this long adds to the open alert instead of making a new one. */
  foldMs?: number;
};

export type Fired = { rule: Rule; event: Event; key: string };

const DEFAULT_FOLD_MS = 10 * 60_000;
export const foldMs = (r: Rule) => r.foldMs ?? DEFAULT_FOLD_MS;

/** The keys an alert is remembered under for `after` rules: its IP and its account. */
export const alertKeys = (e: Event) => [e.srcip && `ip:${e.srcip}`, e.username && `user:${e.username}`].filter((k): k is string => !!k);

/**
 * Runs each event past every rule. Time is the events' own, not the clock's, so replaying old lines (the first run,
 * or catching up after a restart) fires the same alerts as reading them live did.
 */
export class Engine {
  private windows = new Map<string, { ts: number; value: string }[]>();
  private groupHits = new Map<string, number>();
  private lastSweep = 0;
  private longestMs: number;

  constructor(private rules: Rule[]) {
    this.longestMs = Math.max(0, ...rules.map((r) => Math.max(r.threshold?.windowMs ?? 0, r.after?.windowMs ?? 0)));
  }

  process(e: Event): Fired[] {
    if (e.ts - this.lastSweep > this.longestMs) this.sweep(e.ts);
    const fired: Fired[] = [];
    for (const rule of this.rules) {
      if (!rule.match(e)) continue;
      const key = rule.key?.(e) ?? e.srcip ?? e.username ?? "all";
      if (rule.threshold && !this.counted(rule, key, e)) continue;
      if (rule.after && !this.followed(rule.after, e)) continue;
      fired.push({ rule, event: e, key });
      for (const g of rule.groups ?? []) for (const k of alertKeys(e)) this.groupHits.set(`${g} ${k}`, e.ts);
    }
    return fired;
  }

  private counted(rule: Rule, key: string, e: Event): boolean {
    const { count, windowMs, distinct } = rule.threshold!;
    const id = `${rule.id} ${key}`;
    const hits = (this.windows.get(id) ?? []).filter((h) => e.ts - h.ts < windowMs);
    hits.push({ ts: e.ts, value: distinct ? distinct(e) : String(e.id) });
    if (new Set(hits.map((h) => h.value)).size < count) {
      this.windows.set(id, hits);
      return false;
    }
    // counting starts afresh, so a sustained attack fires again each `count` (and folds into the open alert)
    this.windows.delete(id);
    return true;
  }

  private followed(after: NonNullable<Rule["after"]>, e: Event): boolean {
    return after.keys(e).some((k) => {
      const at = this.groupHits.get(`${after.group} ${k}`);
      return at !== undefined && e.ts - at < after.windowMs;
    });
  }

  private sweep(now: number) {
    this.lastSweep = now;
    for (const [id, hits] of this.windows) if (hits.every((h) => now - h.ts >= this.longestMs)) this.windows.delete(id);
    for (const [id, at] of this.groupHits) if (now - at >= this.longestMs) this.groupHits.delete(id);
  }
}
