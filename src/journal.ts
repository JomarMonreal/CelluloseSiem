import { type ChildProcess, spawn } from "node:child_process";
import { createInterface } from "node:readline";

export type Entry = Record<string, unknown>;

// lines are handed over in batches: at most this many, or whatever came in this long
const BATCH = 500;
const BATCH_MS = 250;
const RESTART_MS = 5_000;
// after a batch couldn't be saved (a full disk, say): long enough not to spin, short enough to catch up soon
const RETRY_MS = 60_000;

/**
 * Follows part of the journal through `journalctl -f`: `matches` are journalctl's own arguments (`--unit x`,
 * `FIELD=value`). It starts from just after `cursor`, or from `firstRun` (e.g. `--lines=all`) the first time. If
 * journalctl exits it's started again from the last line handed over, so nothing is missed or read twice, as long
 * as the journal still has it.
 */
export default class Journal {
  private child?: ChildProcess;
  private pending: Entry[] = [];
  private timer?: NodeJS.Timeout;
  private stopped = false;
  // set when a batch couldn't be saved, until journalctl has been restarted from the last saved line
  private failed = false;

  constructor(
    private matches: string[],
    private cursor: string | undefined,
    private firstRun: string[],
    /** Called with each batch and the cursor after it; save the two together. */
    private onBatch: (entries: Entry[], cursor: string) => void,
  ) {}

  start() {
    this.pending = [];
    const from = this.cursor ? [`--after-cursor=${this.cursor}`] : this.firstRun;
    // --follow alone only reads the current boot (systemd 259), even from an older cursor: whatever the server wrote
    // after the last line read and before a reboot would be skipped
    const args = ["--output=json", "--follow", "--boot=all", "--no-pager", ...from, ...this.matches];
    const child = spawn("journalctl", args, {
      stdio: ["ignore", "pipe", "inherit"],
    });
    this.child = child;
    createInterface({ input: child.stdout! }).on("line", (line) => {
      try {
        this.pending.push(JSON.parse(line) as Entry);
      } catch {
        return;
      }
      if (this.pending.length >= BATCH) this.flush();
      else this.timer ??= setTimeout(() => this.flush(), BATCH_MS);
    });
    child.on("error", (err) => console.error("journalctl:", err.message));
    child.on("close", (code) => {
      if (!this.failed) this.flush();
      if (this.stopped) return;
      const wait = this.failed ? RETRY_MS : RESTART_MS;
      if (!this.failed) console.error(`journalctl exited (${code}), restarting in ${wait / 1000}s`);
      this.failed = false;
      setTimeout(() => this.start(), wait);
    });
  }

  private flush() {
    clearTimeout(this.timer);
    this.timer = undefined;
    if (!this.pending.length || this.failed) return;
    const batch = this.pending;
    this.pending = [];
    const cursor = String(batch.at(-1)!.__CURSOR);
    try {
      this.onBatch(batch, cursor);
    } catch (err) {
      // nothing of the batch was saved and the cursor didn't move: drop it and read it again from the journal later
      console.error(`couldn't save ${batch.length} lines, retrying in ${RETRY_MS / 1000}s:`, (err as Error).message);
      this.failed = true;
      this.child?.kill();
      return;
    }
    this.cursor = cursor;
  }

  stop() {
    this.stopped = true;
    this.child?.kill();
  }
}
