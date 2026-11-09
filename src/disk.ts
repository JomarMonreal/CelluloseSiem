import { statfs } from "node:fs/promises";

export type DiskStatus = { path: string; freeMb: number; totalMb: number; low: boolean | null; checkedAt: number };

/**
 * Watches free space on the disk `path` is on (the laptop's, shared with the game server and journald), and
 * reports when it drops below `minFreeMb` and when it recovers.
 */
export default class Disk {
  readonly status: DiskStatus;
  private timer?: NodeJS.Timeout;

  constructor(
    path: string,
    private minFreeMb: number,
    private everyMs: number,
    private onChange: (low: boolean, s: DiskStatus) => void,
  ) {
    this.status = { path, freeMb: 0, totalMb: 0, low: null, checkedAt: 0 };
  }

  start() {
    void this.check();
    this.timer = setInterval(() => void this.check(), this.everyMs);
  }

  stop() {
    clearInterval(this.timer);
  }

  private async check() {
    try {
      const s = await statfs(this.status.path);
      // bavail, not bfree: what a non-root process like this one may actually still write
      Object.assign(this.status, {
        freeMb: Math.floor((s.bavail * s.bsize) / 2 ** 20),
        totalMb: Math.floor((s.blocks * s.bsize) / 2 ** 20),
        checkedAt: Date.now(),
      });
    } catch (err) {
      console.error("disk check:", (err as Error).message);
      return;
    }
    const low = this.status.freeMb < this.minFreeMb;
    if (low === this.status.low) return;
    const first = this.status.low === null;
    this.status.low = low;
    if (!first || low) this.onChange(low, this.status);
  }
}
