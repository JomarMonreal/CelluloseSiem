import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";

/** code: expected to change when you rebuild; config: secrets, services and system files, which rarely should. */
export type Watched = { path: string; kind: "code" | "config" };
/** For each watched path, a fingerprint of every file under it, by path relative to it ("" for the path itself). */
export type Snapshot = Record<string, Record<string, string>>;
export type Change = { path: string; kind: Watched["kind"]; changed: string[]; added: string[]; removed: string[] };

const MAX_DEPTH = 3;
const MAX_FILES = 5_000;
const MAX_HASH_BYTES = 5 * 2 ** 20;

/**
 * A file's fingerprint: size, change time, mode and owner, plus its content's hash when this process may read it.
 * Files it can't read (your .env, root's secrets) still show changes through the rest.
 */
async function fingerprint(path: string): Promise<string | null> {
  let s;
  try {
    s = await stat(path);
  } catch {
    return null;
  }
  const meta = `${s.size}:${Math.round(s.mtimeMs)}:${s.mode.toString(8)}:${s.uid}`;
  if (!s.isFile() || s.size > MAX_HASH_BYTES) return meta;
  try {
    return `${meta}:${createHash("sha256").update(await readFile(path)).digest("hex").slice(0, 16)}`;
  } catch {
    return meta;
  }
}

async function walk(root: string, rel: string, depth: number, out: Record<string, string>) {
  if (Object.keys(out).length >= MAX_FILES) return;
  const full = rel ? join(root, rel) : root;
  let entries;
  try {
    entries = await readdir(full, { withFileTypes: true });
  } catch {
    // a file, or a directory we may not list: its own fingerprint is all there is
    const fp = await fingerprint(full);
    if (fp) out[rel] = fp;
    return;
  }
  for (const e of entries) {
    const r = rel ? join(rel, e.name) : e.name;
    if (e.isDirectory() && depth < MAX_DEPTH) await walk(root, r, depth + 1, out);
    else if (!e.isDirectory()) {
      const fp = await fingerprint(join(root, r));
      if (fp) out[r] = fp;
    }
  }
}

export async function snapshot(watched: Watched[]): Promise<Snapshot> {
  const snap: Snapshot = {};
  for (const w of watched) {
    snap[w.path] = {};
    await walk(w.path, "", 0, snap[w.path]);
  }
  return snap;
}

/** What differs between two snapshots, per watched path. Paths new to the watch list aren't changes. */
export function diff(before: Snapshot, after: Snapshot, watched: Watched[]): Change[] {
  const changes: Change[] = [];
  for (const w of watched) {
    const a = before[w.path];
    const b = after[w.path] ?? {};
    if (!a) continue;
    const changed = Object.keys(b).filter((k) => k in a && a[k] !== b[k]);
    const added = Object.keys(b).filter((k) => !(k in a));
    const removed = Object.keys(a).filter((k) => !(k in b));
    if (changed.length || added.length || removed.length) changes.push({ path: w.path, kind: w.kind, changed, added, removed });
  }
  return changes;
}
