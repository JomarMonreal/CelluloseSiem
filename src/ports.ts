import { readFile } from "node:fs/promises";

/**
 * TCP ports listening on this machine that other machines can reach, read from /proc/net/tcp and tcp6 (no
 * privileges needed). Ports only this machine can reach are left out: editors and dev tools open and close
 * those all day.
 */
export async function networkListeners(): Promise<string[]> {
  const found = new Set<string>();
  for (const [file, v6] of [
    ["/proc/net/tcp", false],
    ["/proc/net/tcp6", true],
  ] as const) {
    let text: string;
    try {
      text = await readFile(file, "utf8");
    } catch {
      continue;
    }
    for (const line of text.split("\n").slice(1)) {
      const cols = line.trim().split(/\s+/);
      // st 0A is LISTEN
      if (cols.length < 4 || cols[3] !== "0A") continue;
      const [hexAddr, hexPort] = cols[1].split(":");
      const addr = v6 ? ipv6(hexAddr) : ipv4(hexAddr);
      if (isLoopback(addr)) continue;
      found.add(`${v6 ? `[${addr}]` : addr}:${parseInt(hexPort, 16)}`);
    }
  }
  return [...found].sort();
}

// the kernel prints addresses as 32-bit words in host (little-endian) byte order
function ipv4(hex: string): string {
  return [3, 2, 1, 0].map((i) => parseInt(hex.slice(i * 2, i * 2 + 2), 16)).join(".");
}

function ipv6(hex: string): string {
  const bytes: number[] = [];
  for (let w = 0; w < 4; w++) for (const i of [3, 2, 1, 0]) bytes.push(parseInt(hex.slice(w * 8 + i * 2, w * 8 + i * 2 + 2), 16));
  if (bytes.slice(0, 10).every((b) => b === 0) && bytes[10] === 0xff && bytes[11] === 0xff) return `::ffff:${bytes.slice(12).join(".")}`;
  const groups = Array.from({ length: 8 }, (_, i) => ((bytes[i * 2] << 8) | bytes[i * 2 + 1]).toString(16));
  // the usual short form: the longest run of two or more zero groups becomes ::
  let best = { at: -1, len: 1 };
  for (let i = 0; i < 8; i++) {
    let j = i;
    while (j < 8 && groups[j] === "0") j++;
    if (j - i > best.len) best = { at: i, len: j - i };
  }
  if (best.at < 0) return groups.join(":");
  return `${groups.slice(0, best.at).join(":")}::${groups.slice(best.at + best.len).join(":")}`;
}

function isLoopback(addr: string): boolean {
  return addr.startsWith("127.") || addr === "::1" || addr.startsWith("::ffff:127.");
}
