import { NOTIFY_URL } from "./config.js";
import type { Alert } from "./store.js";

/** Pushes one alert to NOTIFY_URL. */
export function notify(a: Alert) {
  return push("Cellulose SIEM", `Level ${a.level}: ${a.title}`, a.level >= 12 ? "high" : "default");
}

/** Pushes a message to NOTIFY_URL: a Discord webhook gets JSON, anything else (ntfy) gets plain text. */
export async function push(title: string, text: string, priority: "default" | "high" | "low" = "default") {
  if (!NOTIFY_URL) return;
  const discord = /^https:\/\/(discord|discordapp)\.com\/api\/webhooks\//.test(NOTIFY_URL);
  try {
    const res = await fetch(NOTIFY_URL, {
      method: "POST",
      headers: discord ? { "content-type": "application/json" } : { "content-type": "text/plain", title, priority, tags: priority === "high" ? "warning" : "shield" },
      body: discord ? JSON.stringify({ content: `**${title}**\n${text}`.slice(0, 2000), allowed_mentions: { parse: [] } }) : text,
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) console.error(`notify: HTTP ${res.status}`);
  } catch (err) {
    console.error("notify:", (err as Error).message);
  }
}
