// The dashboard. Every string from the API may be attacker-written (usernames, reasons, event names): it only ever
// goes in through textContent, never as HTML.

const REFRESH_MS = 10_000;
const PAGE = 50;
// alert cards shown before "Show more": the most serious come first, so these are the ones that matter
const ALERTS_SHOWN = 6;
const HOUR = 3_600_000;
const $ = (id) => document.getElementById(id);
const SVG = "http://www.w3.org/2000/svg";

function el(tag, props = {}, ...children) {
  const node = tag.startsWith("svg:") ? document.createElementNS(SVG, tag.slice(4)) : document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) if (c != null && c !== false) node.append(c instanceof Node ? c : String(c));
  return node;
}

async function api(path, init) {
  const res = await fetch(path, init);
  // signed out (session expired, or the SIEM restarted): back to the sign-in page
  if (res.status === 401) {
    location.href = "/login";
    throw new Error("signed out");
  }
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
  return res.json();
}

// words

const plural = (n, one, many = `${one}s`) => `${n.toLocaleString()} ${n === 1 ? one : many}`;
const fullTime = (ts) => new Date(ts).toLocaleString(undefined, { weekday: "short", month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
const clock = (ts) => new Date(ts).toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
function ago(ts) {
  const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  const today = new Date().toDateString() === new Date(ts).toDateString();
  if (s < 12 * 3600 || today) return `${Math.round(s / 3600)} h ago`;
  if (s < 48 * 3600) return `yesterday ${clock(ts)}`;
  return new Date(ts).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}
const when = (ts) => el("time", { class: "when", datetime: new Date(ts).toISOString(), title: fullTime(ts) }, ago(ts));
const gb = (mb) => (mb >= 1024 ? `${(mb / 1024).toFixed(1)} GB` : mb < 1 ? "under 1 MB" : `${Math.round(mb)} MB`);

const SEVERITY = [
  { min: 12, band: "critical", word: "Critical" },
  { min: 10, band: "high", word: "High" },
  { min: 7, band: "medium", word: "Medium" },
  { min: 0, band: "low", word: "Low" },
];
const severity = (level) => SEVERITY.find((s) => level >= s.min);
const severityTag = (level) => {
  const s = severity(level);
  return el("span", { class: `severity ${s.band}`, title: `level ${level}` }, el("span", { class: "sev-icon", "aria-hidden": "true" }), s.word);
};

// what each event is called, and a sentence about it
const LIMITS = {
  auth_ip: "too many sign-in attempts from this IP",
  login_user: "too many sign-in attempts on this account",
  signup_ip: "too many new accounts from this IP",
  rooms_ip: "too many rooms",
  db_reads_ip: "too many lookups",
  events_socket: "too many messages",
  actions_tick: "too many moves at once",
};
const EVENTS = {
  auth_ok: ["Signed in", (f, e) => `${e.username ?? "someone"}${f.method === "resume" ? " (returning session)" : ""}`],
  auth_fail: ["Failed sign-in", (f) => [f.target && `'${f.target}'`, f.reason].filter(Boolean).join(": ")],
  signup_ok: ["New account", (f, e) => e.username ?? ""],
  signup_fail: ["Sign-up refused", (f) => [f.target && `'${f.target}'`, f.reason].filter(Boolean).join(": ")],
  logout_all: ["Signed out everywhere", (f, e) => e.username ?? ""],
  password_changed: ["Password changed", (f, e) => e.username ?? ""],
  session_kicked: ["Signed in elsewhere", (f) => `the session from ${f.old_srcip ?? "another device"} was ended`],
  rate_limit: ["Rate-limited", (f) => LIMITS[f.limit] ?? f.limit],
  conn_refused: ["Too many connections", (f) => `already had ${f.open} open`],
  origin_refused: ["Blocked website", (f) => `a page on ${f.origin} tried to connect`],
  bad_request: ["Malformed request", (f) => f.reason ?? ""],
  unknown_event: ["Unknown request", (f) => `'${f.event}'`],
  server_error: ["Request caused an error", (f) => `'${f.event}'`],
  avatar_rejected: ["Picture refused", (f) => f.reason ?? ""],
  ranked_pair: ["Repeat ranked match", (f) => `${f.user} and ${f.other} met ${f.times} times in 24 h`],
  server_start: ["Server started", (f) => (f.production ? "production" : "development")],
  server_stop: ["Server stopped", (f) => f.signal ?? ""],
  server_crash: ["Server crashed", (f) => f.error ?? ""],
  unit_started: ["Service started", () => ""],
  unit_stopped: ["Service stopped", () => ""],
  unit_exit: ["Server process exited", (f) => `${f.code} ${f.status}`],
  unit_failed: ["Service failed", (f) => f.result ?? ""],
  unit_restart: ["Restarted after dying", (f) => `restart #${f.counter}`],
  probe_down: ["Health check failing", (f) => `${f.target === "public" ? "public address" : "server"}: ${f.detail}`],
  probe_up: ["Health check OK again", (f) => (f.target === "public" ? "public address" : "server")],
  disk_low: ["Disk almost full", (f) => `${gb(f.free_mb)} free`],
  disk_ok: ["Disk space OK again", (f) => `${gb(f.free_mb)} free`],
  // games and fair play
  game_player: ["Game played", (f) => `${f.kind} ${f.mode === "ctf" ? "capture the flag" : "strongest 500"}: place ${f.place ?? "?"} of ${f.players}, ${plural(f.actions ?? 0, "move")}${f.burst >= 4 || f.fast >= 5 ? ", inhumanly fast" : ""}`],
  game_rejected: ["Impossible move", (f) => `${f.reason} (${f.kind} game)`],
  win_trading: ["Win trading pattern", (f) => `${f.winner} ahead of ${f.loser} in ${f.ahead} of ${f.games} ranked games`],
  throwing: ["Throwing pattern", (f) => `${f.user} sat out ${f.idle} of ${f.games} ranked games`],
  smurf: ["Possible smurf", (f) => `${f.user} won ${f.wins} of their first ${f.games} ranked games`],
  linked_accounts: ["Linked accounts", (f) => `${f.a} and ${f.b} shared ${f.shared_ip}, met in ${f.games} ranked games`],
  shared_ip: ["Accounts sharing an IP", (f) => f.users ?? ""],
  // the laptop
  sudo_command: ["Admin command (sudo)", (f) => f.command ?? ""],
  sudo_denied: ["Admin access refused", (f) => (f.attempts ? `${f.attempts} wrong passwords: ${f.command}` : (f.reason ?? ""))],
  su_session: ["Switched user (su)", (f) => `to ${f.as}`],
  local_auth_fail: ["Wrong laptop password", () => ""],
  local_password_changed: ["Laptop password changed", () => ""],
  ssh_login: ["SSH login", (f) => f.method ?? ""],
  ssh_fail: ["SSH login failed", (f) => f.method ?? ""],
  user_added: ["New laptop user", (f) => `uid ${f.uid}, shell ${f.shell}`],
  user_removed: ["Laptop user removed", () => ""],
  group_member_added: ["Added to a group", (f) => f.group ?? ""],
  login_session: ["Logged in on the laptop", () => ""],
  lid_closed: ["Lid closed", () => ""],
  laptop_sleep: ["Laptop went to sleep", () => "the game is offline until it wakes"],
  laptop_wake: ["Laptop woke up", () => ""],
  laptop_shutdown: ["Laptop shutting down", () => ""],
  tunnel_up: ["Tunnel connected", (f) => (f.location ? `via ${f.location}` : "")],
  tunnel_drop: ["Tunnel connection dropped", (f) => f.error ?? ""],
  oom_kill: ["Out of memory", (f) => `killed ${f.process}`],
  port_opened: ["New open port", (f) => f.listen ?? ""],
  file_changed: ["Watched file changed", (f) => `${f.path}: ${f.summary}`],
  log: ["Server output", (f) => f.message ?? ""],
  systemd: ["System message", (f) => f.message ?? ""],
};
function describe(e) {
  const [label, say] = EVENTS[e.evt] ?? [e.evt, () => ""];
  return { label, text: String(say(e.fields, e) ?? "") };
}

const FILTERS = [
  { name: "Everything", evt: "" },
  { name: "Sign-ins", evt: "auth_ok,auth_fail,signup_ok,signup_fail,session_kicked,password_changed,logout_all" },
  { name: "Failed sign-ins", evt: "auth_fail" },
  { name: "Blocked or suspicious", evt: "rate_limit,conn_refused,origin_refused,bad_request,unknown_event,server_error,avatar_rejected,ranked_pair" },
  { name: "Games", evt: "game_player,game_rejected,ranked_pair,win_trading,throwing,smurf,linked_accounts,shared_ip" },
  {
    name: "Laptop",
    evt: "sudo_command,sudo_denied,su_session,local_auth_fail,local_password_changed,ssh_login,ssh_fail,user_added,user_removed,group_member_added,login_session,lid_closed,laptop_sleep,laptop_wake,laptop_shutdown,tunnel_up,tunnel_drop,oom_kill,port_opened,file_changed",
  },
  { name: "Server", evt: "server_start,server_stop,server_crash,unit_started,unit_stopped,unit_exit,unit_failed,unit_restart,probe_down,probe_up,disk_low,disk_ok" },
  { name: "Server output", evt: "log,systemd" },
];

// state

const state = {
  filter: FILTERS[0],
  who: null, // { kind: "ip" | "user", value }
  q: "",
  oldestId: 0,
  paged: false,
  open: new Set(), // alert ids whose details are showing
  related: new Map(), // alert id -> events, or null while loading
  rules: {},
  timeline: null,
  allAlerts: false,
};

// header, verdict, health

function renderTop(s) {
  const probeChip = (name, p) => {
    if (!p) return null;
    const cls = p.up === null ? "unknown" : p.up ? "good" : "bad";
    const word = p.up === null ? "checking" : p.up ? "online" : "down";
    return el("span", { class: "chip", title: `${p.url}: ${p.detail}, since ${fullTime(p.since)}` }, el("span", { class: `dot ${cls}`, "aria-hidden": "true" }), `${name} ${word}`);
  };
  $("chips").replaceChildren(...[probeChip("Server", s.probes.local), probeChip("Public", s.probes.public)].filter(Boolean));
  $("signout").hidden = !s.signOut;

  const open = s.openAlerts.reduce((n, a) => n + a.n, 0);
  const top = s.openAlerts.length ? Math.max(...s.openAlerts.map((a) => a.level)) : 0;
  let band, icon, title, text;
  if (s.probes.local?.up === false) {
    [band, icon, title] = ["critical", "!", "The game server is down"];
    text = "Players can't play right now. Open the \"Server not responding\" alert below for what to do.";
  } else if (open && top >= 12) {
    [band, icon, title] = ["critical", "!", `${plural(open, "alert")}, at least one urgent`];
    text = "Something may be under attack or broken right now. Start with the critical ones at the top.";
  } else if (open && top >= 10) {
    [band, icon, title] = ["high", "!", `${plural(open, "alert")} to look at`];
    text = "Nothing urgent got through, but someone was trying something. Each alert says what to do.";
  } else if (open) {
    [band, icon, title] = ["medium", "i", plural(open, "minor alert")];
    text = "Worth a look when you have a minute. Mark them handled once you have.";
  } else if (s.probes.public?.up === false) {
    [band, icon, title] = ["high", "!", "The game isn't reachable from the internet"];
    text = "The server itself is fine; the Cloudflare tunnel or the laptop's connection is the likely problem.";
  } else {
    [band, icon, title] = ["good", "✓", "All clear"];
    text = `No open alerts. ${plural(s.eventsSince, "event")} in the last 24 hours${s.lastEventTs ? `, the latest ${ago(s.lastEventTs)}` : ""}.`;
  }
  $("verdict").className = `verdict ${band}`;
  $("verdict-icon").textContent = icon;
  $("verdict-title").textContent = title;
  $("verdict-text").textContent = text;
  document.title = open ? `(${open}) Cellulose SIEM` : "Cellulose SIEM";
}

function renderHealth(s) {
  const row = (ok, name, detail, extra) =>
    el(
      "li",
      {},
      el("div", { class: "health-row" }, el("span", { class: `dot ${ok === null ? "unknown" : ok ? "good" : "bad"}`, "aria-hidden": "true" }), el("span", {}, name), el("span", { class: "sub" }, detail)),
      extra,
    );
  // "since" only once it means something: right after the SIEM starts, every check is "since just now"
  const since = (p) => (Date.now() - p.since > 5 * 60_000 ? ` since ${ago(p.since)}` : "");
  const probe = (name, p) => p && row(p.up, name, p.up === null ? "checking…" : `${p.up ? "online" : `down: ${p.detail}`}${since(p)}`);
  const st = s.storage;
  const diskUsed = st.diskTotalMb ? 1 - st.diskFreeMb / st.diskTotalMb : 0;
  $("health").replaceChildren(
    ...[
      probe("Game server", s.probes.local),
      probe("Public address", s.probes.public),
      row(
        st.diskLow === null ? null : !st.diskLow,
        "Laptop disk",
        st.diskTotalMb ? `${gb(st.diskFreeMb)} free of ${gb(st.diskTotalMb)}` : "checking…",
        st.diskTotalMb ? bar(diskUsed, `${Math.round(diskUsed * 100)}% used`, st.diskLow) : null,
      ),
      row(true, "SIEM database", `${gb(st.dbMb)} of the ${gb(st.maxDbMb)} limit`, bar(st.dbMb / st.maxDbMb, `${Math.round((st.dbMb / st.maxDbMb) * 100)}% of the limit`)),
      row(s.lastEventTs ? true : null, "Last line from the server", s.lastEventTs ? ago(s.lastEventTs) : "none yet"),
      row(true, "Ports open to the network", s.laptop.ports.length ? s.laptop.ports.join(", ") : "none"),
      row(
        s.laptop.files.checkedAt ? true : null,
        "Watched files",
        s.laptop.files.checkedAt ? `${s.laptop.files.watched} watched, ${s.laptop.files.changedAt ? `last change ${ago(s.laptop.files.changedAt)}` : "no changes since the SIEM started"}` : "first check running…",
      ),
    ].filter(Boolean),
  );
}
function bar(fraction, label, warn = false) {
  const fill = el("span");
  // CSSOM, not a style attribute: the page's CSP allows the one and not the other
  fill.style.width = `${Math.max(1, Math.min(100, fraction * 100))}%`;
  return el("div", { class: `bar ${warn ? "warn" : ""}`, role: "img", "aria-label": label }, fill);
}

// alerts

function renderAlerts(alerts) {
  $("handle-all").hidden = !alerts.some((a) => !a.acked);
  if (!alerts.length) {
    $("alerts").replaceChildren(el("p", { class: "empty" }, $("show-handled").checked ? "No alerts yet." : "Nothing needs your attention."));
    return;
  }
  const shown = state.allAlerts ? alerts : alerts.slice(0, ALERTS_SHOWN);
  const hidden = alerts.length - shown.length;
  $("alerts").replaceChildren(
    ...shown.map(alertCard),
    hidden
      ? el("button", { type: "button", class: "quiet wide", onclick: () => ((state.allAlerts = true), void loadAlerts()) }, `Show ${plural(hidden, "more alert")}`)
      : null,
  );
}

function alertCard(a) {
  const rule = state.rules[a.rule] ?? { name: a.rule, explain: "", todo: [], mitre: [] };
  const isOpen = state.open.has(a.id);
  return el(
    "article",
    { class: `card ${severity(a.level).band} ${a.acked ? "handled" : ""}` },
    el("div", { class: "card-top" }, severityTag(a.level), el("h3", {}, rule.name), a.acked ? el("span", { class: "tag" }, "handled") : null),
    el("p", { class: "what" }, a.title),
    el(
      "div",
      { class: "meta" },
      el("span", {}, a.count > 1 ? `${plural(a.count, "time")}, last ` : "", when(a.last_ts)),
      a.srcip ? el("span", {}, "IP ", el("button", { class: "link mono", type: "button", onclick: () => showWho("ip", a.srcip) }, a.srcip)) : null,
      a.username ? el("span", {}, "account ", el("button", { class: "link", type: "button", onclick: () => showWho("user", a.username) }, a.username)) : null,
    ),
    el(
      "div",
      { class: "actions" },
      el("button", { type: "button", "aria-expanded": String(isOpen), onclick: () => toggleDetail(a.id) }, isOpen ? "Hide details" : "What does this mean?"),
      a.acked ? null : el("button", { type: "button", class: "quiet", onclick: () => handle(a.id) }, "Mark handled"),
    ),
    isOpen ? alertDetail(a, rule) : null,
  );
}

function alertDetail(a, rule) {
  if (!state.related.has(a.id)) void loadRelated(a.id);
  const related = state.related.get(a.id);
  const source = `Rule ${a.rule} · first seen ${fullTime(a.first_ts)}`;
  return el(
    "div",
    { class: "detail" },
    rule.explain ? el("div", {}, el("h4", {}, "What it means"), el("p", {}, rule.explain)) : null,
    rule.todo.length ? el("div", {}, el("h4", {}, "What to do"), el("ol", {}, rule.todo.map((t) => el("li", {}, withCode(t))))) : null,
    el(
      "div",
      {},
      el("h4", {}, "Related activity"),
      !related
        ? el("p", { class: "empty" }, "Loading…")
        : related.length
          ? [
              el("ul", { class: "list events" }, related.slice(0, 5).map(eventItem)),
              a.srcip || a.username
                ? el("button", { type: "button", class: "quiet", onclick: () => showWho(a.srcip ? "ip" : "user", a.srcip ?? a.username) }, `See all activity from ${a.srcip ? "this IP" : "this account"}`)
                : null,
            ]
          : el("p", { class: "empty" }, "Nothing else from this IP or account around then."),
    ),
    el(
      "p",
      { class: "mitre" },
      rule.mitre.length
        ? ["Technique: ", rule.mitre.flatMap((id, i) => [i ? ", " : "", el("a", { href: `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`, target: "_blank", rel: "noopener noreferrer" }, id)]), ` · ${source}`]
        : source,
    ),
  );
}

// the advice is ours, not attacker text: `backticks` become code, nothing else is interpreted
const withCode = (text) => text.split(/`([^`]+)`/).map((part, i) => (i % 2 ? el("code", {}, part) : part));

async function loadRelated(id) {
  state.related.set(id, null);
  try {
    state.related.set(id, await api(`/api/alerts/${id}/related`));
  } catch {
    state.related.set(id, []);
  }
  await loadAlerts();
}

function toggleDetail(id) {
  if (state.open.has(id)) state.open.delete(id);
  else state.open.add(id);
  void loadAlerts();
}

async function handle(id) {
  await api(`/api/alerts/${id}/ack`, { method: "POST" });
  state.open.delete(id);
  await refresh();
}

async function loadAlerts() {
  renderAlerts(await api(`/api/alerts?all=${$("show-handled").checked ? 1 : 0}`));
}

// activity chart: stacked bars per hour, each hour a hit target with a tooltip, and a table view below

const SERIES = [
  { key: "other", name: "Normal", cls: "s1", color: "--series-1" },
  { key: "failed", name: "Failed sign-ins", cls: "s2", color: "--series-2" },
  { key: "blocked", name: "Blocked or suspicious", cls: "s3", color: "--series-3" },
];
const swatch = (s) => {
  const i = el("i", { "aria-hidden": "true" });
  i.style.background = `var(${s.color})`;
  return i;
};
const hourLabel = (hour) => `${clock(hour * HOUR)} – ${clock((hour + 1) * HOUR)}`;

function renderChart({ hours }) {
  const nowHour = Math.floor(Date.now() / HOUR);
  const byHour = new Map(hours.map((h) => [h.hour, h]));
  const data = Array.from({ length: 24 }, (_, i) => {
    const hour = nowHour - 23 + i;
    const h = byHour.get(hour) ?? {};
    return { hour, other: h.other ?? 0, failed: h.failed ?? 0, blocked: h.blocked ?? 0 };
  });
  const totals = Object.fromEntries(SERIES.map((s) => [s.key, data.reduce((n, d) => n + d[s.key], 0)]));
  $("legend").replaceChildren(...SERIES.map((s) => el("span", {}, swatch(s), s.name, " ", el("b", {}, totals[s.key].toLocaleString()))));
  $("chart-table").replaceChildren(
    ...data
      .filter((d) => d.other + d.failed + d.blocked)
      .reverse()
      .map((d) => el("tr", {}, el("td", {}, hourLabel(d.hour)), el("td", { class: "num" }, d.other), el("td", { class: "num" }, d.failed), el("td", { class: "num" }, d.blocked))),
  );

  const box = $("chart");
  const max = Math.max(...data.map((d) => d.other + d.failed + d.blocked));
  if (!max) {
    box.replaceChildren(el("p", { class: "empty" }, "No player activity in the last 24 hours."));
    return;
  }
  const W = Math.max(280, box.clientWidth);
  const H = box.clientHeight || 180;
  const pad = { top: 8, right: 4, bottom: 22, left: 30 };
  const step = niceStep(max);
  const top = Math.ceil(max / step) * step;
  const plotW = W - pad.left - pad.right;
  const plotH = H - pad.top - pad.bottom;
  const y = (v) => pad.top + plotH - (v / top) * plotH;
  const slot = plotW / data.length;
  const GAP = 2;
  const barW = Math.max(3, slot - GAP);

  const svg = el("svg:svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Events per hour over the last 24 hours. The table below has the numbers." });
  for (let v = 0; v <= top; v += step) {
    svg.append(el("svg:line", { class: v ? "grid" : "base", x1: pad.left, x2: W - pad.right, y1: y(v), y2: y(v) }));
    svg.append(el("svg:text", { class: "tick", x: pad.left - 6, y: y(v) + 4, "text-anchor": "end" }, v.toLocaleString()));
  }
  data.forEach((d, i) => {
    const x = pad.left + i * slot + GAP / 2;
    const col = el("svg:g", { class: "col" });
    const present = SERIES.filter((s) => d[s.key] > 0);
    let base = 0;
    present.forEach((s, j) => {
      // a 2px gap of surface between stacked segments; only the topmost gets rounded corners
      const gap = j ? GAP : 0;
      const h = Math.max(1, y(base) - y(base + d[s.key]) - gap);
      const yTop = y(base) - gap - h;
      const last = j === present.length - 1;
      col.append(el("svg:path", { class: `seg ${s.cls}`, d: last ? roundedTop(x, yTop, barW, h, Math.min(4, barW / 2, h)) : `M${x},${yTop}h${barW}v${h}h${-barW}Z` }));
      base += d[s.key];
    });
    const label = `${hourLabel(d.hour)}: ${SERIES.map((s) => `${d[s.key]} ${s.name.toLowerCase()}`).join(", ")}`;
    const hit = el("svg:rect", { class: "hit", x: pad.left + i * slot, y: pad.top, width: slot, height: plotH, tabindex: "0", "aria-label": label });
    const show = () => showTip(d, pad.left + i * slot + slot / 2, W);
    hit.addEventListener("pointerenter", show);
    hit.addEventListener("focus", show);
    hit.addEventListener("pointerleave", hideTip);
    hit.addEventListener("blur", hideTip);
    col.append(hit);
    svg.append(col);
    const isNow = i === data.length - 1;
    if (isNow || (d.hour + 1) % 6 === 0) {
      svg.append(el("svg:text", { class: "tick", x: x + barW / 2, y: H - 6, "text-anchor": isNow ? "end" : "middle" }, isNow ? "now" : clock((d.hour + 1) * HOUR)));
    }
  });
  box.replaceChildren(svg);
}

function roundedTop(x, y, w, h, r) {
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
}
function niceStep(max) {
  const raw = max / 3;
  const mag = 10 ** Math.floor(Math.log10(raw || 1));
  return [1, 2, 5, 10].map((m) => m * mag).find((s) => s >= raw);
}

function showTip(d, cx, W) {
  const tip = $("tooltip");
  tip.replaceChildren(
    el("div", { class: "t-head" }, hourLabel(d.hour)),
    ...SERIES.map((s) => el("div", { class: "t-row" }, swatch(s), s.name, el("b", {}, d[s.key].toLocaleString()))),
  );
  tip.hidden = false;
  const w = tip.offsetWidth;
  tip.style.left = `${Math.min(Math.max(0, cx - w / 2), W - w)}px`;
  tip.style.top = "-8px";
  tip.style.transform = "translateY(-100%)";
}
const hideTip = () => ($("tooltip").hidden = true);

// daily summary

function renderDigests(digests) {
  const [latest, ...older] = digests;
  if (!latest) {
    $("digest-day").textContent = "";
    $("digest").replaceChildren(el("p", { class: "empty" }, "The first summary arrives tomorrow morning: a short report of the day before."));
    $("digest-older").hidden = true;
    return;
  }
  $("digest-day").textContent = `made ${ago(latest.ts)}`;
  $("digest").replaceChildren(digestBody(latest));
  $("digest-older").hidden = !older.length;
  $("digest-list").replaceChildren(...older.map((d) => el("div", { class: "digest-old" }, el("h4", {}, new Date(d.ts).toLocaleDateString(undefined, { weekday: "long", month: "short", day: "numeric" })), digestBody(d))));
}

// the stored text, a line per topic; the first line is the headline
const digestBody = (d) => {
  const [head, ...rest] = d.text.split("\n");
  return el("div", { class: "digest" }, el("p", { class: "digest-head" }, head), el("ul", {}, rest.map((line) => el("li", {}, line.replace(/^• /, "")))));
};

// IPs

function renderIps(rows) {
  if (!rows.length) {
    $("ips").replaceChildren(el("li", { class: "empty" }, "No player activity in the last 24 hours."));
    return;
  }
  $("ips").replaceChildren(
    ...rows.map((r) => {
      const tags = [
        r.auth_ok && plural(r.auth_ok, "sign-in"),
        r.auth_fail && plural(r.auth_fail, "failed sign-in"),
        r.signups && plural(r.signups, "new account"),
        r.limited && `rate-limited ${plural(r.limited, "time")}`,
        r.probing && plural(r.probing, "odd request"),
      ].filter(Boolean);
      return el(
        "li",
        {},
        el("div", { class: "line" }, el("button", { class: "link mono", type: "button", onclick: () => showWho("ip", r.srcip) }, r.srcip), when(r.last_ts)),
        el("div", { class: "tags" }, (tags.length ? tags : [plural(r.n, "event")]).map((t) => el("span", { class: "tag" }, t))),
      );
    }),
  );
}

// activity log

function eventItem(e) {
  const { label, text } = describe(e);
  const raw = e.source === "log" || e.source === "systemd";
  // the account is already in the sentence for these
  const showUser = e.username && !["auth_ok", "signup_ok", "logout_all", "password_changed"].includes(e.evt);
  return el(
    "li",
    {},
    el("div", { class: "line" }, el("span", { class: "label" }, label), when(e.ts)),
    text ? el("div", { class: raw ? "raw" : "sub" }, text) : null,
    e.srcip || showUser
      ? el(
          "div",
          { class: "tags" },
          e.srcip ? el("button", { class: "link mono tag", type: "button", onclick: () => showWho("ip", e.srcip) }, e.srcip) : null,
          showUser ? el("button", { class: "link tag", type: "button", onclick: () => showWho("user", e.username) }, e.username) : null,
        )
      : null,
  );
}

function eventQuery(before) {
  const p = new URLSearchParams({ limit: String(PAGE) });
  if (state.filter.evt) p.set("evt", state.filter.evt);
  if (state.who) p.set(state.who.kind, state.who.value);
  if (state.q) p.set("q", state.q);
  if (before) p.set("before", String(before));
  return `/api/events?${p}`;
}

async function loadEvents({ older = false } = {}) {
  const rows = await api(eventQuery(older ? state.oldestId : 0));
  const list = $("events");
  if (older) list.append(...rows.map(eventItem));
  else list.replaceChildren(...rows.map(eventItem));
  state.paged = older;
  if (rows.length) state.oldestId = rows.at(-1).id;
  if (!list.children.length) list.replaceChildren(el("li", { class: "empty" }, state.who || state.q || state.filter.evt ? "Nothing matches." : "Nothing logged yet."));
  $("older").hidden = rows.length < PAGE;
}

function renderFilters() {
  $("filters").replaceChildren(
    ...FILTERS.map((f) =>
      el(
        "button",
        {
          type: "button",
          "aria-pressed": String(f === state.filter),
          onclick: () => {
            state.filter = f;
            renderFilters();
            void loadEvents();
          },
        },
        f.name,
      ),
    ),
  );
  const who = $("who");
  who.hidden = !state.who;
  if (state.who) {
    who.replaceChildren(
      `Only ${state.who.kind === "ip" ? "IP" : "account"} `,
      el("b", { class: "mono" }, state.who.value),
      el(
        "button",
        {
          type: "button",
          class: "quiet",
          onclick: () => {
            state.who = null;
            renderFilters();
            void loadEvents();
          },
        },
        "Show everyone",
      ),
    );
  }
}

function showWho(kind, value) {
  state.who = { kind, value };
  state.filter = FILTERS[0];
  renderFilters();
  void loadEvents();
  $("log").scrollIntoView({ behavior: "smooth", block: "start" });
}

// wiring

let searchTimer;
$("q").addEventListener("input", () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    state.q = $("q").value.trim();
    void loadEvents();
  }, 300);
});
$("search").addEventListener("submit", (ev) => ev.preventDefault());
$("older").addEventListener("click", () => void loadEvents({ older: true }));
$("show-handled").addEventListener("change", () => void loadAlerts());
$("handle-all").addEventListener("click", async () => {
  if (!confirm("Mark every open alert as handled?")) return;
  await api("/api/alerts/all/ack", { method: "POST" });
  state.open.clear();
  await refresh();
});
let resizeTimer;
window.addEventListener("resize", () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => state.timeline && renderChart(state.timeline), 150);
});

async function refresh() {
  try {
    const [summary, timeline, ips, digests] = await Promise.all([api("/api/summary"), api("/api/timeline"), api("/api/ips"), api("/api/digests")]);
    state.rules = summary.rules;
    state.timeline = timeline;
    renderTop(summary);
    renderHealth(summary);
    renderChart(timeline);
    renderIps(ips);
    renderDigests(digests);
    await loadAlerts();
    // the log only refreshes on its newest page, and not while you're typing, so it doesn't move under you
    if (!state.paged && document.activeElement !== $("q")) await loadEvents();
  } catch (err) {
    if (err.message === "signed out") return;
    $("verdict").className = "verdict critical";
    $("verdict-icon").textContent = "!";
    $("verdict-title").textContent = "Can't reach the SIEM";
    $("verdict-text").textContent = `${err.message}. Is the laptop on and the cellulose-siem service running?`;
  }
}

renderFilters();
void refresh();
setInterval(refresh, REFRESH_MS);
