// aqt-ui front end: plain ES module, no build step.
// Every piece of data is put into the page with textContent or attributes, never as markup,
// because evidence (quarantined pages, reasons, excerpts) is untrusted. All text goes through
// vis(), which shows hidden characters (bidi controls, zero-width characters, ...) as <U+XXXX>.
import { DE, GLOSSARY, NEEDS, REASONS_DE, REFUSALS_DE, STEPS_DE } from "./i18n.js";
import { MESSAGES } from "./messages.js";
import { vis } from "./text.js";

// ---- language: English by default, German on request; the choice stays in this browser ------------
let LANG = "en";
// the stored choice; without one, the system's language (German or English)
try { const kept = localStorage.getItem("aqt-ui-lang"); if (kept === "de" || (kept === null && /^de\b/i.test(navigator.language || ""))) LANG = "de"; } catch (e) { /* storage blocked: stay English */ }
// t('English words {n}', { n: 3 }): the German entry when German is chosen, else the English words.
function t(text, vars) {
  const out = (LANG === "de" && DE[text]) || text;
  return vars ? out.replace(/\{(\w+)\}/g, (all, key) => (vars[key] === undefined || vars[key] === null ? all : String(vars[key]))) : out;
}
// ---- sentences of the tools: the server sends the English text and, next to it, its message code and
// parameters (aqt_evidence.Text). msg() shows the German from messages.js; it falls back to the English
// it was sent when the code is unknown, or when the English template filled with the parameters is not
// exactly that text (then the code does not describe it). A stored sentence comes without parameters:
// its code is then a family (a code prefix) and the entry whose English template it matches is used.
function pyText(value) {          // a parameter as Python's str() wrote it into the English sentence
  return value === null || value === undefined ? "None" : value === true ? "True" : value === false ? "False" : String(value);
}
function isCoded(value) { return !!value && typeof value === "object" && typeof value.code === "string"; }
function render(code, args, lang) {
  const values = args || {};
  if (code === "aqt.join") {
    const parts = (values.items || []).map((item) => (isCoded(item) ? render(item.code, item.args, lang) : pyText(item)));
    return parts.includes(null) ? null : parts.join(values.sep ?? ", ");
  }
  const entry = MESSAGES[code];
  if (!entry) return null;
  let failed = false;
  const out = entry[lang].replace(/\{(\w+)\}/g, (all, name) => {
    const value = values[name];
    if (!(name in values) || Array.isArray(value)) { failed = true; return all; }
    if (!isCoded(value)) return pyText(value);
    const inner = render(value.code, value.args, lang);
    if (inner === null) failed = true;
    return inner || "";
  });
  return failed ? null : out;
}
function recognise(family, english) {
  const group = family.split(".").slice(0, 2).join(".") + ".";
  const plain = (value) => {        // a parameter that is itself a fixed sentence of the group ("unknown source")
    const found = Object.keys(MESSAGES).find((c) => c.startsWith(group) && MESSAGES[c].en === value && !/\{\w+\}/.test(value));
    return found ? { code: found, args: {} } : value;
  };
  for (const [code, entry] of Object.entries(MESSAGES)) {
    if (!code.startsWith(family)) continue;
    const names = [];
    const pattern = entry.en.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\\\{(\w+)\\\}/g, (all, name) => { names.push(name); return "(.*?)"; });
    const found = new RegExp(`^${pattern}$`, "s").exec(english);
    if (found) return { code, args: Object.fromEntries(names.map((name, i) => [name, plain(found[i + 1])])) };
  }
  return null;
}
function msg(code, args, english) {
  const text = english === null || english === undefined ? "" : String(english);
  if (LANG !== "de" || !code || !text) return text;
  let found = { code, args };
  if (args === null || args === undefined) {
    found = MESSAGES[code] && !/\{\w+\}/.test(MESSAGES[code].en) ? { code, args: {} } : recognise(code, text);
    if (!found) return text;
  }
  if (render(found.code, found.args, "en") !== text) return text;
  return render(found.code, found.args, "de") ?? text;
}
// obj[name] in the chosen language, with its code and parameters from obj[name + "_code" / "_args"].
function msgOf(obj, name) { return obj ? msg(obj[`${name}_code`], obj[`${name}_args`], obj[name]) : ""; }
// A list of sentences with their codes (the {name}_codes field beside it).
function msgList(list, codes) { return (list || []).map((text, i) => (codes && codes[i] ? msg(codes[i].code, codes[i].args, text) : text)); }
// A code word of a tool (validate kinds, chain status ...) in German, else the code itself.
function codeWord(prefix, value) {
  const entry = LANG === "de" && value ? MESSAGES[`${prefix}${value}`] : null;
  return entry ? entry.de : value;
}

function setLang(lang) {
  LANG = lang === "de" ? "de" : "en";
  try { localStorage.setItem("aqt-ui-lang", LANG); } catch (e) { /* not remembered; works for this page */ }
  shellLabels();
  renderTopbar();
  route();
}

// Navigation by tasks: four areas and Settings. The tools behind them are not menu entries: their open
// points are cases (Needs you), their history is under Evidence. Case pages (/case/<id>) and change
// pages (/change/<project>/<plan>) have no inspector. The first-run setup is /welcome.
const AREAS = [
  { id: "home", path: "/", label: "Needs you" },
  { id: "changes", path: "/changes", label: "Changes", inspector: true },
  { id: "projects", path: "/projects", label: "Projects" },
  { id: "evidence", path: "/evidence", label: "Evidence" },
];
const SETTINGS = { id: "settings", path: "/settings", label: "Settings" };
const WELCOME = { id: "welcome", path: "/welcome", label: "Set up AQT" };
// Evidence: the records of each tool, one section each (/evidence/<id>).
const EVIDENCE = [
  { id: "trail", label: "Audit trail", tip: "trail", inspector: true },
  { id: "signatures", label: "Signatures", inspector: true },
  { id: "quarantine", label: "Held pages", tip: "quarantine", inspector: true },
  { id: "capa", label: "Deviations and CAPA", tip: "capa", inspector: true },
  { id: "qualifications", label: "Qualifications", tip: "qualification", inspector: true },
  { id: "export", label: "Export for auditors" },
];
// The views of 0.2 and where they are now: old bookmarks and links keep working.
const MOVED = { "/health": "/settings", "/trail": "/evidence/trail", "/quarantine": "/evidence/quarantine",
  "/signatures": "/evidence/signatures", "/capa": "/evidence/capa", "/qualifications": "/evidence/qualifications",
  "/evidence": "/evidence/trail" };
// Where a "Needs you" entry comes from, in words.
const VIEW_WORDS = { trail: "Audit trail", quarantine: "Held pages", changes: "Changes", capa: "CAPA", qualifications: "Qualifications" };
const S = { csrf: "", mode: null, overview: null, view: "home", installed: {}, install: {}, setup: null };
// the command that adds a package to this installation (the server knows how it was installed)
function installOf(pkg) { return S.install[pkg] || `pip install ${pkg}`; }
const TEXT_ATTRS = new Set(["title", "aria-label", "placeholder"]);
const $ = (id) => document.getElementById(id);

// ---- DOM helper: text and attributes only ---------------------------------------------------
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") el.className = value;
    else if (key === "text") el.textContent = vis(value);
    else if (key.startsWith("on") && typeof value === "function") el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, value === true ? "" : TEXT_ATTRS.has(key) ? vis(value) : String(value));
  }
  append(el, children);
  return el;
}
function append(el, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.appendChild(child instanceof Node ? child : document.createTextNode(vis(child)));
  }
  return el;
}
// Native Element.append() would turn null into the text "null"; put() skips empty children.
function put(el, ...children) { return append(el, children); }
function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }
function announce(text) { const live = $("live"); clear(live); setTimeout(() => { live.textContent = vis(text); }, 30); }

// ---- formatting --------------------------------------------------------------------------------
function fmtTime(iso) {
  if (!iso) return "–";
  const d = new Date(iso);
  if (isNaN(d)) return String(iso);
  const date = d.toLocaleDateString("sv-SE");
  const time = d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
  const tz = new Intl.DateTimeFormat("en-GB", { timeZoneName: "short" }).formatToParts(d).find((p) => p.type === "timeZoneName");
  return `${date} ${time} ${tz ? tz.value : ""}`.trim();
}
function ago(iso) {
  if (!iso) return t("never");
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (isNaN(s)) return String(iso);
  if (s < 90) return t("just now");
  if (s < 5400) return t("{n} min ago", { n: Math.round(s / 60) });
  if (s < 172800) return t("{n} h ago", { n: Math.round(s / 3600) });
  return t("{n} days ago", { n: Math.round(s / 86400) });
}
function short(hash, n = 12) {
  if (!hash) return "–";
  const value = String(hash).replace(/^sha256:/, "");
  return value.length > n ? value.slice(0, n) + "…" : value;
}
function num(n) { return n === null || n === undefined ? "–" : Number(n).toLocaleString(LANG === "de" ? "de-DE" : "en-US"); }
// Test counts of a receipt in words: "2 of 2 passed (pytest)".
function countsText(c) {
  if (!c || typeof c !== "object") return "";
  const parts = [];
  if (c.total !== undefined && c.passed !== undefined) parts.push(t("{passed} of {total} passed", c));
  else if (c.passed !== undefined) parts.push(t("{passed} passed", c));
  if (c.failed) parts.push(t("{n} failed", { n: c.failed }));
  if (c.errors) parts.push(t("{n} errors", { n: c.errors }));
  if (c.skipped) parts.push(t("{n} skipped", { n: c.skipped }));
  return parts.join(", ") + (c.source ? ` (${c.source})` : "");
}

const ICON = { pass: "✓", warn: "!", fail: "✕", info: "●", neutral: "○" };
function st(kind, word) {
  return h("span", { class: `st ${kind}` }, h("span", { class: "ico", "aria-hidden": "true", text: ICON[kind] || "○" }), word);
}
const STATUS_KIND = {
  pass: "pass", intact: "pass", valid: "pass", go: "pass", released: "pass", effective: "pass", succeeded: "pass",
  approved: "pass", running: "pass", closed: "neutral",
  warn: "warn", warned: "warn", expiring: "warn", manual_verify_required: "warn", prepared: "warn", pending: "info",
  unverified: "info", problems: "warn", missing: "warn", unknown: "warn", expired: "fail", open: "warn", changed: "fail",
  fail: "fail", broken: "fail", held: "fail", threat: "fail", "no-go": "fail", invalid: "fail", invalidated: "fail",
  revoked: "fail", "unknown-signer": "warn", "unknown-key": "warn", unbound: "warn", unconfirmed: "warn", triggered: "fail", rejected: "neutral", "not-effective": "fail",
  failed: "fail", stale: "warn", ok: "pass", fresh: "pass", signed: "pass", "signed-verified": "pass", implemented: "info",
  "awaiting-approval": "warn", unsigned: "warn", planned: "info", cancelled: "neutral", critical: "fail", major: "warn", minor: "info",
};
// A refusal code in words (the server sends the English words), or "" for a code without words.
function refusalWords(code, english) {
  return (LANG === "de" && (REFUSALS_DE[code] || (MESSAGES[`refusal.${code}`] || {}).de)) || english || "";
}
// A status word: its colour comes from the English key, the word shown from the chosen language.
function stWord(word, label) {
  const key = String(word || "").toLowerCase();
  return st(STATUS_KIND[key] || "neutral", label || t(String(word || "–")));
}
function hashButton(value, n) {
  if (!value) return h("span", { class: "muted", text: "–" });
  return h("button", {
    class: "hash", type: "button", title: `${value} (${t("click to copy")})`, "aria-label": `hash ${value}, ${t("click to copy")}`,
    onclick: () => { navigator.clipboard?.writeText(String(value)).then(() => announce(t("Copied")), () => {}); },
  }, short(value, n));
}
function kv(pairs) {
  return h("dl", { class: "kv" }, pairs.filter(Boolean).map(([k, v]) => [h("dt", { text: k }), h("dd", {}, v ?? "–")]));
}
function section(title, ...children) { return h("section", { class: "section" }, h("h2", {}, title), children); }
function inspSection(title, ...children) { return h("section", { class: "insp-section" }, title ? h("h3", { text: title }) : null, children); }
function empty(title, text) { return h("div", { class: "empty" }, h("strong", { text: title }), text ? h("span", { text }) : null); }
function errorBox(error) {
  const box = h("div", { class: "error-box", role: "alert" }, (error.data && error.data.message_code ? msgOf(error.data, "message") : error.message) || String(error));
  if (error.data && error.data.install) put(box, h("div", { class: "small" }, t("Install:"), " ", h("code", { text: error.data.install })));
  return box;
}
function tabs(items, current, onPick) {
  return h("div", { class: "tabs", role: "tablist" }, items.map(([id, label]) =>
    h("button", { role: "tab", "aria-selected": current === id ? "true" : "false", type: "button", text: label, onclick: () => onPick(id) })));
}

// ---- API ----------------------------------------------------------------------------------------
// Two ways to the same API. In the desktop app (aqt-desktop) there is no web server: the page hands each
// request to the app, which passes it to the AQT core over stdin/stdout and returns the core's answer
// (status, content type and body), so no session key or cookie is needed. In a browser the page asks the
// aqt ui server with fetch.
const APP = window.__TAURI__ ? window.__TAURI__.core : null;
async function core(method, path, body) {
  try {   // /api/session: what the core said when it started (its ready event)
    if (path === "/api/session") return { status: 200, body: await APP.invoke("core_session") };
    return await APP.invoke("core_request", { method, path, body: body === undefined ? null : body });
  } catch (reason) {
    throw new Error(t("The AQT core does not answer: {reason}", { reason: String(reason) }));
  }
}
function answered(answer) { return answer.status >= 200 && answer.status < 300; }
// The session key: handed over once by the login page (a meta tag), then kept in this tab's
// sessionStorage, which other ports of 127.0.0.1 cannot read. Every API request carries it.
function sessionKey() {
  const meta = document.querySelector('meta[name="aqt-csrf"]');
  if (meta && meta.content) {
    const key = meta.content;
    meta.remove();
    try { sessionStorage.setItem("aqt-ui-key", key); } catch (e) { /* storage blocked: kept for this page only */ }
    if (location.pathname === "/login") history.replaceState(null, "", "/");
    return key;
  }
  try { return sessionStorage.getItem("aqt-ui-key") || ""; } catch (e) { return ""; }
}
async function api(path) {
  if (APP) {
    const answer = await core("GET", path);
    const data = answer.body ?? { message: answer.text || `HTTP ${answer.status}` };
    if (!answered(answer)) throw Object.assign(new Error(data.message || `HTTP ${answer.status}`), { status: answer.status, data });
    return data;
  }
  const response = await fetch(path, { headers: { Accept: "application/json", "X-AQT-CSRF": S.csrf }, credentials: "same-origin" });
  const data = await response.json().catch(() => ({ message: `HTTP ${response.status}` }));
  if (!response.ok) throw Object.assign(new Error(data.message || `HTTP ${response.status}`), { status: response.status, data });
  return data;
}
async function post(path, body) {
  if (APP) {
    const answer = await core("POST", path, body || {});
    return { status: answer.status, data: answer.body ?? { ok: false, message: answer.text || `HTTP ${answer.status}` } };
  }
  const response = await fetch(path, {
    method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-AQT-CSRF": S.csrf, Accept: "application/json" },
    body: JSON.stringify(body || {}),
  });
  const data = await response.json().catch(() => ({ ok: false, message: `HTTP ${response.status}` }));
  return { status: response.status, data };
}
// A file from the API, saved through a blob link (a plain link would lack the session key); in the app,
// through the system's save dialog.
async function download(path, fallbackName) {
  if (APP) {
    const answer = await core("GET", path);
    if (!answered(answer)) throw new Error((answer.body && answer.body.message) || answer.text || `HTTP ${answer.status}`);
    const text = answer.text ?? (answer.base64 === undefined ? JSON.stringify(answer.body, null, 2) : null);
    try {
      await APP.invoke("save_file", { name: answer.filename || fallbackName, text, base64: answer.base64 ?? null });
    } catch (reason) { throw new Error(String(reason)); }
    return;
  }
  const response = await fetch(path, { headers: { "X-AQT-CSRF": S.csrf }, credentials: "same-origin" });
  if (!response.ok) {
    const data = await response.json().catch(() => ({ message: `HTTP ${response.status}` }));
    throw new Error(data.message || `HTTP ${response.status}`);
  }
  const named = /filename="([^"]+)"/.exec(response.headers.get("Content-Disposition") || "");
  const url = URL.createObjectURL(await response.blob());
  const link = h("a", { href: url, download: (named && named[1]) || fallbackName, hidden: true });
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}
function downloadButton(path, name, label, cls) {
  const out = h("span", { class: "small", "aria-live": "polite" });
  const button = h("button", { class: cls || "btn small", type: "button", text: label, onclick: async () => {
    clear(out);
    button.disabled = true;
    try { await download(path, name); } catch (error) { put(out, " ", h("span", { class: "result refused", text: String(error.message || error) })); }
    finally { button.disabled = false; }
  } });
  return h("span", {}, button, out);
}

// ---- shell: rail, top bar, inspector --------------------------------------------------------------
function shellLabels() {
  document.documentElement.lang = LANG;
  $("skip").textContent = vis(t("Skip to content"));
  $("menu-btn").textContent = vis(t("Menu"));
  $("refresh").textContent = vis(t("Refresh"));
  $("brand-sub").textContent = vis(t("quality desk, this machine only"));
  $("rail").setAttribute("aria-label", t("Areas"));
  $("status-pill").setAttribute("aria-label", t("Status"));
  inspector().setAttribute("aria-label", t("Details"));
  const lang = $("lang");
  lang.value = LANG;
  lang.setAttribute("aria-label", t("Language"));
}

function navLink(area, count, hot) {
  return h("li", {}, h("a", {
    href: area.path, "aria-current": S.view === area.id ? "page" : null,
    onclick: (event) => { event.preventDefault(); go(area.path); $("rail").classList.remove("open"); $("menu-btn").setAttribute("aria-expanded", "false"); },
  }, h("span", { class: "label", text: t(area.label) }),
     count ? h("span", { class: `count ${hot ? "hot" : ""}`, "aria-label": t("{n} need attention", { n: count }), text: count }) : null));
}
function renderRail() {
  const nav = clear($("nav"));
  const counts = (S.overview && S.overview.counts) || {};
  for (const area of AREAS) {
    const n = area.id === "home" ? counts.overview : area.id === "changes" ? counts.changes : 0;
    put(nav, navLink(area, n || 0, true));
  }
  // Settings at the foot of the rail; a mark when the setup has a problem
  const problems = setupProblems().length;
  put(clear($("nav-settings")), navLink(SETTINGS, problems, problems > 0));
  const foot = clear($("railfoot"));
  if (S.overview) put(foot, t("Checked {time}", { time: fmtTime(S.overview.checked_at) }));
}

// The trail status line of the top bar and the home page: [kind, words].
function trailLine(status) {
  let kind = "info", text;
  if (status.state === "intact") {
    kind = "pass";
    text = t("Trail intact · seq {seq} · {anchor}", { seq: num(status.head_seq), anchor: status.last_anchor ? t("anchored {ago}", { ago: ago(status.last_anchor) }) : t("not anchored") });
  } else if (status.state === "broken") { kind = "fail"; text = t("Broken from seq {seq}", { seq: num(status.check && status.check.first_bad_seq) }); }
  else if (status.state === "changed") { kind = "fail"; text = t("Trail changed since the last check"); }
  else if (status.state === "problems") { kind = "warn"; text = t("Trail: verification found problems"); }
  else if (status.state === "missing") { kind = "warn"; text = t("No trail yet"); }
  else text = status.verifying ? t("Trail: verifying…") : t("Trail: not verified yet");
  if (status.state !== "missing" && status.writer && !status.writer.running) { text += ` · ${t("writer down")}`; if (kind === "pass") kind = "warn"; }
  if (status.writer && status.writer.spooled) { text += ` · ${t("{n} spooled", { n: status.writer.spooled })}`; if (kind === "pass") kind = "warn"; }
  if (status.test_mode) { text += ` · ${t("TEST MODE")}`; if (kind === "pass") kind = "warn"; }
  return [kind, text];
}
function renderTopbar() {
  const broken = $("broken");
  broken.hidden = true;
  const status = S.overview && S.overview.status;
  if (status) {
    if (status.state === "broken") {
      broken.hidden = false;
      put(clear(broken), t("Trail broken from seq {seq}: {reason}", { seq: num(status.check.first_bad_seq), reason: msgOf(status.check, "reason") }));
    } else if (status.state === "changed") {
      broken.hidden = false;
      put(clear(broken), t("Trail changed since the last check: {reason}. Verify it again.", { reason: msgOf(status, "changed") }));
    }
    writerBar(status);
  }
  renderPill();
  const badge = clear($("mode-badge"));
  const ribbon = clear($("ribbon"));
  if (S.mode) {
    badge.hidden = S.mode.decisions;
    badge.className = "badge off";
    put(badge, t("Read-only"));
    ribbon.hidden = S.mode.decisions;
    if (!S.mode.decisions) put(ribbon, h("strong", { text: `${t("Read-only")}. ` }), S.mode.reason);
  }
}

// ---- the status pill: "Everything in order", or the most important problem with its one fix ---------
// Setup checks that need a look (from GET /api/setup; aqt status's own list).
function setupProblems() {
  const rows = (S.setup && S.setup.checks) || [];
  return rows.filter((c) => c.result === "fail").concat(rows.filter((c) => c.result === "warn" && c.id !== "egress"));
}
function pillState() {
  const ov = S.overview;
  if (!ov) return { kind: "info", text: t("Checking…") };
  const setup = ov.setup || {};
  const status = ov.status || {};
  if (setup.needed) return { kind: "warn", text: t("Setup not finished"), fix: t("Continue setup"), path: "/welcome" };
  if (["broken", "changed", "problems"].includes(status.state)) return { kind: "fail", text: t("The audit trail does not verify"), fix: t("See why"), path: `/case/trail:trail_${status.state}` };
  if (status.state !== "missing" && status.writer && !status.writer.running) return { kind: "fail", text: t("Trail writer stopped"), fix: t("Restart"), apply: "writer", path: "/settings" };
  if (status.writer && status.writer.spooled) return { kind: "warn", text: t("{n} record(s) wait outside the trail", { n: status.writer.spooled }), fix: t("Move them in"), apply: "spool", path: "/settings" };
  const problem = setupProblems()[0];
  if (problem) return { kind: problem.result === "fail" ? "fail" : "warn", text: `${t(CHECK_WORDS[problem.id] || problem.id)}: ${problem.result === "fail" ? t("needs a fix") : t("needs a look")}`,
    fix: t("Fix"), apply: problem.can_apply ? problem.id : null, path: `/settings#check-${problem.id}` };
  if (status.test_mode) return { kind: "warn", text: t("Test mode is on"), fix: t("See why"), path: "/case/trail:test_mode" };
  return { kind: "pass", text: t("Everything in order") };
}
function renderPill() {
  const box = clear($("status-pill"));
  const p = pillState();
  put(box, h("span", { class: `pill ${p.kind}` }, h("span", { "aria-hidden": "true", text: ICON[p.kind] }), p.text));
  if (p.fix) {
    const button = h("button", { class: "btn small pill-fix", type: "button", text: p.fix });
    button.addEventListener("click", async () => {
      if (p.apply && S.mode && S.mode.decisions) { button.disabled = true; await applyStep(p.apply); button.disabled = false; }
      else go(p.path);
    });
    put(box, button);
  }
}
// Apply one setup step (aqt setup's own) and show what happened; returns the answer.
async function applyStep(id) {
  const { status, data } = await post("/api/setup/apply", { check: id });
  const ok = status === 200 && data.ok;
  announce(ok ? t("Done: {what}", { what: t(CHECK_WORDS[id] || id) }) : `${t("Not done:")} ${data.error || (data.check && data.check.explanation) || data.message || ""}`);
  await Promise.all([refresh().catch(() => null), loadSetup().catch(() => null)]);
  if (!ok && location.pathname !== "/settings") go(`/settings#check-${id}`);
  else if (S.view === "settings") route();
  return { status, data };
}
// The setup checks (aqt status). Kept in S.setup for the pill and Settings.
async function loadSetup() {
  try { S.setup = await api("/api/setup"); } catch (error) { S.setup = null; throw error; }
  renderRail();
  renderTopbar();               // the pill and the writer banner use the checks
  return S.setup;
}

// Writer down: a banner on every page with the one fix (records wait in the spool until it runs again).
function writerBar(status) {
  const bar = $("writer");
  if (!bar) return;
  const down = status && status.state !== "missing" && status.writer && !status.writer.running;
  bar.hidden = !down;
  if (!down) return;
  const service = S.setup && S.setup.service;
  put(clear(bar), h("strong", { text: `${t("The trail writer is not running.")} ` }), t("Records wait in a spool until it runs again."), " ",
    service && S.mode && S.mode.decisions ? h("button", { class: "btn small", type: "button", text: t("Restart the writer"), onclick: (e) => { e.target.disabled = true; applyStep("writer"); } })
      : [t("Start it in a terminal:"), " ", h("code", { text: "aqt-trail serve" })]);
}

const inspector = () => $("inspector");
function setInspector(...children) {
  const el = clear(inspector());
  el.append(h("div", { class: "sheet-head" }, h("strong", { text: t("Details") }),
    h("button", { class: "btn small", type: "button", onclick: closeSheet, text: t("Close") })));
  append(el, children);
  el.classList.remove("closed");
  el.scrollTop = 0;
}
function placeholder(text) {
  const el = clear(inspector());
  el.append(h("div", { class: "placeholder", text }));
  el.classList.add("closed");
}
function closeSheet() { inspector().classList.add("closed"); }

// ---- keyboard: j/k move through the queue, Enter opens a case, n goes to the next case, Escape
// closes the sheet. Letters never act while a field has the focus.
function typing(el) { return !!el && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName)); }
function queueButtons() { return [...document.querySelectorAll(".queue button.case-line")]; }
function moveQueue(step) {
  const list = queueButtons();
  if (!list.length) return false;
  const at = list.indexOf(document.activeElement);
  const next = list[at < 0 ? (step > 0 ? 0 : list.length - 1) : Math.min(list.length - 1, Math.max(0, at + step))];
  next.focus();
  next.scrollIntoView({ block: "nearest" });
  return true;
}
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") { closeSheet(); return; }
  if (event.defaultPrevented || event.altKey || event.ctrlKey || event.metaKey || typing(event.target) || document.querySelector("dialog[open]")) return;
  if ((event.key === "j" || event.key === "k") && S.view === "home" && !S.page) {
    if (moveQueue(event.key === "j" ? 1 : -1)) event.preventDefault();
  } else if (event.key === "n" && (S.view === "home" || S.caseId)) {
    event.preventDefault();
    nextCase();
  }
});

function selectRow(tbody, row) {
  for (const other of tbody.querySelectorAll("tr.row")) other.setAttribute("aria-selected", other === row ? "true" : "false");
}
function rowKeys(event) {
  const row = event.currentTarget;
  if (event.key === "Enter" || event.key === " ") { event.preventDefault(); row.click(); }
  else if (event.key === "ArrowDown" && row.nextElementSibling) { event.preventDefault(); row.nextElementSibling.focus(); }
  else if (event.key === "ArrowUp" && row.previousElementSibling) { event.preventDefault(); row.previousElementSibling.focus(); }
}
function table(headers, rows, onOpen, rowClass) {
  const tbody = h("tbody");
  for (const item of rows) {
    const tr = h("tr", { class: `row ${rowClass ? rowClass(item.data) : ""}`, tabindex: "0", "aria-selected": "false", onkeydown: rowKeys });
    tr.addEventListener("click", () => { selectRow(tbody, tr); onOpen(item.data); });
    for (const cell of item.cells) put(tr, cell instanceof Node && cell.tagName === "TD" ? cell : h("td", {}, cell));
    put(tbody, tr);
  }
  const thead = h("thead", {}, h("tr", {}, headers.map((x) => (typeof x === "string" ? h("th", { scope: "col", text: x }) : x))));
  return { table: h("table", { class: "list" }, thead, tbody), tbody };
}
const th = (text, cls) => h("th", { scope: "col", class: cls, text });
// A table to read, without row selection.
function plainTable(headers, rows) {
  return h("table", { class: "list plain" }, h("thead", {}, h("tr", {}, headers.map((x) => h("th", { scope: "col", text: x })))),
    h("tbody", {}, rows.map((cells) => h("tr", {}, cells.map((cell) => (cell instanceof Node && cell.tagName === "TD" ? cell : h("td", {}, cell)))))));
}

// ---- glossary: the everyday word first, the GMP term beside it, two sentences when the pointer rests ----
function gloss(key) {
  const entry = GLOSSARY[key];
  if (!entry) return null;
  return (LANG === "de" && entry.de) || entry.en;
}
let termCount = 0;
// The noun of a term (e.g. "Release" / "Freigabe") with its explanation as a tooltip and as the description a
// screen reader reads on focus.
function termNode(key, text) {
  const g = gloss(key);
  if (!g) return h("span", { text: text || key });
  const id = `term-${++termCount}`;
  return h("span", { class: "term-wrap" }, h("span", { class: "term", tabindex: "0", "data-tip": g.tip, "aria-describedby": id, text: text || g.noun }),
    h("span", { class: "sr-only", id, text: g.tip }));
}
// A word for a list or a heading: "Release for use (release)", with the tooltip.
function termLabel(key) {
  const g = gloss(key);
  if (!g) return key;
  return h("span", {}, termNode(key, g.word), g.term.toLowerCase() !== g.word.toLowerCase() ? h("span", { class: "gmp", text: ` (${g.term})` }) : null);
}
// A value as a shell word: plain when it is safe, else in single quotes.
function sq(value) {
  const text = String(value ?? "");
  return /^[A-Za-z0-9._:/@%+=,-]+$/.test(text) ? text : `'${text.replace(/'/g, "'\\''")}'`;
}

// ---- decision panel ----------------------------------------------------------------------------------
// One component for every human-only action: the choices, each with the one sentence of what it does, and
// a button with a verb and an object. The button opens the signing sheet, the same for every signature.
// command(action) gives the equivalent aqt command ("Show as command"), where one exists.
// onDone(result, action) replaces the default reload after a recorded decision (case pages).
let panelCount = 0;
function decisionPanel({ actions, subject, signers, submit, note, fields, noSigners, title, onDone, command }) {
  const box = h("section", { class: "decision", "aria-label": title || t("Decision") });
  put(box, h("h3", { text: title || t("Decision") }));
  if (!S.mode || !S.mode.decisions) {
    put(box, h("div", { class: "off" }, h("strong", { text: `${t("Read-only")}. ` }), S.mode ? S.mode.reason : ""));
    return box;
  }
  if (!signers || !signers.length) {
    put(box, h("div", { class: "off" }, noSigners || [t("No signing identity is set up yet."), " ", link(t("Set up your identity"), "/welcome")]));
    return box;
  }
  let chosen = actions[0];
  const button = h("button", { class: `btn ${chosen.danger ? "danger" : "primary"}`, type: "button", text: chosen.button });
  const shown = h("div", { class: "as-command", hidden: true });
  const toggle = command ? h("button", { class: "btn small ghost", type: "button", "aria-expanded": "false", text: t("Show as command") }) : null;
  const showCommand = () => {
    if (!command || shown.hidden) return;
    const text = command(chosen);
    put(clear(shown), text ? [h("p", { class: "small muted", text: t("The same decision in a terminal; it asks for your passphrase there.") }), commandLine(text)]
      : h("p", { class: "small muted", text: t("No aqt command does exactly this.") }));
  };
  if (toggle) toggle.addEventListener("click", () => {
    shown.hidden = !shown.hidden;
    toggle.setAttribute("aria-expanded", String(!shown.hidden));
    toggle.textContent = vis(shown.hidden ? t("Show as command") : t("Hide the command"));
    showCommand();
  });
  const consequence = h("p", { class: "consequence" });
  const sayConsequence = () => put(clear(consequence), title === chosen.label ? null : h("strong", { text: `${chosen.label}: ` }), chosen.consequence || "");
  const pick = (a) => {
    chosen = a;
    button.textContent = vis(a.button); button.className = `btn ${a.danger ? "danger" : "primary"}`;
    sayConsequence();
    showCommand();
  };
  const worded = actions.some((a) => a.consequence);
  const choice = worded && actions.length > 1 ? h("div", { class: "choice-list", role: "radiogroup", "aria-label": t("Decision") },
    actions.map((a) => {
      const b = h("button", { class: `choice${a.danger ? " danger" : ""}`, type: "button", role: "radio", "aria-checked": a === chosen ? "true" : "false" },
        h("strong", { text: a.label }), a.consequence ? h("span", { text: a.consequence }) : null);
      b.addEventListener("click", () => {
        for (const other of choice.children) other.setAttribute("aria-checked", String(other === b));
        pick(a);
      });
      return b;
    }))
    : worded ? (sayConsequence(), consequence)
    : actions.length > 1 ? h("div", { class: "chips", role: "radiogroup", "aria-label": t("Decision") },
    actions.map((a) => {
      const b = h("button", { class: "chip-btn", type: "button", role: "radio", "aria-checked": a === chosen ? "true" : "false", "aria-pressed": a === chosen ? "true" : "false", text: a.label });
      b.addEventListener("click", () => {
        for (const other of choice.children) { const on = other === b; other.setAttribute("aria-checked", String(on)); other.setAttribute("aria-pressed", String(on)); }
        pick(a);
      });
      return b;
    })) : null;
  const result = h("div", { "aria-live": "polite" });
  const row = h("div", { class: "actions" }, button, toggle);
  button.addEventListener("click", async () => {
    clear(result);
    const answer = await signSheet({ action: chosen, subject, signers, submit, note });
    if (!answer) { button.focus(); return; }
    const { data } = answer;
    const text = `${t("Recorded as {record}", { record: data.record_id || "a record" })}${data.time ? " · " + fmtTime(data.time) : ""}. ${msgOf(data, "message")}`;
    put(result, h("div", { class: "result ok", role: "status", text }));
    announce(text);
    row.remove();                       // the decision is made; show what was recorded
    shown.remove();
    if (choice) choice.remove();
    if (fields) fields.remove();
    if (onDone) onDone(data, chosen);
    else setTimeout(async () => { await refresh(); route(true); }, 600);
    result.scrollIntoView({ block: "nearest" });
  });
  put(box, choice, fields || null, note ? h("p", { class: "small muted", text: note }) : null, row, shown, result);
  return box;
}

// ---- the signing sheet: one dialog for every signature -------------------------------------------------
// It says in one sentence what is signed (the meaning, the subject and a short summary), shows the ID and
// asks for a reason and the passphrase. "What exactly is signed?" opens the content and its hash. A wrong
// passphrase leaves the sheet open with a calm message; the failed attempt is recorded as before. Resolves
// with the answer of a recorded decision, or null when the person cancels.
function signSheet({ action, subject, signers, submit, note }) {
  return new Promise((resolve) => {
    const n = ++panelCount;
    const label = subject.label instanceof Node ? subject.label.textContent : String(subject.label ?? "");
    const select = signers.length > 1 ? h("select", { id: `ss-signer-${n}` }, signers.map((x) => h("option", { value: x.id, text: `${x.name || x.id} (${x.role || t("no role")})` }))) : null;
    const who = () => signers.find((x) => x.id === (select ? select.value : "")) || signers[0];
    const reason = h("textarea", { id: `ss-reason-${n}`, required: true, "aria-required": "true", maxlength: "2000", rows: "3" });
    const pass = h("input", { id: `ss-pass-${n}`, type: "password", autocomplete: "off", spellcheck: "false", "aria-required": "true" });
    const message = h("div", { "aria-live": "polite" });
    const sign = h("button", { class: `btn ${action.danger ? "danger" : "primary"}`, type: "button", text: action.button });
    const cancel = h("button", { class: "btn ghost", type: "button", text: t("Cancel") });
    const idLine = h("p", { class: "id-line" });
    const signerCell = h("dd");
    const reasonCell = h("dd", { class: "keep-lines" });
    const fill = () => {
      const x = who();
      put(clear(idLine), h("code", { text: x.id }), " ", h("span", { class: "muted", text: `${x.name || "?"} · ${x.role || t("no role")}` }));
      put(clear(signerCell), `${x.name || "?"} · ${x.id} · ${x.role || t("no role")}`);
      put(clear(reasonCell), reason.value.trim() || "–");
    };
    if (select) select.addEventListener("change", fill);
    reason.addEventListener("input", fill);
    fill();
    const g = gloss(action.meaning);
    const dlg = h("dialog", { class: "sign-sheet", "aria-labelledby": `ss-title-${n}`, "aria-describedby": `ss-what-${n}` },
      h("h2", { id: `ss-title-${n}`, text: action.label }),
      h("p", { class: "sign-sentence", id: `ss-what-${n}` }, h("span", { class: "lead", text: t("You sign:") }), " ",
        g ? termNode(action.meaning) : h("strong", { text: t(action.meaning) }), " ", t("of"), " ", label, subject.summary ? ` (${subject.summary})` : "", "."),
      action.consequence ? h("p", { class: "small muted", text: action.consequence }) : null,
      h("div", { class: "field" }, select ? [h("label", { for: select.id, text: t("Who signs") }), select] : [h("span", { class: "label", text: t("Your ID") }), idLine]),
      h("div", { class: "field" }, h("label", { for: reason.id, text: t("Reason (recorded with your signature)") }), reason),
      h("div", { class: "field" }, h("label", { for: pass.id, text: t("Passphrase (used once, never stored)") }), pass),
      h("details", { class: "what-signed" }, h("summary", { text: t("What exactly is signed?") }),
        h("dl", { class: "manifest" },
          h("dt", { text: t("Signer") }), signerCell,
          h("dt", { text: t("Meaning") }), h("dd", {}, g ? `${g.noun} · ` : "", h("code", { text: action.meaning })),
          h("dt", { text: t("Subject") }), h("dd", { text: label }),
          h("dt", { text: t("Content hash") }), h("dd", {}, subject.hash ? h("code", { class: "full-hash", text: subject.hash }) : t("none: the record itself is signed")),
          h("dt", { text: t("Reason") }), reasonCell,
          h("dt", { text: t("Time") }), h("dd", { text: t("when you press the button, in your time zone") })),
        note ? h("p", { class: "small muted", text: note }) : null),
      message,
      h("div", { class: "actions" }, sign, cancel));
    let done = false;
    const finish = (answer) => {
      if (done) return;
      done = true;
      pass.value = "";
      if (dlg.open) dlg.close();
      dlg.remove();
      resolve(answer);
    };
    const say = (kind, text) => { put(clear(message), h("div", { class: `result ${kind}`, role: "status", text })); };
    sign.addEventListener("click", async () => {
      if (!reason.value.trim()) { say("stale", t("A reason is required.")); reason.focus(); return; }
      if (!pass.value) { say("stale", t("Enter your passphrase.")); pass.focus(); return; }
      sign.disabled = true;
      const passphrase = pass.value;
      pass.value = "";
      try {
        const { status, data } = await submit(action, { reason: reason.value.trim(), passphrase, signer_id: who().id });
        if (data.ok) { finish({ status, data }); return; }
        const said = msgOf(data, "message");
        if (data.reason_code === "auth_failed") say("stale", t("The passphrase did not unlock your key. Type it again; the attempt was recorded."));
        else if (status === 409) say("stale", `${t("Not signed:")} ${said}`);
        else say("refused", `${t("Refused:")} ${refusalWords(data.reason_code, data.reason_text) ? refusalWords(data.reason_code, data.reason_text) + ". " : ""}${said}${data.record_id ? ` (${t("refusal recorded as {record}", { record: data.record_id })})` : ""}`);
        pass.focus();
      } catch (error) {
        say("refused", String(error.message || error));
      } finally {
        sign.disabled = false;
      }
    });
    pass.addEventListener("keydown", (event) => { if (event.key === "Enter") { event.preventDefault(); sign.click(); } });
    cancel.addEventListener("click", () => finish(null));
    dlg.addEventListener("cancel", (event) => { event.preventDefault(); finish(null); });
    document.body.appendChild(dlg);
    dlg.showModal();
    reason.focus();
  });
}

// ---- router ----------------------------------------------------------------------------------------
function go(path, replace) {
  if (replace) history.replaceState(null, "", path); else history.pushState(null, "", path);
  route();
}
window.addEventListener("popstate", () => route());
function query() { return new URLSearchParams(location.search); }
function setQuery(params) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v) q.set(k, v);
  const text = q.toString();
  history.replaceState(null, "", location.pathname + (text ? "?" + text : ""));
}

function setTitle(text) {
  $("title").textContent = vis(text);
  document.title = vis(`${text} · ${t("AQT quality desk")}`);
}
async function route(keepInspector) {
  const moved = MOVED[location.pathname];
  if (moved) history.replaceState(null, "", moved + location.search + location.hash);
  const path = location.pathname;
  const page = path.startsWith("/case/") ? "case" : path.startsWith("/change/") ? "change" : null;
  const part = path.startsWith("/evidence/") ? EVIDENCE.find((x) => x.id === path.slice("/evidence/".length)) : null;
  const area = page === "case" ? AREAS[0] : page === "change" ? AREAS[1] : part ? AREAS[3]
    : path === WELCOME.path ? WELCOME : path === SETTINGS.path ? SETTINGS : AREAS.find((v) => v.path === path) || AREAS[0];
  const changed = S.path !== path;
  S.view = area.id;
  S.page = page;
  S.path = path;
  if (page !== "case") S.caseId = null;
  setTitle(page === "change" ? t("Changes") : part ? `${t("Evidence")}: ${t(part.label)}` : t(area.label));
  const shell = document.querySelector(".shell");
  shell.classList.toggle("no-insp", !!page || !(part ? part.inspector : area.inspector));
  shell.classList.toggle("onboarding", area === WELCOME);
  renderRail();
  const main = clear($("main"));
  put(main, h("div", { class: "empty", text: t("Loading…") }));
  if (keepInspector !== true) placeholder(t("Select an item to see its details."));
  if (changed) { main.scrollTop = 0; window.scrollTo(0, 0); }
  try {
    await (page === "case" ? renderCase(main) : page === "change" ? renderChangeRoute(main) : part ? renderEvidence(main, part) : RENDER[area.id](main));
    if (page && changed && !location.hash) main.focus({ preventScroll: true });
    if (location.hash.startsWith("#check-")) document.getElementById(location.hash.slice(1))?.scrollIntoView({ block: "center" });
  } catch (error) {
    put(clear(main), part ? evidenceTabs(part) : null, errorBox(error));
  }
}

// ---- Home: the queue --------------------------------------------------------------------------------
const SEVERITY_KIND = { critical: "fail", high: "warn", medium: "info", low: "neutral" };
// Title and detail of a "Needs you" entry in the chosen language (English comes from the server).
function needText(item) {
  const de = LANG === "de" && NEEDS[item.key];
  if (!de) return [item.title, msgOf(item, "detail")];
  // Only enumerated words are translated (ALCOA++ attributes, validate kinds and triggers); ids, sources and
  // names are data and stay as they are.
  const word = (key, value) => (key === "kind" ? codeWord("validate.kind.", value)
    : key === "triggers" ? String(value).split(", ").map((x) => codeWord("validate.trigger.", x)).join(", ")
      : key === "attribute" ? t(String(value)) : typeof value === "number" ? num(value) : String(value));
  const fill = (text) => text.replace(/\{(\w+)\}/g, (all, key) => (item.args[key] === undefined ? all : word(key, item.args[key])));
  const detail = de[1] === null ? msgOf(item, "detail") : de[1] === "@reason" ? (REASONS_DE[item.args.reason_code] || item.detail) : fill(de[1]);
  return [fill(de[0]), detail];
}
// The desktop app hands each "queue" event of the core here and shows the system notifications in the words
// the page gives back in its language (show_notifications); without an answer it uses the core's English.
const NOTICE = { case_held: "Quarantine holds content from {source}", case_warned: "Quarantine warns about content from {source}" };
if (APP) window.aqtQueue = (seq, body) => {
  const cases = {};
  for (const item of body.new || []) {
    try { cases[item.id] = NOTICE[item.key] ? t(NOTICE[item.key], item.args) : needText(item)[0]; } catch (e) { /* the core's English */ }
  }
  const words = { cases, many: t("{n} new cases need you", { n: (body.new || []).length }), review: t("Review it in Agent Quality Toolkit"), show: t("Show the case") };
  APP.invoke("show_notifications", { seq, words }).catch(() => {});
};
// The page of a case: /case/<id> (the id is readable: "quarantine:Q7SEGGW", "plan:0:s01" ...).
function casePath(item) { return `/case/${encodeURIComponent(item.id).replace(/%3A/gi, ":")}`; }
// How long a case has been waiting ("waiting for 3 h"), or "" when its start is unknown.
function sinceText(item) {
  const moment = item.since ? new Date(item.since) : null;
  if (!moment || isNaN(moment) || moment.getTime() > Date.now() + 60000) return "";
  const s = Math.max(0, (Date.now() - moment.getTime()) / 1000);
  const length = s < 60 ? t("less than a minute") : s < 5400 ? t("{n} min", { n: Math.round(s / 60) })
    : s < 172800 ? t("{n} h", { n: Math.round(s / 3600) }) : t("{n} days", { n: Math.round(s / 86400) });
  return t("waiting for {length}", { length });
}
async function renderHome(main) {
  const data = S.overview || (await refresh());
  clear(main);
  const status = data.status;
  if (!data.needs.length) {
    const [kind, line] = trailLine(status);
    put(main, h("div", { class: "home" }, h("div", { class: "allclear" },
      h("strong", { text: t("Everything in order") }),
      h("p", { class: "trail-line" }, st(kind, line)),
      h("p", { class: "small muted", text: t("Last check {time}.", { time: fmtTime(data.checked_at) }) }),
      h("p", { class: "small" }, link(t("Health of the trail and the tools"), "/settings")))));
    return;
  }
  const queue = h("ol", { class: "queue", "aria-label": t("Needs you") });
  data.needs.forEach((item, index) => {
    const where = VIEW_WORDS[item.view];
    const [title, detail] = needText(item);
    const since = sinceText(item);
    const button = h("button", { class: "case-line", type: "button", "data-index": String(index) },
      st(SEVERITY_KIND[item.severity] || "neutral", t(item.severity)),
      h("span", { class: "what" }, h("strong", { text: title }), detail ? h("span", { text: detail }) : null),
      h("span", { class: "when" }, since ? h("span", { text: since }) : null,
        h("span", { class: "where", text: where ? t(where) : "" })));
    button.addEventListener("click", () => { S.queueAt = index; go(casePath(item)); });
    put(queue, h("li", {}, button));
  });
  const [kind, line] = trailLine(status);
  put(main, h("div", { class: "home" },
    h("p", { class: "home-intro small muted" }, t("Open cases: {n}, most urgent first.", { n: data.needs.length }), " ",
      h("span", { class: "keys", text: t("Keys: j and k move, Enter opens, n opens the next case.") })),
    queue,
    h("p", { class: "trail-line small" }, st(kind, line), " ",
      link(t("Settings"), "/settings"))));
  const list = queueButtons();
  if (S.queueAt !== undefined && list.length) list[Math.min(S.queueAt, list.length - 1)].focus({ preventScroll: false });
}

// ---- Health (in Settings): trail status, ALCOA++, tool health, refusals -----------------------------------
function healthSections(data) {
  const out = [];
  const main = { put: (...x) => out.push(...x) };
  const status = data.status;
  const check = status.check || {};
  const words = { intact: t("Intact"), broken: t("Broken from seq {seq}", { seq: num(check.first_bad_seq) }), problems: t("Problems found"), changed: t("Changed since the last check"),
    unverified: status.verifying ? t("Verifying…") : t("Not verified yet"), missing: t("No trail yet") };
  const verifyBtn = h("button", { class: "btn small", type: "button", text: status.verifying ? t("Verifying…") : t("Verify now"), disabled: status.verifying,
    onclick: async () => { verifyBtn.disabled = true; verifyBtn.textContent = vis(t("Verifying…")); await post("/api/trail/verify"); pollVerify(); } });
  const band = h("dl", { class: "band" },
    [[t("Trail"), stWord(status.state, words[status.state])], [t("Records"), num(status.records)], [t("Head seq"), num(status.head_seq)],
     [t("Last full check"), check.checked_at ? `${ago(check.checked_at)}${status.appended_since_check ? ` · ${t("{n} newer not yet verified", { n: num(status.appended_since_check) })}` : ""}` : t("not yet")],
     [t("Writer"), stWord(status.writer.running ? "running" : "missing", status.writer.running ? t("Running") : t("Not running"))],
     [t("Spool"), status.writer.spooled ? stWord("warn", t("{n} waiting", { n: status.writer.spooled })) : t("empty")],
     [t("Last anchor"), status.last_anchor ? ago(status.last_anchor) : t("none")],
     [t("Last review"), status.last_review ? ago(status.last_review) : t("none")],
     [t("Test mode"), status.test_mode ? stWord("warn", t("On")) : t("Off")],
     [t("Review parameters"), profileWord(status.review_profile)]]
      .map(([k, v]) => h("div", {}, h("dt", { text: k }), h("dd", {}, v))));
  main.put(section([`${t("Trail status")} `, h("span", { class: "hint" }, verifyBtn)], band,
    status.state === "broken" ? h("p", { class: "small", text: `${t("Verifier:")} ${msgOf(check, "summary")}` }) : null));

  const strip = h("div", { class: "alcoa" });
  if (data.alcoa.length) {
    for (const item of data.alcoa) {
      const chip = h("button", { class: "chip-btn", type: "button", title: `${item.id}: ${msgOf(item, "detail")}` }, stWord(item.status, `${t(item.attribute)} ${t(item.status)}`));
      chip.addEventListener("click", () => setInspector(inspSection("ALCOA++", h("p", { class: "insp-title", text: t(item.attribute) }), stWord(item.status),
        h("p", { text: msgOf(item, "detail") }), kv([[t("Catalogue"), h("code", { text: item.id })], [t("Related"), item.related.join(", ")]]),
        h("p", { class: "small muted", text: t("pass means the check found nothing; it does not mean a process is compliant.") }))));
      put(strip, chip);
    }
  } else put(strip, h("span", { class: "muted", text: status.verifying ? t("Computed after the verification finishes…") : t("Not computed yet: run Verify now.") }));
  main.put(section("ALCOA++", strip));

  const tools = h("div", { class: "tools" }, data.tools.map((x) => h("div", {},
    h("div", {}, h("strong", { text: x.package }), " ", x.installed ? stWord(x.problem ? "warn" : "pass", x.problem ? t("problem") : t("installed")) : stWord("neutral", t("not installed"))),
    h("div", { class: "small muted", text: x.installed ? (x.problem || t("last record {ago}", { ago: x.last_record ? ago(x.last_record) : t("none") })) : x.install }))));
  main.put(section(t("Tool health"), tools));

  if (data.refusals.length) {
    const rows = data.refusals.slice().reverse().map((r) => ({ data: r, cells: [h("td", { class: "small time", text: fmtTime(r.time) }), r.type, h("td", { class: "mono small hide-narrow", text: r.actor.id }), refusalWords(r.reason_code, r.reason_text) ? `${refusalWords(r.reason_code, r.reason_text)} (${r.reason_code})` : r.reason_code || ""] }));
    const x = table([t("Time"), t("Type"), th(t("Claimed actor"), "hide-narrow"), t("Reason code")], rows, (r) => go(`/evidence/trail?type=*.refused#${r.id}`));
    main.put(section(t("Refusals in the last 24 h"), x.table));
  }
  return out;
}

async function refresh(force) {
  const data = await api("/api/overview");
  S.overview = data;
  renderRail();
  renderTopbar();
  if (force && (S.view === "home" || S.view === "settings") && !S.page) route();
  return data;
}
let verifyTimer = null;
function pollVerify() {
  if (verifyTimer) return;
  verifyTimer = setInterval(async () => {
    const data = await refresh().catch(() => null);
    if (data && !data.status.verifying) { clearInterval(verifyTimer); verifyTimer = null; announce(t("Verification finished: {state}", { state: t(data.status.state) })); route(); }
  }, 1000);
}

// ---- Case pages ----------------------------------------------------------------------------------------
// One page per queue entry: the subject and its STOP point at the top, the evidence in the middle,
// the allowed decisions (each with its consequence) or the way to resolve it at the bottom. The
// parts come from the same builders as the inspector of the tool views. After a decision the page
// shows what was recorded and offers the next case (n).
function nextCaseItem(currentId) {
  const needs = (S.overview && S.overview.needs) || [];
  if (!needs.length) return null;
  const at = needs.findIndex((n) => n.id === currentId);
  if (at >= 0) return needs[at + 1] || (needs[0].id !== currentId ? needs[0] : null);
  return needs[Math.min(S.queueAt || 0, needs.length - 1)];
}
function nextCase() {
  const needs = (S.overview && S.overview.needs) || [];
  if (!S.caseId) {                      // on the queue: the line with the focus, else the first
    const at = queueButtons().indexOf(document.activeElement);
    const item = needs[Math.max(0, at)];
    if (item) { S.queueAt = Math.max(0, at); go(casePath(item)); }
    return;
  }
  const next = nextCaseItem(S.caseId);
  if (next) S.queueAt = needs.indexOf(next);
  go(next ? casePath(next) : "/");
}
function link(text, path) {
  return h("a", { href: path, onclick: (e) => { e.preventDefault(); go(path); }, text });
}
function stopMark(kind) {
  return kind === "person" ? h("span", { class: "octagon", "aria-hidden": "true", text: "STOP" })
    : h("span", { class: `wait-mark ${kind}`, "aria-hidden": "true" });
}
// The frame of a case page. stop: [kind, words] with kind person (a red STOP: waits for you),
// evidence or fix; links: [[words, path]]. Returns body() and decide() to fill it.
function caseFrame(main, item, { title, stop, links, settled }) {
  clear(main);
  const needs = (S.overview && S.overview.needs) || [];
  const at = item ? needs.findIndex((n) => n.id === item.id) : -1;
  const [needTitle, needDetail] = item ? needText(item) : [title, ""];
  const since = item ? sinceText(item) : "";
  const next = nextCaseItem(S.caseId);
  const head = h("header", { class: "case-head" },
    h("nav", { class: "crumbs", "aria-label": t("Where you are") }, link(t("All cases"), "/"),
      at >= 0 ? h("span", { class: "muted", text: t("case {n} of {total}", { n: at + 1, total: needs.length }) }) : null,
      h("span", { class: "spacer" }),
      h("button", { class: "btn small", type: "button", onclick: nextCase, title: t("Next case (n)") }, next ? t("Next case") : t("Back to Needs you"))),
    item ? st(SEVERITY_KIND[item.severity] || "neutral", t(item.severity)) : null,
    h("h2", { class: "case-title", text: needTitle || title }),
    needDetail ? h("p", { class: "case-why", text: needDetail }) : null,
    item && stop ? h("p", { class: `stopline ${stop[0]}` }, stopMark(stop[0]), h("span", { text: stop[1] }))
      : h("p", { class: "stopline settled" }, settled || st("pass", t("This case no longer needs you."))),
    h("p", { class: "case-meta small" },
      since ? h("span", { text: since }) : null,
      item && item.code ? h("span", {}, `${t("Code")} `, h("code", { text: item.code })) : null,
      (links || []).map(([words, path]) => link(words, path))));
  const body = h("div", { class: "case-body" });
  const decideBox = h("section", { class: "case-decide" });
  put(main, h("article", { class: "case", "aria-label": needTitle || title }, head, body, decideBox));
  document.title = vis(`${needTitle || title} · ${t("AQT quality desk")}`);
  return {
    body: (...children) => put(body, ...children),
    decide: (heading, ...children) => { put(clear(decideBox), heading ? h("h3", { class: "decide-title", text: heading }) : null, ...children); },
    root: main,
  };
}
// After a decision on a case page: reload the queue, show the case again with what was recorded.
function caseDone(main) {
  return async (data, chosen) => {
    const path = location.pathname;
    await refresh().catch(() => null);
    if (location.pathname === path) await renderCase(main, { data, chosen });
  };
}
function recordedBlock({ data, chosen }) {
  const next = S.caseId ? nextCaseItem(S.caseId) : null;
  const button = h("button", { class: "btn primary", type: "button", onclick: () => (S.caseId ? nextCase() : go("/")),
    text: next ? t("Next case") : t("Back to Needs you") });
  setTimeout(() => button.focus(), 0);
  return h("div", { class: "recorded", role: "status" },
    h("p", { class: "recorded-title" }, st("pass", t("Recorded: {decision}", { decision: chosen.label }))),
    kv([[t("Record"), h("code", { text: data.record_id || "–" })], [t("Time"), fmtTime(data.time)], data.message ? [t("Result"), msgOf(data, "message")] : null]),
    h("div", { class: "actions" }, button, S.caseId ? h("span", { class: "small muted", text: next ? t("or press n") : t("Nothing else needs you.") }) : null));
}
// How to resolve a case that has no decision on the page: a sentence and the exact command(s).
function commandLine(command) {
  const copy = h("button", { class: "btn small ghost", type: "button", text: t("Copy"),
    onclick: () => { navigator.clipboard?.writeText(command).then(() => announce(t("Copied")), () => {}); } });
  return h("div", { class: "command" }, h("code", { text: command }), copy);
}
function resolveSteps(steps) {
  return h("ol", { class: "resolve" }, steps.filter(Boolean).map(([words, ...commands]) =>
    h("li", {}, h("p", { text: words }), commands.filter(Boolean).map(commandLine))));
}
function caseEmpty(frame, words) { frame.decide(t("Decide"), h("p", { class: "muted", text: words || t("No decision is open for this case.") })); }

// A project is named by its position in ui.toml, a plan by its id; a case id never holds a query, a
// fragment, a backslash, control characters or a ".." part. Every part that goes into an API address is
// checked and encoded on its own.
const PROJECT_PART = /^[0-9]{1,4}$/;
const PLAN_PART = /^(?!\.\.?$)[A-Za-z0-9._-]{1,200}$/;
const UNSAFE_CASE_ID = /[?#\\\u0000-\u001f\u007f]|(^|[:/])\.\.?([:/]|$)/;
function changeApi(project, planId, tail) {
  if (!PROJECT_PART.test(String(project)) || !PLAN_PART.test(String(planId))) throw new Error(t("Unknown case"));
  return `/api/change/${encodeURIComponent(project)}/${encodeURIComponent(planId)}${tail || ""}`;
}
function changePath(project, planId) {
  return PROJECT_PART.test(String(project)) && PLAN_PART.test(String(planId)) ? `/change/${encodeURIComponent(project)}/${encodeURIComponent(planId)}` : "/changes";
}
async function renderCase(main, notice) {
  let id;
  try { id = decodeURIComponent(location.pathname.slice("/case/".length)); } catch (e) { id = ""; }
  let data = S.overview || (await refresh());
  if (!notice && !data.needs.some((n) => n.id === id)) data = await refresh();   // a case newer than the last check
  const at = data.needs.findIndex((n) => n.id === id);
  const item = at >= 0 ? data.needs[at] : null;
  S.caseId = id;
  if (at >= 0) S.queueAt = at;
  const [kind, ...rest] = id.split(":");
  if (!Object.hasOwn(CASES, kind) || UNSAFE_CASE_ID.test(id)) { clear(main); put(main, empty(t("Unknown case"), id)); return; }
  await CASES[kind]({ main, id, item, rest, notice, done: caseDone(main) });
}

const CASES = {
  async quarantine({ main, item, rest, notice, done }) {
    const q = query();
    const full = q.get("full") === "1";
    const page = parseInt(q.get("page") || "0", 10) || 0;
    const c = await quarantineCase(rest.join(":"), full, page);
    const open = (f, pg) => { setQuery({ full: f ? "1" : "", page: f && pg ? String(pg) : "" }); route().then(() => document.getElementById("case-content")?.scrollIntoView({ block: "start" })); };
    const parts = quarantineParts(c, { full, open, onDone: done });
    const f = caseFrame(main, item, {
      title: t("Quarantine case {id}", { id: c.case_id }),
      stop: ["person", c.state === "warned" ? t("Waits for you: confirm the content as harmless or declare a threat") : t("Waits for you: release the content or declare a threat")],
      settled: ["held", "warned"].includes(c.state) ? null : stWord(c.state),
      links: [[t("Open in {view}", { view: t("Held pages") }), `/evidence/quarantine?item=${encodeURIComponent(c.case_id)}`]],
    });
    parts.content.id = "case-content";
    parts.summary.querySelector(".insp-title")?.remove();          // the page title names the case
    f.body(parts.summary, parts.evidence, parts.content, parts.history, parts.journal);
    if (notice) f.decide(t("Decided"), recordedBlock(notice));
    else if (parts.decision) f.decide(null, parts.decision);
    else caseEmpty(f);
  },

  async action({ main, item, rest, notice, done }) {
    const a = await api(`/api/changes/actions/${encodeURIComponent(rest.join(":"))}`);
    const x = actionParts(a, a.signers, { onDone: done });
    x.summary.querySelector(".insp-title")?.remove();
    const unknown = a.status === "unknown";
    const f = caseFrame(main, item, {
      title: t("Prepared action {id}", { id: a.id }),
      stop: ["person", unknown ? t("Waits for you: find out what happened, then resolve the outcome in a terminal") : t("Waits for you: approve or reject this exact version")],
      settled: stWord(a.status),
      links: [[t("Open in {view}", { view: t("Changes") }), `/changes?tab=actions&item=${encodeURIComponent(a.id)}`]],
    });
    f.body(x.summary, x.spec);
    if (notice) f.decide(t("Decided"), recordedBlock(notice));
    else if (unknown) f.decide(t("How to resolve"), resolveSteps([[t("Check the external state first (did it run?), then record what happened, in your own terminal:"),
      `aqt-signoff resolve ${a.id} --as succeeded --reason "…"`, `aqt-signoff resolve ${a.id} --as not-applied --reason "…"`]]));
    else if (x.decision) f.decide(null, x.decision);
    else caseEmpty(f);
  },

  async plan(args) { await planCase(args, "plan"); },
  async gate(args) { await planCase(args, "gate"); },

  async release({ main, item, rest, notice, done }) {
    const [project, ...plan] = rest;
    await renderChange(main, { project, planId: plan.join(":"), item, notice, done });
  },

  async capa({ main, item, rest, notice, done }) {
    const data = await api("/api/capa");
    if (rest[0] === "overdue") {
      const overdue = data.deviations.filter((d) => d.overdue);
      const f = caseFrame(main, item, { title: t("Overdue deviations"), stop: ["person", t("Waits for the person handling the deviation: record the investigation")],
        links: [[t("Open in {view}", { view: t("CAPA") }), "/evidence/capa?tab=deviations"]] });
      f.body(inspSection(t("Deviations"), overdue.length ? h("ul", { class: "evidence-list" }, overdue.map((d) => h("li", {},
        link(`${d.dev_id} ${d.title}`, `/evidence/capa?tab=deviations&item=${encodeURIComponent(d.dev_id)}`), ` · ${t("due")} ${fmtTime(d.due)}`))) : h("p", { class: "muted", text: t("No deviation is overdue.") })));
      f.decide(t("How to resolve"), resolveSteps([[t("Record the investigation in a terminal (5 whys, factors, root cause):"),
        `aqt-capa investigate ${(overdue[0] && overdue[0].dev_id) || "DEV-…"} --why "…" --root-cause "…" --root-category …`]]));
      return;
    }
    const wanted = query().get("candidate");
    const candidate = data.candidates.find((c) => c.candidate_id === wanted) || data.candidates[0];
    const f = caseFrame(main, item, { title: t("CAPA candidates"), stop: ["person", t("Waits for you: accept or dismiss each candidate")],
      links: [[t("Open in {view}", { view: t("CAPA") }), "/evidence/capa?tab=candidates"]] });
    if (!candidate) { f.body(empty(t("No open candidates"), t("aqt-capa scan finds candidates in the evidence."))); if (notice) f.decide(t("Decided"), recordedBlock(notice)); return; }
    const x = candidateParts(candidate, data.signers, { onDone: done });
    const others = data.candidates.filter((c) => c !== candidate);
    f.body(x.summary, others.length ? inspSection(t("Other candidates ({n})", { n: others.length }), h("ul", { class: "evidence-list" },
      others.map((c) => h("li", {}, h("a", { href: "#", onclick: (e) => { e.preventDefault(); setQuery({ candidate: c.candidate_id }); route(); }, text: candidateTitle(c) }), ` · ${c.rule}`)))) : null);
    if (notice) f.decide(t("Decided"), recordedBlock(notice));
    else f.decide(null, x.decision);
  },

  async trail({ main, item, rest, notice, done }) {
    await refresh().catch(() => null);
    const ov = S.overview;
    const status = ov.status;
    const check = status.check || {};
    const code = rest[0];
    const trailLink = [t("Open in {view}", { view: t("Audit trail") }), "/evidence/trail"];
    const integrity = () => inspSection(t("Integrity"), stWord(status.state), kv([[t("Records"), num(status.records)], [t("Head seq"), num(status.head_seq)],
      [t("Checked"), check.checked_at ? fmtTime(check.checked_at) : t("not yet")], check.first_bad_seq != null ? [t("Broken from seq"), num(check.first_bad_seq)] : null,
      check.reason ? [t("Reason"), msgOf(check, "reason")] : null, status.changed ? [t("Changed"), msgOf(status, "changed")] : null]),
      check.summary ? h("p", { class: "small break", text: `${t("Verifier:")} ${msgOf(check, "summary")}` }) : null,
      msgList(check.problems, check.problem_codes).map((p) => h("p", { class: "small break", text: `${t("Problem:")} ${p}` })),
      msgList(check.warnings, check.warning_codes).map((w) => h("p", { class: "small muted break", text: `${t("Warning:")} ${w}` })));
    const verify = () => h("div", { class: "actions" }, h("button", { class: "btn small", type: "button", text: t("Verify now"),
      onclick: async (e) => { e.target.disabled = true; await post("/api/trail/verify"); pollVerify(); } }));
    if (["trail_broken", "trail_changed", "trail_problems"].includes(code)) {
      const f = caseFrame(main, item, { title: t("Trail integrity"), stop: ["fix", t("Waits for a fix: find out why the trail does not verify")], links: [trailLink] });
      f.body(integrity());
      f.decide(t("How to resolve"), resolveSteps([[t("Do not edit the trail. Compare it with your last export or external head, find the cause, then verify again:"), "aqt-trail verify"]]), verify());
    } else if (code === "alcoa") {
      const result = (ov.alcoa || []).find((a) => a.id === rest.slice(1).join(":"));
      const f = caseFrame(main, item, { title: t("ALCOA++ result"), stop: ["fix", t("Waits for a look at the records behind this result")], links: [trailLink] });
      f.body(result ? inspSection(t("ALCOA++"), stWord(result.status, `${t(result.attribute)} ${t(result.status)}`), h("p", { text: msgOf(result, "detail") }),
        kv([[t("Catalogue"), h("code", { text: result.id })], [t("Related"), (result.related || []).join(", ") || "–"]]),
        h("p", { class: "small muted", text: t("pass means the check found nothing; it does not mean a process is compliant.") })) : h("p", { class: "muted", text: t("Not computed yet: run Verify now.") }));
      f.decide(t("How to resolve"), resolveSteps([[t("Read the full report with the records it names:"), "aqt-trail alcoa"]]));
    } else if (code === "refusals") {
      const f = caseFrame(main, item, { title: t("Refused decision attempts"), stop: ["person", t("Waits for a look: who tried to decide, and why")],
        links: [[t("Open in {view}", { view: t("Audit trail") }), "/evidence/trail?type=*.refused"]] });
      const rows = ov.refusals.slice().reverse().map((r) => ({ data: r, cells: [h("td", { class: "small time", text: fmtTime(r.time) }), r.type, h("td", { class: "mono small", text: r.actor.id }),
        refusalWords(r.reason_code, r.reason_text) ? `${refusalWords(r.reason_code, r.reason_text)} (${r.reason_code})` : r.reason_code || ""] }));
      f.body(inspSection(t("Refusals in the last 24 h"), table([t("Time"), t("Type"), t("Claimed actor"), t("Reason code")], rows, (r) => go(`/evidence/trail?type=*.refused#${r.id}`)).table));
      f.decide(t("How to resolve"), h("p", { text: t("Nothing to sign: each attempt is already recorded. If an agent tried to decide, check its instructions; repeated attempts become CAPA candidates.") }));
    } else if (code === "review_due") {
      const profile = status.review_profile || {};
      const f = caseFrame(main, item, { title: t("Audit-trail review"), stop: ["person", t("Waits for you: review the audit trail and sign the review")], links: [[t("Open in {view}", { view: t("Audit trail") }), "/evidence/trail?panel=review"]] });
      f.body(inspSection(t("Audit-trail review"), kv([[t("Last review"), status.last_review ? `${fmtTime(status.last_review)} (${ago(status.last_review)})` : t("none")],
        [t("Records"), num(status.records)], [t("Profile"), [profile.name || "?", " · ", profileWord(profile)]]]), profileNotes(profile, status.test_mode)));
      if (notice) { f.decide(t("Decided"), recordedBlock(notice)); return; }
      const out = h("div", { "aria-live": "polite" });
      const run = h("button", { class: "btn primary", type: "button", text: t("Prepare worksheet") });
      run.addEventListener("click", async () => {
        run.disabled = true;
        const { status: code2, data } = await post("/api/trail/review/run", {});
        run.disabled = false;
        if (code2 !== 200 || !data.ok) { put(clear(out), h("div", { class: "result refused", text: msgOf(data, "message") || `HTTP ${code2}` })); return; }
        f.decide(t("Decide"), ...reviewPanel(data, { onDone: done }));
      });
      f.decide(t("Decide"), h("p", { class: "small muted", text: t("Runs the risk queries over a period and lists the findings. Preparing writes a worksheet file, no evidence; the signed review is recorded in the trail.") }),
        h("div", { class: "actions" }, run), out);
    } else {
      const fixes = {
        trail_missing: [t("Waits for a fix: set up the audit trail"), [t("Set up the trail, a signing key and the hooks in a terminal (safe to run again):"), "aqt setup"]],
        writer_down: [t("Waits for a fix: start the trail writer"), [t("Start the writer in a terminal:"), "aqt-trail serve"]],
        spooled: [t("Waits for a fix: move the spooled records into the trail"), [t("Append the spooled records to the trail:"), "aqt-trail drain"]],
        unanchored: [t("Waits for a fix: anchor the trail head"), [t("Sign the head and add an RFC 3161 time stamp:"), "aqt-trail checkpoint --anchor"]],
        test_mode: [t("Waits for a fix in trail.toml"), [t("Remove the line test_tsa = true from the [anchor] section of trail.toml.")]],
        review_params: [t("Waits for a fix in trail.toml"), [t("Check the [review] section of trail.toml and remove the values you did not set.")]],
      }[code] || [t("Waits for a fix"), [t("See the Health view for details.")]];
      const f = caseFrame(main, item, { title: t("Trail"), stop: ["fix", fixes[0]], links: [[t("Settings"), "/settings"]] });
      f.body(code === "review_params" || code === "test_mode" ? inspSection(t("Review parameters"), profileNotes(status.review_profile, status.test_mode)) : integrity());
      // the one fix as a button where the app can do it; the command stays beside it
      const step = { trail_missing: null, writer_down: "writer", spooled: "spool" }[code];
      const canDo = S.mode && S.mode.decisions && (code === "trail_missing" || (step && S.setup && (S.setup.checks || []).some((c) => c.id === step && c.can_apply)));
      f.decide(t("How to resolve"), canDo ? h("div", { class: "actions fix-first" }, h("button", { class: "btn primary", type: "button",
        text: code === "trail_missing" ? t("Open the setup") : t(FIX_WORDS[step][0]),
        onclick: async (e) => { if (!step) { go("/welcome"); return; } e.target.disabled = true; await applyStep(step); route(); } })) : null,
        resolveSteps([fixes[1]]));
    }
  },

  async qualification({ main, item, rest }) {
    const data = await api("/api/qualifications");
    const subject = rest.join(":");
    const q = data.qualifications.find((x) => x.subject_id === subject);
    const f = caseFrame(main, item, { title: t("Qualification of {subject}", { subject }), stop: ["fix", t("Waits for requalification")],
      links: [[t("Open in {view}", { view: t("Qualifications") }), "/evidence/qualifications"]] });
    if (q) f.body(inspSection(t("Qualification"), stWord(q.state), kv([[t("Kind"), codeWord("validate.kind.", q.kind)], [t("Decision"), t(q.decision)], [t("Conclusion"), codeWord("validate.conclusion.", q.conclusion)],
      [t("Valid until"), fmtTime(q.valid_until)], [t("Approved by"), `${q.approver_name || ""} ${q.approver || ""}`], [t("Triggers"), triggerWords(q.triggers) || t("none recorded")], [t("Record"), h("code", { text: q.record })]])));
    f.decide(t("How to resolve"), resolveSteps([[t("Run the validation again under the locked protocol and qualify the new run, in your own terminal:"),
      "aqt-validate detector run protocol.toml --out runs/<new>", 'aqt-validate qualify runs/<new> --approve --reason "…"']]));
  },
};

// A plan version to approve, or a gate that is not GO: the gate's evidence and the approval.
async function planCase({ main, item, rest, notice, done }, kind) {
  const [project, ...plan] = rest;
  const planId = plan.join(":");
  const d = await api(changeApi(project, planId));
  const p = d.plan;
  const g = gateParts(p, d.root, d.signers, { onDone: done });
  const manual = p.decision === "MANUAL_VERIFY_REQUIRED";
  const f = caseFrame(main, item, {
    title: kind === "plan" ? t("Plan version of {plan} to approve", { plan: planId }) : t("Gate {decision} for {plan}", { decision: p.decision || "–", plan: planId }),
    stop: kind === "plan" ? ["person", t("Waits for you: approve this plan version")]
      : manual ? ["person", t("Waits for a person: the gate needs a manual check")] : ["evidence", t("Waits for evidence: checks, a review or the finish")],
    settled: p.decision === "GO" ? st("pass", "GO") : null,
    links: [[t("Change page"), changePath(project, planId)]],
  });
  f.body(inspSection(t("Steps of the change"), timelineView(d.steps, p, (step) => go(`${changePath(project, planId)}#step-${step}`))),
    g.reasons, g.receipts, g.approval);
  if (notice) f.decide(t("Decided"), recordedBlock(notice));
  else if (kind === "plan" && g.decision) f.decide(null, g.decision);
  else f.decide(t("How to resolve"), resolveSteps(gateFixes(p)), g.decision ? h("div", { class: "case-also" }, g.decision) : null);
}
function gateFixes(p) {
  const codes = new Set((p.reasons || []).map((r) => r.code));
  const any = (...names) => [...codes].some((c) => names.some((n) => (n.endsWith("_") ? c.startsWith(n) : c === n)));
  return [
    any("receipt_", "junit_", "command_modified_worktree") ? [t("Run the declared checks again on the current code (agent or you):"), `aqt-change run --plan ${p.path} --all`] : null,
    any("review_fail", "review_concerns", "review_waived", "review_independence_below_policy", "review_unverified") ? [t("Add a review of the current diff that meets the policy:"), `aqt-change review add ${p.path} --reviewer … --independence … --verdict PASS --reason "…"`] : null,
    any("manual_item_agent_attested", "waiver_present") ? [t("Attest the manual check yourself, with its evidence:"), `aqt-change attest ${p.path} --item … --reason "…"`] : null,
    any("unapproved_change", "scope_undeclared") ? [t("Compare the changed files with the approved scope; undo what is outside it or reconcile the plan:"), `aqt-change reconcile-diff ${p.path}`] : null,
    any("not_finished") ? [t("Finish the change when the work is done (agent or you):"), `aqt-change finish ${p.path} --key … --summary "…" --path …`] : null,
    [t("See every reason in your terminal:"), `aqt-change gate ${p.path}`],
  ];
}

// ---- Change page: Plan -> Checks -> Review -> Gate -> Release ----------------------------------------
const STEP_LABELS = { plan: "Plan", checks: "Checks", review: "Review", gate: "Gate", release: "Release" };
const stepLabel = (id) => (LANG === "de" && STEPS_DE[id]) || STEP_LABELS[id];
const STEP_STATES = { done: "Done", person: "Waits for you", evidence: "Waits for evidence", open: "Open" };
function stepLine(step, p) {
  const a = p.approval || {};
  const release = p.release || {};
  if (step.id === "plan") return a.state ? t(APPROVAL_WORDS[a.state] || a.state) : t("not begun");
  if (step.id === "checks") {
    const fresh = p.receipts.filter((r) => r.state === "ok").length;
    return p.receipts.length ? t("{n} of {total} fresh", { n: fresh, total: p.receipts.length }) : t("No verification items.");
  }
  if (step.id === "review") {
    const counting = (p.review_records || []).filter((r) => r.counts).length;
    return step.codes.length ? reasonText(p.reasons.find((r) => r.code === step.codes[0]) || { code: step.codes[0], text: step.codes[0] })
      : counting ? t("Reviews that count: {n}", { n: counting }) : t("none needed");
  }
  if (step.id === "gate") return p.decision || t("not evaluated");
  if (release.state === "released") return t("released");
  if (release.state === "unbound") return t("not tied to this change");
  if (!p.finish) return t("not finished");
  return p.decision === "GO" ? t("ready to sign") : t("waits for GO");
}
function timelineView(steps, p, onPick) {
  return h("ol", { class: "timeline", "aria-label": t("Steps of the change") }, steps.map((step) =>
    h("li", { class: `step ${step.state}${step.current ? " current" : ""}`, "aria-current": step.current ? "step" : null },
      h("button", { type: "button", onclick: () => onPick(step.id) },
        step.current && step.state === "person" ? h("span", { class: "octagon", "aria-hidden": "true", text: "STOP" })
          : h("span", { class: "mark", "aria-hidden": "true", text: step.state === "done" ? "✓" : "" }),
        h("span", { class: "step-name", text: stepLabel(step.id) }),
        h("span", { class: "step-state", text: step.current && step.state === "person" ? t("STOP: waits for you") : t(STEP_STATES[step.state]) }),
        h("span", { class: "step-line", text: stepLine(step, p) })))));
}
const STEP_STOPS = {
  person: { plan: "Waits for you: approve this plan version", checks: "Waits for you: attest the manual checks", review: "Waits for you: look at the review's concerns",
    gate: "Waits for a person: the gate needs a manual check", release: "Waits for you: sign the finished change as released" },
  evidence: { plan: "Waits for evidence: the plan was not begun", checks: "Waits for evidence: the declared checks must pass on the current code",
    review: "Waits for evidence: a review that counts", gate: "Waits for evidence: the gate is NO-GO", release: "Waits for evidence: the change is not finished, or its gate is not GO" },
};
function stopWords(step) {
  return step.id === "release" && step.unbound ? t("Waits for you: the finish record is not tied to this change; nothing can be signed")
    : t(STEP_STOPS[step.state][step.id]);
}
async function renderChangeRoute(main) {
  const [, , project, plan] = location.pathname.split("/");
  let planId = "";
  try { planId = decodeURIComponent(plan || ""); } catch (e) { /* not a plan id: refused below */ }
  await renderChange(main, { project, planId });
}
async function renderChange(main, { project, planId, item, notice, done, fresh }) {
  const d = await api(changeApi(project, planId, fresh ? "?fresh=1" : ""));
  const p = d.plan;
  const asCase = location.pathname.startsWith("/case/");
  const onDone = done || (async (data, chosen) => { await refresh().catch(() => null); await renderChange(main, { project, planId, notice: { data, chosen } }); });
  const current = d.steps.find((s) => s.current);
  const title = t("Change {plan}", { plan: p.plan_id });
  let f;
  if (asCase) {
    f = caseFrame(main, item, { title, stop: current ? [current.state, stopWords(current)] : null,
      settled: (p.release || {}).state === "released" ? stWord("released") : null,
      links: [[t("Change page"), changePath(project, planId)]] });
  } else {
    clear(main);
    document.title = vis(`${title} · ${t("AQT quality desk")}`);
    const body = h("div", { class: "case-body" });
    const decideBox = h("section", { class: "case-decide" });
    put(main, h("article", { class: "case change" }, h("header", { class: "case-head" },
      h("nav", { class: "crumbs", "aria-label": t("Where you are") }, link(t("Changes"), "/changes")),
      h("h2", { class: "case-title", text: title }),
      h("p", { class: "case-why" }, h("span", { class: "mono small", text: d.root }), " ", h("span", { class: "mono small muted", text: p.path })),
      current ? h("p", { class: `stopline ${current.state}` }, stopMark(current.state), h("span", { text: stopWords(current) }))
        : h("p", { class: "stopline settled" }, stWord("released"))), body, decideBox));
    f = { body: (...c) => put(body, ...c), decide: (heading, ...c) => put(clear(decideBox), h("h3", { class: "decide-title", text: heading }), ...c) };
  }
  const sections = {};
  const pick = (id) => sections[id] && sections[id].scrollIntoView({ block: "start", behavior: "smooth" });
  const again = h("button", { class: "btn small ghost", type: "button", text: t("Evaluate again"),
    onclick: async () => { again.disabled = true; await renderChange(main, { project, planId, item, notice, done, fresh: true }); } });
  f.body(h("div", { class: "timeline-wrap" }, timelineView(d.steps, p, pick),
    h("p", { class: "small muted" }, t("Gate evaluated {time}.", { time: fmtTime(p.evaluated_at) }), " ", again)),
    notice ? recordedBlock(notice) : null);
  if (p.error) f.body(h("div", { class: "error-box", text: p.error }));
  const g = gateParts(p, d.root, d.signers, { onDone });
  const a = p.approval || {};
  const step = (id, ...children) => {
    const box = h("section", { class: "step-section", id: `step-${id}` }, h("h3", { text: stepLabel(id) }), ...children);
    sections[id] = box;
    return box;
  };
  const reviews = p.review_records || [];
  f.body(
    step("plan", kv([[t("File"), h("span", { class: "mono", text: p.path })], [t("Version"), a.record ? h("code", { text: a.record }) : "–"], [t("Hash"), hashButton(a.sha256, 16)],
      [t("State"), approvalChip(p.approval)], [t("Since"), p.approval_time ? fmtTime(p.approval_time) : "–"]]),
      d.steps[0].state === "open" ? h("p", { class: "small muted", text: t("Not signed. The gate policy of this project does not require a signed plan approval.") }) : null,
      g.decision && !notice ? h("div", { class: "case-also" }, g.decision) : null),
    step("checks", receiptList(p.receipts)),
    step("review", reviews.length ? plainTable([t("Reviewer"), t("Independence"), t("Verdict"), t("Counts"), t("Time")],
      reviews.map((r) => [h("td", { class: "mono small wrap", text: r.reviewer || "–" }), t(r.independence || "–"), stWord(r.verdict === "PASS" ? "pass" : r.verdict === "FAIL" ? "fail" : "warn", r.verdict || "–"),
        r.counts ? t("yes") : t("no"), h("td", { class: "small time", text: fmtTime(r.time) })]))
      : h("p", { class: "muted", text: t("No reviews recorded.") })),
    step("gate", h("p", {}, gateChip(p.decision)), p.reasons.length ? reasonList(p.reasons) : h("p", { text: t("No reasons: the gate is GO.") })),
    releaseSection(step, d, p, { onDone, notice }));
  const wanted = location.hash.startsWith("#step-") ? sections[location.hash.slice(6)] : null;
  if (wanted) wanted.scrollIntoView({ block: "start" });
}
// What the trail writer observed of a record's sender: route, harness, process chain, chain status.
function observedText(o) {
  return [o.via || "?", o.harness, (o.process_chain || []).join(" ← "), o.chain_status ? `(${o.chain_status})` : null].filter(Boolean).join(" · ");
}
// The short summary of a change for the signing sheet: gate, checks, reviews.
function releaseSummary(p) {
  const fresh = (p.receipts || []).filter((r) => r.state === "ok").length;
  const reviews = (p.review_records || []).filter((r) => r.counts).length;
  return [`${t("Gate")} ${p.decision || "–"}`, (p.receipts || []).length ? t("{n} of {total} checks fresh", { n: fresh, total: p.receipts.length }) : null,
    t("reviews that count: {n}", { n: reviews })].filter(Boolean).join(", ");
}
function releaseSection(step, d, p, { onDone, notice }) {
  const release = p.release;
  const fin = p.finish_record || {};
  // tasks the accepted plan still has open: seen before anything is signed
  const open = (p.open_tasks || []).length ? h("div", { class: "flag-box" }, h("p", { class: "flag", text: t("Open tasks in the plan:") }),
    h("ul", { class: "evidence-list" }, p.open_tasks.map((x) => h("li", {}, h("strong", { text: x.id || "–" }), " ", x.text)))) : null;
  if (!p.finish) return step("release", open, h("p", { class: "muted", text: t("Not finished yet: the change.finish record is written by aqt-change finish.") }));
  if (p.finish_problem || (release && release.state === "unbound")) {
    // the record the gate names is not tied to this change: nothing to show as released, nothing to sign
    return step("release", open, kv([[t("Finish record"), h("code", { text: p.finish })], [t("HEAD now"), p.head ? hashButton(p.head, 40) : "–"]]),
      h("p", { class: "flag", role: "alert" }, stWord("fail", t("not tied to this change")), " ", msgOf(p, "finish_problem")),
      h("p", { class: "small muted", text: t("The finish record that aqt-change's local copy names cannot be released here. It must be this plan's latest change.finish record in the evidence (with a trail, in the trail), the same as the local copy, and a finish of what the gate evaluates now: the accepted plan version, the receipts the gate counts and HEAD (or a commit with HEAD's files). After later changes, finish the change again with aqt-change finish.") }));
  }
  // the finish names a commit (or, after finish --no-commit, only the head before the change); HEAD is what the
  // gate evaluated. "By" is what the record says; the observed sender is what the trail writer saw.
  const sameHead = !!(fin.commit && p.head && fin.commit === p.head);
  const parts = [kv([[t("Finish record"), h("code", { text: p.finish })], [t("Time"), fmtTime(fin.time)],
    [t("By (as the record says)"), fin.by || "–"], [t("Observed sender"), fin.observed ? observedText(fin.observed) : t("not observed (no trail writer)")],
    fin.commit ? [t("Finished commit"), hashButton(fin.commit, 40)] : [t("Head before the change"), fin.head ? hashButton(fin.head, 40) : "–"],
    [t("HEAD now"), p.head ? [hashButton(p.head, 40), fin.commit ? ` ${sameHead ? t("(the finished commit)") : t("(same files as the finished commit)")}` : ""] : "–"],
    [t("Hash"), hashButton(fin.sha256 || (release && release.sha256), 16)]]), open];
  if (!d.installed["aqt-signoff"] || (release && release.state === "unavailable")) {
    parts.push(h("p", { class: "small" }, t("aqt-signoff is not installed"), ": ", h("code", { text: installOf("aqt-signoff") })));
    return step("release", ...parts);
  }
  if (release.state === "missing") {
    parts.push(h("p", { class: "flag", text: msgOf(release, "detail") }), h("p", { class: "small muted", text: t("The finish record is not in the audit trail, so it cannot be signed here. Start the writer and drain the spool.") }));
    return step("release", ...parts);
  }
  const pol = d.release_policy || { min_signatures: 1, roles: [], distinct_from_author: false };
  const result = release.policy || {};
  parts.push(h("p", {}, stWord(release.state === "released" ? "released" : "unsigned", release.state === "released" ? t("released") : t("not released yet")), " ",
    h("span", { class: "small muted", text: msgOf(release, "summary") })));
  if (release.signatures.length) parts.push(plainTable([t("Printed name"), "ID", t("Role"), t("Local time"), t("Reason"), t("Status")], release.signatures.map((x) =>
    [x.name, h("td", { class: "mono small", text: x.id }), x.role, h("td", { class: "small", text: x.local }), h("td", { class: "wrap small", text: x.reason }),
      h("td", {}, stWord(x.status), x.status !== "valid" && x.detail ? h("span", { class: "small muted", text: ` ${msgOf(x, "detail")}` }) : null)])));
  parts.push(h("p", { class: "small muted" }, t("Policy [policy.released] in signoff.toml: {n} valid signature(s), {roles}, {author}.", {
    n: pol.min_signatures, roles: pol.roles.length ? t("roles {list}", { list: pol.roles.join(", ") }) : t("any role"),
    author: pol.distinct_from_author ? t("not by an author of the change") : t("the author may sign") }),
    result.note ? ` ${msgOf(result, "note")}` : ""));
  parts.push(h("p", { class: "small" }, t("Download the manifest:"), " ",
    downloadButton(`/api/signatures/manifest?record=${encodeURIComponent(p.finish)}&format=md`, "release-manifest.md", "Markdown", "btn small ghost"), " ",
    downloadButton(`/api/signatures/manifest?record=${encodeURIComponent(p.finish)}&format=html`, "release-manifest.html", "HTML", "btn small ghost")));
  if (notice) { /* the recorded decision is shown below the timeline */ }
  else if (p.decision === "GO" && release.state !== "released") {
    const authors = new Set(result.authors || []);
    const signers = (d.signers || []).filter((s) => (!pol.roles.length || pol.roles.includes(s.role)) && !(pol.distinct_from_author && authors.has(s.id)));
    parts.push(decisionPanel({
      title: t("Sign released"),
      actions: [{ id: "release", label: t("Sign released"), meaning: "released", button: t("Sign and release the change"),
        consequence: t("You sign the finished change as released. The signature is bound to its change.finish record and that record's hash; the gate is checked again before anything is signed.") }],
      signers, subject: { summary: releaseSummary(p), label: !fin.commit ? t("change {plan}, finish record {record}, head before the change {before}, HEAD {head}", { plan: p.plan_id, record: p.finish, before: fin.head || "–", head: p.head || "–" })
        : sameHead ? t("change {plan}, finish record {record}, commit {commit}", { plan: p.plan_id, record: p.finish, commit: fin.commit })
          : t("change {plan}, finish record {record}, commit {commit}, HEAD {head}", { plan: p.plan_id, record: p.finish, commit: fin.commit, head: p.head || "–" }), hash: release.sha256 },
      noSigners: pol.roles.length ? t("No registered signer may sign this release: [policy.released] allows the roles {list}.", { list: pol.roles.join(", ") }) : null,
      command: () => `aqt signoff sign --record ${sq(p.finish)} --meaning released --reason "…"`,
      onDone, submit: (x, values) => post(changeApi(d.project, p.plan_id, "/release"), { ...values, record: p.finish, sha256: release.sha256, path: p.path }),
    }));
  } else if (release.state !== "released") parts.push(h("p", { class: "small muted", text: t("Sign released is offered when the gate is GO.") }));
  return step("release", ...parts);
}

// ---- Trail -------------------------------------------------------------------------------------------
const TRAIL_FILTERS = ["type", "actor", "session", "subject", "since", "until"];
const TRAIL_PAGE = 100;
async function renderTrail(main) {
  const q = query();
  const params = Object.fromEntries(TRAIL_FILTERS.map((k) => [k, q.get(k) || ""]));
  const offset = Math.max(0, parseInt(q.get("offset") || "0", 10) || 0);
  const search = new URLSearchParams(Object.entries(params).filter(([, v]) => v));
  search.set("offset", String(offset));
  search.set("limit", String(TRAIL_PAGE));
  const data = await api(`/api/trail/records?${search}`);
  clear(main);
  const inputs = {};
  const bar = h("div", { class: "filterbar trail-filters", role: "search" });
  const typeSelect = h("select", { "aria-label": t("Record type") }, h("option", { value: "", text: t("All types") }),
    h("option", { value: "*.refused", text: t("All refusals (*.refused)") }), data.types.map((x) => h("option", { value: x, text: x })));
  typeSelect.value = params.type;
  inputs.type = typeSelect;
  put(bar, typeSelect);
  for (const [key, label] of [["actor", t("Actor id")], ["session", t("Session")], ["subject", t("Subject ref")], ["since", t("Since (2026-10-01)")], ["until", t("Until")]]) {
    inputs[key] = h("input", { type: "text", placeholder: label, "aria-label": label, value: params[key] });
    put(bar, inputs[key]);
  }
  const apply = () => { setQuery(Object.fromEntries(TRAIL_FILTERS.map((k) => [k, inputs[k].value.trim()]))); route(); };
  bar.addEventListener("keydown", (e) => { if (e.key === "Enter") apply(); });
  put(bar, h("span", { class: "bar-actions" },
    h("button", { class: "btn small primary", type: "button", text: t("Apply"), onclick: apply }),
    h("button", { class: "btn small ghost", type: "button", text: t("Clear"), onclick: () => { setQuery({}); route(); } }),
    h("button", { class: "btn small", type: "button", text: t("Integrity, review, export"), onclick: () => integrityPanel(true) })));
  put(main, bar);
  if (!data.rows.length) {
    put(main, empty(t("No records match"), data.total ? "" : t("Change or clear the filter.")));
    integrityPanel();
    return;
  }
  const rows = data.rows.map((r) => {
    const mismatch = r.attribution === "agent";
    const observedCell = mismatch ? h("span", { class: "flag", title: t("claims a human but came from an agent harness"), text: `! ${r.observed.harness || r.observed.drained_by || r.observed.via}` })
      : r.attribution === "unconfirmed" ? h("span", { class: "flag", title: t("claims a human, but the sender was not confirmed (chain status {status})", { status: r.observed.chain_status || r.observed.via || "–" }), text: `? ${t("unconfirmed")}` })
      : (r.observed.via ? `${r.observed.via}${r.observed.harness ? " · " + r.observed.harness : ""}` : "–");
    return { data: r, cells: [
      h("td", { class: "seq", text: r.chain.seq ?? "" }),
      h("td", { class: "small time", text: fmtTime(r.time) }),
      h("td", {}, r.type, r.signed ? h("span", { class: "muted small", text: ` · ${t("signature attached")}` }) : null),
      h("td", { class: "hide-narrow", text: r.action }),
      h("td", { class: "mono small wrap", text: r.actor.id }),
      h("td", { class: "hide-narrow small" }, observedCell),
      h("td", { class: "hide-narrow mono small wrap", text: (r.subject && r.subject.ref) || "" }),
    ] };
  });
  const x = table([h("th", { scope: "col", class: "num", text: "Seq" }), t("Time"), t("Type"), th(t("Action"), "hide-narrow"), t("Claimed actor"),
    th(t("Observed"), "hide-narrow"), th(t("Subject"), "hide-narrow")], rows, openRecord,
    (r) => (r.type === "trail.anchor" ? "anchor" : r.type === "trail.gap" ? "gap" : r.type.endsWith(".refused") ? "refusal" : ""));
  x.table.classList.add("with-filter");
  put(main, x.table, pager(data));
  const wanted = location.hash.slice(1);
  const pre = wanted && [...x.tbody.children].find((tr, i) => rows[i].data.id === wanted);
  if (pre) { pre.click(); pre.scrollIntoView({ block: "center" }); } else integrityPanel(q.get("panel") === "review" ? "review" : false);
}
// Newer / older pages; the offset stays in the address with the filters.
function pager(data) {
  const from = data.offset + 1;
  const to = data.offset + data.rows.length;
  const goTo = (offset) => {
    const q = query();
    if (offset > 0) q.set("offset", String(offset)); else q.delete("offset");
    history.replaceState(null, "", location.pathname + (q.toString() ? "?" + q : ""));
    route();
  };
  return h("nav", { class: "pager", "aria-label": t("Pages") },
    h("button", { class: "btn small", type: "button", text: t("Newest"), disabled: data.offset === 0, onclick: () => goTo(0) }),
    h("button", { class: "btn small", type: "button", text: t("Newer"), disabled: data.offset === 0, onclick: () => goTo(Math.max(0, data.offset - data.limit)) }),
    h("span", { class: "small muted", text: t("Records {from}–{to} of {total}, newest first", { from: num(from), to: num(to), total: num(data.total) }) }),
    h("button", { class: "btn small", type: "button", text: t("Older"), disabled: !data.more, onclick: () => goTo(data.offset + data.limit) }));
}

function integrityPanel(open) {
  const status = S.overview && S.overview.status;
  const check = (status && status.check) || {};
  const button = h("button", { class: "btn small", type: "button", text: t("Verify now"), onclick: async () => { button.disabled = true; button.textContent = vis(t("Verifying…")); await post("/api/trail/verify"); pollVerify(); } });
  const parts = [inspSection(t("Integrity"), status ? stWord(status.state) : null,
    h("p", { class: "break", text: msgOf(check, "summary") || t("Not verified yet.") }),
    check.checked_at ? kv([[t("Checked"), fmtTime(check.checked_at)], [t("Took"), `${check.seconds ?? "?"} s`], [t("Signatures"), num(check.signatures)], [t("Anchors"), num(check.anchors)]]) : null,
    msgList(check.problems, check.problem_codes).map((p) => h("p", { class: "small break", text: `${t("Problem:")} ${p}` })),
    msgList(check.warnings, check.warning_codes).map((w) => h("p", { class: "small muted break", text: `${t("Warning:")} ${w}` })),
    h("div", { class: "actions" }, button))];
  const alcoa = (S.overview && S.overview.alcoa) || [];
  if (alcoa.length) parts.push(inspSection("ALCOA++", alcoa.map((a) => h("p", { class: "small" }, stWord(a.status, t(a.attribute)), " ", msgOf(a, "detail")))));
  parts.push(reviewStart(), exportSection());
  setInspector(...parts);
  if (open === "review") document.getElementById("review-start")?.scrollIntoView({ block: "start" });
  else if (!open && window.matchMedia("(max-width: 1100px)").matches) closeSheet();
}

// Audit-trail review: prepare a worksheet (writes no evidence), then dispose of each finding and sign.
function reviewStart() {
  const since = h("input", { type: "text", placeholder: t("Since (2026-10-01)"), "aria-label": t("Since") });
  const until = h("input", { type: "text", placeholder: t("Until"), "aria-label": t("Until") });
  const out = h("div", { "aria-live": "polite" });
  const run = h("button", { class: "btn small primary", type: "button", text: t("Prepare worksheet") });
  run.addEventListener("click", async () => {
    run.disabled = true;
    clear(out);
    const { status, data } = await post("/api/trail/review/run", { since: since.value.trim(), until: until.value.trim() });
    run.disabled = false;
    if (status !== 200 || !data.ok) { put(out, h("div", { class: "result refused", text: msgOf(data, "message") || `HTTP ${status}` })); return; }
    setInspector(...reviewPanel(data));
  });
  return h("section", { class: "insp-section", id: "review-start" }, h("h3", { text: t("Audit-trail review") }),
    h("p", { class: "small muted", text: t("Runs the risk queries over a period and lists the findings. Preparing writes a worksheet file, no evidence; the signed review is recorded in the trail.") }),
    h("div", { class: "field-row" }, since, until), h("div", { class: "actions" }, run), out);
}
// The review profile's parameters, those that differ from aqt-trail's built-in defaults marked (trail.toml
// belongs to the user's account, so an agent can edit it).
function profileWord(profile) {
  const differs = Object.keys((profile && profile.differs_from_builtin) || {});
  return differs.length ? stWord("warn", t("{n} differ", { n: differs.length })) : t("Built-in");
}
function profileNotes(profile, testMode) {
  const differs = (profile && profile.differs_from_builtin) || {};
  const keys = Object.keys(differs).sort();
  return [
    testMode ? h("p", { class: "flag", text: t("TEST MODE: TEST ONLY anchors count ([anchor] test_tsa = true in trail.toml). Never for real use.") }) : null,
    keys.length ? h("p", { class: "flag", text: t("These parameters differ from the built-in defaults: {list}. A review signs them; check that you set them in trail.toml.",
      { list: keys.map((k) => `${k}=${JSON.stringify(differs[k].value)} (${t("built-in")} ${JSON.stringify(differs[k].builtin)})`).join(", ") }) }) : null,
  ];
}
function reviewPanel(sheet, { onDone } = {}) {
  const scope = sheet.scope;
  const profile = sheet.profile || {};
  const testMode = !!(S.overview && S.overview.status && S.overview.status.test_mode) || (profile.params || {}).test_tsa === true;
  const dispositions = {};
  const notes = {};
  const list = h("div", { class: "findings" });
  if (!sheet.findings.length) put(list, h("p", { class: "small", text: t("No findings in this period.") }));
  for (const f of sheet.findings) {
    const select = h("select", { "aria-label": t("Disposition of {id}", { id: f.id }) },
      ["ok", "explained", "deviation"].map((d) => h("option", { value: d, text: t(d) })));
    const note = h("input", { type: "text", placeholder: t("Note (needed unless ok)"), "aria-label": t("Note on {id}", { id: f.id }) });
    dispositions[f.id] = select;
    notes[f.id] = note;
    put(list, h("div", { class: "finding" },
      h("p", { class: "small" }, h("strong", { text: f.id }), " ", stWord(f.severity), ` ${f.query} · `,
        t("{n} record(s)", { n: f.record_ids.length })),
      h("p", { class: "small muted break", text: findingText(sheet, f) }), h("div", { class: "field-row" }, select, note)));
  }
  const actors = sheet.actors_reviewed || [];
  const signers = (sheet.signers || []).filter((s) => !actors.includes(s.id));
  const panel = decisionPanel({
    title: t("Sign the review"),
    actions: [{ id: "sign", label: t("Sign review"), meaning: "reviewed", button: t("Sign the review"),
      consequence: t("Records the signed review of seq {from}–{to} with your dispositions; it then counts as the last review.", { from: scope.from_seq, to: scope.to_seq }) }],
    signers, onDone,
    noSigners: (sheet.signers || []).length ? t("Every registered signer acted in this period. The review needs an independent person who did not act in it.") : null,
    subject: { label: t("worksheet {id}, seq {from}–{to}", { id: sheet.id, from: scope.from_seq, to: scope.to_seq }), hash: scope.head },
    note: t("Independence: people who acted in the period may not sign its review."),
    command: () => `aqt trail review sign ${sq(sheet.path)} --reviewer <${t("your ID")}> ${Object.entries(dispositions).map(([k, el]) => `--disposition ${sq(`${k}=${el.value}`)}`).join(" ") || "--disposition all=ok"} --reason "…"`,
    submit: (a, values) => post(`/api/trail/review/${encodeURIComponent(sheet.id)}/sign`, {
      ...values, head: scope.head, worksheet_sha256: sheet.worksheet_sha256,
      dispositions: Object.fromEntries(Object.entries(dispositions).map(([k, el]) => [k, el.value])),
      notes: Object.fromEntries(Object.entries(notes).map(([k, el]) => [k, el.value])),
    }),
  });
  return [
    inspSection(t("Audit-trail review"), h("p", { class: "insp-title mono", text: sheet.id }),
      kv([[t("Records"), `seq ${scope.from_seq}–${scope.to_seq} (${num(scope.count)})`], [t("Period"), `${scope.since || t("start")} – ${scope.until || t("now")}`],
        [t("Head"), hashButton(scope.head, 16)], [t("Acted in the period"), actors.join(", ") || t("none")], [t("Worksheet"), h("span", { class: "mono small", text: sheet.path })],
        [t("Profile"), [profile.name || "?", " · ", profileWord(profile)]],
        [t("Parameters"), h("span", { class: "mono small break", text: Object.entries(profile.params || {}).sort().map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(", ") })]]),
      profileNotes(profile, testMode)),
    inspSection(t("Findings ({n})", { n: sheet.findings.length }), list),
    panel,
  ];
}
// A finding's explanation in the chosen language (its code is in the worksheet's finding_codes).
function findingText(sheet, f) {
  const c = (sheet.finding_codes || {})[f.id];
  return c ? msg(c.code, c.args, f.explanation) : f.explanation;
}
function exportSection() {
  return inspSection(t("Export"),
    h("p", { class: "small muted", text: t("A verification bundle: the trail, checkpoints, public keys and instructions, for an auditor to check offline. Creating it records nothing.") }),
    downloadButton("/api/trail/export", "aqt-trail-bundle.tar.gz", t("Download bundle (.tar.gz)")));
}

// How far the writer's observation backs a human claim, in the review's words (aqt-trail attribution).
function attributionNote(a) {
  if (!a || a.state === "human") return null;
  const text = a.state === "agent" ? (a.drained ? t("This record claims a human; it came through the spool and was drained by an agent harness ({harness}).", { harness: a.harness || "?" }) : t("This record claims a human but came from an agent harness."))
    : a.state === "unconfirmed" ? (a.via === "spool" ? t("Unconfirmed: this record claims a human, but it came through the spool, so its sender was not observed.") : t("Unconfirmed: this record claims a human, but the sender's process chain was incomplete or unreadable (chain status {status}).", { status: a.chain_status || "–" }))
    : t("Legacy: written before chain status existed; only the absence of agent markers speaks for a human.");
  return h("p", { class: a.state === "legacy" ? "small muted" : "flag", text });
}
async function openRecord(row) {
  const data = await api(`/api/trail/record/${encodeURIComponent(row.id)}`);
  const r = data.record;
  const obs = data.observed || {};
  const drained = obs.drained_by || null;
  const sig = data.signature;
  setInspector(
    inspSection(t("Record"), h("p", { class: "insp-title mono", text: r.id }), kv([
      [t("Type"), r.type], [t("Action"), r.action], [t("Time"), fmtTime(r.time)], ["UTC", h("span", { class: "mono", text: r.time })],
      ["Seq", num((r.chain || {}).seq)], [t("Previous"), hashButton((r.chain || {}).prev)],
      [t("Meaning"), r.meaning ? t(r.meaning) : "–"], [t("Reason"), r.reason || "–"], [t("Subject"), r.subject ? `${r.subject.kind}: ${r.subject.ref}` : "–"],
    ])),
    inspSection(t("Who"), kv([
      [t("Claimed"), `${r.actor.id}${r.actor.role ? " (" + r.actor.role + ")" : ""}`],
      [t("Observed"), obs.process_chain && obs.process_chain.length ? obs.process_chain.join(" ← ") : (obs.via || obs.origin || t("not observed"))],
      [t("Harness"), obs.harness || t("none detected")], [t("Via"), obs.via || obs.origin || "–"],
      [t("Chain status"), obs.chain_status ? `${codeWord("trail.chain_status.", obs.chain_status)}${obs.chain_detail ? " (" + msg("trail.observe.", null, obs.chain_detail) + ")" : ""}` : "–"],
      drained ? [t("Drained by"), `${(drained.process_chain || []).join(" ← ") || "–"}${drained.harness ? " · " + drained.harness : ""} · ${drained.chain_status || "–"}`] : null,
    ]), attributionNote(data.attribution)),
    inspSection(t("Signatures"), (r.sig || []).map((s) => kv([[t("Writer key"), h("code", { text: s.key })]])),
      sig ? kv([[t("Detached"), h("span", {}, stWord(sig.status), ` ${sig.meaning ? t(sig.meaning) : "–"} · ${sig.signer || "–"}`)],
        sig.detail ? [t("Check"), msgOf(sig, "detail")] : null, [t("Key"), h("code", { text: sig.key || "–" })]]) : null),
    inspSection(t("Stored record (text)"), h("pre", { class: "json", text: JSON.stringify(r, null, 2) })),
  );
}

// ---- Quarantine ----------------------------------------------------------------------------------
async function renderQuarantine(main) {
  const q = query();
  const tab = q.get("tab") || (q.get("trust") ? "sources" : "cases");
  const state = q.get("state") || "held";
  const data = await api(`/api/quarantine?state=${encodeURIComponent(state)}`);
  clear(main);
  put(main, tabs([["cases", t("Cases")], ["sources", t("Trusted sources ({n})", { n: data.sources.length })]], tab, (id) => { setQuery({ tab: id }); route(); }));
  if (tab === "sources") {
    put(main, h("div", { class: "filterbar" },
      h("button", { class: "btn small primary", type: "button", text: t("Trust a source…"), onclick: () => trustForm("", data.signers) }),
      h("span", { class: "small muted", text: t("Trust lowers the band of later content from a domain. It releases no case.") })));
    if (q.get("trust") !== null) trustForm(q.get("trust") || "", data.signers);
    if (!data.sources.length) { put(main, empty(t("No trusted sources"), t("Every source is scanned with the normal thresholds."))); return; }
    const rows = data.sources.map((s) => ({ data: s, cells: [h("td", { class: "mono", text: s.domain }), s.subdomains ? t("with subdomains") : t("exact"),
      h("td", {}, stWord(s.active ? "valid" : "expired", s.active ? t("until {date}", { date: s.expires }) : t("expired {date}", { date: s.expires }))), h("td", { class: "mono small", text: s.by || "" })] }));
    put(main, table([t("Domain"), t("Scope"), t("Expires"), t("Trusted by")], rows, (s) => openSource(s, data.signers)).table);
    return;
  }
  const counts = data.counts || {};
  const bar = h("div", { class: "filterbar" }, h("div", { class: "chips", role: "group", "aria-label": t("Case state") },
    [["held", t("Held")], ["warned", t("Warned")], ["released", t("Released")], ["threat", t("Threat")], ["all", t("All")]].map(([id, label]) =>
      h("button", { class: "chip-btn", type: "button", "aria-pressed": state === id ? "true" : "false",
        text: `${label}${id === "all" ? "" : ` ${counts[id] || 0}`}`, onclick: () => { setQuery({ state: id }); route(); } }))),
    data.outbox ? h("span", { class: "small", text: t("{n} record(s) waiting in the quarantine outbox (aqt-quarantine flush)", { n: data.outbox }) }) : null,
    data.journal_problem_count ? h("span", { class: "small flag", title: data.journal_problems.join("\n"), text: t("{n} journal line(s) ignored: malformed, or reopening a case (aqt-quarantine doctor)", { n: data.journal_problem_count }) }) : null);
  put(main, bar);
  if (!data.cases.length) {
    put(main, empty(state === "held" ? t("No held cases") : t("No cases in this state"), state === "held" ? t("Nothing waits for a quarantine decision.") : ""));
    return;
  }
  const rows = data.cases.map((c) => ({ data: c, cells: [
    h("td", { class: "mono", text: c.case_id }), h("td", {}, stWord(c.state)), h("td", { class: "hide-narrow", text: t(c.band) }),
    h("td", { class: "wrap", text: c.domain || c.tool || "–" }), h("td", { class: "num", text: num(c.score_ppm) }),
    h("td", { class: "small", text: ago(c.opened) }), h("td", { class: "hide-narrow mono small", text: c.session || "–" }),
    h("td", { class: "hide-narrow num", text: c.refused ? `${c.refused}` : "" })] }));
  const x = table([t("Case"), t("State"), th(t("Band"), "hide-narrow"), t("Source"), th(t("Score ppm"), "num"), t("Age"),
    th(t("Session"), "hide-narrow"), th(t("Refused"), "hide-narrow num")], rows, (c) => openCase(c.case_id, false));
  x.table.classList.add("with-filter");
  put(main, x.table);
  const wanted = q.get("item");
  const index = wanted ? data.cases.findIndex((c) => c.case_id === wanted) : -1;
  if (index >= 0) x.tbody.children[index].click();
}

const TRUST_NOTE = "Trusting a source only lowers the band for content that arrives from this domain later. It does not release any held case: decide those one by one.";
function trustForm(domain, signers) {
  const nextYear = new Date(Date.now() + 90 * 86400000).toISOString().slice(0, 10);
  const domainInput = h("input", { id: "trust-domain", type: "text", value: domain, placeholder: "docs.example.org", spellcheck: "false" });
  const expires = h("input", { id: "trust-expires", type: "date", value: nextYear, min: new Date().toISOString().slice(0, 10) });
  const subdomains = h("input", { id: "trust-sub", type: "checkbox" });
  const label = h("span", {});
  const describe = () => { label.textContent = vis(t("domain {domain} until {date}{sub}", { domain: domainInput.value.trim() || "?", date: expires.value || "?", sub: subdomains.checked ? t(", with subdomains") : "" })); };
  for (const el of [domainInput, expires, subdomains]) el.addEventListener("input", describe);
  subdomains.addEventListener("change", describe);
  describe();
  const fields = h("div", {},
    h("div", { class: "field" }, h("label", { for: "trust-domain", text: t("Domain") }), domainInput),
    h("div", { class: "field" }, h("label", { for: "trust-expires", text: t("Trusted until") }), expires),
    h("div", { class: "check" }, subdomains, h("label", { for: "trust-sub", text: t("Include subdomains") })));
  setInspector(
    inspSection(t("Trust a source"), h("p", { class: "note-box", text: t(TRUST_NOTE) })),
    decisionPanel({
      actions: [{ id: "trust", label: t("Trust source"), meaning: "approved", button: t("Sign and trust") }],
      signers, fields, subject: { label },
      command: () => `aqt quarantine trust-source ${sq(domainInput.value.trim() || "<domain>")} --expires ${sq(expires.value || "<YYYY-MM-DD>")}${subdomains.checked ? " --subdomains" : ""} --reason "…"`,
      submit: (a, values) => post("/api/quarantine/sources/trust", { ...values, domain: domainInput.value.trim(), expires: expires.value, subdomains: subdomains.checked }),
    }));
}
function openSource(s, signers) {
  setInspector(
    inspSection(t("Trusted source"), h("p", { class: "insp-title mono", text: s.domain }),
      kv([[t("Expires"), s.expires], [t("Subdomains"), s.subdomains ? t("yes") : t("no")], [t("By"), s.by], [t("Reason"), s.reason], [t("Record"), h("code", { text: s.record })]]),
      h("p", { class: "small muted", text: t(TRUST_NOTE) })),
    s.active ? decisionPanel({
      actions: [{ id: "revoke", label: t("Revoke trust"), meaning: "rejected", button: t("Sign and revoke trust"), danger: true }],
      signers, subject: { label: t("trust in {domain} ({record})", { domain: s.domain, record: s.record }) },
      command: () => `aqt quarantine trust-source ${sq(s.domain)} --revoke --reason "…"`,
      submit: (a, values) => post("/api/quarantine/sources/revoke", { ...values, domain: s.domain, record: s.record }),
    }) : null);
}

// Release and declare are offered only after every page of the content was shown in this session.
function quarantineCase(caseId, full, page) {
  return api(`/api/quarantine/${encodeURIComponent(caseId)}${full ? `?full=1&page=${page || 0}` : ""}`);
}
async function openCase(caseId, full, page) {
  const c = await quarantineCase(caseId, full, page);
  const p = quarantineParts(c, { full, open: (f, pg) => openCase(caseId, f, pg) });
  setInspector(p.summary, p.evidence, p.content, p.journal, p.history, p.decision);
}
// The parts of a quarantine case, for the inspector and the case page. open(full, page) shows
// another view of the content; onDone goes to the decision panel.
function quarantineParts(c, { full, open, onDone }) {
  const content = h("div");
  const unseen = c.unseen_pages || [];
  if (c.content) {
    const pre = h("pre", { class: "text", tabindex: "0", "aria-label": t("Case content, untrusted") });
    for (const w of c.content.windows) {
      if (w.cut_before) put(pre, h("span", { class: "muted", text: "… " }));
      for (const piece of w.pieces) put(pre, piece.mark ? h("mark", { title: piece.mark.split("; ").map(detectorReason).join("; "), text: piece.text }) : document.createTextNode(vis(piece.text)));
      if (w.cut_after) put(pre, h("span", { class: "muted", text: " …" }));
      put(pre, "\n\n");
    }
    put(content, h("p", { class: "untrusted", text: t("Untrusted third-party text. Highlighted passages are detector evidence; hidden characters are shown as <U+XXXX>.") }), pre,
      !full && !c.content.complete ? h("button", { class: "btn small", type: "button", text: t("Show full content ({n} characters)", { n: num(c.content.chars) }), onclick: () => open(true, unseen.length ? unseen[0] : 0) }) : null,
      full && c.content.pages > 1 ? contentPager(c, (p) => open(true, p)) : null);
  } else put(content, h("p", { class: "muted", text: msgOf(c, "content_error") || t("Content not available.") }));
  const fullFirst = c.needs_full_view ? h("div", { class: "note-box" },
    h("p", { class: "small", text: t("Release and threat declaration need the whole content on screen first. Not shown yet: {n} of {pages} page(s).", { n: unseen.length, pages: c.content.pages }) }),
    h("button", { class: "btn small primary", type: "button", text: t("Show page {page}", { page: unseen[0] + 1 }), onclick: () => open(true, unseen[0]) })) : null;
  const actions = [];
  if (c.can_release) actions.push({ id: "release", label: t("Release"), meaning: "released", button: t("Sign and release"),
    consequence: c.reached_model ? t("Confirms the content as harmless. The agent already received it, marked as untrusted.")
      : c.state === "threat" ? t("Overrules the threat decision: the agent receives this content with its next prompt, still marked as untrusted.")
        : t("The agent receives this content with its next prompt, still marked as untrusted.") });
  if (c.can_declare) actions.push({ id: "threat", label: t("Declare threat"), meaning: "rejected", button: t("Sign and declare threat"), danger: true,
    consequence: c.reached_model ? t("Records the case as a threat. The agent already received the content; that cannot be taken back.")
      : t("The content stays withheld from the agent, and the case is recorded as a threat.") });
  const panel = actions.length ? decisionPanel({
    actions, signers: c.signers, subject: { label: t("case {id}, content", { id: c.case_id }), hash: c.content_sha256,
      summary: [c.domain || c.tool || null, t("score {n} ppm", { n: num(c.score_ppm) })].filter(Boolean).join(", ") },
    note: c.state === "threat" ? t("This case was declared a threat; releasing it overrules that decision.") : null, onDone,
    command: (a) => a.id === "release" ? `aqt quarantine release ${sq(c.case_id)}${c.state === "threat" ? " --overrule-threat" : ""} --reason "…"` : `aqt quarantine declare-threat ${sq(c.case_id)} --reason "…"`,
    submit: (a, values) => post(`/api/quarantine/${encodeURIComponent(c.case_id)}/${a.id}`, { ...values, content_sha256: c.content_sha256, overrule_threat: c.state === "threat" }),
  }) : null;
  return {
    summary: inspSection(t("Quarantine case"), h("p", { class: "insp-title mono", text: c.case_id }), stWord(c.state), " ", h("span", { class: "muted small", text: `${t("band")} ${t(c.band)}` }),
      kv([[t("Source"), c.ref || c.domain || "–"], [t("Tool"), c.tool], [t("Session"), c.session || "–"], [t("Score"), `${num(c.score_ppm)} ppm`],
        [t("Detectors"), c.detectors.map((d) => `${d.id} ${d.version}: ${num(d.score_ppm)} ppm`).join("; ") || "–"],
        [t("Thresholds"), `${c.thresholds.version || "?"} ${c.thresholds.calibrated ? t("calibrated") : t("NOT calibrated (defaults)")}`],
        [t("Opened"), fmtTime(c.opened)], [t("Reached model"), c.reached_model ? t("yes") : t("no")], [t("Content"), hashButton(c.content_sha256)], [t("Record"), h("code", { text: c.opened_record })]]),
      c.domain ? h("p", { class: "small" }, link(t("Trust {domain} for later content…", { domain: c.domain }), `/evidence/quarantine?tab=sources&trust=${encodeURIComponent(c.domain)}`)) : null),
    evidence: c.evidence.length ? inspSection(t("Detector findings"), h("ul", { class: "evidence-list" }, c.evidence.map((e) => h("li", {}, h("strong", { text: e.label }), ` (${e.detector}): ${detectorReason(e.reason)} `, h("code", { text: e.excerpt }))))) : null,
    content: inspSection(t("Content"), content),
    journal: c.journal_problems && c.journal_problems.length ? inspSection(t("Journal lines ignored for this case"),
      c.journal_problems.map((p) => h("p", { class: "small flag break", text: p }))) : null,
    history: c.decisions.length || c.refusals.length ? inspSection(t("History"),
      c.decisions.map((d) => h("p", { class: "small" }, `${fmtTime(d.time)} ${d.action} · ${d.display || ""} ${d.by} · ${t("signature")} `, stWord(d.status), d.honoured ? "" : ` (${t("not honoured")})`, d.note ? ` ${msgOf(d, "note")}` : "", h("br"), h("span", { class: "muted", text: `${t("Reason")}: ${d.reason}` }))),
      c.refusals.map((r) => h("p", { class: "small" }, stWord("fail", t("refused")), ` ${fmtTime(r.time)} ${r.attempted}${refusalWords(r.reason_code) ? ": " + refusalWords(r.reason_code) : ""} (${r.reason_code}${r.markers.length ? "; " + r.markers.join(", ") : ""})`))) : null,
    decision: fullFirst ? inspSection(t("Decision"), fullFirst) : panel,
  };
}
// A detector's span reason (records keep the English): the catalogue entry it matches.
function detectorReason(reason) { return msg("quarantine.detector.", null, reason); }
function contentPager(c, open) {
  const w = c.content.windows[0];
  const page = c.content.page;
  return h("nav", { class: "pager", "aria-label": t("Pages") },
    h("button", { class: "btn small", type: "button", text: t("Previous page"), disabled: page === 0, onclick: () => open(page - 1) }),
    h("span", { class: "small muted", text: t("Page {page} of {pages}, characters {from}–{to} of {n}", { page: page + 1, pages: c.content.pages, from: num(w.from + 1), to: num(w.to), n: num(c.content.chars) }) }),
    h("button", { class: "btn small", type: "button", text: t("Next page"), disabled: page + 1 >= c.content.pages, onclick: () => open(page + 1) }));
}

// ---- Changes ------------------------------------------------------------------------------------------
async function renderChanges(main) {
  const q = query();
  const tab = q.get("tab") || (q.get("item") && q.get("item").startsWith("act_") ? "actions" : "gates");
  const data = await api("/api/changes");
  clear(main);
  put(main, tabs([["gates", t("Gates")], ["actions", t("Prepared actions ({n})", { n: data.actions.length })]], tab, (id) => { setQuery({ tab: id }); route(); }));
  if (tab === "actions") {
    if (!data.installed["aqt-signoff"]) { put(main, empty(t("aqt-signoff is not installed"), installOf("aqt-signoff"))); return; }
    if (!data.actions.length) { put(main, empty(t("No prepared actions"), t("Actions appear here when an agent prepares one with aqt-signoff action prepare."))); return; }
    const order = { prepared: 0, expired: 0, unknown: 1, approved: 2, claimed: 3 };
    const actions = data.actions.slice().sort((a, b) => (order[a.status] ?? 9) - (order[b.status] ?? 9));
    const rows = actions.map((a) => ({ data: a, cells: [h("td", { class: "mono", text: a.id }), h("td", {}, stWord(a.status)), h("td", { class: "wrap", text: (a.spec && a.spec.description) || msgOf(a, "detail") }),
      h("td", { class: "hide-narrow mono small", text: (a.preparer && a.preparer.id) || "" }), h("td", { class: "hide-narrow" }, hashButton(a.action_sha256, 10))] }));
    const x = table([t("Action"), t("Status"), t("What"), th(t("Prepared by"), "hide-narrow"), th("Hash", "hide-narrow")], rows, (a) => openAction(a.id, data.signers));
    put(main, x.table);
    const wanted = q.get("item");
    const i = wanted ? actions.findIndex((a) => a.id === wanted) : -1;
    if (i >= 0) x.tbody.children[i].click();
    return;
  }
  if (!data.installed["aqt-change"]) { put(main, empty(t("aqt-change is not installed"), installOf("aqt-change"))); return; }
  if (!data.projects.length) { put(main, h("div", { class: "empty" }, h("strong", { text: t("No project connected yet") }), h("span", { text: t("Changes appear here once a project is connected.") }), " ", link(t("Connect a project…"), "/projects"))); return; }
  for (const project of data.projects) {
    const box = section(h("span", { class: "path", text: project.root }));
    if (project.error) put(box, h("div", { class: "error-box", text: project.error }));
    else if (!project.plans.length) put(box, h("p", { class: "muted", text: t("No registered plans in this repository.") }));
    else {
      const rows = project.plans.map((p) => ({ data: p, cells: [h("td", { class: "mono", text: p.plan_id }), h("td", {}, gateChip(p.decision)),
        h("td", { class: "wrap small" }, p.error ? p.error : (p.reasons[0] ? [reasonText(p.reasons[0]), " ", h("code", { class: "muted", text: p.reasons[0].code })] : t("All checks passed"))),
        h("td", { class: "hide-narrow" }, approvalChip(p.approval)), h("td", { class: "hide-narrow mono small", text: p.path })] }));
      const x = table([t("Plan"), t("Gate"), t("First reason"), th(t("Approval"), "hide-narrow"), th(t("File"), "hide-narrow")], rows, (p) => openGate(p, project.root, data.signers, project.project));
      put(box, x.table);
      const wanted = q.get("item");
      const i = wanted ? project.plans.findIndex((p) => p.plan_id === wanted) : -1;
      if (i >= 0) x.tbody.children[i].click();
    }
    put(main, box);
  }
}
function reasonText(r) { return (LANG === "de" && REASONS_DE[r.code]) || r.text; }
function gateChip(decision) {
  if (!decision) return stWord("neutral", t("not evaluated"));
  return decision === "GO" ? st("pass", "GO") : decision === "NO-GO" ? st("fail", "NO-GO") : st("warn", "MANUAL");
}
const APPROVAL_WORDS = { signed: "approved", unsigned: "not approved", stale: "approval stale", invalid: "approval invalid", unverified: "approval not verified" };
function approvalChip(a) {
  if (!a) return "–";
  return stWord(a.state, t(APPROVAL_WORDS[a.state] || a.state));
}
function openGate(p, root, signers, project) {
  const g = gateParts(p, root, signers, {});
  setInspector(g.gate, g.reasons, g.receipts, g.approval,
    project !== null && project !== undefined ? inspSection(null, h("div", { class: "actions" }, h("button", { class: "btn small", type: "button", text: t("Open the change page"),
      onclick: () => go(changePath(project, p.plan_id)) }))) : null,
    g.decision);
}
function reasonList(reasons) {
  return h("ul", { class: "evidence-list" }, reasons.map((r) => h("li", {}, reasonText(r), " ", h("code", { class: "muted", text: r.code }), r.item ? ` · ${t("check item")} ${r.item}` : "", r.detail ? ` · ${msgOf(r, "detail")}` : "")));
}
function receiptList(receipts) {
  return receipts.length ? receipts.map((r) => h("div", { class: "receipt small" }, h("strong", { text: r.item }), " ", stWord(r.state === "ok" ? "fresh" : r.state, r.state === "ok" ? t("fresh") : t(r.state)), " ", r.text || "",
    r.commands.map((c) => h("div", { class: "muted" }, h("code", { text: c.command }), ` · ${t(c.state || "")}${c.counts ? " · " + countsText(c.counts) : ""}`)))) : h("p", { class: "muted", text: t("No verification items.") });
}
// The parts of a gate, for the inspector, the case pages and the change page.
function gateParts(p, root, signers, { onDone }) {
  const a = p.approval || {};
  const canApprove = a.record && a.sha256 && a.state !== "signed";
  return {
    gate: inspSection(t("Gate"), h("p", { class: "insp-title mono", text: p.plan_id }), gateChip(p.decision), kv([[t("File"), p.path], [t("Evaluated"), fmtTime(p.evaluated_at)], [t("Finish"), p.finish ? h("code", { text: p.finish }) : t("not finished")]])),
    reasons: p.error ? inspSection(t("Not evaluated"), h("p", { class: "small", text: p.error })) : inspSection(t("Reasons"), p.reasons.length ? reasonList(p.reasons) : h("p", { text: t("No reasons: the gate is GO.") })),
    receipts: inspSection(t("Receipts"), receiptList(p.receipts)),
    approval: inspSection(t("Approval"), kv([[t("State"), approvalChip(p.approval)], [t("Version"), a.record ? h("code", { text: a.record }) : "–"], [t("Hash"), hashButton(a.sha256, 16)], [t("Reviews"), (p.reviews || []).join(", ") || t("none fresh")]])),
    decision: canApprove ? decisionPanel({
      title: t("Approve this plan version"), onDone,
      actions: [{ id: "approve", label: t("Approve plan"), meaning: "approved", button: t("Sign and approve plan"),
        consequence: t("You sign this version of the plan. The agent works within its scope; a later change of its scope or checks makes the approval stale.") }],
      signers, subject: { label: t("plan {plan}, version {record}", { plan: p.plan_id, record: a.record }), hash: a.sha256 },
      command: () => `aqt signoff sign --record ${sq(a.record)} --meaning approved --reason "…"`,
      submit: (x, values) => post("/api/changes/plans/approve", { ...values, root, plan_id: p.plan_id, record: a.record, sha256: a.sha256 }),
    }) : null,
  };
}
async function openAction(id, signers) {
  const a = await api(`/api/changes/actions/${encodeURIComponent(id)}`);
  const x = actionParts(a, signers || a.signers, {});
  setInspector(x.summary, x.spec, x.decision);
}
// The parts of a prepared action, for the inspector and the case page.
function actionParts(a, signers, { onDone }) {
  const open = a.spec_ok && ["prepared", "approved", "expired"].includes(a.status);
  const specText = JSON.stringify(a.spec, null, 2);
  return {
    summary: inspSection(t("Prepared action"), h("p", { class: "insp-title mono", text: a.id }), stWord(a.status), a.detail ? h("span", { class: "muted small", text: ` ${msgOf(a, "detail")}` }) : null,
      kv([[t("Version"), a.version], [t("Prepared by"), (a.preparer && a.preparer.id) || "–"], ["Hash", hashButton(a.action_sha256, 16)], [t("Updated"), fmtTime(a.updated_at)],
        [t("Approvals"), a.approvals.length ? a.approvals.map((x) => `${x.signer} (${x.role})`).join(", ") : t("none")]])),
    spec: inspSection(t("What will run (text)"),
      a.spec_ok ? null : h("p", { class: "flag", role: "alert", text: `${t("Not decidable here:")} ${msgOf(a, "spec_error")}` }),
      vis(specText) !== specText ? h("p", { class: "flag", text: t("The specification contains hidden characters, shown as <U+XXXX>. Check exactly what will run.") }) : null,
      h("pre", { class: "json", text: specText })),
    decision: open ? decisionPanel({
      actions: [{ id: "approve", label: t("Approve"), meaning: "approved", button: t("Sign and approve"),
        consequence: t("Counts as an approval of this exact version (its hash); with enough approvals it may run once. A changed version needs a new approval.") },
      { id: "reject", label: t("Reject"), meaning: "rejected", button: t("Sign and reject"), danger: true,
        consequence: t("This version will not run. The agent has to prepare a new version.") }],
      signers, subject: { label: t("action {id} v{version}", { id: a.id, version: a.version }), hash: a.action_sha256 }, onDone,
      command: (choice) => `aqt signoff ${choice.id} ${sq(a.id)} --hash ${sq(a.action_sha256)} --reason "…"`,
      submit: (choice, values) => post(`/api/changes/actions/${encodeURIComponent(a.id)}/${choice.id}`, { ...values, expected_hash: a.action_sha256 }),
    }) : null,
  };
}

// ---- Signatures --------------------------------------------------------------------------------------
async function renderSignatures(main) {
  clear(main);
  if (!S.installed.aqt_signoff) { put(main, empty(t("aqt-signoff is not installed"), installOf("aqt-signoff"))); return; }
  const kind = h("select", { "aria-label": t("What to verify") }, [["file", t("Local file path")], ["record", t("Record ID")], ["sha256", t("SHA-256 hash")]].map(([v, x]) => h("option", { value: v, text: x })));
  const value = h("input", { class: "grow", type: "text", placeholder: "/home/me/project/plan.md", "aria-label": t("Value to verify") });
  const out = h("div");
  const run = async () => {
    clear(out);
    if (!value.value.trim()) return;
    const params = new URLSearchParams({ [kind.value]: value.value.trim() });
    try {
      const r = await api(`/api/signatures/verify?${params}`);
      const rows = r.rows.map((x) => ({ data: x, cells: [x.name, h("td", { class: "mono small", text: x.id }), x.role, t(x.meaning), h("td", { class: "small", text: x.local }), h("td", { class: "wrap small", text: x.reason }), h("td", {}, stWord(x.status), x.status !== "valid" && x.detail ? h("span", { class: "small muted", text: ` ${msgOf(x, "detail")}` }) : null)] }));
      put(out, section(t("Result"), h("p", {}, stWord(r.ok ? "valid" : "warn", msgOf(r, "summary"))), kv([[t("Subject"), `${r.subject.kind}: ${r.subject.ref}`], [t("Content"), hashButton(r.subject.sha256, 20)]]),
        rows.length ? table([t("Printed name"), "ID", t("Role"), t("Meaning"), t("Local time"), t("Reason"), t("Status")], rows, (x) => setInspector(inspSection(t("Signature"), kv(Object.entries(x).map(([k, v]) => [k, String(v)]))))).table : h("p", { class: "muted", text: t("No signatures over this content.") }),
        h("p", { class: "small" }, t("Download the manifest:"), " ", downloadButton(`/api/signatures/manifest?${params}&format=md`, "signature-manifest.md", "Markdown", "btn small ghost"), " ",
          downloadButton(`/api/signatures/manifest?${params}&format=html`, "signature-manifest.html", "HTML", "btn small ghost")),
        h("p", { class: "small muted", text: t("Viewing never records anything. aqt-signoff verify in a terminal records a changed-content invalidation.") })));
    } catch (error) { put(out, errorBox(error)); }
  };
  put(main, h("div", { class: "filterbar", role: "search" }, kind, value, h("button", { class: "btn small primary", type: "button", text: t("Verify"), onclick: run })), out);
  value.addEventListener("keydown", (e) => { if (e.key === "Enter") run(); });
  const reg = await api("/api/signatures");
  const rows = reg.signers.map((s) => ({ data: s, cells: [s.name, h("td", { class: "mono small", text: s.id }), s.role, h("td", {}, s.active_key ? stWord("valid", t("active key")) : stWord("revoked", t("no active key"))), h("td", { class: "hide-narrow mono small", text: s.active_key || "" })] }));
  put(main, section([`${t("Signer registry")} `, h("span", { class: "hint muted", text: reg.path })], rows.length ? table([t("Printed name"), "ID", t("Role"), t("Key"), th(t("Key ID"), "hide-narrow")], rows,
    (s) => setInspector(inspSection(t("Signer"), h("p", { class: "insp-title", text: s.name }), kv([["ID", s.id], [t("Role"), s.role]]),
      s.keys.map((k) => kv([[t("Key"), h("code", { text: k.key_id })], [t("Enrolled"), fmtTime(k.enrolled_at)], [t("Revoked"), k.revoked_at ? fmtTime(k.revoked_at) : t("no")]]))))).table
    : h("p", { class: "muted", text: t("No signers registered. Enrol in a terminal: aqt-signoff init") })));
}

// ---- CAPA --------------------------------------------------------------------------------------------
const CAPA_NOTE = "aqt-capa records this decision under your signer ID once your passphrase has unlocked your key; the record itself carries no signature, as on the command line.";
async function renderCapa(main) {
  const data = await api("/api/capa");
  const c = data.counts;
  // Candidates waiting for a decision come first; otherwise the deviations.
  const tab = query().get("tab") || (c.candidates ? "candidates" : "deviations");
  clear(main);
  put(main, tabs([["candidates", t("Candidates ({n})", { n: c.candidates })], ["deviations", t("Deviations ({n} open)", { n: c.open })], ["effectiveness", t("Effectiveness")]],
    tab, (id) => { setQuery({ tab: id }); route(); }));
  if (tab === "candidates") {
    if (!data.candidates.length) { put(main, empty(t("No open candidates"), t("aqt-capa scan finds candidates in the evidence."))); return; }
    const rows = data.candidates.map((x) => ({ data: x, cells: [h("td", { class: "mono small", text: x.candidate_id }), h("td", { class: "hide-narrow", text: x.rule }), h("td", { class: "wrap", text: candidateTitle(x) }), x.severity ? t(x.severity) : "–", h("td", { class: "small hide-narrow", text: ago(x.time) })] }));
    put(main, table([t("Candidate"), th(t("Rule"), "hide-narrow"), t("What"), t("Severity"), th(t("When"), "hide-narrow")], rows, (x) => {
      const c = candidateParts(x, data.signers, {});
      setInspector(c.summary, c.decision);
    }).table);
    return;
  }
  if (tab === "effectiveness") {
    if (data.effectiveness_error) put(main, h("div", { class: "error-box", text: data.effectiveness_error }));
    if (!data.effectiveness.length) { put(main, empty(t("No running effectiveness checks"), t("They start when a corrective action is approved."))); return; }
    const rows = data.effectiveness.map((e) => ({ data: e, cells: [h("td", { class: "mono", text: e.action_id }), h("td", { class: "mono", text: e.dev_id }), h("td", {}, stWord(e.result)), h("td", { class: "wrap small", text: msgList(e.reasons, e.reason_codes).join("; ") })] }));
    put(main, table([t("Action"), t("Deviation"), t("Result"), t("Why")], rows, (e) => openDeviation(e.dev_id)).table,
      h("p", { class: "small muted section", text: t("Shown without recording; aqt-capa effectiveness in a terminal records changed results.") }));
    return;
  }
  if (!data.deviations.length) { put(main, empty(t("No deviations"), t("Accepted candidates and deviations opened with aqt-capa appear here."))); return; }
  const rows = data.deviations.map((d) => ({ data: d, cells: [h("td", { class: "mono", text: d.dev_id }), h("td", {}, d.overdue ? st("fail", t("overdue")) : stWord(d.state === "closed" ? "closed" : "open", t(d.state))),
    h("td", { class: "wrap", text: d.title }), h("td", { class: "hide-narrow", text: t(d.severity) }), h("td", { class: "hide-narrow small", text: d.due ? fmtTime(d.due) : "–" })] }));
  put(main, table([t("Deviation"), t("State"), t("Title"), th(t("Severity"), "hide-narrow"), th(t("Due"), "hide-narrow")], rows, (d) => openDeviation(d.dev_id)).table,
    h("p", { class: "section small" }, downloadButton("/api/capa/trends", "capa-trends.md", t("Download the trend summary (Markdown)"), "btn small ghost")));
}
// A candidate's title (stored English): the catalogue entry of its rule that it matches.
function candidateTitle(x) { return msg(`capa.candidate.${String(x.rule || "").replace(/-/g, "_")}`, null, x.title); }
// The parts of a CAPA candidate, for the inspector and the case page.
function candidateParts(x, signers, { onDone }) {
  return {
    summary: inspSection(t("Candidate"), h("p", { class: "insp-title", text: candidateTitle(x) }),
      kv([["ID", h("code", { text: x.candidate_id })], [t("Rule"), x.rule], [t("Source"), `${x.source_type}: ${x.source_ref}`], [t("Severity"), x.severity ? t(x.severity) : "–"], [t("Session"), x.session || "–"], [t("Time"), fmtTime(x.time)]])),
    decision: decisionPanel({
      actions: [{ id: "accept", label: t("Accept as deviation"), meaning: "accepted", button: t("Accept as deviation"),
        consequence: t("Opens a deviation that needs an investigation and, where needed, a corrective action.") },
      { id: "dismiss", label: t("Dismiss"), meaning: "dismissed", button: t("Dismiss candidate"), danger: true,
        consequence: t("Closes the candidate with your reason; no deviation is opened.") }],
      signers, subject: { label: t("candidate {id}", { id: x.candidate_id }) }, note: t(CAPA_NOTE), onDone,
      command: (a) => `aqt capa candidate ${a.id} ${sq(x.candidate_id)} --reason "…"`,
      submit: (a, values) => post(`/api/capa/candidates/${encodeURIComponent(x.candidate_id)}/${a.id}`, values),
    }),
  };
}
async function openDeviation(devId) {
  const d = await api(`/api/capa/${encodeURIComponent(devId)}`);
  const dev = d.deviation;
  const approvals = d.actions.filter((a) => a.state === "implemented" && a.approval && !a.approval.approved && a.implemented_hash).map((a) => decisionPanel({
    title: t("Approve corrective action {id}", { id: a.action_id }),
    actions: [{ id: "approve", label: t("Approve"), meaning: "approved", button: t("Sign and approve action") }],
    signers: d.signers.filter((s) => s.id !== a.implementer),
    noSigners: t("Only the person who implemented the action is registered; approval needs another person."),
    subject: { label: t("implementation of {id} ({path})", { id: a.action_id, path: a.path }), hash: a.implemented_hash },
    command: () => `aqt capa action approve ${sq(a.action_id)} --reason "…"`,
    note: t("Signs the implementation record (aqt-signoff, meaning approved). The effectiveness check starts with this approval."),
    submit: (x, values) => post(`/api/capa/actions/${encodeURIComponent(a.action_id)}/approve`, { ...values, expected_hash: a.implemented_hash }),
  }));
  let close = null;
  if (dev.state !== "closed") {
    const noAction = h("input", { id: `no-action-${dev.dev_id}`, type: "checkbox" });
    const fields = d.actions.length ? null : h("div", { class: "check" }, noAction, h("label", { for: `no-action-${dev.dev_id}`, text: t("Close without a corrective action (give the justification as the reason)") }));
    close = decisionPanel({
      title: t("Close the deviation"),
      actions: [{ id: "close", label: t("Close"), meaning: "closed", button: t("Close deviation") }],
      signers: d.signers, fields, subject: { label: t("deviation {id} as of record {record}", { id: dev.dev_id, record: d.version || "–" }) },
      command: () => `aqt capa close ${sq(dev.dev_id)}${noAction.checked ? " --no-action" : ""} --reason "…"`,
      note: t("Closing needs a recorded investigation and, with actions, a passed effectiveness check. ") + t(CAPA_NOTE),
      submit: (x, values) => post(`/api/capa/${encodeURIComponent(dev.dev_id)}/close`, { ...values, version: d.version, no_action: noAction.checked }),
    });
  }
  setInspector(
    inspSection(t("Deviation"), h("p", { class: "insp-title", text: `${dev.dev_id} ${dev.title}` }), stWord(dev.state === "closed" ? "closed" : "open", t(dev.state)),
      kv([[t("Severity"), t(dev.severity)], [t("Category"), dev.category], [t("Opened"), fmtTime(dev.opened_at)], [t("Due"), dev.due ? fmtTime(dev.due) : "–"]])),
    d.investigation ? inspSection(t("Investigation"), kv([[t("Root cause"), d.investigation.root_cause || "–"], [t("Category"), d.investigation.root_category || "–"],
      [t("Why chain"), (d.investigation.whys || []).join(" → ") || "–"], [t("Factors"), (d.investigation.factors || []).map((f) => `${f.category}: ${f.text}`).join("; ") || "–"]])) : null,
    d.actions.length ? inspSection(t("Actions"), d.actions.map((a) => h("div", { class: "small action-line" }, h("strong", { text: a.action_id }), ` ${t(a.kind)} · ${a.path}: ${a.description} · `, stWord(a.state, t(a.state)),
      ` · ${t("approval")} ${t((a.approval && a.approval.status) || "none")} · ${t("effectiveness")} ${t((a.last_evaluation && a.last_evaluation.result) || "not evaluated")}`))) : null,
    inspSection(t("Timeline"), d.timeline.map((x) => h("p", { class: "small" }, h("span", { class: "mono", text: fmtTime(x.time) }), ` ${x.type} ${x.action} · ${x.actor}`, x.reason ? h("span", { class: "muted", text: ` · ${x.reason}` }) : null))),
    approvals,
    close,
  );
}

// ---- Qualifications -----------------------------------------------------------------------------------
function triggerWords(triggers) { return (triggers || []).map((x) => codeWord("validate.trigger.", x)).join(", "); }
async function renderQualifications(main) {
  const data = await api("/api/qualifications");
  clear(main);
  if (!data.qualifications.length) put(main, empty(t("No qualifications recorded"), data.installed ? t("Qualify a detector with aqt-validate (in a terminal).") : t("aqt-validate is not installed.")));
  else {
    const words = (q) => ({ valid: t("valid until {date}", { date: String(q.valid_until).slice(0, 10) }), expiring: t("expires in {n} day(s)", { n: q.days_left }), expired: t("expired"), triggered: t("triggered: {list}", { list: triggerWords(q.triggers) }), rejected: t("rejected") })[q.state];
    const rows = data.qualifications.map((q) => ({ data: q, cells: [h("td", { class: "wrap", text: q.subject_id }), codeWord("validate.kind.", q.kind), h("td", {}, stWord(q.state, words(q))), h("td", { class: "num", text: q.days_left ?? "–" }),
      h("td", { class: "hide-narrow mono small", text: q.approver || "" }), h("td", { class: "hide-narrow" }, q.same_thresholds === null ? "–" : q.same_thresholds ? stWord("pass", t("same as qualified")) : stWord("warn", t("different file in use")))] }));
    put(main, table([t("Subject"), t("Kind"), t("Status"), th(t("Days left"), "num"), th(t("Approver"), "hide-narrow"), th(t("Thresholds"), "hide-narrow")], rows, (q) => setInspector(
      inspSection(t("Qualification"), h("p", { class: "insp-title", text: q.subject_id }), stWord(q.state, words(q)),
        kv([[t("Kind"), codeWord("validate.kind.", q.kind)], [t("Decision"), t(q.decision)], [t("Conclusion"), codeWord("validate.conclusion.", q.conclusion)], [t("Valid until"), fmtTime(q.valid_until)], [t("Approved by"), `${q.approver_name || ""} ${q.approver || ""}`],
          [t("Reason"), q.reason], [t("Band"), q.band ? t(q.band) : "–"], [t("Expected FPR ≤"), q.expected_fpr_upper_ppm != null ? `${num(q.expected_fpr_upper_ppm)} ppm` : "–"], [t("Record"), h("code", { text: q.record })],
          [t("Triggers"), triggerWords(q.triggers) || t("none recorded")]])),
      q.report_summary ? inspSection(t("Run report"), kv([[t("Issued"), fmtTime(q.report_summary.time)], [t("Report"), q.report_summary.subject || "–"]]), h("pre", { class: "json", text: JSON.stringify(q.report_summary.data, null, 2) })) : null,
    )).table);
  }
  const x = data.thresholds;
  put(main, section(t("Thresholds in use (aqt-quarantine)"), !x ? h("p", { class: "muted", text: t("aqt-quarantine is not installed.") }) : x.error ? h("div", { class: "error-box", text: msgOf(x, "error") })
    : kv([[t("Version"), x.version], [t("Calibrated"), x.calibrated ? stWord("pass", t("calibrated")) : stWord("warn", t("not calibrated (defaults)"))], ["SHA-256", hashButton(x.sha256, 20)], [t("File"), h("span", { class: "break", text: x.path })]]),
    h("p", { class: "small muted", text: t("Requalification triggers are shown as recorded; aqt-validate check in a terminal evaluates and records new ones.") })));
}

// ---- Evidence: the records of every tool, one section each --------------------------------------------
const EVIDENCE_RENDER = { trail: renderTrail, signatures: renderSignatures, quarantine: renderQuarantine, capa: renderCapa,
  qualifications: renderQualifications, export: renderExport };
function evidenceTabs(part) {
  return h("nav", { class: "area-tabs", "aria-label": t("Evidence") }, EVIDENCE.map((x) => {
    const g = x.tip ? gloss(x.tip) : null;
    return h("a", { href: `/evidence/${x.id}`, "aria-current": x === part ? "page" : null, title: g ? `${g.term}: ${g.tip}` : null,
      onclick: (e) => { e.preventDefault(); go(`/evidence/${x.id}`); } }, t(x.label));
  }));
}
async function renderEvidence(main, part) {
  await EVIDENCE_RENDER[part.id](main);
  main.prepend(evidenceTabs(part));
}
async function renderExport(main) {
  clear(main);
  put(main,
    section(t("Audit trail bundle"), h("p", { class: "lede", text: t("A verification bundle: the trail, checkpoints, public keys and instructions, for an auditor to check offline. Creating it records nothing.") }),
      downloadButton("/api/trail/export", "aqt-trail-bundle.tar.gz", t("Download bundle (.tar.gz)"), "btn primary")),
    section(t("Signature manifests"), h("p", { class: "lede", text: t("Every signature can be printed as a manifest with printed name, meaning, time and reason. Verify a file, record or hash under Signatures, or open a change, then download its manifest.") }),
      link(t("Open Signatures"), "/evidence/signatures")),
    S.installed.aqt_capa ? section(t("Deviations and CAPA"), h("p", { class: "lede", text: t("The trend summary of deviations and corrective actions, as Markdown.") }),
      downloadButton("/api/capa/trends", "capa-trends.md", t("Download the trend summary (Markdown)"))) : null);
}

// ---- Settings: is everything running, who am I, language, the aqt command, the glossary ----------------
// The checks of aqt status in everyday words (the explanation beside them is the tool's own sentence).
const CHECK_WORDS = { packages: "Toolkit packages", command: "The aqt command", "trail.init": "Audit trail", service: "Background service", writer: "Trail writer",
  spool: "Waiting records", sink: "Where records go", signer: "Your signing identity", "signoff.config": "Signing settings",
  "trail.config": "Review settings", "trail.intact": "Trail integrity", vectors: "Self-test", egress: "Outbound checkpoint (optional)" };
// The fix of each step the app can apply: [button, what it does].
const FIX_WORDS = {
  "trail.init": ["Create the trail", "Creates the trail folder and its service key. Nothing else changes."],
  service: ["Install and start the service", "Writes a user service that starts the writer at login, and starts it now."],
  writer: ["Restart the writer", "Starts the background service that writes the trail."],
  spool: ["Move the records into the trail", "Appends the records that waited in the spool, after a gap marker."],
  "signoff.config": ["Write the signing settings", "Writes signoff.toml with your default signer and time zone. An existing file is never replaced."],
  "trail.config": ["Write the review settings", "Writes trail.toml with your time zone and working hours for the review. An existing file is never replaced."],
};
const RESULT_KIND = { ok: "pass", warn: "warn", fail: "fail", skip: "neutral" };
const RESULT_WORDS = { ok: "in order", warn: "needs a look", fail: "needs a fix", skip: "not used here" };
function checkRow(row, { words, fixes, onFix } = {}) {
  const title = t((words || CHECK_WORDS)[row.id] || row.id);
  const problem = row.result === "warn" || row.result === "fail";
  const fix = (fixes || FIX_WORDS)[row.id];
  const out = h("div", { "aria-live": "polite" });
  let action = null;
  if (problem && row.can_apply && fix && S.mode && S.mode.decisions && onFix) {
    const button = h("button", { class: "btn small primary", type: "button", text: t(fix[0]) });
    button.addEventListener("click", async () => { button.disabled = true; await onFix(row, out); button.disabled = false; });
    action = h("div", { class: "fix" }, button, h("span", { class: "small muted", text: t(fix[1]) }));
  } else if (problem && row.id === "signer" && S.mode && S.mode.decisions && !(S.setup && S.setup.signer)) {
    action = h("div", { class: "fix" }, h("button", { class: "btn small primary", type: "button", text: t("Set up your identity"), onclick: () => go("/welcome") }));
  } else if (problem && row.fix) {        // a command to run, or advice in words
    action = /^(aqt|aqt-[a-z]+|systemctl|journalctl|git|uv|pip|pipx|cd|echo)\b/.test(row.fix)
      ? h("div", { class: "fix" }, h("span", { class: "small muted", text: t("In a terminal:") }), commandLine(row.fix))
      : h("p", { class: "small" }, h("strong", { text: `${t("What to do:")} ` }), row.fix);
  }
  return h("li", { class: `check-row ${row.result}`, id: `check-${row.id}` },
    st(RESULT_KIND[row.result] || "neutral", t(RESULT_WORDS[row.result] || row.result)),
    h("div", { class: "check-what" }, h("strong", { text: title }), h("span", { class: "small muted break", text: row.explanation }), action, out));
}
async function renderSettings(main) {
  const data = S.overview || (await refresh());
  let setup = null;
  let problem = null;
  try { setup = await loadSetup(); } catch (error) { problem = error; }
  clear(main);
  const page = h("div", { class: "settings" });
  put(main, page);
  // 1. is everything running? aqt status, each problem with its one fix
  if (setup) {
    const rows = setup.checks.slice().sort((a, b) => ({ fail: 0, warn: 1, ok: 2, skip: 3 })[a.result] - ({ fail: 0, warn: 1, ok: 2, skip: 3 })[b.result]);
    const open = rows.filter((r) => r.result === "fail" || r.result === "warn").length;
    const onFix = async (row, out) => {
      const { data: answer } = await applyStep(row.id);
      if (!answer.ok) put(clear(out), h("div", { class: "result refused", text: `${t("Not done:")} ${answer.error || (answer.check && answer.check.explanation) || answer.message || ""}` }));
    };
    const problems = rows.filter((r) => r.result === "fail" || r.result === "warn");
    const fine = rows.filter((r) => !problems.includes(r));
    put(page, section(t("Is everything running?"),
      h("p", { class: "lede" }, open ? t("{n} thing(s) need a look. Each has its fix.", { n: open }) : t("Everything in order."), " ",
        h("span", { class: "small muted" }, t("The same list as"), " ", h("code", { text: "aqt status" }), ".")),
      problems.length ? h("ul", { class: "checks" }, problems.map((row) => checkRow(row, { onFix }))) : null,
      h("details", { class: "all-checks", open: !!location.hash.startsWith("#check-") && !problems.some((r) => `#check-${r.id}` === location.hash) },
        h("summary", { text: t("Show the {n} checks that are in order", { n: fine.length }) }),
        h("ul", { class: "checks" }, fine.map((row) => checkRow(row, { onFix }))))));
  } else put(page, section(t("Is everything running?"), errorBox(problem)));
  // 2. who you are
  put(page, await identitySection(setup));
  // 3. the audit trail and the tools
  put(page, healthSections(data));
  // 4. language
  const radios = h("div", { class: "radio-row", role: "radiogroup", "aria-label": t("Language") }, [["en", "English"], ["de", "Deutsch"]].map(([value, words]) =>
    h("label", { class: "radio" }, h("input", { type: "radio", name: "settings-lang", value, checked: LANG === value, onchange: () => setLang(value) }), words)));
  put(page, section(t("Language"), radios, h("p", { class: "small muted", text: t("Labels change at once. Records and the tools' own messages keep the words they were written in.") })));
  // 5. the app's own settings (desktop app only) and the aqt command
  put(page, await appSection());
  put(page, section(t("Use the aqt command in a terminal"), commandSection(setup)));
  // 6. glossary
  put(page, section(t("Words used here"), glossaryList()));
}
async function identitySection(setup) {
  const box = section(t("Who you are"));
  let rows = [];
  try { rows = S.installed.aqt_signoff ? (await api("/api/signatures")).signers.filter((x) => x.active_key) : []; } catch (e) { rows = []; }
  if (!rows.length) {
    put(box, h("p", { class: "lede", text: t("No signing identity is set up yet. You need one to sign decisions.") }),
      S.mode && S.mode.decisions ? h("button", { class: "btn primary", type: "button", text: t("Set up your identity"), onclick: () => go("/welcome") }) : null);
    return box;
  }
  put(box, h("ul", { class: "people" }, rows.map((x) => h("li", {}, h("strong", { text: x.name }), " ", h("code", { text: x.id }),
    h("span", { class: "muted", text: ` · ${x.role}` }), h("span", { class: "small muted break", text: ` · ${t("key")} ${x.active_key}` })))),
  h("p", { class: "small muted" }, t("Your ID stands in every signature you make and is never reused."), " ", t("Another person enrols in their own terminal:"), " ", h("code", { text: "aqt signoff init" })));
  return box;
}
function commandSection(setup) {
  const where = (setup && setup.command) || {};
  return [h("p", { class: "lede", text: t("Everything the app does, the aqt command does too, for agents, scripts and anyone who likes the terminal. Both write to the same audit trail.") }),
    kv([[t("On your PATH"), where.on_path ? h("code", { text: where.on_path }) : t("not yet")], where.this ? [t("This app's command"), h("code", { text: where.this })] : null]),
    commandLine("aqt status"), commandLine("aqt project init <folder>"), commandLine("aqt --help")];
}
// ---- the app's own settings, kept by the desktop shell (desktop_settings): start at login, the tray, the aqt
// command (AppImage, macOS) and aqt:// links (AppImage). They act at once and can be switched back.
async function desktopSettings(change) {
  return APP.invoke("desktop_settings", change ? { change } : {});
}
function appSettingRows(d, { keys, onChange }) {
  const can = !!(S.mode && S.mode.decisions);
  const out = h("div", { "aria-live": "polite" });
  const fail = (error) => put(clear(out), h("div", { class: "result refused", text: String(error.message || error) }));
  const rows = [];
  const words = { autostart: [t("Start in the background at login"), null],
    close_to_tray: [t("Keep running in the tray when the window is closed"), d.tray ? null : t("No tray icon shows on this desktop, so closing the window quits the app.")] };
  for (const key of keys.filter((k) => words[k])) {
    const input = h("input", { type: "checkbox", id: `app-${key}`, checked: !!d[key], disabled: !can });
    input.addEventListener("change", async () => {
      input.disabled = true;
      try { const fresh = await desktopSettings({ [key]: input.checked }); input.checked = !!fresh[key]; announce(t("Saved")); if (onChange) onChange(fresh); }
      catch (error) { input.checked = !input.checked; fail(error); }
      finally { input.disabled = !can; }
    });
    rows.push(h("div", { class: "check" }, input, h("label", { for: input.id }, words[key][0], words[key][1] ? h("span", { class: "small muted", text: ` ${words[key][1]}` }) : null)));
  }
  // something to install: the aqt command where the shell offers it (AppImage, macOS), aqt:// links in an AppImage
  const install = (key, done, button, what) => {
    const offered = key === "aqt_command" ? d.aqt_command != null : !!d.appimage;
    if (!keys.includes(key) || !offered) return null;
    if (d[key]) return h("p", { class: "small" }, st("pass", done));
    const b = h("button", { class: "btn small", type: "button", text: button, disabled: !can });
    b.addEventListener("click", async () => { b.disabled = true; try { const fresh = await desktopSettings({ [key]: true }); put(b.parentNode, st(fresh[key] ? "pass" : "warn", fresh[key] ? done : t("Not done:"))); b.remove(); } catch (error) { b.disabled = false; fail(error); } });
    return h("p", { class: "small" }, b, what ? h("span", { class: "muted", text: ` ${what}` }) : null);
  };
  const mac = d.aqt_command_folder === "/usr/local/bin";
  rows.push(mac
    ? install("aqt_command", t("The aqt command is installed in /usr/local/bin."), t("Install 'aqt' command"),
      t("Links aqt and aqt-toolkit in /usr/local/bin to this app's command, so that agents and terminals find it. macOS asks for an administrator's password. An aqt of another program there is never replaced."))
    : install("aqt_command", t("The aqt command is installed in ~/.local/bin."), t("Install the aqt command")),
    install("links", t("aqt:// links open this app."), t("Register aqt:// links")));
  return [...rows, can ? null : h("p", { class: "small muted", text: t("Read-only: these settings cannot be changed here.") }), out];
}
async function appSection() {
  if (!APP) return null;
  let d;
  try { d = await desktopSettings(); } catch (error) { return section(t("This app"), errorBox(error)); }
  return section(t("This app"), appSettingRows(d, { keys: ["autostart", "close_to_tray", "aqt_command", "links"] }));
}
function glossaryList() {
  return h("dl", { class: "glossary" }, Object.keys(GLOSSARY).map((key) => {
    const g = gloss(key);
    return [h("dt", {}, g.word, g.term.toLowerCase() !== g.word.toLowerCase() ? h("span", { class: "gmp", text: ` (${g.term})` }) : null), h("dd", { text: g.tip })];
  }));
}

// ---- Projects: the folders AQT watches ------------------------------------------------------------------
const PROJECT_WORDS = { project: "Git repository", "claude.hooks": "Agent hooks", "claude.deny": "Blocked decision commands",
  instructions: "Agent instructions", "change.settings": "Change control settings", "ui.project": "Listed in AQT",
  "git.hook": "Commit message check (optional)", committed: "Committed to git" };
const PROJECT_DOES = {
  "claude.hooks": "Claude Code reports each step of the agent to the audit trail, and fetched web pages pass the quarantine.",
  "claude.deny": "The agent may not run AQT's decision commands or edit AQT's folders.",
  instructions: "A short block in CLAUDE.md or AGENTS.md tells the agent how to work under AQT.",
  "change.settings": "A plan needs your signed approval, and checks count only when the audit trail confirms them.",
  "ui.project": "AQT shows this project's plans and changes. This is what connects the folder.",
  "git.hook": "Git checks the AQT lines in commit messages.",
};
async function renderProjects(main) {
  const data = await api("/api/projects");
  clear(main);
  const page = h("div", { class: "projects" });
  const flow = h("div", { class: "connect-box" });
  const start = h("button", { class: "btn primary", type: "button", text: t("Connect a project…"), disabled: !(S.mode && S.mode.decisions) });
  start.addEventListener("click", () => { start.hidden = true; connectFlow(flow, { onDone: () => route(), onLater: () => { clear(flow); start.hidden = false; start.focus(); } }); });
  put(main, page);
  put(page, h("header", { class: "area-head" }, h("p", { class: "lede", text: t("The folders AQT watches. Agents that work in them report to AQT through hooks; their changes appear under Changes.") }),
    S.mode && S.mode.decisions ? start : h("p", { class: "small muted", text: t("Read-only: connecting a project is not possible here.") })), flow);
  if (!data.projects.length) put(page, empty(t("No project connected yet"), t("Connect a project folder. AQT shows what it will add, file by file, before anything is written.")));
  for (const project of data.projects) {
    const problems = project.checks.filter((c) => c.result === "warn" || c.result === "fail");
    const head = h("h2", {}, h("span", { class: "path", text: project.root }), " ",
      project.missing ? st("fail", t("folder not found")) : problems.length ? st(problems.some((c) => c.result === "fail") ? "fail" : "warn", t("{n} thing(s) to do", { n: problems.length })) : st("pass", t("set up")));
    const box = h("section", { class: "section project" }, head);
    if (project.missing) put(box, h("p", { class: "muted", text: project.error || t("The folder does not exist any more.") }));
    else {
      put(box, h("ul", { class: "checks compact" }, project.checks.filter((c) => c.result !== "skip").map((row) => checkRow(row, { words: PROJECT_WORDS, fixes: {} }))));
      if (problems.some((c) => c.can_apply) && S.mode && S.mode.decisions) {
        const again = h("div", { class: "connect-box" });
        put(box, h("div", { class: "actions" }, h("button", { class: "btn small", type: "button", text: t("Add what is missing…"),
          onclick: (e) => { e.target.hidden = true; connectFlow(again, { path: project.root, onDone: () => route(), onLater: () => { clear(again); e.target.hidden = false; } }); } })), again);
      }
    }
    put(page, box);
  }
  put(page, h("p", { class: "small muted section", text: t("Disconnecting a project is not available yet: remove its line from [changes] projects in {file}.", { file: data.config }) }));
}

// The connect flow (Projects and the first-run setup): choose a folder, see each change per file, leave out
// what you do not want, connect. Every changed file is backed up first; nothing is committed.
function connectFlow(box, { path, onDone, onLater, laterLabel }) {
  clear(box);
  const out = h("div", { class: "preview" });
  const pathInput = h("input", { id: "project-path", type: "text", class: "grow", spellcheck: "false", placeholder: "/home/you/code/project", value: path || "" });
  const show = async (value) => {
    clear(out);
    if (!value) return;
    pathInput.value = value;
    put(out, h("p", { class: "muted", text: t("Looking at the folder…") }));
    try { previewList(out, await api(`/api/projects/preview?path=${encodeURIComponent(value)}`), { onDone, onLater, laterLabel }); }
    catch (error) { put(clear(out), errorBox(error)); }
  };
  const pick = APP ? h("button", { class: "btn primary", type: "button", text: t("Choose folder…"), onclick: async () => {
    let picked = null;
    try { picked = await APP.invoke("pick_folder"); } catch (error) { put(clear(out), h("div", { class: "result refused", text: String(error) })); return; }
    if (picked) show(picked);
  } }) : null;
  const look = h("button", { class: `btn ${APP ? "" : "primary"}`, type: "button", text: t("Show what changes"), onclick: () => show(pathInput.value.trim()) });
  pathInput.addEventListener("keydown", (e) => { if (e.key === "Enter") show(pathInput.value.trim()); });
  put(box, h("div", { class: "folder-row" }, pick,
    h("label", { for: "project-path", class: APP ? "or" : "", text: APP ? t("or type the path") : t("Project folder (full path)") }), pathInput, look,
    onLater ? h("button", { class: "btn ghost", type: "button", text: laterLabel || t("Later"), onclick: onLater }) : null), out);
  if (path) show(path);
  else (pick || pathInput).focus();
}
function previewList(out, data, { onDone, onLater, laterLabel }) {
  clear(out);
  const boxes = {};
  const items = data.items.map((item) => {
    const todo = item.can_apply;
    const locked = item.id === "ui.project";
    const box = h("input", { type: "checkbox", id: `pi-${item.id}`, checked: todo, disabled: !todo || locked });
    if (todo) boxes[item.id] = box;
    const state = todo ? null : item.result === "ok" ? st("pass", t("already in place")) : item.result === "skip" ? st("neutral", t("not used here")) : st("warn", t("yours to do"));
    return h("li", { class: `item${todo ? "" : " done"}` }, box,
      h("div", {}, h("label", { for: box.id }, h("strong", { text: t(PROJECT_WORDS[item.id] || item.id) }), " ", item.file ? h("code", { class: "muted", text: item.file }) : null, " ", state),
        h("p", { class: "small", text: t(PROJECT_DOES[item.id] || "") }),
        !todo && item.result !== "ok" && item.result !== "skip" ? h("p", { class: "small muted break", text: item.explanation }) : null,
        locked && todo ? h("p", { class: "small muted", text: t("Always part of connecting.") }) : null,
        todo && item.backup ? h("p", { class: "small muted", text: t("The file exists: a backup copy is saved first.") }) : null,
        todo && item.preview ? h("details", {}, h("summary", { text: t("Show what is added") }), h("pre", { class: "json", text: item.preview })) : null));
  });
  const result = h("div", { "aria-live": "polite" });
  const connect = h("button", { class: "btn primary", type: "button", text: data.connected && !Object.keys(boxes).length ? t("Nothing to add") : t("Connect project"), disabled: !Object.keys(boxes).length });
  connect.addEventListener("click", async () => {
    const chosen = Object.entries(boxes).filter(([, el]) => el.checked).map(([id]) => id);
    if (!chosen.length) { put(clear(result), h("div", { class: "result stale", text: t("Choose at least one item.") })); return; }
    connect.disabled = true;
    const { status, data: done } = await post("/api/projects/connect", { path: data.root, items: chosen });
    connect.disabled = false;
    if (status !== 200) { put(clear(result), h("div", { class: "result refused", text: `${t("Not connected:")} ${refusalWords(done.reason_code, done.reason_text) || ""} ${msgOf(done, "message")}` })); return; }
    const errors = Object.entries(done.errors || {});
    put(clear(out), h("div", { class: `result ${errors.length ? "stale" : "ok"}`, role: "status" },
      h("p", { class: "recorded-title" }, st(errors.length ? "warn" : "pass", errors.length ? t("Connected with problems") : t("Connected: {root}", { root: done.root }))),
      errors.length ? h("ul", { class: "evidence-list" }, errors.map(([id, error]) => h("li", {}, h("strong", { text: t(PROJECT_WORDS[id] || id) }), `: ${error}`))) : null,
      done.said.length ? h("ul", { class: "evidence-list small" }, done.said.map((line) => h("li", { text: line }))) : null,
      h("p", { class: "small muted", text: t("Backups: {dir}. Nothing was committed; commit the new files when you are ready.", { dir: done.backup_dir }) })));
    announce(errors.length ? t("Connected with problems") : t("Connected: {root}", { root: done.root }));
    await refresh().catch(() => null);
    if (onDone) put(out, h("div", { class: "actions" }, h("button", { class: "btn primary", type: "button", text: t("Continue"), onclick: () => onDone(done) })));
  });
  put(out, h("p", { class: "lede" }, t("What connecting adds to"), " ", h("code", { text: data.root }), data.git ? "" : ` (${t("not a git repository: change control is skipped")})`),
    h("ul", { class: "items" }, items),
    h("p", { class: "small muted", text: t("Before a file is changed, a backup copy is saved in {dir}. Nothing is committed.", { dir: data.backup_dir }) }),
    h("div", { class: "actions" }, connect, onLater ? h("button", { class: "btn ghost", type: "button", text: laterLabel || t("Later"), onclick: onLater }) : null), result,
    h("details", { class: "as-command-box" }, h("summary", { text: t("Show as command") }), commandLine(`aqt project init ${sq(data.root)}`)));
}

// ---- First-run setup (/welcome): six steps ---------------------------------------------------------------
// Welcome and language, who you are, your passphrase, the audit trail with its background writer, the first
// project, done. Steps 2 and 3 only collect and check; the signing key is made in step 4 after the trail
// exists (as aqt setup orders it), so its enrolment record lands in the trail. Read-only: explained, no action.
const STEP_NAMES = ["Welcome", "Who you are", "Your passphrase", "Audit trail", "First project", "Done"];
const W = { step: 1, reached: 1, name: "", role: "", other: "", custom: "", customOpen: false, id: "", check: null };
let pendingPass = "";      // the passphrase between step 3 and the signing key in step 4: page memory only
const ROLES = [["developer", "Developer"], ["quality-manager", "Quality manager"]];
const SUBSTEPS = [["trail.init", "Create the audit trail"], ["service", "Install the background service"], ["writer", "Start the writer"],
  ["spool", "Move waiting records into the trail"], ["enrol", "Create your signing key"], ["signoff.config", "Save your signing settings"],
  ["trail.config", "Save your review settings"]];

async function renderWelcome(main) {
  let setup;
  try { setup = await loadSetup(); } catch (error) {       // e.g. aqt-cli is not installed: say how, and a way out
    put(clear(main), h("div", { class: "onboard-wrap" }, errorBox(error), h("div", { class: "actions" },
      h("button", { class: "btn", type: "button", text: t("Open Needs you"), onclick: () => go("/") }))));
    return;
  }
  clear(main);
  const list = h("ol", { class: "steps", "aria-label": t("Setup steps") });
  const body = h("section", { class: "step-body", "aria-labelledby": "step-title" });
  put(main, h("div", { class: "onboard-wrap" }, h("p", { class: "onboard-brand" }, "Agent Quality Toolkit", h("span", { class: "muted", text: ` · ${t("Set up AQT")}` })),
    h("div", { class: "onboard" }, list, body)));
  const readOnly = !S.mode || !S.mode.decisions;
  const enrolled = () => !!(S.setup && S.setup.signer);
  const doneStep = (n) => (n === 2 || n === 3 ? enrolled() || W.reached > n : n === 4 ? !(S.setup && S.setup.needed) : W.reached > n);
  const goStep = (n) => { W.step = n; W.reached = Math.max(W.reached, n); draw(); document.getElementById("step-title")?.focus(); };
  const title = (words) => h("h2", { id: "step-title", tabindex: "-1", text: words });
  const nav = (...buttons) => h("div", { class: "actions step-actions" }, ...buttons);
  const back = (n) => h("button", { class: "btn ghost", type: "button", text: t("Back"), onclick: () => goStep(n) });
  const drawList = () => {
    put(clear(list), STEP_NAMES.map((name, i) => {
      const n = i + 1;
      const state = n === W.step ? "current" : doneStep(n) ? "done" : "todo";
      const mark = h("span", { class: "step-mark", "aria-hidden": "true", text: state === "done" ? "✓" : String(n) });
      const words = h("span", { class: "step-name", text: t(name) });
      const reachable = !readOnly && n <= W.reached && n !== W.step;
      return h("li", { class: `step ${state}`, "aria-current": state === "current" ? "step" : null },
        reachable ? h("button", { type: "button", onclick: () => goStep(n) }, mark, words) : h("span", { class: "step-static" }, mark, words),
        state === "done" ? h("span", { class: "sr-only", text: t("done") }) : null);
    }));
  };
  const steps = {
    1: () => [title(t("Welcome")),
      h("p", { class: "lede", text: t("AQT watches what your AI coding agents do and keeps a tamper-evident record of it.") }),
      h("p", { text: t("When something needs a person (a held web page, a plan to approve, a change to release), it waits for you. You decide here and sign each decision with your passphrase.") }),
      h("p", { text: t("Setting up takes about five minutes: who you are, your passphrase, the audit trail and your first project. Nothing leaves this computer.") }),
      h("fieldset", { class: "radio-row" }, h("legend", { text: t("Language") }), [["en", "English"], ["de", "Deutsch"]].map(([value, words]) =>
        h("label", { class: "radio" }, h("input", { type: "radio", name: "ob-lang", value, checked: LANG === value, onchange: () => setLang(value) }), words))),
      nav(h("button", { class: "btn primary", type: "button", text: t("Set up"), onclick: () => goStep(enrolled() ? 4 : 2) }),
        h("button", { class: "btn ghost", type: "button", text: t("Set up later"), onclick: () => go("/") }))],
    2: () => (enrolled() ? [title(t("Who you are")), h("p", { class: "lede", text: t("You already have a signing identity: {ids}.", { ids: S.setup.signers.join(", ") }) }),
      nav(h("button", { class: "btn primary", type: "button", text: t("Continue"), onclick: () => goStep(4) }), back(1))] : whoStep()),
    3: () => (enrolled() ? [title(t("Your passphrase")), h("p", { class: "lede", text: t("Your signing key exists already; its passphrase stays as it is.") }),
      nav(h("button", { class: "btn primary", type: "button", text: t("Continue"), onclick: () => goStep(4) }), back(2))] : passStep()),
    4: () => trailStep(),
    5: () => projectStep(),
    6: () => doneStepBody(),
  };
  function whoStep() {
    const name = h("input", { id: "ob-name", type: "text", autocomplete: "name", value: W.name, "aria-describedby": "ob-name-hint" });
    const other = h("input", { id: "ob-role-other", type: "text", value: W.other, "aria-label": t("Your role, in your words"), placeholder: t("for example Reviewer") });
    const roleRadios = [...ROLES, ["", "Other"]].map(([value, words]) => {
      const checked = value ? W.role === value : !!W.role && !ROLES.some(([v]) => v === W.role);
      return h("label", { class: "radio" }, h("input", { type: "radio", name: "ob-role", value, checked, onchange: () => { W.role = value || other.value.trim(); if (!value) other.focus(); update(); } }), t(words));
    });
    other.addEventListener("input", () => { W.other = other.value; roleRadios[2].querySelector("input").checked = true; W.role = other.value.trim(); update(); });
    const idCode = h("code", { class: "id-big", text: W.id || "human:…" });
    const custom = h("input", { id: "ob-custom", type: "text", spellcheck: "false", value: W.custom || W.id, "aria-describedby": "ob-id-msg" });
    const customBox = h("div", { class: "field", hidden: !W.customOpen }, h("label", { for: "ob-custom", text: t("Your ID (lower case letters, digits, . _ or -)") }), custom);
    const customize = h("button", { class: "btn small ghost", type: "button", "aria-expanded": String(W.customOpen), text: t("Customise") });
    const message = h("p", { id: "ob-id-msg", class: "small", "aria-live": "polite" });
    const next = h("button", { class: "btn primary", type: "button", text: t("Continue"), disabled: true, onclick: () => goStep(3) });
    customize.addEventListener("click", () => { W.customOpen = !W.customOpen; customBox.hidden = !W.customOpen; customize.setAttribute("aria-expanded", String(W.customOpen)); if (W.customOpen) { custom.value = W.custom || W.id.replace(/^human:/, ""); custom.focus(); } else { W.custom = ""; update(); } });
    let timer = null;
    let asked = 0;
    async function check() {
      const ticket = ++asked;
      const q = new URLSearchParams({ name: W.name, id: W.customOpen ? W.custom : "" });
      let answer = null;
      try { answer = await api(`/api/setup/signer-id?${q}`); } catch (error) { put(clear(message), h("span", { class: "flag", text: String(error.message || error) })); return; }
      if (ticket !== asked) return;              // a newer check is on its way
      W.check = answer;
      W.id = answer.id;
      idCode.textContent = vis(answer.id || "human:…");
      clear(message);
      if (!answer.id) put(message, h("span", { class: "muted", text: t("Type your name: the ID is made from it.") }));
      else if (answer.taken) put(message, st("fail", t("This ID is already used. IDs are never reused: change it under Customise.")));
      else if (!answer.valid) put(message, st("warn", t("Only lower case letters, digits, . _ and - after human:. For example {id}.", { id: answer.suggestion || "human:alice" })));
      else put(message, st("pass", t("This ID can be used.")));
      next.disabled = !(answer.valid && W.name.trim() && W.role.trim());
    }
    function update() {
      W.name = name.value;
      W.custom = custom.value;
      next.disabled = true;
      clearTimeout(timer);
      timer = setTimeout(check, 200);
    }
    name.addEventListener("input", update);
    custom.addEventListener("input", update);
    setTimeout(() => { name.focus(); if (W.name) check(); }, 0);
    return [title(t("Who are you?")),
      h("p", { class: "lede", text: t("Your name and role appear with every signature you make.") }),
      h("div", { class: "field" }, h("label", { for: "ob-name", text: t("Your name, as it appears on signatures") }), name,
        h("span", { id: "ob-name-hint", class: "small muted", text: t("For example Alice Example.") })),
      h("fieldset", { class: "radio-row roles" }, h("legend", { text: t("Your role") }), roleRadios, other),
      h("div", { class: "id-box" }, h("p", { class: "id-line" }, h("span", { text: `${t("Your ID:")} ` }), idCode, " ", customize), customBox, message,
        h("p", { class: "small muted", text: t("Your ID stands in every signature you make. It is never given to anyone else, also not later.") })),
      nav(next, back(1))];
  }
  function passStep() {
    const minimum = (S.setup && S.setup.passphrase_min) || 12;
    const one = h("input", { id: "ob-pass", type: "password", autocomplete: "new-password", spellcheck: "false", "aria-describedby": "ob-pass-hint" });
    const two = h("input", { id: "ob-pass2", type: "password", autocomplete: "new-password", spellcheck: "false" });
    const hint = h("p", { id: "ob-pass-hint", class: "small", "aria-live": "polite" });
    const next = h("button", { class: "btn primary", type: "button", text: t("Continue"), disabled: true });
    const judge = () => {
      const a = one.value;
      clear(hint);
      let ok = false;
      if (!a) put(hint, h("span", { class: "muted", text: t("At least {n} characters. Several words work well.", { n: minimum }) }));
      else if (a.length < minimum) put(hint, st("warn", t("Too short: at least {n} characters ({m} so far).", { n: minimum, m: a.length })));
      else if (two.value && two.value !== a) put(hint, st("fail", t("The two entries differ.")));
      else {
        ok = !!two.value;
        put(hint, st("pass", a.length >= 20 || /\S+\s+\S+\s+\S+/.test(a) ? t("Strong.") : t("Long enough. Longer is stronger.")),
          two.value ? null : h("span", { class: "muted", text: ` ${t("Now type it again.")}` }));
      }
      next.disabled = !ok;
    };
    one.addEventListener("input", judge);
    two.addEventListener("input", judge);
    const proceed = () => { if (next.disabled) return; pendingPass = one.value; one.value = ""; two.value = ""; goStep(4); };
    next.addEventListener("click", proceed);
    two.addEventListener("keydown", (e) => { if (e.key === "Enter") proceed(); });
    setTimeout(() => { one.focus(); judge(); }, 0);
    return [title(t("Your passphrase")),
      h("p", { class: "lede", text: t("It unlocks your signing key. AQT asks for it at every signature.") }),
      h("div", { class: "field" }, h("label", { for: "ob-pass", text: t("Passphrase") }), one),
      h("div", { class: "field" }, h("label", { for: "ob-pass2", text: t("Type it again") }), two), hint,
      h("ul", { class: "plain-list" }, h("li", { text: t("It is never stored, not even by this app.") }), h("li", { text: t("Without it, nobody can sign in your name.") }),
        h("li", { text: t("If you lose it, you set up a new identity. Your earlier signatures stay valid.") })),
      nav(next, back(2))];
  }
  function trailStep() {
    const rows = Object.fromEntries((S.setup.checks || []).map((c) => [c.id, c]));
    const subs = SUBSTEPS.filter(([id]) => id !== "spool" || (rows.spool && rows.spool.result !== "ok")).map(([id, label]) => {
      const row = rows[id];
      // done when its check is in order; everything else is applied (a step that does not apply here, such as a
      // service without systemd, answers "skip" then)
      const state = id === "enrol" ? (enrolled() ? "done" : "todo") : row && row.result === "ok" ? "done" : "todo";
      return { id, label, state, detail: "", fix: "" };
    });
    const listEl = h("ol", { class: "substeps", "aria-live": "polite" });
    const drawSubs = () => put(clear(listEl), subs.map((x) => h("li", { class: `sub ${x.state}` },
      h("span", { class: "sub-mark", "aria-hidden": "true", text: { done: "✓", skipped: "–", failed: "✕", running: "…", todo: "○" }[x.state] }),
      h("div", {}, h("strong", { text: t(x.label) }), h("span", { class: "sr-only", text: ` ${t({ done: "done", skipped: "not used here", failed: "failed", running: "running", todo: "to do" }[x.state])}` }),
        x.detail ? h("p", { class: "small muted break", text: x.detail }) : null,
        x.fix ? h("div", { class: "fix" }, h("span", { class: "small muted", text: t("In a terminal:") }), commandLine(x.fix)) : null,
        x.extra || null))));
    const allDone = () => subs.every((x) => x.state === "done" || x.state === "skipped");
    const go4 = h("button", { class: "btn primary", type: "button", text: allDone() ? t("Continue") : t("Set up and start") });
    const run = async () => {
      if (allDone()) { goStep(5); return; }
      go4.disabled = true;
      for (const x of subs) {
        if (x.state === "done" || x.state === "skipped") continue;
        Object.assign(x, { state: "running", detail: "", fix: "", extra: null });
        drawSubs();
        if (x.id === "enrol") {
          if (!pendingPass) {
            Object.assign(x, { state: "failed", detail: t("Type your passphrase first: it is not kept after a reload."), extra: h("button", { class: "btn small", type: "button", text: t("Back to the passphrase"), onclick: () => goStep(3) }) });
            break;
          }
          const { status, data } = await post("/api/setup/enrol", { name: W.name.trim(), role: W.role.trim(), signer_id: W.id, passphrase: pendingPass });
          if (status === 200 && data.ok) {
            pendingPass = "";
            Object.assign(x, { state: "done", detail: data.counts ? t("{id}: your key counts now.", { id: data.signer_id }) : t("{id}: your key counts once another enrolled signer approves it.", { id: data.signer_id }) });
            continue;
          }
          const back2 = status === 400 ? h("button", { class: "btn small", type: "button", text: t("Change name or ID"), onclick: () => goStep(2) }) : null;
          Object.assign(x, { state: "failed", detail: `${refusalWords(data.reason_code, data.reason_text) ? refusalWords(data.reason_code, data.reason_text) + ". " : ""}${msgOf(data, "message")}`, extra: back2 });
          break;
        }
        const { status, data } = await post("/api/setup/apply", { check: x.id });
        const row = data.check || {};
        if (status === 200 && data.ok) { Object.assign(x, { state: row.result === "skip" ? "skipped" : "done", detail: row.result === "skip" ? row.explanation : "" }); continue; }
        Object.assign(x, { state: "failed", detail: [data.error, row.explanation || msgOf(data, "message")].filter(Boolean).join(". "), fix: row.fix || "" });
        break;
      }
      drawSubs();
      await Promise.all([loadSetup().catch(() => null), refresh().catch(() => null)]);
      go4.disabled = false;
      go4.textContent = vis(allDone() ? t("Continue") : t("Try again"));
      drawList();
      if (allDone()) { announce(t("The audit trail runs and your signing key is ready.")); go4.focus(); }
    };
    go4.addEventListener("click", run);
    drawSubs();
    return [title(t("Audit trail")),
      h("p", { class: "lede" }, t("AQT keeps a tamper-evident record of what agents and people do:"), " ", termNode("trail"), ". ",
        t("A small background service writes it, also when the app is closed.")),
      S.setup.service ? null : h("p", { class: "note-box", text: t("This computer has no systemd user session, so AQT cannot install the background service here. Start the writer yourself when the step asks for it; it must keep running.") }),
      listEl, nav(go4, back(enrolled() ? 1 : 3))];
  }
  function projectStep() {
    const box = h("div", { class: "connect-box" });
    setTimeout(() => connectFlow(box, { onDone: () => goStep(6), onLater: () => goStep(6), laterLabel: t("Later") }), 0);
    return [title(t("First project")),
      h("p", { class: "lede", text: t("Choose the folder of a project your agents work in. AQT shows, file by file, what it adds before anything is written.") }),
      box];
  }
  function doneStepBody() {
    const p = pillState();
    const app = h("div", { class: "app-settings" });
    if (APP) (async () => {
      let d;
      try { d = await desktopSettings(); } catch (error) { return; }
      if (!W.autostartOffered) {          // pre-checked: start in the background at login (switch it off here)
        W.autostartOffered = true;
        if (!d.autostart) { try { d = await desktopSettings({ autostart: true }); } catch (error) { /* shown unchecked */ } }
      }
      put(clear(app), appSettingRows(d, { keys: ["autostart", "aqt_command"] }));
    })();
    return [title(p.kind === "pass" ? t("Everything is set up") : t("Almost done")),
      h("p", { class: "status-line" }, st(p.kind, p.text), p.fix && p.path ? [" ", link(p.fix, p.path)] : null),
      h("p", { class: "lede", text: t("Start your agent as usual in your project. When something needs your decision, AQT shows it under Needs you.") }),
      app,
      h("details", { class: "as-command-box" }, h("summary", { text: t("Use the aqt command in a terminal") }), commandSection(S.setup)),
      nav(h("button", { class: "btn primary", type: "button", text: t("Open Needs you"), onclick: () => go("/") }))];
  }
  function draw() {
    drawList();
    if (readOnly) {
      put(clear(body), title(t("AQT cannot be set up from here")),
        h("p", { class: "lede", text: t("Setting up writes your keys and settings, so only you can do it.") }),
        h("div", { class: "off" }, h("strong", { text: `${t("Read-only")}. ` }), S.mode ? S.mode.reason : ""),
        h("p", { text: t("Start AQT yourself, outside any agent session, and open the setup again.") }),
        nav(h("button", { class: "btn ghost", type: "button", text: t("Look around read-only"), onclick: () => go("/") })));
      return;
    }
    put(clear(body), steps[W.step]());
  }
  draw();
}

const RENDER = { home: renderHome, changes: renderChanges, projects: renderProjects, settings: renderSettings, welcome: renderWelcome };

// ---- start ---------------------------------------------------------------------------------------------
async function start() {
  shellLabels();
  $("lang").addEventListener("change", (event) => setLang(event.target.value));
  $("menu-btn").addEventListener("click", () => {
    const open = $("rail").classList.toggle("open");
    $("menu-btn").setAttribute("aria-expanded", String(open));
  });
  $("refresh").addEventListener("click", async () => { await refresh(); route(); announce(t("Refreshed")); });
  S.csrf = APP ? "" : sessionKey();
  try {
    const session = await api("/api/session");
    S.mode = session.mode;
    S.installed = session.installed;
    S.install = session.install || {};
    renderTopbar();
    await refresh();
  } catch (error) {
    put(clear($("main")), errorBox(error));
    return;
  }
  // not set up yet (no trail or no signer): the window opens on the setup; deep links still open their page
  if (S.overview.setup && S.overview.setup.needed && location.pathname === "/") history.replaceState(null, "", WELCOME.path);
  route();
  loadSetup().catch(() => null);
  setInterval(() => { loadSetup().catch(() => null); }, 300000);
  setInterval(() => { refresh().catch(() => {}); }, 15000);
  const status = S.overview && S.overview.status;
  if (status && status.verifying) pollVerify();
}
start();
