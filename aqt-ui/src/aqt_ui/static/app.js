// aqt-ui front end: plain ES module, no build step.
// Every piece of data is put into the page with textContent or attributes, never as markup,
// because evidence (quarantined pages, reasons, excerpts) is untrusted. All text goes through
// vis(), which shows hidden characters (bidi controls, zero-width characters, ...) as <U+XXXX>.
import { DE, NEEDS, REASONS_DE, REFUSALS_DE, STEPS_DE } from "./i18n.js";
import { vis } from "./text.js";

// ---- language: English by default, German on request; the choice stays in this browser ------------
let LANG = "en";
try { if (localStorage.getItem("aqt-ui-lang") === "de") LANG = "de"; } catch (e) { /* storage blocked: stay English */ }
// t('English words {n}', { n: 3 }): the German entry when German is chosen, else the English words.
function t(text, vars) {
  const out = (LANG === "de" && DE[text]) || text;
  return vars ? out.replace(/\{(\w+)\}/g, (all, key) => (vars[key] === undefined || vars[key] === null ? all : String(vars[key]))) : out;
}
function setLang(lang) {
  LANG = lang === "de" ? "de" : "en";
  try { localStorage.setItem("aqt-ui-lang", LANG); } catch (e) { /* not remembered; works for this page */ }
  shellLabels();
  renderTopbar();
  route();
}

// Home is the queue; Health and the tool views are secondary (auditors use them read-only).
// Case pages (/case/<id>) and change pages (/change/<project>/<plan>) have no inspector.
const VIEWS = [
  { id: "home", path: "/", label: "Needs you" },
  { id: "health", path: "/health", label: "Health", inspector: true },
  { id: "trail", path: "/trail", label: "Trail", tool: true, inspector: true },
  { id: "quarantine", path: "/quarantine", label: "Quarantine", tool: true, inspector: true },
  { id: "changes", path: "/changes", label: "Changes", tool: true, inspector: true },
  { id: "signatures", path: "/signatures", label: "Signatures", tool: true, inspector: true },
  { id: "capa", path: "/capa", label: "CAPA", tool: true, inspector: true },
  { id: "qualifications", path: "/qualifications", label: "Qualifications", tool: true, inspector: true },
];
const S = { csrf: "", mode: null, overview: null, view: "home", installed: {} };
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
  return (LANG === "de" && REFUSALS_DE[code]) || english || "";
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
  const box = h("div", { class: "error-box", role: "alert" }, error.message || String(error));
  if (error.data && error.data.install) put(box, h("div", { class: "small" }, t("Install:"), " ", h("code", { text: `uv pip install -e ${error.data.install}` })));
  return box;
}
function tabs(items, current, onPick) {
  return h("div", { class: "tabs", role: "tablist" }, items.map(([id, label]) =>
    h("button", { role: "tab", "aria-selected": current === id ? "true" : "false", type: "button", text: label, onclick: () => onPick(id) })));
}

// ---- API ----------------------------------------------------------------------------------------
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
  const response = await fetch(path, { headers: { Accept: "application/json", "X-AQT-CSRF": S.csrf }, credentials: "same-origin" });
  const data = await response.json().catch(() => ({ message: `HTTP ${response.status}` }));
  if (!response.ok) throw Object.assign(new Error(data.message || `HTTP ${response.status}`), { status: response.status, data });
  return data;
}
async function post(path, body) {
  const response = await fetch(path, {
    method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-AQT-CSRF": S.csrf, Accept: "application/json" },
    body: JSON.stringify(body || {}),
  });
  const data = await response.json().catch(() => ({ ok: false, message: `HTTP ${response.status}` }));
  return { status: response.status, data };
}
// A file from the API, saved through a blob link (a plain link would lack the session key).
async function download(path, fallbackName) {
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
  $("menu-btn").textContent = vis(t("Views"));
  $("refresh").textContent = vis(t("Refresh"));
  $("brand-sub").textContent = vis(t("quality desk, this machine only"));
  $("rail").setAttribute("aria-label", t("Views"));
  inspector().setAttribute("aria-label", t("Details"));
  const lang = $("lang");
  lang.value = LANG;
  lang.setAttribute("aria-label", t("Language"));
}

function renderRail() {
  const nav = clear($("nav"));
  const counts = (S.overview && S.overview.counts) || {};
  let grouped = false;
  for (const view of VIEWS) {
    if (view.tool && !grouped) { put(nav, h("li", { class: "nav-group", text: t("Records and tools") })); grouped = true; }
    const n = (view.id === "home" ? counts.overview : view.id === "health" ? 0 : counts[view.id]) || 0;
    const link = h("a", {
      href: view.path, "aria-current": S.view === view.id ? "page" : null,
      onclick: (event) => { event.preventDefault(); go(view.path); $("rail").classList.remove("open"); $("menu-btn").setAttribute("aria-expanded", "false"); },
    }, h("span", { class: "label", text: t(view.label) }),
       n ? h("span", { class: `count ${view.id === "signatures" ? "" : "hot"}`, "aria-label": t("{n} need attention", { n }), text: n }) : null);
    put(nav, h("li", {}, link));
  }
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
  const pill = clear($("trail-pill"));
  const broken = $("broken");
  broken.hidden = true;
  const status = S.overview && S.overview.status;
  if (status) {
    if (status.state === "broken") {
      broken.hidden = false;
      put(clear(broken), t("Trail broken from seq {seq}: {reason}", { seq: num(status.check.first_bad_seq), reason: status.check.reason || "" }));
    } else if (status.state === "changed") {
      broken.hidden = false;
      put(clear(broken), t("Trail changed since the last check: {reason}. Verify it again.", { reason: status.changed || "" }));
    }
    writerBar(status);
    const [kind, text] = trailLine(status);
    pill.className = `pill ${kind}`;
    put(pill, h("span", { "aria-hidden": "true", text: ICON[kind] }), text);
  } else put(pill, t("Trail: loading"));
  const badge = clear($("mode-badge"));
  const ribbon = clear($("ribbon"));
  if (S.mode) {
    badge.className = `badge ${S.mode.decisions ? "on" : "off"}`;
    put(badge, S.mode.decisions ? t("Decisions on · passphrase per decision") : t("Read-only"));
    ribbon.hidden = S.mode.decisions;
    if (!S.mode.decisions) put(ribbon, h("strong", { text: `${t("Read-only")}. ` }), S.mode.reason);
  }
}

// Writer down: a banner on every page with the fix (records wait in the spool until it runs again).
function writerBar(status) {
  const bar = $("writer");
  if (!bar) return;
  const down = status && status.state !== "missing" && status.writer && !status.writer.running;
  bar.hidden = !down;
  if (down) put(clear(bar), h("strong", { text: `${t("The trail writer is not running.")} ` }),
    t("Start it in a terminal:"), " ", h("code", { text: "aqt-trail serve" }), status.writer.socket ? h("span", { class: "small", text: ` (${t("socket")} ${status.writer.socket})` }) : null);
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
  if (event.defaultPrevented || event.altKey || event.ctrlKey || event.metaKey || typing(event.target)) return;
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

// ---- decision panel ----------------------------------------------------------------------------------
// One component for every human-only action, laid out like a signature manifestation. An action
// may carry one sentence on its consequence; with several, they are offered as a list of choices.
// onDone(result, action) replaces the default reload after a recorded decision (case pages).
let panelCount = 0;
function decisionPanel({ actions, subject, signers, submit, note, fields, noSigners, title, onDone }) {
  const n = ++panelCount;
  const box = h("section", { class: "decision", "aria-label": title || t("Decision") });
  put(box, h("h3", { text: title || t("Decision") }));
  if (!S.mode || !S.mode.decisions) {
    put(box, h("div", { class: "off" }, h("strong", { text: `${t("Read-only")}. ` }), S.mode ? S.mode.reason : ""));
    return box;
  }
  if (!signers || !signers.length) {
    put(box, h("div", { class: "off", text: noSigners || t("No signer is registered. Enrol yourself in a terminal first: aqt-signoff init") }));
    return box;
  }
  let chosen = actions[0];
  const signerSelect = h("select", { id: `dp-signer-${n}` }, signers.map((s) => h("option", { value: s.id, text: `${s.name || s.id} (${s.role || t("no role")})` })));
  const meaningCell = h("dd", { text: t(chosen.meaning) });
  const signerCell = h("dd");
  const showSigner = () => {
    const s = signers.find((x) => x.id === signerSelect.value) || signers[0];
    put(clear(signerCell), `${s.name || "?"} · ${s.id} · ${s.role || t("no role")}`);
  };
  const button = h("button", { class: `btn ${chosen.danger ? "danger" : "primary"}`, type: "button", text: chosen.button });
  const pick = (a) => {
    chosen = a;
    meaningCell.textContent = vis(t(a.meaning)); button.textContent = vis(a.button); button.className = `btn ${a.danger ? "danger" : "primary"}`;
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
    : worded ? h("p", { class: "consequence" }, title === chosen.label ? null : h("strong", { text: `${chosen.label}: ` }), chosen.consequence)
    : actions.length > 1 ? h("div", { class: "chips", role: "radiogroup", "aria-label": t("Decision") },
    actions.map((a) => {
      const b = h("button", { class: "chip-btn", type: "button", role: "radio", "aria-checked": a === chosen ? "true" : "false", "aria-pressed": a === chosen ? "true" : "false", text: a.label });
      b.addEventListener("click", () => {
        for (const other of choice.children) { const on = other === b; other.setAttribute("aria-checked", String(on)); other.setAttribute("aria-pressed", String(on)); }
        pick(a);
      });
      return b;
    })) : null;
  const reason = h("textarea", { id: `dp-reason-${n}`, required: true, "aria-required": "true", maxlength: "2000" });
  const pass = h("input", { id: `dp-pass-${n}`, type: "password", autocomplete: "off", spellcheck: "false", "aria-required": "true" });
  const result = h("div", { "aria-live": "polite" });
  signerSelect.addEventListener("change", showSigner);
  showSigner();
  button.addEventListener("click", async () => {
    clear(result);
    if (!reason.value.trim()) { put(result, h("div", { class: "result stale", text: t("A reason is required.") })); reason.focus(); return; }
    if (!pass.value) { put(result, h("div", { class: "result stale", text: t("Enter your passphrase.") })); pass.focus(); return; }
    button.disabled = true;
    const passphrase = pass.value;
    pass.value = "";
    try {
      const { status, data } = await submit(chosen, { reason: reason.value.trim(), passphrase, signer_id: signerSelect.value });
      const kind = data.ok ? "ok" : status === 409 ? "stale" : "refused";
      let text;
      if (data.ok) text = `${t("Recorded as {record}", { record: data.record_id || "a record" })}${data.time ? " · " + fmtTime(data.time) : ""}. ${data.message || ""}`;
      else if (status === 409) text = `${t("Not signed:")} ${data.message}`;
      else text = `${t("Refused:")} ${refusalWords(data.reason_code, data.reason_text) ? refusalWords(data.reason_code, data.reason_text) + ". " : ""}${data.message}${data.record_id ? ` (${t("refusal recorded as {record}", { record: data.record_id })})` : ""}`;
      put(result, h("div", { class: `result ${kind}`, role: "status", text }));
      announce(text);
      if (data.ok) {
        form.remove();                       // the decision is made; show what was recorded
        if (choice) choice.remove();
        if (fields) fields.remove();
        if (onDone) onDone(data, chosen);
        else setTimeout(async () => { await refresh(); route(true); }, 600);
      }
      result.scrollIntoView({ block: "nearest" });
    } catch (error) {
      put(result, h("div", { class: "result refused", text: String(error.message || error) }));
    } finally {
      button.disabled = false;
    }
  });
  const form = h("div", {},
    signers.length > 1 ? h("div", { class: "field" }, h("label", { for: `dp-signer-${n}`, text: t("Who signs") }), signerSelect) : null,
    h("div", { class: "field" }, h("label", { for: `dp-reason-${n}`, text: t("Reason (required, recorded with the decision)") }), reason),
    h("div", { class: "field" }, h("label", { for: `dp-pass-${n}`, text: t("Passphrase of your signing key (used once, never stored)") }), pass),
    note ? h("p", { class: "small muted", text: note }) : null,
    h("div", { class: "actions" }, button));
  put(box,
    choice,
    fields || null,
    h("dl", { class: "manifest", "aria-label": t("What will be signed") },
      h("dt", { text: t("Signer") }), signerCell,
      h("dt", { text: t("Meaning") }), meaningCell,
      h("dt", { text: t("Subject") }), h("dd", {}, subject.label, subject.hash ? [" ", hashButton(subject.hash, 16)] : null)),
    form,
    result,
  );
  return box;
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
  document.title = `${text} · ${t("AQT quality desk")}`;
}
async function route(keepInspector) {
  const path = location.pathname;
  const page = path.startsWith("/case/") ? "case" : path.startsWith("/change/") ? "change" : null;
  const view = page === "case" ? VIEWS[0] : page === "change" ? VIEWS.find((v) => v.id === "changes")
    : VIEWS.find((v) => v.path === path) || VIEWS[0];
  const changed = S.path !== path;
  S.view = view.id;
  S.page = page;
  S.path = path;
  if (page !== "case") S.caseId = null;
  setTitle(page === "change" ? t("Changes") : t(view.label));
  document.querySelector(".shell").classList.toggle("no-insp", !!page || !view.inspector);
  renderRail();
  const main = clear($("main"));
  put(main, h("div", { class: "empty", text: t("Loading…") }));
  if (keepInspector !== true) placeholder(t("Select an item to see its details."));
  if (changed) { main.scrollTop = 0; window.scrollTo(0, 0); }
  try {
    await (page === "case" ? renderCase(main) : page === "change" ? renderChangeRoute(main) : RENDER[view.id](main));
    if (page && changed && !location.hash) main.focus({ preventScroll: true });
  } catch (error) {
    put(clear(main), errorBox(error));
  }
}

// ---- Home: the queue --------------------------------------------------------------------------------
const SEVERITY_KIND = { critical: "fail", high: "warn", medium: "info", low: "neutral" };
// Title and detail of a "Needs you" entry in the chosen language (English comes from the server).
function needText(item) {
  const de = LANG === "de" && NEEDS[item.key];
  if (!de) return [item.title, item.detail];
  const fill = (text) => text.replace(/\{(\w+)\}/g, (all, key) => (item.args[key] === undefined ? all : typeof item.args[key] === "number" ? num(item.args[key]) : t(String(item.args[key]))));
  const detail = de[1] === null ? item.detail : de[1] === "@reason" ? (REASONS_DE[item.args.reason_code] || item.detail) : fill(de[1]);
  return [fill(de[0]), detail];
}
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
      h("p", { class: "small" }, h("a", { href: "/health", onclick: (e) => { e.preventDefault(); go("/health"); }, text: t("Health of the trail and the tools") })))));
    return;
  }
  const queue = h("ol", { class: "queue", "aria-label": t("Needs you") });
  data.needs.forEach((item, index) => {
    const target = VIEWS.find((v) => v.id === item.view);
    const [title, detail] = needText(item);
    const since = sinceText(item);
    const button = h("button", { class: "case-line", type: "button", "data-index": String(index) },
      st(SEVERITY_KIND[item.severity] || "neutral", t(item.severity)),
      h("span", { class: "what" }, h("strong", { text: title }), detail ? h("span", { text: detail }) : null),
      h("span", { class: "when" }, since ? h("span", { text: since }) : null,
        h("span", { class: "where", text: target ? t(target.label) : "" })));
    button.addEventListener("click", () => { S.queueAt = index; go(casePath(item)); });
    put(queue, h("li", {}, button));
  });
  const [kind, line] = trailLine(status);
  put(main, h("div", { class: "home" },
    h("p", { class: "home-intro small muted" }, t("Open cases: {n}, most urgent first.", { n: data.needs.length }), " ",
      h("span", { class: "keys", text: t("Keys: j and k move, Enter opens, n opens the next case.") })),
    queue,
    h("p", { class: "trail-line small" }, st(kind, line), " ",
      h("a", { href: "/health", onclick: (e) => { e.preventDefault(); go("/health"); }, text: t("Health") }))));
  const list = queueButtons();
  if (S.queueAt !== undefined && list.length) list[Math.min(S.queueAt, list.length - 1)].focus({ preventScroll: false });
}

// ---- Health: trail status, ALCOA++, tool health, refusals ---------------------------------------------
async function renderHealth(main) {
  const data = S.overview || (await refresh());
  clear(main);
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
  put(main, section([`${t("Trail status")} `, h("span", { class: "hint" }, verifyBtn)], band,
    status.state === "broken" ? h("p", { class: "small", text: `${t("Verifier:")} ${check.summary}` }) : null));

  const strip = h("div", { class: "alcoa" });
  if (data.alcoa.length) {
    for (const item of data.alcoa) {
      const chip = h("button", { class: "chip-btn", type: "button", title: `${item.id}: ${item.detail}` }, stWord(item.status, `${t(item.attribute)} ${t(item.status)}`));
      chip.addEventListener("click", () => setInspector(inspSection("ALCOA++", h("p", { class: "insp-title", text: t(item.attribute) }), stWord(item.status),
        h("p", { text: item.detail }), kv([[t("Catalogue"), h("code", { text: item.id })], [t("Related"), item.related.join(", ")]]),
        h("p", { class: "small muted", text: t("pass means the check found nothing; it does not mean a process is compliant.") }))));
      put(strip, chip);
    }
  } else put(strip, h("span", { class: "muted", text: status.verifying ? t("Computed after the verification finishes…") : t("Not computed yet: run Verify now.") }));
  put(main, section("ALCOA++", strip));

  const tools = h("div", { class: "tools" }, data.tools.map((x) => h("div", {},
    h("div", {}, h("strong", { text: x.package }), " ", x.installed ? stWord(x.problem ? "warn" : "pass", x.problem ? t("problem") : t("installed")) : stWord("neutral", t("not installed"))),
    h("div", { class: "small muted", text: x.installed ? (x.problem || t("last record {ago}", { ago: x.last_record ? ago(x.last_record) : t("none") })) : x.install }))));
  put(main, section(t("Tool health"), tools));

  if (data.refusals.length) {
    const rows = data.refusals.slice().reverse().map((r) => ({ data: r, cells: [h("td", { class: "small time", text: fmtTime(r.time) }), r.type, h("td", { class: "mono small hide-narrow", text: r.actor.id }), refusalWords(r.reason_code, r.reason_text) ? `${refusalWords(r.reason_code, r.reason_text)} (${r.reason_code})` : r.reason_code || ""] }));
    const x = table([t("Time"), t("Type"), th(t("Claimed actor"), "hide-narrow"), t("Reason code")], rows, (r) => go(`/trail?type=*.refused#${r.id}`));
    put(main, section(t("Refusals in the last 24 h"), x.table));
  }
}

async function refresh(force) {
  const data = await api("/api/overview");
  S.overview = data;
  renderRail();
  renderTopbar();
  if (force && (S.view === "home" || S.view === "health") && !S.page) route();
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
  document.title = `${needTitle || title} · ${t("AQT quality desk")}`;
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
    kv([[t("Record"), h("code", { text: data.record_id || "–" })], [t("Time"), fmtTime(data.time)], data.message ? [t("Result"), data.message] : null]),
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

async function renderCase(main, notice) {
  const id = decodeURIComponent(location.pathname.slice("/case/".length));
  let data = S.overview || (await refresh());
  if (!notice && !data.needs.some((n) => n.id === id)) data = await refresh();   // a case newer than the last check
  const at = data.needs.findIndex((n) => n.id === id);
  const item = at >= 0 ? data.needs[at] : null;
  S.caseId = id;
  if (at >= 0) S.queueAt = at;
  const [kind, ...rest] = id.split(":");
  if (!CASES[kind]) { clear(main); put(main, empty(t("Unknown case"), id)); return; }
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
      links: [[t("Open in {view}", { view: t("Quarantine") }), `/quarantine?item=${encodeURIComponent(c.case_id)}`]],
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
        links: [[t("Open in {view}", { view: t("CAPA") }), "/capa?tab=deviations"]] });
      f.body(inspSection(t("Deviations"), overdue.length ? h("ul", { class: "evidence-list" }, overdue.map((d) => h("li", {},
        link(`${d.dev_id} ${d.title}`, `/capa?tab=deviations&item=${encodeURIComponent(d.dev_id)}`), ` · ${t("due")} ${fmtTime(d.due)}`))) : h("p", { class: "muted", text: t("No deviation is overdue.") })));
      f.decide(t("How to resolve"), resolveSteps([[t("Record the investigation in a terminal (5 whys, factors, root cause):"),
        `aqt-capa investigate ${(overdue[0] && overdue[0].dev_id) || "DEV-…"} --why "…" --root-cause "…" --root-category …`]]));
      return;
    }
    const wanted = query().get("candidate");
    const candidate = data.candidates.find((c) => c.candidate_id === wanted) || data.candidates[0];
    const f = caseFrame(main, item, { title: t("CAPA candidates"), stop: ["person", t("Waits for you: accept or dismiss each candidate")],
      links: [[t("Open in {view}", { view: t("CAPA") }), "/capa?tab=candidates"]] });
    if (!candidate) { f.body(empty(t("No open candidates"), t("aqt-capa scan finds candidates in the evidence."))); if (notice) f.decide(t("Decided"), recordedBlock(notice)); return; }
    const x = candidateParts(candidate, data.signers, { onDone: done });
    const others = data.candidates.filter((c) => c !== candidate);
    f.body(x.summary, others.length ? inspSection(t("Other candidates ({n})", { n: others.length }), h("ul", { class: "evidence-list" },
      others.map((c) => h("li", {}, h("a", { href: "#", onclick: (e) => { e.preventDefault(); setQuery({ candidate: c.candidate_id }); route(); }, text: c.title }), ` · ${c.rule}`)))) : null);
    if (notice) f.decide(t("Decided"), recordedBlock(notice));
    else f.decide(null, x.decision);
  },

  async trail({ main, item, rest, notice, done }) {
    await refresh().catch(() => null);
    const ov = S.overview;
    const status = ov.status;
    const check = status.check || {};
    const code = rest[0];
    const trailLink = [t("Open in {view}", { view: t("Trail") }), "/trail"];
    const integrity = () => inspSection(t("Integrity"), stWord(status.state), kv([[t("Records"), num(status.records)], [t("Head seq"), num(status.head_seq)],
      [t("Checked"), check.checked_at ? fmtTime(check.checked_at) : t("not yet")], check.first_bad_seq != null ? [t("Broken from seq"), num(check.first_bad_seq)] : null,
      check.reason ? [t("Reason"), check.reason] : null, status.changed ? [t("Changed"), status.changed] : null]),
      check.summary ? h("p", { class: "small break", text: `${t("Verifier:")} ${check.summary}` }) : null,
      (check.problems || []).map((p) => h("p", { class: "small break", text: `${t("Problem:")} ${p}` })),
      (check.warnings || []).map((w) => h("p", { class: "small muted break", text: `${t("Warning:")} ${w}` })));
    const verify = () => h("div", { class: "actions" }, h("button", { class: "btn small", type: "button", text: t("Verify now"),
      onclick: async (e) => { e.target.disabled = true; await post("/api/trail/verify"); pollVerify(); } }));
    if (["trail_broken", "trail_changed", "trail_problems"].includes(code)) {
      const f = caseFrame(main, item, { title: t("Trail integrity"), stop: ["fix", t("Waits for a fix: find out why the trail does not verify")], links: [trailLink] });
      f.body(integrity());
      f.decide(t("How to resolve"), resolveSteps([[t("Do not edit the trail. Compare it with your last export or external head, find the cause, then verify again:"), "aqt-trail verify"]]), verify());
    } else if (code === "alcoa") {
      const result = (ov.alcoa || []).find((a) => a.id === rest.slice(1).join(":"));
      const f = caseFrame(main, item, { title: t("ALCOA++ result"), stop: ["fix", t("Waits for a look at the records behind this result")], links: [trailLink] });
      f.body(result ? inspSection(t("ALCOA++"), stWord(result.status, `${t(result.attribute)} ${t(result.status)}`), h("p", { text: result.detail }),
        kv([[t("Catalogue"), h("code", { text: result.id })], [t("Related"), (result.related || []).join(", ") || "–"]]),
        h("p", { class: "small muted", text: t("pass means the check found nothing; it does not mean a process is compliant.") })) : h("p", { class: "muted", text: t("Not computed yet: run Verify now.") }));
      f.decide(t("How to resolve"), resolveSteps([[t("Read the full report with the records it names:"), "aqt-trail alcoa"]]));
    } else if (code === "refusals") {
      const f = caseFrame(main, item, { title: t("Refused decision attempts"), stop: ["person", t("Waits for a look: who tried to decide, and why")],
        links: [[t("Open in {view}", { view: t("Trail") }), "/trail?type=*.refused"]] });
      const rows = ov.refusals.slice().reverse().map((r) => ({ data: r, cells: [h("td", { class: "small time", text: fmtTime(r.time) }), r.type, h("td", { class: "mono small", text: r.actor.id }),
        refusalWords(r.reason_code, r.reason_text) ? `${refusalWords(r.reason_code, r.reason_text)} (${r.reason_code})` : r.reason_code || ""] }));
      f.body(inspSection(t("Refusals in the last 24 h"), table([t("Time"), t("Type"), t("Claimed actor"), t("Reason code")], rows, (r) => go(`/trail?type=*.refused#${r.id}`)).table));
      f.decide(t("How to resolve"), h("p", { text: t("Nothing to sign: each attempt is already recorded. If an agent tried to decide, check its instructions; repeated attempts become CAPA candidates.") }));
    } else if (code === "review_due") {
      const profile = status.review_profile || {};
      const f = caseFrame(main, item, { title: t("Audit-trail review"), stop: ["person", t("Waits for you: review the audit trail and sign the review")], links: [[t("Open in {view}", { view: t("Trail") }), "/trail?panel=review"]] });
      f.body(inspSection(t("Audit-trail review"), kv([[t("Last review"), status.last_review ? `${fmtTime(status.last_review)} (${ago(status.last_review)})` : t("none")],
        [t("Records"), num(status.records)], [t("Profile"), [profile.name || "?", " · ", profileWord(profile)]]]), profileNotes(profile, status.test_mode)));
      if (notice) { f.decide(t("Decided"), recordedBlock(notice)); return; }
      const out = h("div", { "aria-live": "polite" });
      const run = h("button", { class: "btn primary", type: "button", text: t("Prepare worksheet") });
      run.addEventListener("click", async () => {
        run.disabled = true;
        const { status: code2, data } = await post("/api/trail/review/run", {});
        run.disabled = false;
        if (code2 !== 200 || !data.ok) { put(clear(out), h("div", { class: "result refused", text: data.message || `HTTP ${code2}` })); return; }
        f.decide(t("Decide"), ...reviewPanel(data, { onDone: done }));
      });
      f.decide(t("Decide"), h("p", { class: "small muted", text: t("Runs the risk queries over a period and lists the findings. Preparing writes a worksheet file, no evidence; the signed review is recorded in the trail.") }),
        h("div", { class: "actions" }, run), out);
    } else {
      const fixes = {
        writer_down: [t("Waits for a fix: start the trail writer"), [t("Start the writer in a terminal:"), "aqt-trail serve"]],
        spooled: [t("Waits for a fix: move the spooled records into the trail"), [t("Append the spooled records to the trail:"), "aqt-trail drain"]],
        unanchored: [t("Waits for a fix: anchor the trail head"), [t("Sign the head and add an RFC 3161 time stamp:"), "aqt-trail checkpoint --anchor"]],
        test_mode: [t("Waits for a fix in trail.toml"), [t("Remove the line test_tsa = true from the [anchor] section of trail.toml.")]],
        review_params: [t("Waits for a fix in trail.toml"), [t("Check the [review] section of trail.toml and remove the values you did not set.")]],
      }[code] || [t("Waits for a fix"), [t("See the Health view for details.")]];
      const f = caseFrame(main, item, { title: t("Trail"), stop: ["fix", fixes[0]], links: [[t("Health"), "/health"]] });
      f.body(code === "review_params" || code === "test_mode" ? inspSection(t("Review parameters"), profileNotes(status.review_profile, status.test_mode)) : integrity());
      f.decide(t("How to resolve"), resolveSteps([fixes[1]]));
    }
  },

  async qualification({ main, item, rest }) {
    const data = await api("/api/qualifications");
    const subject = rest.join(":");
    const q = data.qualifications.find((x) => x.subject_id === subject);
    const f = caseFrame(main, item, { title: t("Qualification of {subject}", { subject }), stop: ["fix", t("Waits for requalification")],
      links: [[t("Open in {view}", { view: t("Qualifications") }), "/qualifications"]] });
    if (q) f.body(inspSection(t("Qualification"), stWord(q.state), kv([[t("Kind"), t(q.kind)], [t("Decision"), t(q.decision)], [t("Conclusion"), q.conclusion],
      [t("Valid until"), fmtTime(q.valid_until)], [t("Approved by"), `${q.approver_name || ""} ${q.approver || ""}`], [t("Triggers"), q.triggers.join(", ") || t("none recorded")], [t("Record"), h("code", { text: q.record })]])));
    f.decide(t("How to resolve"), resolveSteps([[t("Run the validation again under the locked protocol and qualify the new run, in your own terminal:"),
      "aqt-validate detector run protocol.toml --out runs/<new>", 'aqt-validate qualify runs/<new> --approve --reason "…"']]));
  },
};

// A plan version to approve, or a gate that is not GO: the gate's evidence and the approval.
async function planCase({ main, item, rest, notice, done }, kind) {
  const [project, ...plan] = rest;
  const planId = plan.join(":");
  const d = await api(`/api/change/${project}/${encodeURIComponent(planId)}`);
  const p = d.plan;
  const g = gateParts(p, d.root, d.signers, { onDone: done });
  const manual = p.decision === "MANUAL_VERIFY_REQUIRED";
  const f = caseFrame(main, item, {
    title: kind === "plan" ? t("Plan version of {plan} to approve", { plan: planId }) : t("Gate {decision} for {plan}", { decision: p.decision || "–", plan: planId }),
    stop: kind === "plan" ? ["person", t("Waits for you: approve this plan version")]
      : manual ? ["person", t("Waits for a person: the gate needs a manual check")] : ["evidence", t("Waits for evidence: checks, a review or the finish")],
    settled: p.decision === "GO" ? st("pass", "GO") : null,
    links: [[t("Change page"), `/change/${project}/${encodeURIComponent(planId)}`]],
  });
  f.body(inspSection(t("Steps of the change"), timelineView(d.steps, p, (step) => go(`/change/${project}/${encodeURIComponent(planId)}#step-${step}`))),
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
async function renderChangeRoute(main) {
  const [, , project, plan] = location.pathname.split("/");
  await renderChange(main, { project, planId: decodeURIComponent(plan || "") });
}
async function renderChange(main, { project, planId, item, notice, done, fresh }) {
  const d = await api(`/api/change/${project}/${encodeURIComponent(planId)}${fresh ? "?fresh=1" : ""}`);
  const p = d.plan;
  const asCase = location.pathname.startsWith("/case/");
  const onDone = done || (async (data, chosen) => { await refresh().catch(() => null); await renderChange(main, { project, planId, notice: { data, chosen } }); });
  const current = d.steps.find((s) => s.current);
  const title = t("Change {plan}", { plan: p.plan_id });
  let f;
  if (asCase) {
    f = caseFrame(main, item, { title, stop: current ? [current.state, t(STEP_STOPS[current.state][current.id])] : null,
      settled: (p.release || {}).state === "released" ? stWord("released") : null,
      links: [[t("Change page"), `/change/${project}/${encodeURIComponent(planId)}`]] });
  } else {
    clear(main);
    document.title = `${title} · ${t("AQT quality desk")}`;
    const body = h("div", { class: "case-body" });
    const decideBox = h("section", { class: "case-decide" });
    put(main, h("article", { class: "case change" }, h("header", { class: "case-head" },
      h("nav", { class: "crumbs", "aria-label": t("Where you are") }, link(t("Changes"), "/changes")),
      h("h2", { class: "case-title", text: title }),
      h("p", { class: "case-why" }, h("span", { class: "mono small", text: d.root }), " ", h("span", { class: "mono small muted", text: p.path })),
      current ? h("p", { class: `stopline ${current.state}` }, stopMark(current.state), h("span", { text: t(STEP_STOPS[current.state][current.id]) }))
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
function releaseSection(step, d, p, { onDone, notice }) {
  const release = p.release;
  const fin = p.finish_record || {};
  if (!p.finish) return step("release", h("p", { class: "muted", text: t("Not finished yet: the change.finish record is written by aqt-change finish.") }));
  const parts = [kv([[t("Finish record"), h("code", { text: p.finish })], [t("Time"), fmtTime(fin.time)], [t("By"), fin.by || "–"], [t("Commit"), fin.commit ? h("code", { text: String(fin.commit).slice(0, 12) }) : "–"],
    [t("Hash"), hashButton(release && release.sha256, 16)]])];
  if (!d.installed["aqt-signoff"] || (release && release.state === "unavailable")) {
    parts.push(h("p", { class: "small" }, t("aqt-signoff is not installed"), ": ", h("code", { text: "uv pip install -e aqt-signoff" })));
    return step("release", ...parts);
  }
  if (release.state === "missing") {
    parts.push(h("p", { class: "flag", text: release.detail }), h("p", { class: "small muted", text: t("The finish record is not in the audit trail, so it cannot be signed here. Start the writer and drain the spool.") }));
    return step("release", ...parts);
  }
  const pol = d.release_policy || { min_signatures: 1, roles: [], distinct_from_author: false };
  const result = release.policy || {};
  parts.push(h("p", {}, stWord(release.state === "released" ? "released" : "unsigned", release.state === "released" ? t("released") : t("not released yet")), " ",
    h("span", { class: "small muted", text: release.summary })));
  if (release.signatures.length) parts.push(plainTable([t("Printed name"), "ID", t("Role"), t("Local time"), t("Reason"), t("Status")], release.signatures.map((x) =>
    [x.name, h("td", { class: "mono small", text: x.id }), x.role, h("td", { class: "small", text: x.local }), h("td", { class: "wrap small", text: x.reason }), h("td", {}, stWord(x.status))])));
  parts.push(h("p", { class: "small muted" }, t("Policy [policy.released] in signoff.toml: {n} valid signature(s), {roles}, {author}.", {
    n: pol.min_signatures, roles: pol.roles.length ? t("roles {list}", { list: pol.roles.join(", ") }) : t("any role"),
    author: pol.distinct_from_author ? t("not by an author of the change") : t("the author may sign") }),
    result.note ? ` ${result.note}` : ""));
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
      signers, subject: { label: t("change {plan}, finish record {record}", { plan: p.plan_id, record: p.finish }), hash: release.sha256 },
      noSigners: pol.roles.length ? t("No registered signer may sign this release: [policy.released] allows the roles {list}.", { list: pol.roles.join(", ") }) : null,
      onDone, submit: (x, values) => post(`/api/change/${d.project}/${encodeURIComponent(p.plan_id)}/release`, { ...values, record: p.finish, sha256: release.sha256 }),
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
    h("p", { class: "break", text: check.summary || t("Not verified yet.") }),
    check.checked_at ? kv([[t("Checked"), fmtTime(check.checked_at)], [t("Took"), `${check.seconds ?? "?"} s`], [t("Signatures"), num(check.signatures)], [t("Anchors"), num(check.anchors)]]) : null,
    (check.problems || []).map((p) => h("p", { class: "small break", text: `${t("Problem:")} ${p}` })),
    (check.warnings || []).map((w) => h("p", { class: "small muted break", text: `${t("Warning:")} ${w}` })),
    h("div", { class: "actions" }, button))];
  const alcoa = (S.overview && S.overview.alcoa) || [];
  if (alcoa.length) parts.push(inspSection("ALCOA++", alcoa.map((a) => h("p", { class: "small" }, stWord(a.status, t(a.attribute)), " ", a.detail))));
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
    if (status !== 200 || !data.ok) { put(out, h("div", { class: "result refused", text: data.message || `HTTP ${status}` })); return; }
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
      h("p", { class: "small muted break", text: f.explanation }), h("div", { class: "field-row" }, select, note)));
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
      [t("Chain status"), obs.chain_status ? `${obs.chain_status}${obs.chain_detail ? " (" + obs.chain_detail + ")" : ""}` : "–"],
      drained ? [t("Drained by"), `${(drained.process_chain || []).join(" ← ") || "–"}${drained.harness ? " · " + drained.harness : ""} · ${drained.chain_status || "–"}`] : null,
    ]), attributionNote(data.attribution)),
    inspSection(t("Signatures"), (r.sig || []).map((s) => kv([[t("Writer key"), h("code", { text: s.key })]])),
      sig ? kv([[t("Detached"), h("span", {}, stWord(sig.status), ` ${sig.meaning ? t(sig.meaning) : "–"} · ${sig.signer || "–"}`)],
        sig.detail ? [t("Check"), sig.detail] : null, [t("Key"), h("code", { text: sig.key || "–" })]]) : null),
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
      for (const piece of w.pieces) put(pre, piece.mark ? h("mark", { title: piece.mark, text: piece.text }) : document.createTextNode(vis(piece.text)));
      if (w.cut_after) put(pre, h("span", { class: "muted", text: " …" }));
      put(pre, "\n\n");
    }
    put(content, h("p", { class: "untrusted", text: t("Untrusted third-party text. Highlighted passages are detector evidence; hidden characters are shown as <U+XXXX>.") }), pre,
      !full && !c.content.complete ? h("button", { class: "btn small", type: "button", text: t("Show full content ({n} characters)", { n: num(c.content.chars) }), onclick: () => open(true, unseen.length ? unseen[0] : 0) }) : null,
      full && c.content.pages > 1 ? contentPager(c, (p) => open(true, p)) : null);
  } else put(content, h("p", { class: "muted", text: c.content_error || t("Content not available.") }));
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
    actions, signers: c.signers, subject: { label: t("case {id}, content", { id: c.case_id }), hash: c.content_sha256 },
    note: c.state === "threat" ? t("This case was declared a threat; releasing it overrules that decision.") : null, onDone,
    submit: (a, values) => post(`/api/quarantine/${encodeURIComponent(c.case_id)}/${a.id}`, { ...values, content_sha256: c.content_sha256, overrule_threat: c.state === "threat" }),
  }) : null;
  return {
    summary: inspSection(t("Quarantine case"), h("p", { class: "insp-title mono", text: c.case_id }), stWord(c.state), " ", h("span", { class: "muted small", text: `${t("band")} ${t(c.band)}` }),
      kv([[t("Source"), c.ref || c.domain || "–"], [t("Tool"), c.tool], [t("Session"), c.session || "–"], [t("Score"), `${num(c.score_ppm)} ppm`],
        [t("Detectors"), c.detectors.map((d) => `${d.id} ${d.version}: ${num(d.score_ppm)} ppm`).join("; ") || "–"],
        [t("Thresholds"), `${c.thresholds.version || "?"} ${c.thresholds.calibrated ? t("calibrated") : t("NOT calibrated (defaults)")}`],
        [t("Opened"), fmtTime(c.opened)], [t("Reached model"), c.reached_model ? t("yes") : t("no")], [t("Content"), hashButton(c.content_sha256)], [t("Record"), h("code", { text: c.opened_record })]]),
      c.domain ? h("p", { class: "small" }, h("a", { href: `/quarantine?tab=sources&trust=${encodeURIComponent(c.domain)}`, onclick: (e) => { e.preventDefault(); go(`/quarantine?tab=sources&trust=${encodeURIComponent(c.domain)}`); }, text: t("Trust {domain} for later content…", { domain: c.domain }) })) : null),
    evidence: c.evidence.length ? inspSection(t("Evidence"), h("ul", { class: "evidence-list" }, c.evidence.map((e) => h("li", {}, h("strong", { text: e.label }), ` (${e.detector}): ${e.reason} `, h("code", { text: e.excerpt }))))) : null,
    content: inspSection(t("Content"), content),
    journal: c.journal_problems && c.journal_problems.length ? inspSection(t("Journal lines ignored for this case"),
      c.journal_problems.map((p) => h("p", { class: "small flag break", text: p }))) : null,
    history: c.decisions.length || c.refusals.length ? inspSection(t("History"),
      c.decisions.map((d) => h("p", { class: "small" }, `${fmtTime(d.time)} ${d.action} · ${d.display || ""} ${d.by} · ${t("signature")} `, stWord(d.status), d.honoured ? "" : ` (${t("not honoured")})`, d.note ? ` ${d.note}` : "", h("br"), h("span", { class: "muted", text: `${t("Reason")}: ${d.reason}` }))),
      c.refusals.map((r) => h("p", { class: "small" }, stWord("fail", t("refused")), ` ${fmtTime(r.time)} ${r.attempted} (${r.reason_code}${r.markers.length ? "; " + r.markers.join(", ") : ""})`))) : null,
    decision: fullFirst ? inspSection(t("Decision"), fullFirst) : panel,
  };
}
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
    if (!data.installed["aqt-signoff"]) { put(main, empty(t("aqt-signoff is not installed"), "uv pip install -e aqt-signoff")); return; }
    if (!data.actions.length) { put(main, empty(t("No prepared actions"), t("Actions appear here when an agent prepares one with aqt-signoff action prepare."))); return; }
    const order = { prepared: 0, expired: 0, unknown: 1, approved: 2, claimed: 3 };
    const actions = data.actions.slice().sort((a, b) => (order[a.status] ?? 9) - (order[b.status] ?? 9));
    const rows = actions.map((a) => ({ data: a, cells: [h("td", { class: "mono", text: a.id }), h("td", {}, stWord(a.status)), h("td", { class: "wrap", text: (a.spec && a.spec.description) || a.detail || "" }),
      h("td", { class: "hide-narrow mono small", text: (a.preparer && a.preparer.id) || "" }), h("td", { class: "hide-narrow" }, hashButton(a.action_sha256, 10))] }));
    const x = table([t("Action"), t("Status"), t("What"), th(t("Prepared by"), "hide-narrow"), th("Hash", "hide-narrow")], rows, (a) => openAction(a.id, data.signers));
    put(main, x.table);
    const wanted = q.get("item");
    const i = wanted ? actions.findIndex((a) => a.id === wanted) : -1;
    if (i >= 0) x.tbody.children[i].click();
    return;
  }
  if (!data.installed["aqt-change"]) { put(main, empty(t("aqt-change is not installed"), "uv pip install -e aqt-change")); return; }
  if (!data.projects.length) { put(main, empty(t("No projects configured"), t("Add repository roots to ~/.config/aqt/ui.toml:") + '  [changes] projects = ["~/code/project"]')); return; }
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
      onclick: () => go(`/change/${project}/${encodeURIComponent(p.plan_id)}`) }))) : null,
    g.decision);
}
function reasonList(reasons) {
  return h("ul", { class: "evidence-list" }, reasons.map((r) => h("li", {}, reasonText(r), " ", h("code", { class: "muted", text: r.code }), r.item ? ` · ${t("check item")} ${r.item}` : "", r.detail ? ` · ${r.detail}` : "")));
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
    summary: inspSection(t("Prepared action"), h("p", { class: "insp-title mono", text: a.id }), stWord(a.status), a.detail ? h("span", { class: "muted small", text: ` ${a.detail}` }) : null,
      kv([[t("Version"), a.version], [t("Prepared by"), (a.preparer && a.preparer.id) || "–"], ["Hash", hashButton(a.action_sha256, 16)], [t("Updated"), fmtTime(a.updated_at)],
        [t("Approvals"), a.approvals.length ? a.approvals.map((x) => `${x.signer} (${x.role})`).join(", ") : t("none")]])),
    spec: inspSection(t("What will run (text)"),
      a.spec_ok ? null : h("p", { class: "flag", role: "alert", text: `${t("Not decidable here:")} ${a.spec_error}` }),
      vis(specText) !== specText ? h("p", { class: "flag", text: t("The specification contains hidden characters, shown as <U+XXXX>. Check exactly what will run.") }) : null,
      h("pre", { class: "json", text: specText })),
    decision: open ? decisionPanel({
      actions: [{ id: "approve", label: t("Approve"), meaning: "approved", button: t("Sign and approve"),
        consequence: t("Counts as an approval of this exact version (its hash); with enough approvals it may run once. A changed version needs a new approval.") },
      { id: "reject", label: t("Reject"), meaning: "rejected", button: t("Sign and reject"), danger: true,
        consequence: t("This version will not run. The agent has to prepare a new version.") }],
      signers, subject: { label: t("action {id} v{version}", { id: a.id, version: a.version }), hash: a.action_sha256 }, onDone,
      submit: (choice, values) => post(`/api/changes/actions/${encodeURIComponent(a.id)}/${choice.id}`, { ...values, expected_hash: a.action_sha256 }),
    }) : null,
  };
}

// ---- Signatures --------------------------------------------------------------------------------------
async function renderSignatures(main) {
  clear(main);
  if (!S.installed.aqt_signoff) { put(main, empty(t("aqt-signoff is not installed"), "uv pip install -e aqt-signoff")); return; }
  const kind = h("select", { "aria-label": t("What to verify") }, [["file", t("Local file path")], ["record", t("Record ID")], ["sha256", t("SHA-256 hash")]].map(([v, x]) => h("option", { value: v, text: x })));
  const value = h("input", { class: "grow", type: "text", placeholder: "/home/me/project/plan.md", "aria-label": t("Value to verify") });
  const out = h("div");
  const run = async () => {
    clear(out);
    if (!value.value.trim()) return;
    const params = new URLSearchParams({ [kind.value]: value.value.trim() });
    try {
      const r = await api(`/api/signatures/verify?${params}`);
      const rows = r.rows.map((x) => ({ data: x, cells: [x.name, h("td", { class: "mono small", text: x.id }), x.role, t(x.meaning), h("td", { class: "small", text: x.local }), h("td", { class: "wrap small", text: x.reason }), h("td", {}, stWord(x.status), x.status !== "valid" && x.detail ? h("span", { class: "small muted", text: ` ${x.detail}` }) : null)] }));
      put(out, section(t("Result"), h("p", {}, stWord(r.ok ? "valid" : "warn", r.summary)), kv([[t("Subject"), `${r.subject.kind}: ${r.subject.ref}`], [t("Content"), hashButton(r.subject.sha256, 20)]]),
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
    const rows = data.candidates.map((x) => ({ data: x, cells: [h("td", { class: "mono small", text: x.candidate_id }), h("td", { class: "hide-narrow", text: x.rule }), h("td", { class: "wrap", text: x.title }), x.severity ? t(x.severity) : "–", h("td", { class: "small hide-narrow", text: ago(x.time) })] }));
    put(main, table([t("Candidate"), th(t("Rule"), "hide-narrow"), t("What"), t("Severity"), th(t("When"), "hide-narrow")], rows, (x) => {
      const c = candidateParts(x, data.signers, {});
      setInspector(c.summary, c.decision);
    }).table);
    return;
  }
  if (tab === "effectiveness") {
    if (data.effectiveness_error) put(main, h("div", { class: "error-box", text: data.effectiveness_error }));
    if (!data.effectiveness.length) { put(main, empty(t("No running effectiveness checks"), t("They start when a corrective action is approved."))); return; }
    const rows = data.effectiveness.map((e) => ({ data: e, cells: [h("td", { class: "mono", text: e.action_id }), h("td", { class: "mono", text: e.dev_id }), h("td", {}, stWord(e.result)), h("td", { class: "wrap small", text: (e.reasons || []).join("; ") })] }));
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
// The parts of a CAPA candidate, for the inspector and the case page.
function candidateParts(x, signers, { onDone }) {
  return {
    summary: inspSection(t("Candidate"), h("p", { class: "insp-title", text: x.title }),
      kv([["ID", h("code", { text: x.candidate_id })], [t("Rule"), x.rule], [t("Source"), `${x.source_type}: ${x.source_ref}`], [t("Severity"), x.severity ? t(x.severity) : "–"], [t("Session"), x.session || "–"], [t("Time"), fmtTime(x.time)]])),
    decision: decisionPanel({
      actions: [{ id: "accept", label: t("Accept as deviation"), meaning: "accepted", button: t("Accept as deviation"),
        consequence: t("Opens a deviation that needs an investigation and, where needed, a corrective action.") },
      { id: "dismiss", label: t("Dismiss"), meaning: "dismissed", button: t("Dismiss candidate"), danger: true,
        consequence: t("Closes the candidate with your reason; no deviation is opened.") }],
      signers, subject: { label: t("candidate {id}", { id: x.candidate_id }) }, note: t(CAPA_NOTE), onDone,
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
async function renderQualifications(main) {
  const data = await api("/api/qualifications");
  clear(main);
  if (!data.qualifications.length) put(main, empty(t("No qualifications recorded"), data.installed ? t("Qualify a detector with aqt-validate (in a terminal).") : t("aqt-validate is not installed.")));
  else {
    const words = (q) => ({ valid: t("valid until {date}", { date: String(q.valid_until).slice(0, 10) }), expiring: t("expires in {n} day(s)", { n: q.days_left }), expired: t("expired"), triggered: t("triggered: {list}", { list: q.triggers.join(", ") }), rejected: t("rejected") })[q.state];
    const rows = data.qualifications.map((q) => ({ data: q, cells: [h("td", { class: "wrap", text: q.subject_id }), t(q.kind), h("td", {}, stWord(q.state, words(q))), h("td", { class: "num", text: q.days_left ?? "–" }),
      h("td", { class: "hide-narrow mono small", text: q.approver || "" }), h("td", { class: "hide-narrow" }, q.same_thresholds === null ? "–" : q.same_thresholds ? stWord("pass", t("same as qualified")) : stWord("warn", t("different file in use")))] }));
    put(main, table([t("Subject"), t("Kind"), t("Status"), th(t("Days left"), "num"), th(t("Approver"), "hide-narrow"), th(t("Thresholds"), "hide-narrow")], rows, (q) => setInspector(
      inspSection(t("Qualification"), h("p", { class: "insp-title", text: q.subject_id }), stWord(q.state, words(q)),
        kv([[t("Kind"), t(q.kind)], [t("Decision"), t(q.decision)], [t("Conclusion"), q.conclusion], [t("Valid until"), fmtTime(q.valid_until)], [t("Approved by"), `${q.approver_name || ""} ${q.approver || ""}`],
          [t("Reason"), q.reason], [t("Band"), q.band ? t(q.band) : "–"], [t("Expected FPR ≤"), q.expected_fpr_upper_ppm != null ? `${num(q.expected_fpr_upper_ppm)} ppm` : "–"], [t("Record"), h("code", { text: q.record })],
          [t("Triggers"), q.triggers.join(", ") || t("none recorded")]])),
      q.report_summary ? inspSection(t("Run report"), kv([[t("Issued"), fmtTime(q.report_summary.time)], [t("Report"), q.report_summary.subject || "–"]]), h("pre", { class: "json", text: JSON.stringify(q.report_summary.data, null, 2) })) : null,
    )).table);
  }
  const x = data.thresholds;
  put(main, section(t("Thresholds in use (aqt-quarantine)"), !x ? h("p", { class: "muted", text: t("aqt-quarantine is not installed.") }) : x.error ? h("div", { class: "error-box", text: x.error })
    : kv([[t("Version"), x.version], [t("Calibrated"), x.calibrated ? stWord("pass", t("calibrated")) : stWord("warn", t("not calibrated (defaults)"))], ["SHA-256", hashButton(x.sha256, 20)], [t("File"), h("span", { class: "break", text: x.path })]]),
    h("p", { class: "small muted", text: t("Requalification triggers are shown as recorded; aqt-validate check in a terminal evaluates and records new ones.") })));
}

const RENDER = { home: renderHome, health: renderHealth, trail: renderTrail, quarantine: renderQuarantine, changes: renderChanges,
  signatures: renderSignatures, capa: renderCapa, qualifications: renderQualifications };

// ---- start ---------------------------------------------------------------------------------------------
async function start() {
  shellLabels();
  $("lang").addEventListener("change", (event) => setLang(event.target.value));
  $("menu-btn").addEventListener("click", () => {
    const open = $("rail").classList.toggle("open");
    $("menu-btn").setAttribute("aria-expanded", String(open));
  });
  $("refresh").addEventListener("click", async () => { await refresh(); route(); announce(t("Refreshed")); });
  S.csrf = sessionKey();
  try {
    const session = await api("/api/session");
    S.mode = session.mode;
    S.installed = session.installed;
    renderTopbar();
    await refresh();
  } catch (error) {
    put(clear($("main")), errorBox(error));
    return;
  }
  route();
  setInterval(() => { refresh().catch(() => {}); }, 15000);
  const status = S.overview && S.overview.status;
  if (status && status.verifying) pollVerify();
}
start();
