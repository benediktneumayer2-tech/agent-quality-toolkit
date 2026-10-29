// aqt-ui front end: plain ES module, no build step.
// Every piece of data is put into the page with textContent or attributes, never as markup,
// because evidence (quarantined pages, reasons, excerpts) is untrusted. All text goes through
// vis(), which shows hidden characters (bidi controls, zero-width characters, ...) as <U+XXXX>.
import { DE, NEEDS, REASONS_DE } from "./i18n.js";
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

const VIEWS = [
  { id: "overview", path: "/", label: "Overview" },
  { id: "trail", path: "/trail", label: "Trail" },
  { id: "quarantine", path: "/quarantine", label: "Quarantine" },
  { id: "changes", path: "/changes", label: "Changes" },
  { id: "signatures", path: "/signatures", label: "Signatures" },
  { id: "capa", path: "/capa", label: "CAPA" },
  { id: "qualifications", path: "/qualifications", label: "Qualifications" },
];
const S = { csrf: "", mode: null, overview: null, view: "overview", installed: {} };
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
  revoked: "fail", "unknown-signer": "warn", triggered: "fail", rejected: "neutral", "not-effective": "fail",
  failed: "fail", stale: "warn", ok: "pass", fresh: "pass", signed: "pass", "signed-verified": "pass", implemented: "info",
  "awaiting-approval": "warn", unsigned: "warn", planned: "info", cancelled: "neutral", critical: "fail", major: "warn", minor: "info",
};
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
  for (const view of VIEWS) {
    const n = counts[view.id] || 0;
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

function renderTopbar() {
  const pill = clear($("trail-pill"));
  const broken = $("broken");
  broken.hidden = true;
  const status = S.overview && S.overview.status;
  if (status) {
    let kind = "info", text;
    if (status.state === "intact") {
      kind = "pass";
      text = t("Trail intact · seq {seq} · {anchor}", { seq: num(status.head_seq), anchor: status.last_anchor ? t("anchored {ago}", { ago: ago(status.last_anchor) }) : t("not anchored") });
    } else if (status.state === "broken") {
      kind = "fail";
      text = t("Broken from seq {seq}", { seq: num(status.check && status.check.first_bad_seq) });
      broken.hidden = false;
      put(clear(broken), t("Trail broken from seq {seq}: {reason}", { seq: num(status.check.first_bad_seq), reason: status.check.reason || "" }));
    } else if (status.state === "changed") {
      kind = "fail";
      text = t("Trail changed since the last check");
      broken.hidden = false;
      put(clear(broken), t("Trail changed since the last check: {reason}. Verify it again.", { reason: status.changed || "" }));
    } else if (status.state === "problems") { kind = "warn"; text = t("Trail: verification found problems"); }
    else if (status.state === "missing") { kind = "warn"; text = t("No trail yet"); }
    else text = status.verifying ? t("Trail: verifying…") : t("Trail: not verified yet");
    if (status.state !== "missing" && status.writer && !status.writer.running) { text += ` · ${t("writer down")}`; if (kind === "pass") kind = "warn"; }
    if (status.writer && status.writer.spooled) { text += ` · ${t("{n} spooled", { n: status.writer.spooled })}`; if (kind === "pass") kind = "warn"; }
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
document.addEventListener("keydown", (event) => { if (event.key === "Escape") closeSheet(); });

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

// ---- decision panel ----------------------------------------------------------------------------------
// One component for every human-only action, laid out like a signature manifestation.
let panelCount = 0;
function decisionPanel({ actions, subject, signers, submit, note, fields, noSigners, title }) {
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
  const choice = actions.length > 1 ? h("div", { class: "chips", role: "radiogroup", "aria-label": t("Decision") },
    actions.map((a) => {
      const b = h("button", { class: "chip-btn", type: "button", role: "radio", "aria-checked": a === chosen ? "true" : "false", "aria-pressed": a === chosen ? "true" : "false", text: a.label });
      b.addEventListener("click", () => {
        chosen = a;
        for (const other of choice.children) { const on = other === b; other.setAttribute("aria-checked", String(on)); other.setAttribute("aria-pressed", String(on)); }
        meaningCell.textContent = vis(t(a.meaning)); button.textContent = vis(a.button); button.className = `btn ${a.danger ? "danger" : "primary"}`;
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
      else text = `${t("Refused:")} ${data.message}${data.record_id ? ` (${t("refusal recorded as {record}", { record: data.record_id })})` : ""}`;
      put(result, h("div", { class: `result ${kind}`, role: "status", text }));
      announce(text);
      if (data.ok) {
        form.remove();                       // the decision is made; show what was recorded
        if (choice) choice.remove();
        if (fields) fields.remove();
        setTimeout(async () => { await refresh(); route(true); }, 600);
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

async function route(keepInspector) {
  const view = VIEWS.find((v) => v.path === location.pathname) || VIEWS[0];
  S.view = view.id;
  $("title").textContent = vis(t(view.label));
  document.title = `${t(view.label)} · ${t("AQT quality desk")}`;
  renderRail();
  const main = clear($("main"));
  put(main, h("div", { class: "empty", text: t("Loading…") }));
  if (keepInspector !== true) placeholder(t("Select an item to see its details."));
  try {
    await RENDER[view.id](main);
  } catch (error) {
    put(clear(main), errorBox(error));
  }
}

// ---- Overview ----------------------------------------------------------------------------------------
const SEVERITY_KIND = { critical: "fail", high: "warn", medium: "info", low: "neutral" };
// Title and detail of a "Needs you" entry in the chosen language (English comes from the server).
function needText(item) {
  const de = LANG === "de" && NEEDS[item.key];
  if (!de) return [item.title, item.detail];
  const fill = (text) => text.replace(/\{(\w+)\}/g, (all, key) => (item.args[key] === undefined ? all : typeof item.args[key] === "number" ? num(item.args[key]) : t(String(item.args[key]))));
  const detail = de[1] === null ? item.detail : de[1] === "@reason" ? (REASONS_DE[item.args.reason_code] || item.detail) : fill(de[1]);
  return [fill(de[0]), detail];
}
function needTarget(item) {
  const target = VIEWS.find((v) => v.id === item.view);
  if (!target) return "/";
  if (!item.ref) return target.path;
  if (item.view === "trail") return item.ref === "review" ? "/trail?panel=review" : `/trail?${item.ref}`;
  if (item.view === "capa" && item.ref === "candidates") return "/capa?tab=candidates";
  return `${target.path}?item=${encodeURIComponent(item.ref)}`;
}
async function renderOverview(main) {
  const data = S.overview || (await refresh());
  clear(main);
  const status = data.status;
  const check = status.check || {};

  // What needs the person comes first; the state of the record follows.
  const queue = h("ul", { class: "queue", "aria-label": t("Needs you") });
  for (const item of data.needs) {
    const target = VIEWS.find((v) => v.id === item.view);
    const [title, detail] = needText(item);
    const button = h("button", { type: "button" },
      st(SEVERITY_KIND[item.severity] || "neutral", t(item.severity)),
      h("span", { class: "what" }, h("strong", { text: title }), detail ? h("span", { text: detail }) : null),
      h("span", { class: "where", text: target ? t(target.label) : "" }));
    button.addEventListener("click", () => {
      for (const b of queue.querySelectorAll("button")) b.setAttribute("aria-selected", b === button ? "true" : "false");
      setInspector(inspSection(target ? t(target.label) : "", h("p", { class: "insp-title", text: title }),
        st(SEVERITY_KIND[item.severity] || "neutral", t(item.severity)), detail ? h("p", { text: detail }) : null,
        item.code ? kv([[t("Code"), h("code", { text: item.code })]]) : null,
        h("div", { class: "actions" }, h("button", { class: "btn primary", type: "button", text: t("Open in {view}", { view: target ? t(target.label) : "" }),
          onclick: () => go(needTarget(item)) }))));
    });
    put(queue, h("li", {}, button));
  }
  put(main, section(t("Needs you"), data.needs.length ? queue
    : h("div", { class: "allclear" }, h("strong", { text: t("Nothing needs you") }), t("Last check {time}.", { time: fmtTime(data.checked_at) }))));

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
     [t("Last review"), status.last_review ? ago(status.last_review) : t("none")]]
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
    const rows = data.refusals.slice().reverse().map((r) => ({ data: r, cells: [h("td", { class: "small time", text: fmtTime(r.time) }), r.type, h("td", { class: "mono small hide-narrow", text: r.actor.id }), r.reason_code || ""] }));
    const x = table([t("Time"), t("Type"), th(t("Claimed actor"), "hide-narrow"), t("Reason code")], rows, (r) => go(`/trail?type=*.refused#${r.id}`));
    put(main, section(t("Refusals in the last 24 h"), x.table));
  }
}

async function refresh(force) {
  const data = await api("/api/overview");
  S.overview = data;
  renderRail();
  renderTopbar();
  if (force && S.view === "overview") route();
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
    const mismatch = r.actor.kind === "human" && r.observed.harness;
    return { data: r, cells: [
      h("td", { class: "seq", text: r.chain.seq ?? "" }),
      h("td", { class: "small time", text: fmtTime(r.time) }),
      h("td", {}, r.type, r.signed ? h("span", { class: "muted small", text: ` · ${t("signed")}` }) : null),
      h("td", { class: "hide-narrow", text: r.action }),
      h("td", { class: "mono small wrap", text: r.actor.id }),
      h("td", { class: "hide-narrow small" }, mismatch ? h("span", { class: "flag", title: t("claims a human but came from an agent harness"), text: `! ${r.observed.harness}` }) : (r.observed.via ? `${r.observed.via}${r.observed.harness ? " · " + r.observed.harness : ""}` : "–")),
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
function reviewPanel(sheet) {
  const scope = sheet.scope;
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
    actions: [{ id: "sign", label: t("Sign review"), meaning: "reviewed", button: t("Sign the review") }],
    signers,
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
        [t("Head"), hashButton(scope.head, 16)], [t("Acted in the period"), actors.join(", ") || t("none")], [t("Worksheet"), h("span", { class: "mono small", text: sheet.path })]])),
    inspSection(t("Findings ({n})", { n: sheet.findings.length }), list),
    panel,
  ];
}
function exportSection() {
  return inspSection(t("Export"),
    h("p", { class: "small muted", text: t("A verification bundle: the trail, checkpoints, public keys and instructions, for an auditor to check offline. Creating it records nothing.") }),
    downloadButton("/api/trail/export", "aqt-trail-bundle.tar.gz", t("Download bundle (.tar.gz)")));
}

async function openRecord(row) {
  const data = await api(`/api/trail/record/${encodeURIComponent(row.id)}`);
  const r = data.record;
  const obs = data.observed || {};
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
    ]), data.attribution_mismatch ? h("p", { class: "flag", text: t("This record claims a human but came from an agent harness.") }) : null),
    inspSection(t("Signatures"), (r.sig || []).map((s) => kv([[t("Writer key"), h("code", { text: s.key })]])),
      r.data && r.data.signature ? kv([[t("Detached"), `${r.data.signature.statement && t(r.data.signature.statement.meaning)} · ${r.data.signature.statement && r.data.signature.statement.signer && r.data.signature.statement.signer.id}`]]) : null),
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
    data.outbox ? h("span", { class: "small", text: t("{n} record(s) waiting in the quarantine outbox (aqt-quarantine flush)", { n: data.outbox }) }) : null);
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

async function openCase(caseId, full) {
  const c = await api(`/api/quarantine/${encodeURIComponent(caseId)}${full ? "?full=1" : ""}`);
  const content = h("div");
  if (c.content) {
    const pre = h("pre", { class: "text", tabindex: "0", "aria-label": t("Case content, untrusted") });
    for (const w of c.content.windows) {
      if (w.cut_before) put(pre, h("span", { class: "muted", text: "… " }));
      for (const piece of w.pieces) put(pre, piece.mark ? h("mark", { title: piece.mark, text: piece.text }) : document.createTextNode(vis(piece.text)));
      if (w.cut_after) put(pre, h("span", { class: "muted", text: " …" }));
      put(pre, "\n\n");
    }
    put(content, h("p", { class: "untrusted", text: t("Untrusted third-party text. Highlighted passages are detector evidence; hidden characters are shown as <U+XXXX>.") }), pre,
      !full && c.content.windows.some((w) => w.cut_before || w.cut_after) ? h("button", { class: "btn small", type: "button", text: t("Show full content ({n} characters)", { n: num(c.content.chars) }), onclick: () => openCase(caseId, true) }) : null,
      c.content.truncated ? h("p", { class: "small muted", text: t("Shown up to 200,000 characters.") }) : null);
  } else put(content, h("p", { class: "muted", text: c.content_error || t("Content not available.") }));
  const actions = [];
  if (c.can_release) actions.push({ id: "release", label: t("Release"), meaning: "released", button: t("Sign and release") });
  if (c.can_declare) actions.push({ id: "threat", label: t("Declare threat"), meaning: "rejected", button: t("Sign and declare threat"), danger: true });
  const panel = actions.length ? decisionPanel({
    actions, signers: c.signers, subject: { label: t("case {id}, content", { id: c.case_id }), hash: c.content_sha256 },
    note: c.state === "threat" ? t("This case was declared a threat; releasing it overrules that decision.") : null,
    submit: (a, values) => post(`/api/quarantine/${encodeURIComponent(c.case_id)}/${a.id}`, { ...values, content_sha256: c.content_sha256, overrule_threat: c.state === "threat" }),
  }) : null;
  setInspector(
    inspSection(t("Quarantine case"), h("p", { class: "insp-title mono", text: c.case_id }), stWord(c.state), " ", h("span", { class: "muted small", text: `${t("band")} ${t(c.band)}` }),
      kv([[t("Source"), c.ref || c.domain || "–"], [t("Tool"), c.tool], [t("Session"), c.session || "–"], [t("Score"), `${num(c.score_ppm)} ppm`],
        [t("Detectors"), c.detectors.map((d) => `${d.id} ${d.version}: ${num(d.score_ppm)} ppm`).join("; ") || "–"],
        [t("Thresholds"), `${c.thresholds.version || "?"} ${c.thresholds.calibrated ? t("calibrated") : t("NOT calibrated (defaults)")}`],
        [t("Opened"), fmtTime(c.opened)], [t("Reached model"), c.reached_model ? t("yes") : t("no")], [t("Content"), hashButton(c.content_sha256)], [t("Record"), h("code", { text: c.opened_record })]]),
      c.domain ? h("p", { class: "small" }, h("a", { href: `/quarantine?tab=sources&trust=${encodeURIComponent(c.domain)}`, onclick: (e) => { e.preventDefault(); go(`/quarantine?tab=sources&trust=${encodeURIComponent(c.domain)}`); }, text: t("Trust {domain} for later content…", { domain: c.domain }) })) : null),
    c.evidence.length ? inspSection(t("Evidence"), h("ul", { class: "evidence-list" }, c.evidence.map((e) => h("li", {}, h("strong", { text: e.label }), ` (${e.detector}): ${e.reason} `, h("code", { text: e.excerpt }))))) : null,
    inspSection(t("Content"), content),
    c.decisions.length || c.refusals.length ? inspSection(t("History"),
      c.decisions.map((d) => h("p", { class: "small" }, `${fmtTime(d.time)} ${d.action} · ${d.display || ""} ${d.by} · ${t("signature")} `, stWord(d.status), d.honoured ? "" : ` (${t("not honoured")})`, d.note ? ` ${d.note}` : "", h("br"), h("span", { class: "muted", text: `${t("Reason")}: ${d.reason}` }))),
      c.refusals.map((r) => h("p", { class: "small" }, stWord("fail", t("refused")), ` ${fmtTime(r.time)} ${r.attempted} (${r.reason_code}${r.markers.length ? "; " + r.markers.join(", ") : ""})`))) : null,
    panel,
  );
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
      const x = table([t("Plan"), t("Gate"), t("First reason"), th(t("Approval"), "hide-narrow"), th(t("File"), "hide-narrow")], rows, (p) => openGate(p, project.root, data.signers));
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
function openGate(p, root, signers) {
  const a = p.approval || {};
  const canApprove = a.record && a.sha256 && a.state !== "signed";
  setInspector(
    inspSection(t("Gate"), h("p", { class: "insp-title mono", text: p.plan_id }), gateChip(p.decision), kv([[t("File"), p.path], [t("Evaluated"), fmtTime(p.evaluated_at)], [t("Finish"), p.finish ? h("code", { text: p.finish }) : t("not finished")]])),
    p.error ? inspSection(t("Not evaluated"), h("p", { class: "small", text: p.error })) : inspSection(t("Reasons"), p.reasons.length ? h("ul", { class: "evidence-list" }, p.reasons.map((r) => h("li", {}, reasonText(r), " ", h("code", { class: "muted", text: r.code }), r.item ? ` · ${t("check item")} ${r.item}` : "", r.detail ? ` · ${r.detail}` : ""))) : h("p", { text: t("No reasons: the gate is GO.") })),
    inspSection(t("Receipts"), p.receipts.length ? p.receipts.map((r) => h("div", { class: "receipt small" }, h("strong", { text: r.item }), " ", stWord(r.state === "ok" ? "fresh" : r.state, r.state === "ok" ? t("fresh") : t(r.state)), " ", r.text || "",
      r.commands.map((c) => h("div", { class: "muted" }, h("code", { text: c.command }), ` · ${t(c.state || "")}${c.counts ? " · " + countsText(c.counts) : ""}`)))) : h("p", { class: "muted", text: t("No verification items.") })),
    inspSection(t("Approval"), kv([[t("State"), approvalChip(p.approval)], [t("Version"), a.record ? h("code", { text: a.record }) : "–"], [t("Reviews"), (p.reviews || []).join(", ") || t("none fresh")]])),
    canApprove ? decisionPanel({
      title: t("Approve this plan version"),
      actions: [{ id: "approve", label: t("Approve plan"), meaning: "approved", button: t("Sign and approve plan") }],
      signers, subject: { label: t("plan {plan}, version {record}", { plan: p.plan_id, record: a.record }), hash: a.sha256 },
      note: t("You sign this version of the plan. A later change of its scope or checks makes the approval stale."),
      submit: (x, values) => post("/api/changes/plans/approve", { ...values, root, plan_id: p.plan_id, record: a.record, sha256: a.sha256 }),
    }) : null,
  );
}
async function openAction(id, signers) {
  const a = await api(`/api/changes/actions/${encodeURIComponent(id)}`);
  const open = a.spec_ok && ["prepared", "approved", "expired"].includes(a.status);
  const specText = JSON.stringify(a.spec, null, 2);
  setInspector(
    inspSection(t("Prepared action"), h("p", { class: "insp-title mono", text: a.id }), stWord(a.status), a.detail ? h("span", { class: "muted small", text: ` ${a.detail}` }) : null,
      kv([[t("Version"), a.version], [t("Prepared by"), (a.preparer && a.preparer.id) || "–"], ["Hash", hashButton(a.action_sha256, 16)], [t("Updated"), fmtTime(a.updated_at)],
        [t("Approvals"), a.approvals.length ? a.approvals.map((x) => `${x.signer} (${x.role})`).join(", ") : t("none")]])),
    inspSection(t("What will run (text)"),
      a.spec_ok ? null : h("p", { class: "flag", role: "alert", text: `${t("Not decidable here:")} ${a.spec_error}` }),
      vis(specText) !== specText ? h("p", { class: "flag", text: t("The specification contains hidden characters, shown as <U+XXXX>. Check exactly what will run.") }) : null,
      h("pre", { class: "json", text: specText })),
    open ? decisionPanel({
      actions: [{ id: "approve", label: t("Approve"), meaning: "approved", button: t("Sign and approve") }, { id: "reject", label: t("Reject"), meaning: "rejected", button: t("Sign and reject"), danger: true }],
      signers, subject: { label: t("action {id} v{version}", { id: a.id, version: a.version }), hash: a.action_sha256 },
      submit: (choice, values) => post(`/api/changes/actions/${encodeURIComponent(a.id)}/${choice.id}`, { ...values, expected_hash: a.action_sha256 }),
    }) : null,
  );
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
      const rows = r.rows.map((x) => ({ data: x, cells: [x.name, h("td", { class: "mono small", text: x.id }), x.role, t(x.meaning), h("td", { class: "small", text: x.local }), h("td", { class: "wrap small", text: x.reason }), h("td", {}, stWord(x.status))] }));
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
    put(main, table([t("Candidate"), th(t("Rule"), "hide-narrow"), t("What"), t("Severity"), th(t("When"), "hide-narrow")], rows, (x) => setInspector(
      inspSection(t("Candidate"), h("p", { class: "insp-title", text: x.title }),
        kv([["ID", h("code", { text: x.candidate_id })], [t("Rule"), x.rule], [t("Source"), `${x.source_type}: ${x.source_ref}`], [t("Severity"), x.severity ? t(x.severity) : "–"], [t("Session"), x.session || "–"], [t("Time"), fmtTime(x.time)]])),
      decisionPanel({
        actions: [{ id: "accept", label: t("Accept as deviation"), meaning: "accepted", button: t("Accept as deviation") },
          { id: "dismiss", label: t("Dismiss"), meaning: "dismissed", button: t("Dismiss candidate"), danger: true }],
        signers: data.signers, subject: { label: t("candidate {id}", { id: x.candidate_id }) }, note: t(CAPA_NOTE),
        submit: (a, values) => post(`/api/capa/candidates/${encodeURIComponent(x.candidate_id)}/${a.id}`, values),
      }))).table);
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

const RENDER = { overview: renderOverview, trail: renderTrail, quarantine: renderQuarantine, changes: renderChanges,
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
