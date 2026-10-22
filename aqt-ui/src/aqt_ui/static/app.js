// aqt-ui front end: plain ES module, no build step.
// Every piece of data is put into the page with textContent or attributes, never as markup,
// because evidence (quarantined pages, reasons, excerpts) is untrusted.

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
const $ = (id) => document.getElementById(id);

// ---- DOM helper: text and attributes only ---------------------------------------------------
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") el.className = value;
    else if (key === "text") el.textContent = String(value);
    else if (key.startsWith("on") && typeof value === "function") el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, value === true ? "" : String(value));
  }
  append(el, children);
  return el;
}
function append(el, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}
// Native Element.append() would turn null into the text "null"; put() skips empty children.
function put(el, ...children) { return append(el, children); }
function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }
function announce(text) { const live = $("live"); live.textContent = ""; setTimeout(() => { live.textContent = text; }, 30); }

// ---- formatting --------------------------------------------------------------------------------
const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
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
  if (!iso) return "never";
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (isNaN(s)) return String(iso);
  if (s < 90) return "just now";
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  if (s < 172800) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} days ago`;
}
function short(hash, n = 12) {
  if (!hash) return "–";
  const value = String(hash).replace(/^sha256:/, "");
  return value.length > n ? value.slice(0, n) + "…" : value;
}
function num(n) { return n === null || n === undefined ? "–" : Number(n).toLocaleString("en-US"); }

const ICON = { pass: "✓", warn: "!", fail: "✕", info: "●", neutral: "○" };
function st(kind, word) {
  return h("span", { class: `st ${kind}` }, h("span", { class: "ico", "aria-hidden": "true", text: ICON[kind] || "○" }), word);
}
const STATUS_KIND = {
  pass: "pass", intact: "pass", valid: "pass", go: "pass", released: "pass", effective: "pass", succeeded: "pass",
  approved: "pass", running: "pass", closed: "neutral",
  warn: "warn", warned: "warn", expiring: "warn", manual_verify_required: "warn", prepared: "warn", pending: "info",
  unverified: "info", problems: "warn", missing: "warn", unknown: "warn", expired: "fail", open: "warn",
  fail: "fail", broken: "fail", held: "fail", threat: "fail", "no-go": "fail", invalid: "fail", invalidated: "fail",
  revoked: "fail", "unknown-signer": "warn", triggered: "fail", rejected: "neutral", "not-effective": "fail",
  failed: "fail", stale: "warn", ok: "pass", fresh: "pass", signed: "pass", "signed-verified": "pass", implemented: "info",
};
function stWord(word, label) {
  const key = String(word || "").toLowerCase();
  return st(STATUS_KIND[key] || "neutral", label || String(word || "–"));
}
function hashButton(value, n) {
  if (!value) return h("span", { class: "muted", text: "–" });
  return h("button", {
    class: "hash", type: "button", title: `${value} (click to copy)`, "aria-label": `hash ${value}, click to copy`,
    onclick: () => { navigator.clipboard?.writeText(String(value)).then(() => announce("Copied"), () => {}); },
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
  if (error.data && error.data.install) put(box, h("div", { class: "small" }, "Install: ", h("code", { text: `uv pip install -e ${error.data.install}` })));
  return box;
}

// ---- API ----------------------------------------------------------------------------------------
async function api(path) {
  const response = await fetch(path, { headers: { Accept: "application/json" }, credentials: "same-origin" });
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

// ---- shell: rail, top bar, inspector --------------------------------------------------------------
function renderRail() {
  const nav = clear($("nav"));
  const counts = (S.overview && S.overview.counts) || {};
  for (const view of VIEWS) {
    const n = counts[view.id] || 0;
    const link = h("a", {
      href: view.path, "aria-current": S.view === view.id ? "page" : null,
      onclick: (event) => { event.preventDefault(); go(view.path); $("rail").classList.remove("open"); $("menu-btn").setAttribute("aria-expanded", "false"); },
    }, h("span", { class: "label", text: view.label }),
       n ? h("span", { class: `count ${view.id === "signatures" ? "" : "hot"}`, "aria-label": `${n} need attention`, text: n }) : null);
    put(nav, h("li", {}, link));
  }
  const foot = clear($("railfoot"));
  if (S.overview) put(foot, `Checked ${fmtTime(S.overview.checked_at)}`);
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
      text = `Trail intact · seq ${num(status.head_seq)} · ${status.last_anchor ? "anchored " + ago(status.last_anchor) : "not anchored"}`;
    } else if (status.state === "broken") {
      kind = "fail";
      text = `Broken from seq ${num(status.check && status.check.first_bad_seq)}`;
      broken.hidden = false;
      put(clear(broken), `Trail broken from seq ${num(status.check.first_bad_seq)}: ${status.check.reason || ""}`);
    } else if (status.state === "problems") { kind = "warn"; text = "Trail: verification found problems"; }
    else if (status.state === "missing") { kind = "warn"; text = "No trail yet"; }
    else text = status.verifying ? "Trail: verifying…" : "Trail: not verified yet";
    if (status.state !== "missing" && status.writer && !status.writer.running) { text += " · writer down"; if (kind === "pass") kind = "warn"; }
    if (status.writer && status.writer.spooled) { text += ` · ${status.writer.spooled} spooled`; if (kind === "pass") kind = "warn"; }
    pill.className = `pill ${kind}`;
    put(pill, h("span", { "aria-hidden": "true", text: ICON[kind] }), text);
  } else put(pill, "Trail: loading");
  const badge = clear($("mode-badge"));
  const ribbon = clear($("ribbon"));
  if (S.mode) {
    badge.className = `badge ${S.mode.decisions ? "on" : "off"}`;
    put(badge, S.mode.decisions ? "Decisions on · passphrase per decision" : "Read-only");
    ribbon.hidden = S.mode.decisions;
    if (!S.mode.decisions) put(ribbon, h("strong", { text: "Read-only. " }), S.mode.reason);
  }
}

const inspector = () => $("inspector");
function setInspector(...children) {
  const el = clear(inspector());
  el.append(h("div", { class: "sheet-head" }, h("strong", { text: "Details" }),
    h("button", { class: "btn small", type: "button", onclick: closeSheet, text: "Close" })));
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

// ---- decision panel ----------------------------------------------------------------------------------
// One component for every human-only action, laid out like a signature manifestation.
function decisionPanel({ actions, subject, signers, submit, note }) {
  const box = h("section", { class: "decision", "aria-label": "Decision" });
  put(box, h("h3", { text: "Decision" }));
  if (!S.mode || !S.mode.decisions) {
    put(box, h("div", { class: "off" }, h("strong", { text: "Read-only. " }), S.mode ? S.mode.reason : ""));
    return box;
  }
  if (!signers || !signers.length) {
    put(box, h("div", { class: "off", text: "No signer is registered. Enrol yourself in a terminal first: aqt-signoff init" }));
    return box;
  }
  let chosen = actions[0];
  const signerSelect = h("select", { id: "dp-signer" }, signers.map((s) => h("option", { value: s.id, text: `${s.name || s.id} (${s.role || "no role"})` })));
  const meaningCell = h("dd", { text: chosen.meaning });
  const signerCell = h("dd");
  const showSigner = () => {
    const s = signers.find((x) => x.id === signerSelect.value) || signers[0];
    put(clear(signerCell), `${s.name || "?"} · ${s.id} · ${s.role || "no role"}`);
  };
  const button = h("button", { class: `btn ${chosen.danger ? "danger" : "primary"}`, type: "button", text: chosen.button });
  const choice = actions.length > 1 ? h("div", { class: "chips", role: "radiogroup", "aria-label": "Decision" },
    actions.map((a) => {
      const b = h("button", { class: "chip-btn", type: "button", role: "radio", "aria-checked": a === chosen ? "true" : "false", "aria-pressed": a === chosen ? "true" : "false", text: a.label });
      b.addEventListener("click", () => {
        chosen = a;
        for (const other of choice.children) { const on = other === b; other.setAttribute("aria-checked", String(on)); other.setAttribute("aria-pressed", String(on)); }
        meaningCell.textContent = a.meaning; button.textContent = a.button; button.className = `btn ${a.danger ? "danger" : "primary"}`;
      });
      return b;
    })) : null;
  const reason = h("textarea", { id: "dp-reason", required: true, "aria-required": "true", maxlength: "2000" });
  const pass = h("input", { id: "dp-pass", type: "password", autocomplete: "off", spellcheck: "false", "aria-required": "true" });
  const result = h("div", { "aria-live": "polite" });
  signerSelect.addEventListener("change", showSigner);
  showSigner();
  button.addEventListener("click", async () => {
    clear(result);
    if (!reason.value.trim()) { put(result, h("div", { class: "result stale", text: "A reason is required." })); reason.focus(); return; }
    if (!pass.value) { put(result, h("div", { class: "result stale", text: "Enter your passphrase." })); pass.focus(); return; }
    button.disabled = true;
    const passphrase = pass.value;
    pass.value = "";
    try {
      const { status, data } = await submit(chosen, { reason: reason.value.trim(), passphrase, signer_id: signerSelect.value });
      let kind = data.ok ? "ok" : status === 409 ? "stale" : "refused";
      let text;
      if (data.ok) text = `Recorded as ${data.record_id || "a record"}${data.time ? " at " + fmtTime(data.time) : ""}. ${data.message || ""}`;
      else if (status === 409) text = `Not signed: ${data.message}`;
      else text = `Refused: ${data.message}${data.record_id ? ` (refusal recorded as ${data.record_id})` : ""}`;
      put(result, h("div", { class: `result ${kind}`, role: "status", text }));
      announce(text);
      if (data.ok) {
        form.remove();                       // the decision is made; show what was recorded
        if (choice) choice.remove();
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
    signers.length > 1 ? h("div", { class: "field" }, h("label", { for: "dp-signer", text: "Who signs" }), signerSelect) : null,
    h("div", { class: "field" }, h("label", { for: "dp-reason", text: "Reason (required, recorded with the signature)" }), reason),
    h("div", { class: "field" }, h("label", { for: "dp-pass", text: "Passphrase of your signing key (used once, never stored)" }), pass),
    note ? h("p", { class: "small muted", text: note }) : null,
    h("div", { class: "actions" }, button));
  put(box,
    choice,
    h("dl", { class: "manifest", "aria-label": "What will be signed" },
      h("dt", { text: "Signer" }), signerCell,
      h("dt", { text: "Meaning" }), meaningCell,
      h("dt", { text: "Subject" }), h("dd", {}, subject.label, " ", hashButton(subject.hash, 16))),
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
  $("title").textContent = view.label;
  document.title = `${view.label} · AQT quality desk`;
  renderRail();
  const main = clear($("main"));
  put(main, h("div", { class: "empty", text: "Loading…" }));
  if (keepInspector !== true) placeholder("Select an item to see its details.");
  try {
    await RENDER[view.id](main);
  } catch (error) {
    put(clear(main), errorBox(error));
  }
}

// ---- Overview ----------------------------------------------------------------------------------------
async function renderOverview(main) {
  const data = S.overview || (await refresh());
  clear(main);
  const status = data.status;
  const check = status.check || {};
  const words = { intact: "Intact", broken: `Broken from seq ${num(check.first_bad_seq)}`, problems: "Problems found",
    unverified: status.verifying ? "Verifying…" : "Not verified yet", missing: "No trail yet" };
  const verifyBtn = h("button", { class: "btn small", type: "button", text: status.verifying ? "Verifying…" : "Verify now", disabled: status.verifying,
    onclick: async () => { verifyBtn.disabled = true; verifyBtn.textContent = "Verifying…"; await post("/api/trail/verify"); pollVerify(); } });
  const band = h("dl", { class: "band" },
    [["Trail", stWord(status.state, words[status.state])], ["Records", num(status.records)], ["Head seq", num(status.head_seq)],
     ["Last full check", check.checked_at ? `${ago(check.checked_at)}${status.appended_since_check ? ` · ${status.appended_since_check} newer not yet verified` : ""}` : "not yet"],
     ["Writer", stWord(status.writer.running ? "running" : "missing", status.writer.running ? "Running" : "Not running")],
     ["Spool", status.writer.spooled ? stWord("warn", `${status.writer.spooled} waiting`) : "empty"],
     ["Last anchor", status.last_anchor ? ago(status.last_anchor) : "none"],
     ["Last review", status.last_review ? ago(status.last_review) : "none"]]
      .map(([k, v]) => h("div", {}, h("dt", { text: k }), h("dd", {}, v))));
  put(main, section(["Trail status ", h("span", { class: "hint" }, verifyBtn)], band,
    status.state === "broken" ? h("p", { class: "small", text: `Verifier: ${check.summary}` }) : null));

  const strip = h("div", { class: "alcoa" });
  if (data.alcoa.length) {
    for (const item of data.alcoa) {
      const chip = h("button", { class: "chip-btn", type: "button", title: `${item.id}: ${item.detail}` }, stWord(item.status, `${item.attribute} ${item.status}`));
      chip.addEventListener("click", () => setInspector(inspSection("ALCOA++", h("p", { class: "insp-title", text: item.attribute }), stWord(item.status),
        h("p", { text: item.detail }), kv([["Catalogue", h("code", { text: item.id })], ["Related", item.related.join(", ")]]),
        h("p", { class: "small muted", text: "pass means the check found nothing; it does not mean a process is compliant." }))));
      put(strip, chip);
    }
  } else put(strip, h("span", { class: "muted", text: status.verifying ? "Computed after the verification finishes…" : "Not computed yet: run Verify now." }));
  put(main, section("ALCOA++", strip));

  const queue = h("ul", { class: "queue", "aria-label": "Needs you" });
  for (const item of data.needs) {
    const target = VIEWS.find((v) => v.id === item.view);
    const button = h("button", { type: "button" },
      st(item.severity === "critical" ? "fail" : item.severity === "high" ? "warn" : item.severity === "medium" ? "info" : "neutral", item.severity),
      h("span", { class: "what" }, h("strong", { text: item.title }), item.detail ? h("span", { text: item.detail }) : null),
      h("span", { class: "where", text: target ? target.label : "" }));
    button.addEventListener("click", () => {
      for (const b of queue.querySelectorAll("button")) b.setAttribute("aria-selected", b === button ? "true" : "false");
      setInspector(inspSection(target ? target.label : "", h("p", { class: "insp-title", text: item.title }),
        st(item.severity === "critical" ? "fail" : "warn", item.severity), item.detail ? h("p", { text: item.detail }) : null,
        item.code ? kv([["Code", h("code", { text: item.code })]]) : null,
        h("div", { class: "actions" }, h("button", { class: "btn primary", type: "button", text: `Open in ${target ? target.label : "view"}`,
          onclick: () => go(target.path + (item.ref ? `?${item.view === "trail" ? "type=*.refused" : "item=" + encodeURIComponent(item.ref)}` : "")) }))));
    });
    put(queue, h("li", {}, button));
  }
  put(main, section("Needs you", data.needs.length ? queue
    : h("div", { class: "allclear" }, h("strong", { text: "Nothing needs you" }), `Last check ${fmtTime(data.checked_at)}.`)));

  const tools = h("div", { class: "tools" }, data.tools.map((t) => h("div", {},
    h("div", {}, h("strong", { text: t.package }), " ", t.installed ? stWord(t.problem ? "warn" : "pass", t.problem ? "problem" : "installed") : stWord("neutral", "not installed")),
    h("div", { class: "small muted", text: t.installed ? (t.problem || `last record ${t.last_record ? ago(t.last_record) : "none"}`) : t.install }))));
  put(main, section("Tool health", tools));

  if (data.refusals.length) {
    const rows = data.refusals.slice().reverse().map((r) => ({ data: r, cells: [h("td", { class: "small time", text: fmtTime(r.time) }), r.type, h("td", { class: "mono small hide-narrow", text: r.actor.id }), r.reason_code || ""] }));
    const t = table(["Time", "Type", h("th", { class: "hide-narrow", text: "Claimed actor" }), "Reason code"], rows, (r) => go(`/trail?type=*.refused#${r.id}`));
    put(main, section("Refusals in the last 24 h", t.table));
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
    if (data && !data.status.verifying) { clearInterval(verifyTimer); verifyTimer = null; announce(`Verification finished: ${data.status.state}`); route(); }
  }, 1000);
}

// ---- Trail -------------------------------------------------------------------------------------------
const TRAIL_FILTERS = ["type", "actor", "session", "subject", "since", "until"];
async function renderTrail(main) {
  const q = query();
  const params = Object.fromEntries(TRAIL_FILTERS.map((k) => [k, q.get(k) || ""]));
  const search = new URLSearchParams(Object.entries(params).filter(([, v]) => v));
  const data = await api(`/api/trail/records?${search}`);
  clear(main);
  const inputs = {};
  const bar = h("div", { class: "filterbar", role: "search" });
  const typeSelect = h("select", { "aria-label": "Record type" }, h("option", { value: "", text: "All types" }),
    h("option", { value: "*.refused", text: "All refusals (*.refused)" }), data.types.map((t) => h("option", { value: t, text: t })));
  typeSelect.value = params.type;
  inputs.type = typeSelect;
  put(bar, typeSelect);
  for (const [key, label] of [["actor", "Actor id"], ["session", "Session"], ["subject", "Subject ref"], ["since", "Since (2026-10-01)"], ["until", "Until"]]) {
    inputs[key] = h("input", { type: "text", placeholder: label, "aria-label": label, value: params[key] });
    put(bar, inputs[key]);
  }
  const apply = () => { setQuery(Object.fromEntries(TRAIL_FILTERS.map((k) => [k, inputs[k].value.trim()]))); route(); };
  bar.addEventListener("keydown", (e) => { if (e.key === "Enter") apply(); });
  put(bar, h("button", { class: "btn small primary", type: "button", text: "Apply", onclick: apply }),
    h("button", { class: "btn small ghost", type: "button", text: "Clear", onclick: () => { setQuery({}); route(); } }),
    h("span", { class: "small muted", text: `${num(data.total)} record(s)${data.more ? ", newest 300 shown" : ""}` }));
  put(main, bar);
  if (!data.rows.length) { put(main, empty("No records match", "Change or clear the filter.")); integrityPanel(); return; }
  const rows = data.rows.map((r) => {
    const mismatch = r.actor.kind === "human" && r.observed.harness;
    return { data: r, cells: [
      h("td", { class: "seq", text: r.chain.seq ?? "" }),
      h("td", { class: "small time", text: fmtTime(r.time) }),
      h("td", {}, r.type, r.signed ? h("span", { class: "muted small", text: " · signed" }) : null),
      h("td", { class: "hide-narrow", text: r.action }),
      h("td", { class: "mono small wrap", text: r.actor.id }),
      h("td", { class: "hide-narrow small" }, mismatch ? h("span", { class: "flag", title: "claims a human but came from an agent harness", text: `! ${r.observed.harness}` }) : (r.observed.via ? `${r.observed.via}${r.observed.harness ? " · " + r.observed.harness : ""}` : "–")),
      h("td", { class: "hide-narrow mono small wrap", text: (r.subject && r.subject.ref) || "" }),
    ] };
  });
  const t = table([h("th", { scope: "col", class: "num", text: "Seq" }), "Time", "Type", h("th", { class: "hide-narrow", text: "Action" }), "Claimed actor",
    h("th", { class: "hide-narrow", text: "Observed" }), h("th", { class: "hide-narrow", text: "Subject" })], rows, openRecord,
    (r) => (r.type === "trail.anchor" ? "anchor" : r.type === "trail.gap" ? "gap" : r.type.endsWith(".refused") ? "refusal" : ""));
  t.table.classList.add("with-filter");
  put(main, t.table);
  const wanted = location.hash.slice(1);
  const pre = wanted && [...t.tbody.children].find((tr, i) => rows[i].data.id === wanted);
  if (pre) { pre.click(); pre.scrollIntoView({ block: "center" }); } else integrityPanel();
}

function integrityPanel() {
  const status = S.overview && S.overview.status;
  const check = (status && status.check) || {};
  const button = h("button", { class: "btn small", type: "button", text: "Verify now", onclick: async () => { button.disabled = true; button.textContent = "Verifying…"; await post("/api/trail/verify"); pollVerify(); } });
  const parts = [inspSection("Integrity", status ? stWord(status.state) : null,
    h("p", { text: check.summary || "Not verified yet." }),
    check.checked_at ? kv([["Checked", fmtTime(check.checked_at)], ["Took", `${check.seconds ?? "?"} s`], ["Signatures", num(check.signatures)], ["Anchors", num(check.anchors)]]) : null,
    (check.problems || []).map((p) => h("p", { class: "small", text: `Problem: ${p}` })),
    (check.warnings || []).map((w) => h("p", { class: "small muted", text: `Warning: ${w}` })),
    h("div", { class: "actions" }, button))];
  const alcoa = (S.overview && S.overview.alcoa) || [];
  if (alcoa.length) parts.push(inspSection("ALCOA++", alcoa.map((a) => h("p", { class: "small" }, stWord(a.status, a.attribute), " ", a.detail))));
  setInspector(...parts);
  if (window.matchMedia("(max-width: 1100px)").matches) closeSheet();
}

async function openRecord(row) {
  const data = await api(`/api/trail/record/${encodeURIComponent(row.id)}`);
  const r = data.record;
  const obs = data.observed || {};
  setInspector(
    inspSection("Record", h("p", { class: "insp-title mono", text: r.id }), kv([
      ["Type", r.type], ["Action", r.action], ["Time", fmtTime(r.time)], ["UTC", h("span", { class: "mono", text: r.time })],
      ["Seq", num((r.chain || {}).seq)], ["Previous", hashButton((r.chain || {}).prev)],
      ["Meaning", r.meaning || "–"], ["Reason", r.reason || "–"], ["Subject", r.subject ? `${r.subject.kind}: ${r.subject.ref}` : "–"],
    ])),
    inspSection("Who", kv([
      ["Claimed", `${r.actor.id}${r.actor.role ? " (" + r.actor.role + ")" : ""}`],
      ["Observed", obs.process_chain && obs.process_chain.length ? obs.process_chain.join(" ← ") : (obs.via || obs.origin || "not observed")],
      ["Harness", obs.harness || "none detected"], ["Via", obs.via || obs.origin || "–"],
    ]), data.attribution_mismatch ? h("p", { class: "flag", text: "This record claims a human but came from an agent harness." }) : null),
    inspSection("Signatures", (r.sig || []).map((s) => kv([["Writer key", h("code", { text: s.key })]])),
      r.data && r.data.signature ? kv([["Detached", `${r.data.signature.statement && r.data.signature.statement.meaning} by ${r.data.signature.statement && r.data.signature.statement.signer && r.data.signature.statement.signer.id}`]]) : null),
    inspSection("Stored record (text)", h("pre", { class: "json", text: JSON.stringify(r, null, 2) })),
  );
}

// ---- Quarantine ----------------------------------------------------------------------------------
async function renderQuarantine(main) {
  const q = query();
  const tab = q.get("tab") || "cases";
  const state = q.get("state") || "held";
  const data = await api(`/api/quarantine?state=${encodeURIComponent(state)}`);
  clear(main);
  const tabs = h("div", { class: "tabs", role: "tablist" },
    [["cases", "Cases"], ["sources", `Trusted sources (${data.sources.length})`]].map(([id, label]) =>
      h("button", { role: "tab", "aria-selected": tab === id ? "true" : "false", type: "button", text: label, onclick: () => { setQuery({ tab: id }); route(); } })));
  put(main, tabs);
  if (tab === "sources") {
    if (!data.sources.length) { put(main, empty("No trusted sources", "Trust a source in a terminal: aqt-quarantine trust DOMAIN --expires YYYY-MM-DD --reason …")); return; }
    const rows = data.sources.map((s) => ({ data: s, cells: [h("td", { class: "mono", text: s.domain }), s.subdomains ? "with subdomains" : "exact",
      h("td", {}, stWord(s.active ? "valid" : "expired", s.active ? `until ${s.expires}` : `expired ${s.expires}`)), h("td", { class: "mono small", text: s.by || "" })] }));
    const t = table(["Domain", "Scope", "Expires", "Trusted by"], rows, (s) => setInspector(inspSection("Trusted source", h("p", { class: "insp-title mono", text: s.domain }),
      kv([["Expires", s.expires], ["Subdomains", s.subdomains ? "yes" : "no"], ["By", s.by], ["Reason", s.reason], ["Record", h("code", { text: s.record })]]))));
    put(main, t.table);
    return;
  }
  const counts = data.counts || {};
  const bar = h("div", { class: "filterbar" }, h("div", { class: "chips", role: "group", "aria-label": "Case state" },
    [["held", "Held"], ["warned", "Warned"], ["released", "Released"], ["threat", "Threat"], ["all", "All"]].map(([id, label]) =>
      h("button", { class: "chip-btn", type: "button", "aria-pressed": state === id ? "true" : "false",
        text: `${label}${id === "all" ? "" : ` ${counts[id] || 0}`}`, onclick: () => { setQuery({ state: id }); route(); } }))),
    data.outbox ? h("span", { class: "small", text: `${data.outbox} record(s) waiting in the quarantine outbox (aqt-quarantine flush)` }) : null);
  put(main, bar);
  if (!data.cases.length) {
    put(main, empty(state === "held" ? "No held cases" : "No cases in this state", state === "held" ? "Nothing waits for a quarantine decision." : ""));
    return;
  }
  const rows = data.cases.map((c) => ({ data: c, cells: [
    h("td", { class: "mono", text: c.case_id }), h("td", {}, stWord(c.state)), h("td", { class: "hide-narrow", text: c.band }),
    h("td", { class: "wrap", text: c.domain || c.tool || "–" }), h("td", { class: "num", text: num(c.score_ppm) }),
    h("td", { class: "small", text: ago(c.opened) }), h("td", { class: "hide-narrow mono small", text: c.session || "–" }),
    h("td", { class: "hide-narrow num", text: c.refused ? `${c.refused}` : "" })] }));
  const t = table(["Case", "State", h("th", { class: "hide-narrow", text: "Band" }), "Source", h("th", { class: "num", text: "Score ppm" }), "Age",
    h("th", { class: "hide-narrow", text: "Session" }), h("th", { class: "hide-narrow num", text: "Refused" })], rows, (c) => openCase(c.case_id, false));
  t.table.classList.add("with-filter");
  put(main, t.table);
  const wanted = q.get("item");
  const index = wanted ? data.cases.findIndex((c) => c.case_id === wanted) : -1;
  if (index >= 0) t.tbody.children[index].click();
}

async function openCase(caseId, full) {
  const c = await api(`/api/quarantine/${encodeURIComponent(caseId)}${full ? "?full=1" : ""}`);
  const content = h("div");
  if (c.content) {
    const pre = h("pre", { class: "text", tabindex: "0", "aria-label": "Case content, untrusted" });
    for (const w of c.content.windows) {
      if (w.cut_before) put(pre, h("span", { class: "muted", text: "… " }));
      for (const piece of w.pieces) put(pre, piece.mark ? h("mark", { title: piece.mark, text: piece.text }) : document.createTextNode(piece.text));
      if (w.cut_after) put(pre, h("span", { class: "muted", text: " …" }));
      put(pre, "\n\n");
    }
    put(content, h("p", { class: "untrusted", text: "Untrusted third-party text. Highlighted passages are detector evidence; hidden characters are shown as <U+XXXX>." }), pre,
      !full && c.content.windows.some((w) => w.cut_before || w.cut_after) ? h("button", { class: "btn small", type: "button", text: `Show full content (${num(c.content.chars)} characters)`, onclick: () => openCase(caseId, true) }) : null,
      c.content.truncated ? h("p", { class: "small muted", text: "Shown up to 200,000 characters." }) : null);
  } else put(content, h("p", { class: "muted", text: c.content_error || "Content not available." }));
  const actions = [];
  if (c.can_release) actions.push({ id: "release", label: "Release", meaning: "released", button: "Sign and release" });
  if (c.can_declare) actions.push({ id: "threat", label: "Declare threat", meaning: "rejected", button: "Sign and declare threat", danger: true });
  const panel = actions.length ? decisionPanel({
    actions, signers: c.signers, subject: { label: `case ${c.case_id}, content`, hash: c.content_sha256 },
    note: c.state === "threat" ? "This case was declared a threat; releasing it overrules that decision." : null,
    submit: (a, values) => post(`/api/quarantine/${encodeURIComponent(c.case_id)}/${a.id}`, { ...values, content_sha256: c.content_sha256, overrule_threat: c.state === "threat" }),
  }) : null;
  setInspector(
    inspSection("Quarantine case", h("p", { class: "insp-title mono", text: c.case_id }), stWord(c.state), " ", h("span", { class: "muted small", text: `band ${c.band}` }),
      kv([["Source", c.ref || c.domain || "–"], ["Tool", c.tool], ["Session", c.session || "–"], ["Score", `${num(c.score_ppm)} ppm`],
        ["Detectors", c.detectors.map((d) => `${d.id} ${d.version}: ${num(d.score_ppm)} ppm`).join("; ") || "–"],
        ["Thresholds", `${c.thresholds.version || "?"} ${c.thresholds.calibrated ? "calibrated" : "NOT calibrated (defaults)"}`],
        ["Opened", fmtTime(c.opened)], ["Reached model", c.reached_model ? "yes" : "no"], ["Content", hashButton(c.content_sha256)], ["Record", h("code", { text: c.opened_record })]])),
    c.evidence.length ? inspSection("Evidence", h("ul", { class: "evidence-list" }, c.evidence.map((e) => h("li", {}, h("strong", { text: e.label }), ` (${e.detector}): ${e.reason} `, h("code", { text: e.excerpt }))))) : null,
    inspSection("Content", content),
    c.decisions.length || c.refusals.length ? inspSection("History",
      c.decisions.map((d) => h("p", { class: "small" }, `${fmtTime(d.time)} ${d.action} by ${d.display || ""} ${d.by} · signature `, stWord(d.status), d.honoured ? "" : " (not honoured)", d.note ? ` ${d.note}` : "", h("br"), h("span", { class: "muted", text: `Reason: ${d.reason}` }))),
      c.refusals.map((r) => h("p", { class: "small" }, stWord("fail", "refused"), ` ${fmtTime(r.time)} ${r.attempted} (${r.reason_code}${r.markers.length ? "; " + r.markers.join(", ") : ""})`))) : null,
    panel,
  );
}

// ---- Changes ------------------------------------------------------------------------------------------
async function renderChanges(main) {
  const q = query();
  const tab = q.get("tab") || (q.get("item") && q.get("item").startsWith("act_") ? "actions" : "gates");
  const data = await api("/api/changes");
  clear(main);
  put(main, h("div", { class: "tabs", role: "tablist" },
    [["gates", "Gates"], ["actions", `Prepared actions (${data.actions.length})`]].map(([id, label]) =>
      h("button", { role: "tab", "aria-selected": tab === id ? "true" : "false", type: "button", text: label, onclick: () => { setQuery({ tab: id }); route(); } }))));
  if (tab === "actions") {
    if (!data.installed["aqt-signoff"]) { put(main, empty("aqt-signoff is not installed", "uv pip install -e aqt-signoff")); return; }
    if (!data.actions.length) { put(main, empty("No prepared actions", "Actions appear here when an agent prepares one with aqt-signoff action prepare.")); return; }
    const order = { prepared: 0, expired: 0, unknown: 1, approved: 2, claimed: 3 };
    const actions = data.actions.slice().sort((a, b) => (order[a.status] ?? 9) - (order[b.status] ?? 9));
    const rows = actions.map((a) => ({ data: a, cells: [h("td", { class: "mono", text: a.id }), h("td", {}, stWord(a.status)), h("td", { class: "wrap", text: (a.spec && a.spec.description) || a.detail || "" }),
      h("td", { class: "hide-narrow mono small", text: (a.preparer && a.preparer.id) || "" }), h("td", { class: "hide-narrow" }, hashButton(a.action_sha256, 10))] }));
    const t = table(["Action", "Status", "What", h("th", { class: "hide-narrow", text: "Prepared by" }), h("th", { class: "hide-narrow", text: "Hash" })], rows, (a) => openAction(a.id, data.signers));
    put(main, t.table);
    const wanted = q.get("item");
    const i = wanted ? actions.findIndex((a) => a.id === wanted) : -1;
    if (i >= 0) t.tbody.children[i].click();
    return;
  }
  if (!data.installed["aqt-change"]) { put(main, empty("aqt-change is not installed", "uv pip install -e aqt-change")); return; }
  if (!data.projects.length) { put(main, empty("No projects configured", "Add repository roots to ~/.config/aqt/ui.toml:  [changes] projects = [\"~/code/project\"]")); return; }
  for (const project of data.projects) {
    const box = section(h("span", { class: "path", text: project.root }));
    if (project.error) put(box, h("div", { class: "error-box", text: project.error }));
    else if (!project.plans.length) put(box, h("p", { class: "muted", text: "No registered plans in this repository." }));
    else {
      const rows = project.plans.map((p) => ({ data: p, cells: [h("td", { class: "mono", text: p.plan_id }), h("td", {}, gateChip(p.decision)),
        h("td", { class: "wrap small" }, p.error ? p.error : (p.reasons[0] ? [p.reasons[0].text, " ", h("code", { class: "muted", text: p.reasons[0].code })] : "All checks passed")), h("td", { class: "hide-narrow mono small", text: p.path })] }));
      put(box, table(["Plan", "Gate", "First reason", h("th", { class: "hide-narrow", text: "File" })], rows, openGate).table);
    }
    put(main, box);
  }
}
function gateChip(decision) {
  if (!decision) return stWord("neutral", "not evaluated");
  return decision === "GO" ? st("pass", "GO") : decision === "NO-GO" ? st("fail", "NO-GO") : st("warn", "MANUAL");
}
function openGate(p) {
  setInspector(
    inspSection("Gate", h("p", { class: "insp-title mono", text: p.plan_id }), gateChip(p.decision), kv([["File", p.path], ["Evaluated", fmtTime(p.evaluated_at)], ["Finish", p.finish ? h("code", { text: p.finish }) : "not finished"]])),
    p.error ? inspSection("Not evaluated", h("p", { class: "small", text: p.error })) : inspSection("Reasons", p.reasons.length ? h("ul", { class: "evidence-list" }, p.reasons.map((r) => h("li", {}, r.text, " ", h("code", { class: "muted", text: r.code }), r.item ? ` · item ${r.item}` : "", r.detail ? ` · ${r.detail}` : ""))) : h("p", { text: "No reasons: the gate is GO." })),
    inspSection("Receipts", p.receipts.length ? p.receipts.map((r) => h("div", { class: "small" }, h("strong", { text: r.item }), " ", stWord(r.state === "ok" ? "fresh" : r.state, r.state === "ok" ? "fresh" : r.state), " ", r.text || "",
      r.commands.map((c) => h("div", { class: "muted" }, h("code", { text: c.command }), ` ${c.state}${c.counts ? " · " + JSON.stringify(c.counts) : ""}`)))) : h("p", { class: "muted", text: "No verification items." })),
    inspSection("Approval", kv([["State", p.approval ? stWord(p.approval.state === "signed" || p.approval.state === "signed-verified" ? "valid" : "warn", p.approval.state) : "–"], ["Reviews", (p.reviews || []).join(", ") || "none fresh"]]),
      h("p", { class: "small muted", text: "Plan approval through the UI comes later; sign it in a terminal with aqt-signoff sign --record <approval target> --meaning approved." })),
  );
}
async function openAction(id, signers) {
  const a = await api(`/api/changes/actions/${encodeURIComponent(id)}`);
  const open = ["prepared", "approved", "expired"].includes(a.status);
  setInspector(
    inspSection("Prepared action", h("p", { class: "insp-title mono", text: a.id }), stWord(a.status), a.detail ? h("span", { class: "muted small", text: ` ${a.detail}` }) : null,
      kv([["Version", a.version], ["Prepared by", (a.preparer && a.preparer.id) || "–"], ["Hash", hashButton(a.action_sha256, 16)], ["Updated", fmtTime(a.updated_at)],
        ["Approvals", a.approvals.length ? a.approvals.map((x) => `${x.signer} (${x.role})`).join(", ") : "none"]])),
    inspSection("What will run (text)", h("pre", { class: "json", text: JSON.stringify(a.spec, null, 2) })),
    open ? decisionPanel({
      actions: [{ id: "approve", label: "Approve", meaning: "approved", button: "Sign and approve" }, { id: "reject", label: "Reject", meaning: "rejected", button: "Sign and reject", danger: true }],
      signers, subject: { label: `action ${a.id} v${a.version}`, hash: a.action_sha256 },
      submit: (choice, values) => post(`/api/changes/actions/${encodeURIComponent(a.id)}/${choice.id}`, { ...values, expected_hash: a.action_sha256 }),
    }) : null,
  );
}

// ---- Signatures --------------------------------------------------------------------------------------
async function renderSignatures(main) {
  clear(main);
  if (!S.installed.aqt_signoff) { put(main, empty("aqt-signoff is not installed", "uv pip install -e aqt-signoff")); return; }
  const kind = h("select", { "aria-label": "What to verify" }, [["file", "Local file path"], ["record", "Record ID"], ["sha256", "SHA-256 hash"]].map(([v, t]) => h("option", { value: v, text: t })));
  const value = h("input", { class: "grow", type: "text", placeholder: "/home/me/project/plan.md", "aria-label": "Value to verify" });
  const out = h("div");
  const run = async () => {
    clear(out);
    if (!value.value.trim()) return;
    const params = new URLSearchParams({ [kind.value]: value.value.trim() });
    try {
      const r = await api(`/api/signatures/verify?${params}`);
      const rows = r.rows.map((x) => ({ data: x, cells: [x.name, h("td", { class: "mono small", text: x.id }), x.role, x.meaning, h("td", { class: "small", text: x.local }), h("td", { class: "wrap small", text: x.reason }), h("td", {}, stWord(x.status))] }));
      put(out, section("Result", h("p", {}, stWord(r.ok ? "valid" : "warn", r.summary)), kv([["Subject", `${r.subject.kind}: ${r.subject.ref}`], ["Content", hashButton(r.subject.sha256, 20)]]),
        rows.length ? table(["Printed name", "ID", "Role", "Meaning", "Local time", "Reason", "Status"], rows, (x) => setInspector(inspSection("Signature", kv(Object.entries(x).map(([k, v]) => [k, String(v)]))))).table : h("p", { class: "muted", text: "No signatures over this content." }),
        h("p", { class: "small" }, "Download the manifest: ", h("a", { href: `/api/signatures/manifest?${params}&format=md`, download: "signature-manifest.md", text: "Markdown" }), " · ",
          h("a", { href: `/api/signatures/manifest?${params}&format=html`, download: "signature-manifest.html", text: "HTML" })),
        h("p", { class: "small muted", text: "Viewing never records anything. aqt-signoff verify in a terminal records a changed-content invalidation." })));
    } catch (error) { put(out, errorBox(error)); }
  };
  put(main, h("div", { class: "filterbar", role: "search" }, kind, value, h("button", { class: "btn small primary", type: "button", text: "Verify", onclick: run })), out);
  value.addEventListener("keydown", (e) => { if (e.key === "Enter") run(); });
  const reg = await api("/api/signatures");
  const rows = reg.signers.map((s) => ({ data: s, cells: [s.name, h("td", { class: "mono small", text: s.id }), s.role, h("td", {}, s.active_key ? stWord("valid", "active key") : stWord("revoked", "no active key")), h("td", { class: "hide-narrow mono small", text: s.active_key || "" })] }));
  put(main, section(["Signer registry ", h("span", { class: "hint muted", text: reg.path })], rows.length ? table(["Printed name", "ID", "Role", "Key", h("th", { class: "hide-narrow", text: "Key ID" })], rows,
    (s) => setInspector(inspSection("Signer", h("p", { class: "insp-title", text: s.name }), kv([["ID", s.id], ["Role", s.role]]),
      s.keys.map((k) => kv([["Key", h("code", { text: k.key_id })], ["Enrolled", fmtTime(k.enrolled_at)], ["Revoked", k.revoked_at ? fmtTime(k.revoked_at) : "no"]]))))).table
    : h("p", { class: "muted", text: "No signers registered. Enrol in a terminal: aqt-signoff init" })));
}

// ---- CAPA --------------------------------------------------------------------------------------------
async function renderCapa(main) {
  const tab = query().get("tab") || "deviations";
  const data = await api("/api/capa");
  clear(main);
  const c = data.counts;
  put(main, h("div", { class: "tabs", role: "tablist" },
    [["candidates", `Candidates (${c.candidates})`], ["deviations", `Deviations (${c.open} open)`], ["effectiveness", "Effectiveness"]].map(([id, label]) =>
      h("button", { role: "tab", "aria-selected": tab === id ? "true" : "false", type: "button", text: label, onclick: () => { setQuery({ tab: id }); route(); } }))),
  );
  if (tab === "candidates") {
    if (!data.candidates.length) { put(main, empty("No open candidates", "aqt-capa scan finds candidates in the evidence.")); return; }
    const rows = data.candidates.map((x) => ({ data: x, cells: [h("td", { class: "mono small", text: x.candidate_id }), x.rule, h("td", { class: "wrap", text: x.title }), x.severity || "–", h("td", { class: "small", text: ago(x.time) })] }));
    put(main, table(["Candidate", "Rule", "What", "Severity", "When"], rows, (x) => setInspector(inspSection("Candidate", h("p", { class: "insp-title", text: x.title }),
      kv([["ID", h("code", { text: x.candidate_id })], ["Rule", x.rule], ["Source", `${x.source_type}: ${x.source_ref}`], ["Session", x.session || "–"], ["Time", fmtTime(x.time)]]),
      h("p", { class: "small muted", text: "Accept or dismiss in a terminal for now: aqt-capa candidate accept|dismiss ID --reason …" })))).table);
    return;
  }
  if (tab === "effectiveness") {
    if (data.effectiveness_error) put(main, h("div", { class: "error-box", text: data.effectiveness_error }));
    if (!data.effectiveness.length) { put(main, empty("No running effectiveness checks", "")); return; }
    const rows = data.effectiveness.map((e) => ({ data: e, cells: [h("td", { class: "mono", text: e.action_id }), h("td", { class: "mono", text: e.dev_id }), h("td", {}, stWord(e.result)), h("td", { class: "wrap small", text: (e.reasons || []).join("; ") })] }));
    put(main, table(["Action", "Deviation", "Result", "Why"], rows, (e) => openDeviation(e.dev_id)).table,
      h("p", { class: "small muted section", text: "Shown without recording; aqt-capa effectiveness in a terminal records changed results." }));
    return;
  }
  if (!data.deviations.length) { put(main, empty("No deviations", "")); return; }
  const rows = data.deviations.map((d) => ({ data: d, cells: [h("td", { class: "mono", text: d.dev_id }), h("td", {}, d.overdue ? st("fail", "overdue") : stWord(d.state === "closed" ? "closed" : "open", d.state)),
    h("td", { class: "wrap", text: d.title }), h("td", { class: "hide-narrow", text: d.severity }), h("td", { class: "hide-narrow small", text: d.due ? fmtTime(d.due) : "–" })] }));
  put(main, table(["Deviation", "State", "Title", h("th", { class: "hide-narrow", text: "Severity" }), h("th", { class: "hide-narrow", text: "Due" })], rows, (d) => openDeviation(d.dev_id)).table,
    h("p", { class: "section small" }, h("a", { href: "/api/capa/trends", download: "capa-trends.md", text: "Download the trend summary (Markdown)" })));
}
async function openDeviation(devId) {
  const d = await api(`/api/capa/${encodeURIComponent(devId)}`);
  const dev = d.deviation;
  setInspector(
    inspSection("Deviation", h("p", { class: "insp-title", text: `${dev.dev_id} ${dev.title}` }), stWord(dev.state === "closed" ? "closed" : "open", dev.state),
      kv([["Severity", dev.severity], ["Category", dev.category], ["Opened", fmtTime(dev.opened_at)], ["Due", dev.due ? fmtTime(dev.due) : "–"]])),
    d.investigation ? inspSection("Investigation", kv([["Root cause", d.investigation.root_cause || "–"], ["Category", d.investigation.root_category || "–"],
      ["Why chain", (d.investigation.whys || []).join(" → ") || "–"], ["Factors", (d.investigation.factors || []).map((f) => `${f.category}: ${f.text}`).join("; ") || "–"]])) : null,
    d.actions.length ? inspSection("Actions", d.actions.map((a) => h("div", { class: "small" }, h("strong", { text: a.action_id }), ` ${a.kind} on ${a.path}: ${a.description} · `, stWord(a.state),
      ` · approval ${(a.approval && a.approval.status) || "none"} · effectiveness ${(a.last_evaluation && a.last_evaluation.result) || "not evaluated"}`))) : null,
    inspSection("Timeline", d.timeline.map((t) => h("p", { class: "small" }, h("span", { class: "mono", text: fmtTime(t.time) }), ` ${t.type} ${t.action} by ${t.actor}`, t.reason ? h("span", { class: "muted", text: ` · ${t.reason}` }) : null))),
  );
}

// ---- Qualifications -----------------------------------------------------------------------------------
async function renderQualifications(main) {
  const data = await api("/api/qualifications");
  clear(main);
  if (!data.qualifications.length) put(main, empty("No qualifications recorded", data.installed ? "Qualify a detector with aqt-validate (in a terminal)." : "aqt-validate is not installed."));
  else {
    const words = (q) => ({ valid: `valid until ${String(q.valid_until).slice(0, 10)}`, expiring: `expires in ${q.days_left} day(s)`, expired: "expired", triggered: `triggered: ${q.triggers.join(", ")}`, rejected: "rejected" })[q.state];
    const rows = data.qualifications.map((q) => ({ data: q, cells: [h("td", { class: "wrap", text: q.subject_id }), q.kind, h("td", {}, stWord(q.state, words(q))), h("td", { class: "num", text: q.days_left ?? "–" }),
      h("td", { class: "hide-narrow mono small", text: q.approver || "" }), h("td", { class: "hide-narrow" }, q.same_thresholds === null ? "–" : q.same_thresholds ? stWord("pass", "same as qualified") : stWord("warn", "different file in use"))] }));
    put(main, table(["Subject", "Kind", "Status", h("th", { class: "num", text: "Days left" }), h("th", { class: "hide-narrow", text: "Approver" }), h("th", { class: "hide-narrow", text: "Thresholds" })], rows, (q) => setInspector(
      inspSection("Qualification", h("p", { class: "insp-title", text: q.subject_id }), stWord(q.state, words(q)),
        kv([["Kind", q.kind], ["Decision", q.decision], ["Conclusion", q.conclusion], ["Valid until", fmtTime(q.valid_until)], ["Approved by", `${q.approver_name || ""} ${q.approver || ""}`],
          ["Reason", q.reason], ["Band", q.band || "–"], ["Expected FPR ≤", q.expected_fpr_upper_ppm != null ? `${num(q.expected_fpr_upper_ppm)} ppm` : "–"], ["Record", h("code", { text: q.record })],
          ["Triggers", q.triggers.join(", ") || "none recorded"]])),
      q.report_summary ? inspSection("Run report", kv([["Issued", fmtTime(q.report_summary.time)], ["Report", q.report_summary.subject || "–"]]), h("pre", { class: "json", text: JSON.stringify(q.report_summary.data, null, 2) })) : null,
    )).table);
  }
  const t = data.thresholds;
  put(main, section("Thresholds in use (aqt-quarantine)", !t ? h("p", { class: "muted", text: "aqt-quarantine is not installed." }) : t.error ? h("div", { class: "error-box", text: t.error })
    : kv([["Version", t.version], ["Calibrated", t.calibrated ? stWord("pass", "calibrated") : stWord("warn", "not calibrated (defaults)")], ["SHA-256", hashButton(t.sha256, 20)], ["File", t.path]]),
    h("p", { class: "small muted", text: "Requalification triggers are shown as recorded; aqt-validate check in a terminal evaluates and records new ones." })));
}

const RENDER = { overview: renderOverview, trail: renderTrail, quarantine: renderQuarantine, changes: renderChanges,
  signatures: renderSignatures, capa: renderCapa, qualifications: renderQualifications };

// ---- start ---------------------------------------------------------------------------------------------
async function start() {
  $("menu-btn").addEventListener("click", () => {
    const open = $("rail").classList.toggle("open");
    $("menu-btn").setAttribute("aria-expanded", String(open));
  });
  $("refresh").addEventListener("click", async () => { await refresh(); route(); announce("Refreshed"); });
  try {
    const session = await api("/api/session");
    S.csrf = session.csrf;
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
