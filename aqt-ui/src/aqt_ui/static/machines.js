// The desktop app's machines: the window shows the AQT of this computer, or of another machine whose core the
// app starts over SSH (ssh <destination> aqt core --stdio) with the user's own ssh config, keys and agent. The
// page asks the app (the command "machines") for the list, the machine it is on and the connection's state;
// the app tells it each change of the connection (window.aqtConnection). In a browser none of this shows.
// Every text goes into the page with textContent, as in app.js.

export const MACHINE_DE = {
  "Machine": "Rechner", "This computer": "Dieser Rechner", "Machines": "Rechner",
  "quality desk on {machine}": "Qualitätsarbeitsplatz auf {machine}",
  "The window shows the AQT of this computer or of another machine, which it opens over SSH with your own keys: no tunnel, no web page.":
    "Das Fenster zeigt das AQT dieses Rechners oder eines anderen, das es über SSH mit deinen eigenen Schlüsseln öffnet: ohne Tunnel, ohne Webseite.",
  "Shown now": "Wird gezeigt", "Show": "Zeigen", "Test connection": "Verbindung testen", "Remove": "Entfernen",
  "Testing…": "Wird getestet …", "Name": "Name", "SSH destination": "SSH-Ziel", "Add": "Hinzufügen",
  "e.g. Build server": "z. B. Build-Server", "user@host, or a Host from ~/.ssh/config": "user@host oder ein Host aus ~/.ssh/config",
"Added: {name}": "Hinzugefügt: {name}", "Removed: {name}": "Entfernt: {name}",
  "Connected: AQT {version}, {command}": "Verbunden: AQT {version}, {command}",
  "decisions are on": "Entscheidungen sind möglich", "read-only: {reason}": "nur lesend: {reason}",
  "The app runs ssh with your ssh config, keys and agent, and never asks for a password or passphrase: load a key that has a passphrase into your ssh-agent first (ssh-add). Signatures are made with the key on that machine; your passphrase goes there through the SSH connection.":
    "Die App startet ssh mit deiner ssh-Konfiguration, deinen Schlüsseln und deinem Agenten und fragt nie nach einem Passwort oder einer Passphrase: Einen Schlüssel mit Passphrase lädst du vorher in deinen ssh-agent (ssh-add). Unterschrieben wird mit dem Schlüssel auf jenem Rechner; deine Passphrase geht durch die SSH-Verbindung dorthin.",
  "Downloads are saved on this computer. To connect a project there, type its path on that machine.":
    "Downloads werden auf diesem Rechner gespeichert. Ein Projekt dort verbindest du mit seinem Pfad auf jenem Rechner.",
  "Folder on {machine} (full path)": "Ordner auf {machine} (voller Pfad)",
  "Connecting to {machine}…": "Verbindung zu {machine} wird aufgebaut …",
  "The connection to {machine} was lost. Connecting again…": "Die Verbindung zu {machine} ist abgerissen. Neuer Versuch …",
  "Connected to {machine} again.": "Wieder mit {machine} verbunden.",
  "Reconnect": "Neu verbinden", "Start the core again": "Kern neu starten", "Use this computer": "Diesen Rechner nehmen",
  "The data below is from before; it may be out of date.": "Die Daten darunter sind von vorher und vielleicht nicht mehr aktuell.",
  "What ssh said": "Was ssh gemeldet hat",
  "{machine} cannot be reached.": "{machine} ist nicht erreichbar.",
  "The connection to {machine} was lost.": "Die Verbindung zu {machine} ist abgerissen.",
  "Check that it is switched on and on the network, and that this works in a terminal:": "Prüfe, ob er eingeschaltet und im Netz ist und ob das in einem Terminal geht:",
  "{machine} is not a known host yet.": "{machine} ist noch kein bekannter Host.",
  "The app never accepts an unknown host key by itself. Run this once in a terminal, compare the fingerprint and answer yes:":
    "Die App nimmt einen unbekannten Host-Schlüssel nie selbst an. Führe das einmal in einem Terminal aus, vergleiche den Fingerabdruck und antworte mit yes:",
  "The host key of {machine} has changed.": "Der Host-Schlüssel von {machine} hat sich geändert.",
  "That happens when the machine was set up again, or when someone sits in between. Find out why before you trust it; this shows the details:":
    "Das passiert, wenn der Rechner neu aufgesetzt wurde, oder wenn sich jemand dazwischen geschaltet hat. Kläre den Grund, bevor du ihm vertraust; das zeigt die Einzelheiten:",
  "{machine} did not accept your SSH key.": "{machine} hat deinen SSH-Schlüssel nicht angenommen.",
  "Check the user name in the destination ({destination}).": "Prüfe den Benutzernamen im Ziel ({destination}).",
  "Check that your public key is in ~/.ssh/authorized_keys on {machine}.": "Prüfe, ob dein öffentlicher Schlüssel in ~/.ssh/authorized_keys auf {machine} steht.",
  "A key with a passphrase must be loaded in your ssh-agent: the app never asks for it.": "Ein Schlüssel mit Passphrase muss in deinem ssh-agent geladen sein: Die App fragt nie danach.",
  "AQT is not installed on {machine}.": "AQT ist auf {machine} nicht installiert.",
  "Install it there as the README describes, then test again. The app looks for aqt and aqt-toolkit on the PATH of an SSH command and in ~/.local/bin; this shows what an SSH command finds:":
    "Installiere es dort, wie die README es beschreibt, und teste dann noch einmal. Die App sucht aqt und aqt-toolkit im PATH eines SSH-Befehls und in ~/.local/bin; das zeigt, was ein SSH-Befehl findet:",
  "This computer has no ssh command.": "Dieser Rechner hat keinen ssh-Befehl.",
  "Install the OpenSSH client (on Windows: Settings, System, Optional features, OpenSSH Client).": "Installiere den OpenSSH-Client (unter Windows: Einstellungen, System, Optionale Features, OpenSSH-Client).",
  "The AQT core on {machine} stopped.": "Der AQT-Kern auf {machine} wurde beendet.",
  "The AQT core stopped.": "Der AQT-Kern wurde beendet.",
  "The connection was lost after the request was sent, so whether it was carried out is unknown. The app does not send it again. Reload to see what happened before you try again.":
    "Die Verbindung ist abgerissen, nachdem die Anfrage gesendet war. Ob sie ausgeführt wurde, ist daher unbekannt. Die App sendet sie nicht noch einmal. Lade neu, um zu sehen, was geschehen ist, bevor du es noch einmal versuchst.",
  "Outcome unknown.": "Ergebnis unbekannt.", "Reload": "Neu laden",
};

let ui = null;            // the helpers of app.js: APP, h, t, put, clear, announce, commandLine, onBack
let list = [];            // [{name, destination}]
let current = null;       // {name, destination} of the other machine, null on this computer
let state = { state: "ready" };
let lost = false;         // the connection was lost while the page showed data (greyed out)
let loaded = false;       // the page has its data

const t = (text, vars) => ui.t(text, vars);
const call = (change) => ui.APP.invoke("machines", change ? { change } : {});
function take(answer) {
  list = answer.machines || [];
  current = answer.current || null;
  state = answer.state || state;
}

/** The name of the other machine the window is on, or null on this computer (and in a browser). */
export function machineName() { return current ? current.name : null; }
/** The rail's line under the product name on another machine, else null. */
export function machineLine() { return current ? t("quality desk on {machine}", { machine: current.name }) : null; }

/** Before the page loads its data: which machine, the indicator, the state of the connection. */
export async function initMachines(helpers) {
  if (!helpers.APP) return;
  ui = helpers;
  Object.assign(ui.DE, MACHINE_DE);
  window.aqtConnection = (body) => { state = body; if (body.state !== "ready" && loaded) lost = true; draw(); };
  try { take(await call()); } catch (error) { /* an app without machines: this computer */ }
  draw();
}
/** The page has its data (or could not get it): the connection works, or the banner says why not. */
export function pageLoaded(ok) {
  if (!ui) return;
  loaded = ok;
  if (ok && state.state !== "failed") state = { state: "ready" };
  draw();
  if (!ok) call().then((answer) => { take(answer); draw(); }).catch(() => {});   // why the core gave no data
}
/** Labels after a change of language. */
export function relabelMachines() { if (ui) draw(); }

// ---- the machine indicator in the top bar, and the connection banner --------------------------------
function draw() {
  if (!ui) return;
  drawPicker();
  drawBanner();
}
function fillPicker(pick) {
  const { h, put, clear } = ui;
  pick.setAttribute("aria-label", t("Machine"));
  pick.classList.toggle("remote", !!current);
  put(clear(pick), h("option", { value: "", text: t("This computer") }),
    list.map((m) => h("option", { value: m.name, text: m.name })));
  pick.value = current ? current.name : "";
  return pick;
}
function newPicker(id) {
  const pick = ui.h("select", { id, class: "machine-pick" });
  pick.addEventListener("change", () => switchTo(pick.value || null));
  return fillPicker(pick);
}
function drawPicker() {
  let pick = document.getElementById("machine");
  if (!list.length && !current) { if (pick) pick.remove(); return; }
  if (!pick) document.querySelector(".topbar").insertBefore(pick = newPicker("machine"), document.getElementById("mode-badge"));
  fillPicker(pick);
}
/** The first-run setup hides the top bar: its header shows the machine (and lets you switch) with this. */
export function setupPicker() { return ui && (list.length || current) ? newPicker("machine-setup") : null; }
async function switchTo(name) {
  const pick = document.getElementById("machine");
  if (pick) pick.disabled = true;
  try { await call({ select: name }); } catch (error) { if (pick) pick.disabled = false; ui.announce(String(error)); return; }
  location.replace("/");                 // the page reloads its data from the core of that machine
}
async function reconnect() {
  try { await call({ reconnect: true }); } catch (error) { ui.announce(String(error)); return; }
  location.reload();
}

function drawBanner() {
  const { h, put, clear } = ui;
  let bar = document.getElementById("connection");
  if (!bar) {
    bar = h("div", { id: "connection", class: "conn-bar", role: "status", hidden: true });
    document.querySelector(".top-stack").prepend(bar);
  }
  const shell = document.querySelector(".shell");
  const name = current ? current.name : null;
  const failed = state.state === "failed";
  const starting = state.state === "starting";
  shell.classList.toggle("offline", (failed || starting) && loaded);
  clear(bar);
  bar.className = `conn-bar ${failed ? "failed" : "info"}`;
  if (failed) {
    put(bar, failureBox(state.failure || {}));
    if (loaded) put(bar, h("p", { class: "small muted", text: t("The data below is from before; it may be out of date.") }));
    put(bar, h("div", { class: "actions" },
      h("button", { class: "btn small primary", type: "button", text: name ? t("Reconnect") : t("Start the core again"), onclick: reconnect }),
      name ? h("button", { class: "btn small", type: "button", text: t("Use this computer"), onclick: () => switchTo(null) }) : null));
    bar.hidden = false;
  } else if (starting && name) {
    put(bar, h("strong", { text: lost || loaded ? t("The connection to {machine} was lost. Connecting again…", { machine: name }) : t("Connecting to {machine}…", { machine: name }) }));
    bar.hidden = false;
  } else if (lost && name) {
    lost = false;
    put(bar, h("strong", { text: t("Connected to {machine} again.", { machine: name }) }));
    bar.hidden = false;
    setTimeout(() => { if (state.state === "ready") bar.hidden = true; }, 5000);
    if (ui.onBack) ui.onBack();
  } else bar.hidden = true;
}

/** Why the core does not run, in words for its kind, with the one thing to do. */
function failureBox(f) {
  const { h, commandLine } = ui;
  const machine = f.machine || (current && current.name) || "";
  const destination = f.destination || (current && current.destination) || "";
  const v = { machine, destination };
  const words = {
    unreachable: [t("{machine} cannot be reached.", v), t("Check that it is switched on and on the network, and that this works in a terminal:"), `ssh ${destination}`],
    lost: [t("The connection to {machine} was lost.", v), t("Check that it is switched on and on the network, and that this works in a terminal:"), `ssh ${destination}`],
    host_key: [t("{machine} is not a known host yet.", v), t("The app never accepts an unknown host key by itself. Run this once in a terminal, compare the fingerprint and answer yes:"), `ssh ${destination}`],
    host_key_changed: [t("The host key of {machine} has changed.", v), t("That happens when the machine was set up again, or when someone sits in between. Find out why before you trust it; this shows the details:"), `ssh ${destination}`],
    auth: [t("{machine} did not accept your SSH key.", v), null, null],
    missing: [t("AQT is not installed on {machine}.", v), t("Install it there as the README describes, then test again. The app looks for aqt and aqt-toolkit on the PATH of an SSH command and in ~/.local/bin; this shows what an SSH command finds:"), `ssh ${destination} aqt --version`],
    no_ssh: [t("This computer has no ssh command."), t("Install the OpenSSH client (on Windows: Settings, System, Optional features, OpenSSH Client)."), null],
    stopped: [machine ? t("The AQT core on {machine} stopped.", v) : t("The AQT core stopped."), null, null],
  }[f.kind] || [f.message || t("The AQT core stopped."), null, null];
  const [title, hint, command] = words;
  return h("div", { class: "conn-why" },
    h("strong", { text: title }),
    hint ? h("p", { class: "small", text: hint }) : null,
    command ? commandLine(command) : null,
    f.kind === "auth" ? h("ul", { class: "small" },
      h("li", { text: t("Check the user name in the destination ({destination}).", v) }),
      h("li", { text: t("Check that your public key is in ~/.ssh/authorized_keys on {machine}.", v) }),
      h("li", { text: t("A key with a passphrase must be loaded in your ssh-agent: the app never asks for it.") })) : null,
    f.detail || (f.kind === "stopped" && f.message) ? h("details", { class: "tech" }, h("summary", { text: t("What ssh said") }),
      h("pre", { class: "json", text: f.detail || f.message })) : null);
}

// ---- a request whose answer was lost ------------------------------------------------------------------
/** The words for a request that reached the core (or its SSH connection) but got no answer. */
export function unknownText() { return ui ? t("The connection was lost after the request was sent, so whether it was carried out is unknown. The app does not send it again. Reload to see what happened before you try again.") : ""; }
/** The sign sheet's message for such a decision: the outcome is unknown, and a reload shows it. */
export function unknownBox() {
  const { h } = ui;
  return h("div", { class: "result stale", role: "alert" }, h("strong", { text: t("Outcome unknown.") }), " ", unknownText(), " ",
    h("button", { class: "btn small", type: "button", text: t("Reload"), onclick: () => location.reload() }));
}

// ---- Settings, This app: the machines -------------------------------------------------------------------
/** The folder field's label for a project on another machine (the folder dialog only shows this computer). */
export function remoteFolderLabel() { return current ? t("Folder on {machine} (full path)", { machine: current.name }) : null; }

export function machinesPart() {
  if (!ui) return null;
  const { h, put, clear, st, announce } = ui;
  const box = h("div", { class: "machines" });
  const out = h("div", { "aria-live": "polite" });
  const fail = (error) => put(clear(out), h("div", { class: "result refused", text: String(error.message || error) }));
  const name = h("input", { id: "machine-name", type: "text", maxlength: "40", placeholder: t("e.g. Build server"), autocomplete: "off" });
  const dest = h("input", { id: "machine-dest", type: "text", class: "grow", spellcheck: "false", autocomplete: "off", placeholder: t("user@host, or a Host from ~/.ssh/config") });
  const add = h("button", { class: "btn", type: "button", text: t("Add") });
  const redraw = () => { drawPicker(); drawList(); };
  add.addEventListener("click", async () => {
    add.disabled = true;
    try {
      take(await call({ add: { name: name.value, destination: dest.value } }));
      announce(t("Added: {name}", { name: name.value.trim() }));
      name.value = ""; dest.value = ""; clear(out); redraw();
      rows.lastChild.scrollIntoView({ block: "nearest" });
    }
    catch (error) { fail(error); }
    finally { add.disabled = false; }
  });
  const rows = h("ul", { class: "machine-list" });
  function row(m) {
    const here = m ? current && current.name === m.name : !current;
    const result = h("div", { class: "small", "aria-live": "polite" });
    const buttons = [];
    if (!here) buttons.push(h("button", { class: "btn small", type: "button", text: t("Show"), onclick: () => switchTo(m ? m.name : null) }));
    if (m) {
      const test = h("button", { class: "btn small", type: "button", text: t("Test connection") });
      test.addEventListener("click", async () => {
        test.disabled = true;
        put(clear(result), h("span", { class: "muted", text: t("Testing…") }));
        try {
          const answer = await call({ test: m.name });
          const r = answer.test || {};
          if (r.ok) {
            const mode = r.mode && r.mode.decisions ? t("decisions are on") : t("read-only: {reason}", { reason: (r.mode && r.mode.reason) || "" });
            put(clear(result), st("pass", `${t("Connected: AQT {version}, {command}", { version: r.version || "?", command: r.command || "aqt" })} · ${mode}`));
          } else put(clear(result), h("div", { class: "result refused" }, failureBox({ ...(r.failure || {}), machine: m.name, destination: m.destination })));
        } catch (error) { put(clear(result), h("div", { class: "result refused", text: String(error) })); }
        finally { test.disabled = false; }
      });
      buttons.push(test, h("button", { class: "btn small ghost", type: "button", text: t("Remove"), onclick: async () => {
        try { take(await call({ remove: m.name })); announce(t("Removed: {name}", { name: m.name })); if (here) { location.replace("/"); return; } redraw(); } catch (error) { fail(error); }
      } }));
    }
    return h("li", { class: `machine-row${here ? " here" : ""}` },
      h("div", { class: "who" }, h("strong", { text: m ? m.name : t("This computer") }), m ? h("code", { class: "muted", text: m.destination }) : null,
        here ? st("info", t("Shown now")) : null),
      h("div", { class: "row-actions" }, buttons), result);
  }
  function drawList() { put(clear(rows), row(null), list.map(row)); }
  drawList();
  put(box, h("h3", { text: t("Machines") }),
    h("p", { class: "small muted", text: t("The window shows the AQT of this computer or of another machine, which it opens over SSH with your own keys: no tunnel, no web page.") }),
    rows,
    h("div", { class: "machine-add" },
      h("label", { for: name.id, text: t("Name") }), name,
      h("label", { for: dest.id, text: t("SSH destination") }), dest, add),
    out,
    h("p", { class: "small muted", text: t("The app runs ssh with your ssh config, keys and agent, and never asks for a password or passphrase: load a key that has a passphrase into your ssh-agent first (ssh-add). Signatures are made with the key on that machine; your passphrase goes there through the SSH connection.") }),
    current ? h("p", { class: "small muted", text: t("Downloads are saved on this computer. To connect a project there, type its path on that machine.") }) : null);
  return box;
}
