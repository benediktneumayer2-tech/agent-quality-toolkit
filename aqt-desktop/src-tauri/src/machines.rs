//! Machines: the window shows the AQT of this computer or of another machine, whose core it starts over SSH
//! (`ssh <destination> aqt core --stdio`) with the system's OpenSSH: the user's config, keys and agent apply.
//! The protocol is the same; the remote core's guard decides about decisions. The list of machines (names and
//! SSH destinations, no secrets) is kept with the app's settings (`desktop.json`: `machines`, `machine`).
//!
//! Nothing here passes through a local shell: ssh gets its arguments as they are, the destination after `--`.
//! The command run on the other machine is one of a few fixed strings, never built from what the user typed.

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tauri::{AppHandle, Manager, State};

use crate::core::{self, Core, Ended, Launch};
use crate::desktop;

/// ssh never asks (no password or passphrase prompt, no question about an unknown host key: it fails instead),
/// gives up on a host that does not answer, notices a dead connection within 45 s, forwards no agent, X11 or
/// ports (also none from the user's config) and opens no connection-sharing master that would outlive it.
const SSH_OPTIONS: [&str; 13] = [
    "-T", "-a", "-x",
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=15",
    "-o", "ServerAliveInterval=15",
    "-o", "ServerAliveCountMax=3",
    "-o", "ClearAllForwardings=yes",
];
#[cfg(not(windows))]
const SHARING_OFF: [&str; 2] = ["-o", "ControlPath=none"]; // Windows' OpenSSH has no connection sharing
#[cfg(windows)]
const SHARING_OFF: [&str; 0] = [];
/// AQT's command there, in this order: `aqt`; `aqt-toolkit` where another `aqt` (aqtinstall's) comes first on
/// PATH; the link the install puts into `~/.local/bin`, which a command over SSH often lacks on its PATH (on
/// Ubuntu `~/.profile` adds it, and only a login shell reads that). The other machine's shell expands the `~`.
const REMOTE_NAMES: [&str; 3] = ["aqt", "aqt-toolkit", "~/.local/bin/aqt-toolkit"];
const MARK: &str = "@@aqt-probe@@";
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);
const VERSION_PREFIX: &str = "agent-quality-toolkit ";

#[derive(Clone, Debug, PartialEq)]
pub struct Machine {
    pub name: String,
    pub destination: String,
}

// -- arguments --------------------------------------------------------------------------------------------

/// The ssh program: `AQT_SSH` (a command line split on spaces, e.g. `ssh -F /path/config`), else `ssh`.
pub fn ssh_program(setting: Option<&str>) -> Vec<String> {
    match setting.map(str::split_whitespace) {
        Some(words) if setting.is_some_and(|s| !s.trim().is_empty()) => words.map(String::from).collect(),
        _ => vec!["ssh".into()],
    }
}

fn ssh_from_env() -> Vec<String> {
    ssh_program(std::env::var("AQT_SSH").ok().as_deref())
}

/// An SSH destination as ssh takes it: `host`, `user@host`, an alias from `~/.ssh/config`, `ssh://user@host:2222`.
/// Never an option (a leading `-`), no spaces, quotes or shell characters. Err: the code of the refusal.
pub fn check_destination(destination: &str) -> Result<(), &'static str> {
    let ok_char = |c: char| c.is_ascii_alphanumeric() || "._-@:%[]/".contains(c);
    if destination.is_empty() || destination.len() > 255 {
        return Err("destination_length");
    }
    if destination.starts_with('-') {
        return Err("destination_option");
    }
    if !destination.chars().all(ok_char) {
        return Err("destination_chars");
    }
    Ok(())
}

pub fn check_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() || name.chars().count() > 40 {
        return Err("name_length");
    }
    if name.chars().any(char::is_control) {
        return Err("name_control");
    }
    Ok(())
}

/// A refusal of the page's `machines` command: a code the page words in its language, and English words.
fn refused(code: &str, name: &str) -> Value {
    let english = match code {
        "name_length" => "a machine's name has 1 to 40 characters".to_string(),
        "name_control" => "a machine's name has no control characters".to_string(),
        "name_taken" => format!("there is a machine named {name} already"),
        "destination_length" => "an SSH destination has 1 to 255 characters".to_string(),
        "destination_option" => "an SSH destination cannot start with -".to_string(),
        "destination_chars" => "an SSH destination has only letters, digits and . _ - @ : % [ ] /".to_string(),
        "unknown_machine" => format!("there is no machine named {name}"),
        other => other.to_string(),
    };
    json!({"code": code, "message": english, "name": name})
}

fn settings_failed(error: String) -> Value {
    json!({"code": "settings", "message": error})
}

/// `ssh <options> -- <destination> <remote>`: the destination and the remote command are single arguments.
pub fn ssh_command(program: &[String], destination: &str, remote: &str) -> Vec<String> {
    let mut args = program.to_vec();
    args.extend(SSH_OPTIONS.iter().chain(SHARING_OFF.iter()).map(|s| s.to_string()));
    args.extend(["--".to_string(), destination.to_string(), remote.to_string()]);
    args
}

/// The remote core: `aqt core --stdio` (or `aqt-toolkit ...`), with `--read-only` when the app has it. The
/// name is one of REMOTE_NAMES; the other machine's shell runs this line as it is.
pub fn remote_core(name: &str, read_only: bool) -> String {
    let name = REMOTE_NAMES.iter().find(|known| **known == name).copied().unwrap_or("aqt");
    format!("{name} core --stdio{}", if read_only { " --read-only" } else { "" })
}

/// The one probe: which of REMOTE_NAMES is AQT's there, in one SSH connection.
pub fn probe_line() -> String {
    REMOTE_NAMES.map(|name| format!("{name} --version")).join(&format!("; echo {MARK}; "))
}

/// What the probe found: the command to use and its version line, or what `aqt` is there instead.
#[derive(Debug, PartialEq)]
pub struct Found {
    pub name: Option<&'static str>,
    pub version: Option<String>,
    pub other: Option<String>,
}

pub fn parse_probe(stdout: &str) -> Found {
    let parts: Vec<&str> = stdout.splitn(REMOTE_NAMES.len(), MARK).collect();
    let version = |text: &str| text.lines().map(str::trim).find(|l| l.starts_with(VERSION_PREFIX)).map(String::from);
    let first = parts.first().copied().unwrap_or_default();
    let other = first.lines().map(str::trim).rfind(|l| !l.is_empty() && !l.starts_with(VERSION_PREFIX));
    let other = other.map(|l| l.chars().take(120).collect());
    match parts.iter().zip(REMOTE_NAMES).find_map(|(part, name)| version(part).map(|v| (name, v))) {
        Some((name, v)) => Found { name: Some(name), version: Some(v), other: other.filter(|_| name != REMOTE_NAMES[0]) },
        None => Found { name: None, version: None, other },
    }
}

// -- what went wrong --------------------------------------------------------------------------------------

/// Why the core of `machine` does not run: from ssh's exit code (255: ssh itself failed) and its last stderr
/// lines. {"kind", "message" (English), "detail", "machine", "destination"}; the page words each kind itself.
pub fn classify(machine: &Machine, code: Option<i32>, stderr: &str, spawn_error: Option<&std::io::Error>) -> Value {
    let dest = &machine.destination;
    let text = stderr.to_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| text.contains(w));
    let ssh_failed = code == Some(255); // ssh's own failures; anything else is the exit code of the remote command
    let (kind, message) = if let Some(error) = spawn_error {
        if error.kind() == std::io::ErrorKind::NotFound {
            ("no_ssh", "this computer has no ssh command: install the OpenSSH client".to_string())
        } else {
            ("no_ssh", format!("could not run ssh: {error}"))
        }
    } else if ssh_failed && has(&["remote host identification has changed", "has changed and you have requested strict"]) {
        ("host_key_changed", format!("the host key of {dest} has changed; check why before you trust it (ssh {dest} shows the details)"))
    } else if ssh_failed && has(&["host key verification failed", "host key is known", "authenticity of host"]) {
        ("host_key", format!("{dest} is not a known host yet: run once in a terminal: ssh {dest}"))
    } else if ssh_failed && has(&["permission denied", "too many authentication failures", "no more authentication methods"]) {
        ("auth", format!("{dest} did not accept your SSH key"))
    } else if ssh_failed && !has(&["kex_exchange_identification"]) && has(&["closed by remote host", "broken pipe", "not responding", "connection reset"]) {
        ("lost", format!("the connection to {} was lost", machine.name))
    } else if ssh_failed {
        ("unreachable", format!("{} cannot be reached", machine.name))
    } else if code == Some(127) {
        ("missing", format!("AQT is not installed on {} (no aqt or aqt-toolkit on the PATH of an SSH command, none in ~/.local/bin)", machine.name))
    } else {
        ("stopped", format!("the AQT core on {} stopped", machine.name))
    };
    let detail: String = stderr.trim().chars().take(600).collect();
    let message = if detail.is_empty() { message } else { format!("{message} ({detail})") };
    json!({"kind": kind, "message": message, "detail": detail, "machine": machine.name, "destination": dest})
}

/// Runs a command (no shell) to its end, or kills it after `timeout` (an error of kind TimedOut):
/// (exit code, stdout, stderr).
fn output(args: &[String], timeout: Duration) -> std::io::Result<(Option<i32>, String, String)> {
    let mut command = Command::new(&args[0]);
    command.args(&args[1..]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    core::no_window(&mut command);
    let mut child = command.spawn()?;
    let take = |mut pipe: Box<dyn Read + Send>| {
        thread::spawn(move || {
            let mut text = String::new();
            let _ = pipe.read_to_string(&mut text);
            text
        })
    };
    let stdout = take(Box::new(child.stdout.take().expect("piped stdout")));
    let stderr = take(Box::new(child.stderr.take().expect("piped stderr")));
    let deadline = Instant::now() + timeout;
    let code = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code(),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, format!("no answer within {} s", timeout.as_secs())));
            }
        }
    };
    Ok((code, stdout.join().unwrap_or_default(), stderr.join().unwrap_or_default()))
}

/// The probe over SSH: Ok with the command name (and the version), or the classified failure.
pub fn probe(machine: &Machine) -> Result<Found, Value> {
    let args = ssh_command(&ssh_from_env(), &machine.destination, &probe_line());
    let (code, stdout, stderr) = match output(&args, PROBE_TIMEOUT) {
        Ok(done) => done,
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
            return Err(classify(machine, Some(255), &format!("{error}: timed out"), None))
        }
        Err(error) => return Err(classify(machine, None, "", Some(&error))),
    };
    if code == Some(255) {
        return Err(classify(machine, code, &stderr, None));
    }
    let found = parse_probe(&stdout);
    if found.name.is_none() {
        let mut why = stderr.trim().to_string();
        if let Some(other) = &found.other {
            why = format!("aqt there is another program: {other}. {why}");
        }
        return Err(classify(machine, Some(127), &format!("{} not found. {why}", REMOTE_NAMES.join(", ")), None));
    }
    Ok(found)
}

// -- who started this app ---------------------------------------------------------------------------------

/// The local core's command with `--mode-check` in place of `--stdio` (and without `--read-only`).
pub fn mode_check_command(local: &[String]) -> Vec<String> {
    let mut command: Vec<String> = local.iter().filter(|a| *a != "--stdio" && *a != "--read-only").cloned().collect();
    command.push("--mode-check".into());
    command
}

/// The guard's verdict as `--mode-check` printed it: a JSON object with a boolean `decisions` on its last line.
pub fn parse_mode(stdout: &str) -> Option<Value> {
    let line = stdout.lines().rev().find(|line| !line.trim().is_empty())?;
    let mode: Value = serde_json::from_str(line).ok()?;
    mode.get("decisions")?.as_bool()?;
    Some(mode)
}

/// No verdict: read-only, with why.
pub fn unchecked(why: &str) -> Value {
    json!({
        "decisions": false, "markers": [], "harness": null, "explicit": false,
        "reason": format!("This app could not check who started it ({why}), so another machine opens read-only."),
    })
}

static LOCAL_MODE: OnceLock<Value> = OnceLock::new();
const MODE_CHECK_TIMEOUT: Duration = Duration::from_secs(30);

/// Whether a person started this app, as the Python guard sees it: `aqt core --mode-check`, run by the app like
/// its local core (the same environment, the app among its ancestors). The remote guard cannot see who started
/// the app, so an app started by an agent opens other machines read-only, and so does an app whose check could
/// not run. Asked once: the start of the app does not change.
fn local_mode(local: &[String]) -> Value {
    LOCAL_MODE
        .get_or_init(|| {
            let mode = match output(&mode_check_command(local), MODE_CHECK_TIMEOUT) {
                Ok((Some(0), stdout, _)) => parse_mode(&stdout).unwrap_or_else(|| unchecked("no answer from aqt core --mode-check")),
                Ok((code, _, stderr)) => unchecked(&format!("aqt core --mode-check: exit {code:?}: {}", stderr.trim().chars().take(200).collect::<String>())),
                Err(error) => unchecked(&format!("aqt core --mode-check: {error}")),
            };
            eprintln!("[aqt desktop] this app was started {}", if allows(&mode) { "by a person" } else { "without a person's check: other machines open read-only" });
            mode
        })
        .clone()
}

fn allows(mode: &Value) -> bool {
    mode.get("decisions") == Some(&Value::Bool(true))
}

/// The core of `machine`: probed before each start (so a failed restart says why), started again once. Read-only
/// when the app is, and when the local guard did not find a person behind the app.
fn remote_launch(machine: Machine, local: Vec<String>, read_only: bool, restarts: u32) -> Launch {
    let (probed, worded) = (machine.clone(), machine);
    Launch {
        command: Box::new(move || {
            let read_only = read_only || !allows(&local_mode(&local));
            let found = probe(&probed)?;
            let remote = remote_core(found.name.unwrap_or("aqt"), read_only);
            Ok(ssh_command(&ssh_from_env(), &probed.destination, &remote))
        }),
        failure: Box::new(move |ended: &Ended| classify(&worded, ended.code, &ended.stderr.join("\n"), ended.spawn_error.as_ref())),
        restarts,
    }
}

// -- the list in the settings -----------------------------------------------------------------------------

pub fn list(app: &AppHandle) -> Vec<Machine> {
    let all = desktop::settings(app);
    let entries = all.get("machines").and_then(Value::as_array).cloned().unwrap_or_default();
    entries
        .iter()
        .filter_map(|m| {
            let name = m.get("name")?.as_str()?.to_string();
            let destination = m.get("destination")?.as_str()?.to_string();
            (check_name(&name).is_ok() && check_destination(&destination).is_ok()).then_some(Machine { name, destination })
        })
        .collect()
}

fn selected(app: &AppHandle) -> Option<Machine> {
    let name = desktop::settings(app).get("machine").and_then(Value::as_str).map(String::from)?;
    list(app).into_iter().find(|m| m.name == name)
}

fn save_list(app: &AppHandle, machines: &[Machine]) -> Result<(), String> {
    let entries: Vec<Value> = machines.iter().map(|m| json!({"name": m.name, "destination": m.destination})).collect();
    desktop::save(app, "machines", Value::Array(entries))
}

// -- the machine the window is on ---------------------------------------------------------------------------

static REMOTE: Mutex<Option<String>> = Mutex::new(None);

/// The name of the other machine the window is on, None on this computer (notifications and the tray name it).
pub fn remote_name() -> Option<String> {
    REMOTE.lock().unwrap().clone()
}

struct Now {
    machine: Option<Machine>,
    core: Arc<Core>,
}

pub struct Machines {
    local: Vec<String>,
    read_only: bool,
    generation: Arc<AtomicU64>,
    now: Mutex<Now>,
}

impl Machines {
    /// The core of the machine chosen last (this computer when none is).
    pub fn start(app: &AppHandle, local: Vec<String>, read_only: bool) -> Machines {
        let machine = selected(app);
        let generation = Arc::new(AtomicU64::new(0));
        let core = launch(app, &generation, &machine, &local, read_only);
        Machines { local, read_only, generation, now: Mutex::new(Now { machine, core }) }
    }

    pub fn core(&self) -> Arc<Core> {
        self.now.lock().unwrap().core.clone()
    }

    pub fn machine(&self) -> Option<Machine> {
        self.now.lock().unwrap().machine.clone()
    }

    /// The core's ready body for the page. On another machine whose core was opened read-only because no person
    /// was found behind this app, `mode` is the local guard's verdict, so the page says why.
    pub fn session(&self, mut body: Value) -> Value {
        if self.machine().is_some() {
            if let Some(local) = LOCAL_MODE.get().filter(|mode| !allows(mode)) {
                body["mode"] = local.clone();
            }
        }
        body
    }

    /// Another machine (or the same again): a new core there; the old one is stopped. Its requests still waiting
    /// fail as sent (their outcome is unknown); nothing is sent again.
    fn connect(&self, app: &AppHandle, machine: Option<Machine>) {
        let mut now = self.now.lock().unwrap();
        let core = launch(app, &self.generation, &machine, &self.local, self.read_only);
        let old = std::mem::replace(&mut *now, Now { machine, core });
        thread::spawn(move || old.core.stop());
        desktop::queue(app, &json!({"count": 0})); // not the count of the machine before; the new core's first event sets it
    }
}

fn launch(app: &AppHandle, generation: &Arc<AtomicU64>, machine: &Option<Machine>, local: &[String], read_only: bool) -> Arc<Core> {
    let mine = generation.fetch_add(1, Ordering::SeqCst) + 1;
    *REMOTE.lock().unwrap() = machine.as_ref().map(|m| m.name.clone());
    let (events, current) = (app.clone(), generation.clone());
    let on_event = move |event: &str, body: &Value| {
        if current.load(Ordering::SeqCst) != mine {
            return; // a core of the machine before
        }
        match event {
            "queue" => desktop::queue(&events, body),
            "connection" => tell_page(&events, body),
            _ => {}
        }
    };
    match machine {
        None => Core::start(Launch::local(local.to_vec()), on_event),
        Some(machine) => {
            eprintln!("[aqt desktop] machine {} ({})", machine.name, machine.destination);
            Core::start(remote_launch(machine.clone(), local.to_vec(), read_only, 1), on_event)
        }
    }
}

/// The page learns of each change of the connection (`window.aqtConnection`): grey out, reconnect, unknown outcome.
fn tell_page(app: &AppHandle, body: &Value) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.eval(format!("window.aqtConnection && window.aqtConnection({body})"));
    }
}

fn view(app: &AppHandle, machines: &Machines) -> Value {
    let now = machines.now.lock().unwrap();
    json!({
        "machines": list(app).iter().map(|m| json!({"name": m.name, "destination": m.destination})).collect::<Vec<_>>(),
        "current": now.machine.as_ref().map(|m| json!({"name": m.name, "destination": m.destination})),
        "state": now.core.status(),
    })
}

/// "Test connection": the probe, then a core started there until its ready event (version and mode), then stopped.
async fn test(machine: Machine, local: Vec<String>, read_only: bool) -> Value {
    let probed = machine.clone();
    let checked = tauri::async_runtime::spawn_blocking(move || {
        let local = if read_only { None } else { Some(local_mode(&local)) };
        probe(&probed).map(|found| (found, local))
    });
    let (found, local) = match checked.await {
        Ok(Ok(found)) => found,
        Ok(Err(failure)) => return json!({"ok": false, "failure": failure}),
        Err(error) => return json!({"ok": false, "failure": {"kind": "stopped", "message": error.to_string()}}),
    };
    let local = local.filter(|mode| !allows(mode));
    let read_only = read_only || local.is_some();
    let name = found.name.unwrap_or("aqt");
    let remote = remote_core(name, read_only);
    let args = ssh_command(&ssh_from_env(), &machine.destination, &remote);
    let worded = machine.clone();
    let launch = Launch {
        command: Box::new(move || Ok(args.clone())),
        failure: Box::new(move |ended: &Ended| classify(&worded, ended.code, &ended.stderr.join("\n"), ended.spawn_error.as_ref())),
        restarts: 0,
    };
    let core = Core::start(launch, |_, _| {});
    let ready = core.ready().await;
    let stopped = core.clone();
    let _ = tauri::async_runtime::spawn_blocking(move || stopped.stop()).await;
    match ready {
        Ok(body) => json!({"ok": true, "version": body.get("version"), "mode": local.or(body.get("mode").cloned()), "command": name}),
        Err(_) => json!({"ok": false, "failure": core.status().get("failure").cloned().unwrap_or(Value::Null)}),
    }
}

/// The machines for the page's Settings and its machine indicator: {machines, current, state}. `change` may
/// `add` {name, destination}, `remove` a name, `select` a name (null: this computer), `reconnect` (true), or
/// `test` a name: the answer then carries `test` {ok, version, mode, command} or {ok: false, failure}.
/// A refusal is {code, message, name}: the page words the code in its language.
#[tauri::command]
pub async fn machines(app: AppHandle, machines: State<'_, Machines>, change: Option<Value>) -> Result<Value, Value> {
    let change = change.unwrap_or(Value::Null);
    let mut tested = None;
    let find = |name: &str| list(&app).into_iter().find(|m| m.name == name).ok_or_else(|| refused("unknown_machine", name));
    if let Some(add) = change.get("add") {
        let field = |key: &str| add.get(key).and_then(Value::as_str).map(str::trim).unwrap_or_default().to_string();
        let machine = Machine { name: field("name"), destination: field("destination") };
        check_name(&machine.name).map_err(|code| refused(code, &machine.name))?;
        check_destination(&machine.destination).map_err(|code| refused(code, &machine.name))?;
        let mut all = list(&app);
        if all.iter().any(|m| m.name.to_lowercase() == machine.name.to_lowercase()) {
            return Err(refused("name_taken", &machine.name));
        }
        all.push(machine);
        save_list(&app, &all).map_err(settings_failed)?;
    }
    if let Some(name) = change.get("remove").and_then(Value::as_str) {
        let mut all = list(&app);
        all.retain(|m| m.name != name);
        save_list(&app, &all).map_err(settings_failed)?;
        if machines.machine().is_some_and(|m| m.name == name) {
            desktop::save(&app, "machine", Value::Null).map_err(settings_failed)?;
            machines.connect(&app, None);
        }
    }
    if let Some(choice) = change.get("select") {
        let machine = match choice.as_str() {
            Some(name) => Some(find(name)?),
            None => None,
        };
        desktop::save(&app, "machine", choice.as_str().map_or(Value::Null, |n| Value::String(n.into()))).map_err(settings_failed)?;
        machines.connect(&app, machine);
    }
    if change.get("reconnect") == Some(&Value::Bool(true)) {
        machines.connect(&app, machines.machine());
    }
    if let Some(name) = change.get("test").and_then(Value::as_str) {
        tested = Some(test(find(name)?, machines.local.clone(), machines.read_only).await);
    }
    let mut answer = view(&app, &machines);
    if let Some(tested) = tested {
        answer["test"] = tested;
    }
    Ok(answer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine() -> Machine {
        Machine { name: "server".into(), destination: "me@server".into() }
    }

    #[test]
    fn the_destination_and_the_remote_command_are_single_arguments_after_the_options() {
        let args = ssh_command(&["ssh".into()], "me@server", &remote_core("aqt", false));
        assert_eq!(args[0], "ssh");
        let end = args.len();
        assert_eq!(args[end - 3..], ["--", "me@server", "aqt core --stdio"]);
        assert!(args.windows(2).any(|w| w == ["-o", "BatchMode=yes"]));
        assert!(!args.iter().any(|a| a.contains("StrictHostKeyChecking")), "host keys are checked as the user's ssh does");
        // everything before "--" is ours: the user's text comes only after it
        let options = &args[1..end - 3];
        assert!(options.iter().all(|a| SSH_OPTIONS.contains(&a.as_str()) || SHARING_OFF.contains(&a.as_str())));
    }

    #[test]
    fn the_remote_command_is_a_fixed_line() {
        assert_eq!(remote_core("aqt", false), "aqt core --stdio");
        assert_eq!(remote_core("aqt-toolkit", true), "aqt-toolkit core --stdio --read-only");
        assert_eq!(remote_core("~/.local/bin/aqt-toolkit", false), "~/.local/bin/aqt-toolkit core --stdio");
        assert_eq!(remote_core("aqt; rm -rf ~", false), "aqt core --stdio", "only a known name is used");
        assert_eq!(
            probe_line(),
            "aqt --version; echo @@aqt-probe@@; aqt-toolkit --version; echo @@aqt-probe@@; ~/.local/bin/aqt-toolkit --version"
        );
    }

    #[test]
    fn the_ssh_program_can_be_set_like_aqt_core() {
        assert_eq!(ssh_program(None), ["ssh"]);
        assert_eq!(ssh_program(Some("  ")), ["ssh"]);
        assert_eq!(ssh_program(Some("ssh -F /tmp/test config")), ["ssh", "-F", "/tmp/test", "config"]);
        let args = ssh_command(&ssh_program(Some("ssh -F /x/cfg")), "box", "aqt core --stdio");
        assert_eq!(args[..3], ["ssh", "-F", "/x/cfg"]);
    }

    #[test]
    fn destinations_are_hosts_never_options_or_shell_text() {
        for good in ["server", "me@server", "me@10.0.0.7", "srv-01.example.org", "ssh://me@server:2222", "me@[fe80::1%eth0]", "my_alias"] {
            assert!(check_destination(good).is_ok(), "{good}");
        }
        for bad in [
            "", "-oProxyCommand=touch /tmp/x", "-p", "me@server; rm -rf ~", "me@server && x", "a b", "$(id)", "`id`",
            "host|cat", "'host'", "\"host\"", "host\n", "host\\x", "~/x", "host>x", "x".repeat(256).as_str(),
        ] {
            assert!(check_destination(bad).is_err(), "{bad:?}");
        }
        assert_eq!(check_destination("-p"), Err("destination_option"));
        assert_eq!(check_destination("a b"), Err("destination_chars"));
        assert_eq!(refused("name_taken", "Build")["message"], "there is a machine named Build already");
        assert!(check_name("Build server").is_ok());
        assert!(check_name("").is_err() && check_name("a\u{7}b").is_err() && check_name(&"n".repeat(41)).is_err());
    }

    #[test]
    fn the_probe_tells_which_command_is_aqts() {
        let ours = "agent-quality-toolkit 0.2.0 (commands aqt and aqt-toolkit)";
        let found = parse_probe(&format!("{ours}\n{MARK}\n{ours}\n"));
        assert_eq!((found.name, found.version.as_deref()), (Some("aqt"), Some(ours)));
        let other = parse_probe(&format!("aqtinstall(aqt) v3.1.21 on Python 3.12\n{MARK}\n{ours}\n"));
        assert_eq!(other.name, Some("aqt-toolkit"));
        assert_eq!(other.other.as_deref(), Some("aqtinstall(aqt) v3.1.21 on Python 3.12"));
        let home = parse_probe(&format!("{MARK}\n{MARK}\n{ours}\n"));
        assert_eq!(home.name, Some("~/.local/bin/aqt-toolkit"), "installed, but not on the PATH of an SSH command");
        let none = parse_probe(&format!("{MARK}\n{MARK}\n"));
        assert_eq!((none.name, none.other), (None, None));
        let rc_noise = parse_probe(&format!("welcome from .bashrc\n{ours}\n{MARK}\n"));
        assert_eq!(rc_noise.name, Some("aqt"));
    }

    #[test]
    fn the_local_guard_decides_and_no_answer_is_read_only() {
        let local = ["/opt/aqt/aqt".to_string(), "core".into(), "--stdio".into(), "--read-only".into()];
        assert_eq!(mode_check_command(&local), ["/opt/aqt/aqt", "core", "--mode-check"]);
        let person = parse_mode("aqt core: noise\n{\"decisions\": true, \"reason\": \"\", \"markers\": []}\n").unwrap();
        assert!(allows(&person));
        let agent = parse_mode(r#"{"decisions": false, "reason": "Started inside claude-code", "markers": ["env:CLAUDECODE"]}"#).unwrap();
        assert!(!allows(&agent));
        for nothing in ["", "not json", r#"{"decisions": "yes"}"#, "[true]"] {
            assert_eq!(parse_mode(nothing), None, "{nothing}");
        }
        let failed = unchecked("aqt core --mode-check: No such file or directory");
        assert!(!allows(&failed) && failed["reason"].as_str().unwrap().contains("read-only"));
    }

    #[test]
    fn ssh_failures_have_a_kind() {
        let kind = |code, stderr: &str| classify(&machine(), code, stderr, None)["kind"].as_str().unwrap().to_string();
        assert_eq!(kind(Some(255), "No ED25519 host key is known for [127.0.0.1]:2222 and you have requested strict checking.\nHost key verification failed."), "host_key");
        assert_eq!(kind(Some(255), "@@@@@@@\n@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\nHost key verification failed."), "host_key_changed");
        assert_eq!(kind(Some(255), "me@server: Permission denied (publickey)."), "auth");
        assert_eq!(kind(Some(255), "ssh: connect to host server port 22: Connection refused"), "unreachable");
        assert_eq!(kind(Some(255), "ssh: Could not resolve hostname nowhere: Name or service not known"), "unreachable");
        assert_eq!(kind(Some(255), "Connection to server closed by remote host."), "lost");
        assert_eq!(kind(Some(255), "Timeout, server server not responding."), "lost");
        assert_eq!(kind(Some(255), "kex_exchange_identification: Connection closed by remote host"), "unreachable");
        assert_eq!(kind(Some(255), "ssh: connect to host server port 22: Connection timed out"), "unreachable");
        assert_eq!(kind(Some(127), "bash: line 1: aqt: command not found"), "missing");
        assert_eq!(kind(Some(1), "Traceback ...\nValueError: bad"), "stopped");
        assert_eq!(kind(Some(1), "PermissionError: [Errno 13] Permission denied: '/x'"), "stopped", "the remote core's own error");
        let missing = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert_eq!(classify(&machine(), None, "", Some(&missing))["kind"], "no_ssh");
        let host_key = classify(&machine(), Some(255), "Host key verification failed.", None);
        assert!(host_key["message"].as_str().unwrap().contains("ssh me@server"), "{host_key}");
        assert_eq!(host_key["detail"], "Host key verification failed.");
    }
}
