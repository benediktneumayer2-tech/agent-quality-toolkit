//! The app in the operating system: the tray (menu-bar) icon with the number of open cases, one notification
//! per new case, `aqt://` links, the app's own settings (keep running in the tray, start at login) and the
//! `aqt` command of the AppImage and of the macOS app. Links and notifications only open a view; they never
//! decide anything.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, WebviewWindow, Wry};
use tauri_plugin_autostart::ManagerExt;

#[cfg(not(target_os = "macos"))]
pub const SCHEME: &str = "aqt"; // macOS: the app bundle declares the scheme
pub const COMMAND_NAMES: [&str; 2] = ["aqt", "aqt-toolkit"]; // the toolkit's command and its second name
const TRAY: &str = "main";
const SUMMARY_FROM: usize = 4; // this many new cases at once: one notification for all of them

static COUNT: AtomicU64 = AtomicU64::new(0); // the last count, for a tray made after the first queue event
static PAGE_READY: AtomicBool = AtomicBool::new(false);
static PENDING: Mutex<Option<String>> = Mutex::new(None); // a view to open once the page has loaded
static QUEUE_SEQ: AtomicU64 = AtomicU64::new(0);
static UNANNOUNCED: Mutex<Option<HashMap<u64, Vec<Value>>>> = Mutex::new(None); // new cases waiting for words
const WORDS_WAIT: Duration = Duration::from_secs(3); // how long the page may take to word the notifications

/// The tray menu's "Needs you (n)" entry, kept to update its text.
struct NeedsItem(MenuItem<Wry>);

// -- views ------------------------------------------------------------------------------------------------

/// The page path of an `aqt://` link: `aqt://case/<id>` and `aqt://change/<project>/<plan>`, with the
/// character rules of the page itself (`app.js`); anything else is None.
pub fn link_path(link: &str) -> Option<String> {
    let rest = link.strip_prefix("aqt://")?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let (kind, rest) = rest.split_once('/')?;
    let word = |text: &str, extra: &str, max: usize| {
        (1..=max).contains(&text.len())
            && text.chars().all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
            && text != "."
            && text != ".."
    };
    match kind {
        "case" if word(rest, "._:@+-", 200) && !rest.split(':').any(|part| part == "." || part == "..") => {
            Some(format!("/case/{rest}"))
        }
        "change" => {
            let (project, plan) = rest.split_once('/')?;
            let project_ok = (1..=4).contains(&project.len()) && project.chars().all(|c| c.is_ascii_digit());
            (project_ok && word(plan, "._-", 200)).then(|| format!("/change/{project}/{plan}"))
        }
        _ => None,
    }
}

/// An `aqt://` link from the system (a click, `aqt open`, a second start of the app).
pub fn open_link(app: &AppHandle, link: &str) {
    match link_path(link) {
        Some(path) => open_view(app, &path, "link"),
        None => eprintln!("[aqt desktop] ignored the link {link:.120}: not a case or change view"),
    }
}

/// Bring the window to the front.
pub fn show(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// Show the window at `path` through the page's own router (history and popstate): the page keeps its
/// state and no request is made for it. Before the page has loaded, the path waits for it.
pub fn open_view(app: &AppHandle, path: &str, source: &str) {
    eprintln!("[aqt desktop] open {path} ({source})");
    show(app);
    if !PAGE_READY.load(Ordering::SeqCst) {
        *PENDING.lock().unwrap() = Some(path.to_string());
        return;
    }
    if let Some(window) = app.get_webview_window("main") {
        route(&window, path);
    }
}

/// The window's page has loaded: open the view that waited for it.
pub fn page_loaded(window: &WebviewWindow) {
    PAGE_READY.store(true, Ordering::SeqCst);
    if let Some(path) = PENDING.lock().unwrap().take() {
        route(window, &path);
    }
}

fn route(window: &WebviewWindow, path: &str) {
    let path = Value::String(path.to_string()); // a JSON string is a JavaScript string literal
    let script = format!("history.pushState(null, '', {path}); dispatchEvent(new PopStateEvent('popstate'));");
    if let Err(error) = window.eval(script) {
        eprintln!("[aqt desktop] could not open {path}: {error}");
    }
}

// -- tray -------------------------------------------------------------------------------------------------

/// Whether the desktop can show a tray icon now: always on macOS and Windows; on Linux only while a
/// StatusNotifierWatcher runs on the session bus (KDE, Xfce, GNOME with the AppIndicator extension, ...).
/// Without one the icon would show nowhere, so the app must not keep running without its window.
#[cfg(target_os = "linux")]
pub fn tray_host() -> bool {
    let Ok(bus) = zbus::blocking::Connection::session() else { return false };
    let Ok(dbus) = zbus::blocking::fdo::DBusProxy::new(&bus) else { return false };
    let Ok(name) = zbus::names::BusName::try_from("org.kde.StatusNotifierWatcher") else { return false };
    dbus.name_has_owner(name).unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
pub fn tray_host() -> bool {
    true
}

/// `tray_host`, waiting up to `seconds` for it (at login the panel may start after the app).
pub fn wait_for_tray_host(seconds: u64) -> bool {
    for _ in 0..seconds * 2 {
        if tray_host() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    tray_host()
}

/// The tray icon and its menu: Open, Needs you (n), Quit. A left click opens the window where the system
/// reports clicks (Windows, macOS); on Linux the menu is the only way.
pub fn create_tray(app: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open", true, None::<&str>)?;
    let needs = MenuItem::with_id(app, "needs", "Needs you", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &needs, &PredefinedMenuItem::separator(app)?, &quit])?;
    let mut tray = TrayIconBuilder::with_id(TRAY)
        .menu(&menu)
        .tooltip("Agent Quality Toolkit")
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show(app),
            "needs" => open_view(app, "/", "tray"),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                show(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;
    app.manage(NeedsItem(needs));
    set_count(app, COUNT.load(Ordering::SeqCst));
    Ok(())
}

/// Closing the window keeps the app in the tray, unless the setting says to quit or no tray icon shows.
pub fn keep_running(app: &AppHandle) -> bool {
    app.tray_by_id(TRAY).is_some() && close_to_tray(app) && tray_host()
}

fn set_count(app: &AppHandle, count: u64) {
    COUNT.store(count, Ordering::SeqCst);
    if let Some(tray) = app.tray_by_id(TRAY) {
        // the title is the label beside the icon on Linux and the text in the macOS menu bar
        let _ = tray.set_title((count > 0).then(|| count.to_string()));
        let _ = tray.set_tooltip(Some(format!("Agent Quality Toolkit: {count} open case(s)")));
    }
    if let Some(item) = app.try_state::<NeedsItem>() {
        let _ = item.0.set_text(format!("Needs you ({count})"));
    }
}

// -- the queue event and notifications -----------------------------------------------------------------

/// The core's `queue` event: the count for the tray, a notification per new case (one for all of them
/// when many come at once). The first event after a (re)start has no new cases, so nothing is announced.
/// The page words the notifications in its language (`window.aqtQueue`, answered by `show_notifications`);
/// before the page has loaded, or when it does not answer within a few seconds, the core's English is used.
pub fn queue(app: &AppHandle, body: &Value) {
    let count = body.get("count").and_then(Value::as_u64).unwrap_or(0);
    let new = body.get("new").and_then(Value::as_array).cloned().unwrap_or_default();
    eprintln!("[aqt desktop] needs you: {count} open, {} new", new.len());
    set_count(app, count);
    if new.is_empty() {
        return;
    }
    let seq = QUEUE_SEQ.fetch_add(1, Ordering::SeqCst) + 1;
    UNANNOUNCED.lock().unwrap().get_or_insert_with(HashMap::new).insert(seq, new);
    let window = app.get_webview_window("main").filter(|_| PAGE_READY.load(Ordering::SeqCst));
    let asked = window.is_some_and(|window| {
        let script = format!("window.aqtQueue && window.aqtQueue({seq}, {body})");
        window.eval(script).is_ok()
    });
    let app = app.clone();
    std::thread::spawn(move || {
        if asked {
            std::thread::sleep(WORDS_WAIT);
        }
        if let Some(new) = take_unannounced(seq) {
            eprintln!("[aqt desktop] notifications in English: {}", if asked { "the page did not answer" } else { "no page yet" });
            announce(&app, &new, &Value::Null);
        }
    });
}

fn take_unannounced(seq: u64) -> Option<Vec<Value>> {
    UNANNOUNCED.lock().unwrap().as_mut().and_then(|waiting| waiting.remove(&seq))
}

/// The page's words for the notifications of queue event `seq`: `{"cases": {"<id>": "<title>"}, "many":
/// "<n new cases>", "review": "<body line>", "show": "<button>"}`. Too late (English shown already): ignored.
#[tauri::command]
pub fn show_notifications(app: AppHandle, seq: u64, words: Value) {
    if let Some(new) = take_unannounced(seq) {
        eprintln!("[aqt desktop] notifications in the page's words");
        announce(&app, &new, &words);
    }
}

fn announce(app: &AppHandle, new: &[Value], words: &Value) {
    let word = |value: Option<&Value>, english: &str| -> String {
        let text = value.and_then(Value::as_str).filter(|text| !text.trim().is_empty()).unwrap_or(english);
        text.chars().take(300).collect()
    };
    let review = word(words.get("review"), "Review it in Agent Quality Toolkit");
    let show = word(words.get("show"), "Show the case");
    if new.len() >= SUMMARY_FROM {
        let many = word(words.get("many"), &format!("{} new cases need you", new.len()));
        notify(app, &many, &review, &show, "/");
        return;
    }
    for case in new {
        let id = case.get("id").and_then(Value::as_str).unwrap_or_default();
        let english = case.get("title").and_then(Value::as_str).unwrap_or("A new case needs you");
        let title = word(words.get("cases").and_then(|cases| cases.get(id)), english);
        let path = link_path(&format!("aqt://case/{id}")).unwrap_or_else(|| "/".into());
        notify(app, &title, &review, &show, &path);
    }
}

/// One system notification; a click on it opens `path` where the platform reports the click.
fn notify(app: &AppHandle, title: &str, body: &str, button: &str, path: &str) {
    #[cfg(target_os = "macos")]
    {
        static NAMED: std::sync::Once = std::sync::Once::new(); // notifications in this app's name, not Terminal's
        NAMED.call_once(|| {
            let _ = notify_rust::set_application(&app.config().identifier);
        });
    }
    let mut note = notify_rust::Notification::new();
    note.summary(title).body(body).appname("Agent Quality Toolkit");
    #[cfg(target_os = "linux")]
    note.icon("aqt-desktop").action("default", button);
    #[cfg(not(target_os = "linux"))]
    let _ = button;
    #[cfg(target_os = "windows")]
    note.app_id(&app.config().identifier);
    match note.show() {
        #[cfg(not(target_os = "macos"))]
        Ok(shown) => {
            let (app, path) = (app.clone(), path.to_string());
            std::thread::spawn(move || {
                shown.wait_for_action(|action| {
                    if action != "__closed" {
                        open_view(&app, &path, "notification");
                    }
                })
            });
        }
        #[cfg(target_os = "macos")]
        Ok(_) => {
            let _ = (app, path); // a click brings the app to the front; it does not open the case (see the README)
        }
        Err(error) => eprintln!("[aqt desktop] could not show a notification: {error}"),
    }
}

// -- settings ---------------------------------------------------------------------------------------------

fn settings_file(app: &AppHandle) -> Option<PathBuf> {
    app.path().app_config_dir().ok().map(|dir| dir.join("desktop.json"))
}

fn settings(app: &AppHandle) -> Value {
    settings_file(app)
        .and_then(|file| std::fs::read_to_string(file).ok())
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}))
}

fn close_to_tray(app: &AppHandle) -> bool {
    settings(app).get("close_to_tray").and_then(Value::as_bool).unwrap_or(true)
}

fn save(app: &AppHandle, key: &str, value: Value) -> Result<(), String> {
    let file = settings_file(app).ok_or("no folder for the app's settings")?;
    let mut all = settings(app);
    all[key] = value;
    std::fs::create_dir_all(file.parent().unwrap()).map_err(|e| e.to_string())?;
    std::fs::write(&file, serde_json::to_vec_pretty(&all).unwrap()).map_err(|e| format!("{}: {e}", file.display()))
}

/// The app's own settings and what it set up in the system, for the page's Settings. `change` may set
/// `close_to_tray` and `autostart` (true or false), and ask for `aqt_command: true` (the AppImage's
/// `~/.local/bin/aqt`, the macOS app's `/usr/local/bin/aqt`) or `links: true` (register `aqt://` for the AppImage).
/// `aqt_command` is null where there is nothing to install (the .deb has `/usr/bin/aqt`). Async, so that the D-Bus
/// and `xdg-mime` calls run off the main thread.
#[tauri::command]
pub async fn desktop_settings(app: AppHandle, change: Option<Value>) -> Result<Value, String> {
    let change = change.unwrap_or(Value::Null);
    if let Some(on) = change.get("close_to_tray").and_then(Value::as_bool) {
        save(&app, "close_to_tray", on.into())?;
    }
    if let Some(on) = change.get("autostart").and_then(Value::as_bool) {
        let launcher = app.autolaunch();
        if launcher.is_enabled().unwrap_or(!on) != on {
            if on { launcher.enable() } else { launcher.disable() }.map_err(|e| format!("start at login: {e}"))?;
        }
    }
    if change.get("aqt_command") == Some(&Value::Bool(true)) {
        install_command(&app)?;
    }
    if change.get("links") == Some(&Value::Bool(true)) {
        register_links(&app)?;
    }
    let appimage = std::env::var("APPIMAGE").ok();
    Ok(json!({
        "close_to_tray": close_to_tray(&app),
        "tray": app.tray_by_id(TRAY).is_some() && tray_host(),
        "autostart": app.autolaunch().is_enabled().unwrap_or(false),
        "appimage": appimage,
        "aqt_command": command_links(&app).map(|links| links.iter().any(|(_, ours)| *ours)),
        "aqt_command_folder": COMMAND_FOLDER,
        "links": appimage.is_none() || links_registered(&app),
    }))
}

/// Where the `aqt` command's links go: `~/.local/bin` for the AppImage, `/usr/local/bin` for the macOS app (on
/// the PATH of every macOS shell, so agents' hooks find it there).
#[cfg(not(target_os = "macos"))]
const COMMAND_FOLDER: &str = "~/.local/bin";
#[cfg(target_os = "macos")]
const COMMAND_FOLDER: &str = "/usr/local/bin";

/// `~/.local/bin/aqt` and `~/.local/bin/aqt-toolkit` (the second name, for systems where another aqt comes
/// first on PATH), each with whether it is a link to this AppImage.
#[cfg(not(target_os = "macos"))]
fn command_links(app: &AppHandle) -> Option<Vec<(PathBuf, bool)>> {
    let dir = app.path().home_dir().ok()?.join(".local").join("bin");
    let image = std::env::var_os("APPIMAGE")?;
    Some(
        COMMAND_NAMES
            .iter()
            .map(|name| {
                let link = dir.join(name);
                let ours = std::fs::read_link(&link).is_ok_and(|target| target.as_os_str() == image);
                (link, ours)
            })
            .collect(),
    )
}

/// The AppImage's `aqt` command: links `~/.local/bin/aqt` and `~/.local/bin/aqt-toolkit` to the AppImage file,
/// which runs the bundled `aqt` when it is called by either name. Another program under one of these names
/// (an `aqt` from pip or uv, or aqtinstall's) is never replaced; it fails only when neither name is free.
#[cfg(not(target_os = "macos"))]
fn install_command(app: &AppHandle) -> Result<(), String> {
    let links = command_links(app).ok_or("only the AppImage needs this: the .deb package installs /usr/bin/aqt")?;
    let mut taken = Vec::new();
    for (link, ours) in &links {
        if *ours {
            continue;
        }
        if link.symlink_metadata().is_ok() {
            taken.push(link.display().to_string());
            continue;
        }
        #[cfg(unix)]
        {
            std::fs::create_dir_all(link.parent().unwrap()).map_err(|e| e.to_string())?;
            std::os::unix::fs::symlink(std::env::var_os("APPIMAGE").unwrap(), link)
                .map_err(|e| format!("{}: {e}", link.display()))?;
        }
        #[cfg(not(unix))]
        return Err("not on this system".into());
    }
    if taken.len() == links.len() {
        return Err(format!(
            "{} exist already (other programs, e.g. an aqt from pip or uv); remove one first if agents should run this app's aqt",
            taken.join(" and ")
        ));
    }
    Ok(())
}

// -- macOS: the aqt command in /usr/local/bin, as an editor installs its command ---------------------------------

/// The runtime inside the app bundle (`Contents/Resources/runtime/aqt/aqt`), which the links name.
#[cfg(target_os = "macos")]
fn bundled_runtime(app: &AppHandle) -> Option<PathBuf> {
    let runtime = app.path().resource_dir().ok()?.join("runtime").join("aqt").join("aqt");
    runtime.is_file().then_some(runtime)
}

/// `/usr/local/bin/aqt` and `/usr/local/bin/aqt-toolkit`, each with whether it is a link to this app's runtime.
#[cfg(target_os = "macos")]
fn command_links(app: &AppHandle) -> Option<Vec<(PathBuf, bool)>> {
    let runtime = bundled_runtime(app)?;
    Some(
        COMMAND_NAMES
            .iter()
            .map(|name| {
                let link = PathBuf::from(COMMAND_FOLDER).join(name);
                let ours = std::fs::read_link(&link).is_ok_and(|target| target == runtime);
                (link, ours)
            })
            .collect(),
    )
}

/// A link to the runtime of an AQT app bundle that is no longer this one (an older copy, or the app moved):
/// it may be replaced. Anything else under the name (another program, an aqt from pip or uv) never is.
#[cfg(target_os = "macos")]
fn stale_app_link(link: &std::path::Path) -> bool {
    std::fs::read_link(link).is_ok_and(|target| target.ends_with("Contents/Resources/runtime/aqt/aqt"))
}

/// The shell command (run as administrator) that links each name to `runtime`: `ln -s` for a free name, which
/// fails rather than replace something that appeared since; `ln -sfn` only for a stale link to an AQT app.
#[cfg(any(target_os = "macos", test))]
fn link_script(folder: &str, runtime: &str, free: &[String], stale: &[String]) -> String {
    let quote = |text: &str| format!("'{}'", text.replace('\'', "'\\''"));
    let mut parts = vec![format!("mkdir -p {}", quote(folder))];
    parts.extend(free.iter().map(|link| format!("ln -s {} {}", quote(runtime), quote(link))));
    parts.extend(stale.iter().map(|link| format!("ln -sfn {} {}", quote(runtime), quote(link))));
    parts.join(" && ")
}

/// A string literal of AppleScript.
#[cfg(any(target_os = "macos", test))]
fn applescript_string(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The macOS app's `aqt` command: links `/usr/local/bin/aqt` and `/usr/local/bin/aqt-toolkit` to the runtime in
/// the app, through macOS's administrator prompt (`/usr/local/bin` belongs to an administrator). A name taken by
/// another program is never replaced; it fails only when neither name can be linked.
#[cfg(target_os = "macos")]
fn install_command(app: &AppHandle) -> Result<(), String> {
    let runtime = bundled_runtime(app).ok_or("this app has no bundled aqt runtime")?;
    let (mut free, mut stale, mut taken) = (Vec::new(), Vec::new(), Vec::new());
    for (link, ours) in command_links(app).unwrap_or_default() {
        let text = link.display().to_string();
        if ours {
            continue;
        } else if link.symlink_metadata().is_err() {
            free.push(text);
        } else if stale_app_link(&link) {
            stale.push(text);
        } else {
            taken.push(text);
        }
    }
    if taken.len() == COMMAND_NAMES.len() {
        return Err(format!(
            "{} exist already (other programs); remove one first if agents should run this app's aqt",
            taken.join(" and ")
        ));
    }
    if free.is_empty() && stale.is_empty() {
        return Ok(());
    }
    let script = format!(
        "do shell script {} with prompt {} with administrator privileges",
        applescript_string(&link_script(COMMAND_FOLDER, &runtime.display().to_string(), &free, &stale)),
        applescript_string("Agent Quality Toolkit wants to link its aqt command into /usr/local/bin, so that agents and terminals find it.")
    );
    let done = std::process::Command::new("/usr/bin/osascript").arg("-e").arg(&script).output().map_err(|e| e.to_string())?;
    if done.status.success() {
        return Ok(());
    }
    let why = String::from_utf8_lossy(&done.stderr);
    Err(if why.contains("-128") {
        "not installed: the administrator prompt was cancelled".into()
    } else {
        format!("could not link the aqt command: {}", why.trim())
    })
}

#[cfg(any(target_os = "linux", windows))]
fn register_links(app: &AppHandle) -> Result<(), String> {
    use tauri_plugin_deep_link::DeepLinkExt;
    app.deep_link().register(SCHEME).map_err(|e| format!("could not register {SCHEME}:// links: {e}"))
}

#[cfg(not(any(target_os = "linux", windows)))]
fn register_links(_app: &AppHandle) -> Result<(), String> {
    Ok(()) // macOS: the app bundle declares the scheme
}

#[cfg(any(target_os = "linux", windows))]
fn links_registered(app: &AppHandle) -> bool {
    use tauri_plugin_deep_link::DeepLinkExt;
    app.deep_link().is_registered(SCHEME).unwrap_or(false)
}

#[cfg(not(any(target_os = "linux", windows)))]
fn links_registered(_app: &AppHandle) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::{applescript_string, link_path, link_script};

    #[test]
    fn the_macos_link_script_quotes_paths_and_replaces_only_stale_links() {
        let runtime = "/Applications/Agent Quality Toolkit.app/Contents/Resources/runtime/aqt/aqt";
        let script = link_script("/usr/local/bin", runtime, &["/usr/local/bin/aqt".into()], &["/usr/local/bin/it's".into()]);
        assert_eq!(
            script,
            "mkdir -p '/usr/local/bin' && ln -s '/Applications/Agent Quality Toolkit.app/Contents/Resources/runtime/aqt/aqt' \
             '/usr/local/bin/aqt' && ln -sfn '/Applications/Agent Quality Toolkit.app/Contents/Resources/runtime/aqt/aqt' \
             '/usr/local/bin/it'\\''s'"
        );
        assert_eq!(applescript_string(r#"say "hi" \ there"#), r#""say \"hi\" \\ there""#);
    }

    #[test]
    fn links_open_case_and_change_views_only() {
        assert_eq!(link_path("aqt://case/quarantine:Q7SEGGW").as_deref(), Some("/case/quarantine:Q7SEGGW"));
        assert_eq!(link_path("aqt://case/plan:0:s01/").as_deref(), Some("/case/plan:0:s01"));
        assert_eq!(link_path("aqt://change/0/api-v2").as_deref(), Some("/change/0/api-v2"));
        for bad in [
            "aqt://case/../x", "aqt://case/a:..:b", "aqt://case/a?x=1", "aqt://case/", "aqt://case/a/b",
            "aqt://change/x/a", "aqt://change/0/..", "aqt://change/0/a/b", "aqt://other/x", "https://x/case/a",
            "aqt://case/<script>", "aqt://case/a%2Fb",
        ] {
            assert_eq!(link_path(bad), None, "{bad}");
        }
    }
}
