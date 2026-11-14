// Agent Quality Toolkit desktop app: one window with the aqt-ui pages; the AQT core runs as a child process
// and answers the page's API requests over JSON lines. No web server, no port.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod core;
mod desktop;
mod machines;

use std::path::Path;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use base64::Engine;
use serde_json::{json, Value};
use tauri::webview::{NewWindowResponse, PageLoadEvent};
use tauri::{AppHandle, Manager, RunEvent, State, Url, WebviewUrl, WebviewWindowBuilder, WindowEvent};
use tauri_plugin_deep_link::DeepLinkExt;
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_opener::OpenerExt;

use crate::machines::Machines;

static STARTED: OnceLock<Instant> = OnceLock::new();
static PAGE_LOADED: OnceLock<u128> = OnceLock::new(); // ms after start: the window's page has loaded
static PAGE_ANSWERED: OnceLock<u128> = OnceLock::new(); // ms after start: first answer to a page request

fn ms() -> u128 {
    STARTED.get().map_or(0, |t| t.elapsed().as_millis())
}

/// The core command: the runtime shipped with the app; else AQT_CORE (a command line, split on spaces);
/// else `aqt core --stdio` from PATH.
fn core_command(app: &AppHandle, read_only: bool) -> Vec<String> {
    let exe = if cfg!(windows) { "aqt.exe" } else { "aqt" };
    let shipped = match app.path().resource_dir() {
        Ok(dir) => Some(dir.join("runtime").join("aqt").join(exe)),
        Err(error) => {
            // e.g. started through a symbolic link (macOS: /var), which Tauri refuses to resolve resources for
            eprintln!("[aqt desktop] the bundled runtime cannot be found: {error}");
            None
        }
    };
    let mut command: Vec<String> = match (shipped, std::env::var("AQT_CORE")) {
        (Some(path), _) if path.is_file() => vec![path.display().to_string(), "core".into(), "--stdio".into()],
        (_, Ok(line)) if !line.trim().is_empty() => line.split_whitespace().map(String::from).collect(),
        _ => vec!["aqt".into(), "core".into(), "--stdio".into()],
    };
    if read_only && !command.iter().any(|a| a == "--read-only") {
        command.push("--read-only".into());
    }
    command
}

/// Pages of the app itself: tauri://localhost (Linux, macOS) and http(s)://tauri.localhost (Windows).
fn is_app_page(url: &Url) -> bool {
    match url.scheme() {
        "tauri" => url.host_str() == Some("localhost"),
        "http" | "https" => url.host_str() == Some("tauri.localhost"),
        _ => false,
    }
}

/// Any other http(s) address opens in the system browser; nothing else leaves the app.
fn open_outside(app: &AppHandle, url: &Url) {
    if matches!(url.scheme(), "http" | "https") {
        if let Err(error) = app.opener().open_url(url.as_str(), None::<&str>) {
            eprintln!("[aqt desktop] could not open {url}: {error}");
        }
    }
}

#[tauri::command]
async fn core_session(machines: State<'_, Machines>) -> Result<Value, String> {
    machines.core().ready().await
}

/// The core's answer; else {"message", "sent"}: `sent` when the request had reached the core (or the SSH
/// connection to it) and no answer came, so its outcome is unknown. The app never sends it again.
#[tauri::command]
async fn core_request(machines: State<'_, Machines>, method: String, path: String, body: Option<Value>) -> Result<Value, Value> {
    let core = machines.core();
    let answer = core
        .request(&method, &path, body.unwrap_or(Value::Null))
        .await
        .map_err(|error| json!({"message": error.message, "sent": error.sent}))?;
    if answer.get("status").and_then(Value::as_u64) == Some(200) {
        let _ = PAGE_ANSWERED.set(ms());
    }
    Ok(answer)
}

/// A download: the native save dialog, then the file. None when the person cancelled.
#[tauri::command]
async fn save_file(app: AppHandle, name: String, text: Option<String>, base64: Option<String>) -> Result<Option<String>, String> {
    let bytes = match (text, base64) {
        (Some(text), _) => text.into_bytes(),
        (None, Some(data)) => base64::engine::general_purpose::STANDARD.decode(data).map_err(|e| e.to_string())?,
        (None, None) => return Err("nothing to save".into()),
    };
    let name = Path::new(&name).file_name().map_or("download".into(), |n| n.to_string_lossy().into_owned());
    let picked = tauri::async_runtime::spawn_blocking(move || app.dialog().file().set_file_name(name).blocking_save_file())
        .await
        .map_err(|e| e.to_string())?;
    let Some(picked) = picked else { return Ok(None) };
    let path = picked.into_path().map_err(|e| e.to_string())?;
    std::fs::write(&path, bytes).map_err(|e| format!("could not write {}: {e}", path.display()))?;
    Ok(Some(path.display().to_string()))
}

/// The system's folder dialog (connecting a project). The chosen folder's path, or None when the person cancelled.
/// Choosing a folder changes nothing: the page then asks the core for a preview of what connecting would write.
/// It shows this computer's folders, so on another machine the page asks for a path there instead.
#[tauri::command]
async fn pick_folder(app: AppHandle, machines: State<'_, Machines>) -> Result<Option<String>, String> {
    if let Some(machine) = machines.machine() {
        return Err(format!("the folder dialog shows this computer's folders: type a path on {}", machine.name));
    }
    let picked = tauri::async_runtime::spawn_blocking(move || app.dialog().file().blocking_pick_folder())
        .await
        .map_err(|e| e.to_string())?;
    let Some(picked) = picked else { return Ok(None) };
    let path = picked.into_path().map_err(|e| e.to_string())?;
    Ok(Some(path.display().to_string()))
}

/// --smoke: wait for the core, one request, the page's first answer; one JSON line; exit 0 or 1.
async fn smoke(app: AppHandle) {
    let core = app.state::<Machines>().core();
    let machine = app.state::<Machines>().machine().map(|m| m.name);
    let ready = core.ready().await;
    let core_ready_ms = ms();
    let first = match &ready {
        Ok(_) => core.request("GET", "/api/overview", Value::Null).await.map_err(|e| e.message),
        Err(error) => Err(error.clone()),
    };
    let first_response_ms = ms();
    let deadline = Instant::now() + Duration::from_secs(30);
    while PAGE_ANSWERED.get().is_none() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let status = first.as_ref().ok().and_then(|a| a.get("status")).and_then(Value::as_u64);
    let ok = status == Some(200) && PAGE_ANSWERED.get().is_some();
    let ready = ready.unwrap_or_default();
    let error = match (&first, ok) {
        (Err(error), _) => Some(error.clone()),
        (Ok(_), false) if status != Some(200) => Some(format!("GET /api/overview answered {status:?}")),
        (Ok(_), false) => Some("the page made no successful request to the core within 30 s".into()),
        _ => None,
    };
    println!(
        "{}",
        json!({
            "smoke": if ok { "ok" } else { "failed" },
            "core_ready_ms": core_ready_ms,
            "first_response_ms": first_response_ms,
            "window_ms": PAGE_LOADED.get(),
            "page_ms": PAGE_ANSWERED.get(),
            "mode": ready.get("mode"),
            "version": ready.get("version"),
            "core": core.command_line(),
            "machine": machine,
            "error": error,
        })
    );
    app.exit(if ok { 0 } else { 1 });
}

/// CLI mode: `aqt-desktop --cli ARGS`, or the AppImage called through a link named `aqt` or `aqt-toolkit` (the AppImage
/// runtime sets ARGV0 and APPDIR), runs the bundled `aqt` with these arguments in place of this process, in
/// the caller's folder: an AppImage's AppRun changes into its own `usr/`; the caller's folder is in OWD (set
/// by the AppImage runtime when mounted) or else in PWD (set by AppRun's shell, also when extracted).
#[cfg(unix)]
fn cli_mode<R: tauri::Runtime>(context: &tauri::Context<R>) -> Option<std::io::Error> {
    use std::os::unix::process::CommandExt;
    let mut args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let in_appimage = match (std::env::var_os("APPDIR"), std::env::current_exe()) {
        (Some(dir), Ok(exe)) => exe.starts_with(dir),
        _ => false,
    };
    let called = std::env::var_os("ARGV0").and_then(|name| Path::new(&name).file_name().map(|n| n.to_os_string()));
    let named = called.filter(|name| desktop::COMMAND_NAMES.iter().any(|known| name == *known));
    let (name, rest) = if args.get(1).is_some_and(|a| a == "--cli") {
        ("aqt".into(), args.split_off(2))
    } else {
        (named.filter(|_| in_appimage)?, args.split_off(1))
    };
    let runtime = match tauri::utils::platform::resource_dir(context.package_info(), &tauri::Env::default()) {
        Ok(dir) => dir.join("runtime").join("aqt").join("aqt"),
        Err(error) => return Some(std::io::Error::other(error.to_string())),
    };
    let mut command = std::process::Command::new(runtime);
    command.arg0(name); // aqt or aqt-toolkit, as it was called
    if let Some(folder) = ["OWD", "PWD"].iter().find_map(std::env::var_os).filter(|_| in_appimage) {
        command.current_dir(folder);
    }
    Some(command.args(rest).exec())
}

fn main() {
    STARTED.get_or_init(Instant::now);
    let context = tauri::generate_context!();
    #[cfg(unix)]
    if let Some(error) = cli_mode(&context) {
        eprintln!("aqt: cannot run the bundled aqt: {error}");
        std::process::exit(127);
    }
    let args: Vec<String> = std::env::args().collect();
    let smoke_mode = args.iter().any(|a| a == "--smoke") || std::env::var("AQT_DESKTOP_SMOKE").is_ok_and(|v| v == "1");
    let read_only = args.iter().any(|a| a == "--read-only");
    let hidden = args.iter().any(|a| a == "--hidden"); // started at login: only the tray icon, if there is one

    let mut builder = tauri::Builder::default();
    if !smoke_mode {
        // a second start hands its arguments (and so its aqt:// link) to the running app and ends
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            if !args.iter().any(|a| a == "--hidden") {
                desktop::show(app);
            }
        }));
    }
    let app = builder
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::Builder::new().open_js_links_on_click(false).build())
        .plugin(tauri_plugin_autostart::init(tauri_plugin_autostart::MacosLauncher::LaunchAgent, Some(vec!["--hidden"])))
        .invoke_handler(tauri::generate_handler![
            core_session,
            core_request,
            save_file,
            desktop::desktop_settings,
            desktop::show_notifications,
            pick_folder,
            machines::machines
        ])
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                if desktop::keep_running(window.app_handle()) {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .setup(move |app| {
            // this computer's core, or the core of the machine chosen in Settings, started over SSH
            let machines = Machines::start(app.handle(), core_command(app.handle(), read_only), read_only);
            app.manage(machines);
            let tray = !smoke_mode && desktop::wait_for_tray_host(if hidden { 10 } else { 0 });
            let tray = tray && desktop::create_tray(app.handle()).map_err(|e| eprintln!("[aqt desktop] no tray: {e}")).is_ok();
            if !tray && !smoke_mode {
                eprintln!("[aqt desktop] no tray icon here: closing the window quits the app");
            }
            let (nav, popup) = (app.handle().clone(), app.handle().clone());
            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("/".into()))
                .title("Agent Quality Toolkit")
                .inner_size(1280.0, 820.0)
                .min_inner_size(720.0, 480.0)
                .visible(!(hidden && tray))
                .on_navigation(move |url| {
                    let inside = is_app_page(url);
                    if !inside {
                        open_outside(&nav, url);
                    }
                    inside
                })
                .on_new_window(move |url, _| {
                    open_outside(&popup, &url);
                    NewWindowResponse::Deny
                })
                .on_page_load(|window, payload| {
                    if payload.event() == PageLoadEvent::Finished {
                        let _ = PAGE_LOADED.set(ms());
                        desktop::page_loaded(&window);
                    }
                })
                .build()?;
            // aqt:// links: the one this start was given, and those of later starts and clicks
            let links = app.handle().clone();
            app.deep_link().on_open_url(move |event| {
                for url in event.urls() {
                    desktop::open_link(&links, url.as_str());
                }
            });
            if let Ok(Some(urls)) = app.deep_link().get_current() {
                if let Some(url) = urls.first().filter(|_| !smoke_mode) {
                    desktop::open_link(app.handle(), url.as_str());
                }
            }
            if smoke_mode {
                tauri::async_runtime::spawn(smoke(app.handle().clone()));
            }
            Ok(())
        })
        .build(context)
        .expect("could not build the app");
    app.run(|app, event| match event {
        RunEvent::Exit => app.state::<Machines>().core().stop(),
        #[cfg(target_os = "macos")]
        RunEvent::Reopen { .. } => desktop::show(app), // a click on the Dock icon
        _ => {}
    });
}
