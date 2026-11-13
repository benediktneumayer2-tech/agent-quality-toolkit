// Agent Quality Toolkit desktop app: one window with the aqt-ui pages; the AQT core runs as a child process
// and answers the page's API requests over JSON lines. No web server, no port.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod core;

use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine;
use serde_json::{json, Value};
use tauri::webview::{NewWindowResponse, PageLoadEvent};
use tauri::{AppHandle, Manager, RunEvent, State, Url, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_opener::OpenerExt;

use crate::core::Core;

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
    let shipped = app.path().resource_dir().ok().map(|dir| dir.join("runtime").join("aqt").join(exe));
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
async fn core_session(core: State<'_, Arc<Core>>) -> Result<Value, String> {
    core.ready().await
}

#[tauri::command]
async fn core_request(core: State<'_, Arc<Core>>, method: String, path: String, body: Option<Value>) -> Result<Value, String> {
    let answer = core.request(&method, &path, body.unwrap_or(Value::Null)).await?;
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

/// --smoke: wait for the core, one request, the page's first answer; one JSON line; exit 0 or 1.
async fn smoke(app: AppHandle, core: Arc<Core>) {
    let ready = core.ready().await;
    let core_ready_ms = ms();
    let first = match &ready {
        Ok(_) => core.request("GET", "/api/overview", Value::Null).await,
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
            "error": error,
        })
    );
    app.exit(if ok { 0 } else { 1 });
}

fn main() {
    STARTED.get_or_init(Instant::now);
    let args: Vec<String> = std::env::args().collect();
    let smoke_mode = args.iter().any(|a| a == "--smoke") || std::env::var("AQT_DESKTOP_SMOKE").is_ok_and(|v| v == "1");
    let read_only = args.iter().any(|a| a == "--read-only");

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::Builder::new().open_js_links_on_click(false).build())
        .invoke_handler(tauri::generate_handler![core_session, core_request, save_file])
        .setup(move |app| {
            let core = Core::start(core_command(app.handle(), read_only));
            app.manage(core.clone());
            let (nav, popup) = (app.handle().clone(), app.handle().clone());
            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("/".into()))
                .title("Agent Quality Toolkit")
                .inner_size(1280.0, 820.0)
                .min_inner_size(720.0, 480.0)
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
                .on_page_load(|_, payload| {
                    if payload.event() == PageLoadEvent::Finished {
                        let _ = PAGE_LOADED.set(ms());
                    }
                })
                .build()?;
            if smoke_mode {
                tauri::async_runtime::spawn(smoke(app.handle().clone(), core));
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("could not build the app");
    app.run(|app, event| {
        if let RunEvent::Exit = event {
            app.state::<Arc<Core>>().stop();
        }
    });
}
