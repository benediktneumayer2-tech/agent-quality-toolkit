//! Updates of the app itself, from the `latest.json` of the newest GitHub release (tauri-plugin-updater).
//!
//! - **Off** unless the app's config carries the updater's public key (`plugins.updater.pubkey` in
//!   `tauri.conf.json`). Without it the plugin is not loaded and the app never asks for updates.
//! - **On:** a minute after start, then once a day, the app looks for a newer version. A newer one only shows:
//!   a dot at Settings and a line under Settings, *This app*. Nothing is downloaded or installed until the
//!   person agrees there.
//! - **Agreed:** the app downloads the update, checks its signature against the public key (and that it was
//!   signed for the version announced), and keeps it in its cache folder. The next start installs it before
//!   the core starts, checking the signature again, and then starts the new version. A failed install leaves
//!   the app as it was and shows why in Settings.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use tauri::{AppHandle, Manager};
use tauri_plugin_updater::{Update, UpdaterExt};

const FIRST_CHECK: Duration = Duration::from_secs(60);
const EVERY: Duration = Duration::from_secs(24 * 3600);

struct State {
    checked: Option<u128>, // ms since 1970 of the last check
    found: Option<Update>, // the newer version the last check found
    error: Option<String>, // why the last check failed
    busy: bool,            // downloading what the person agreed to
    failed: Option<Value>, // {"version", "reason"}: the install at this start failed
}

static STATE: Mutex<State> = Mutex::new(State { checked: None, found: None, error: None, busy: false, failed: None });

/// Whether this build checks for updates: its config has the updater's public key.
pub fn configured(config: &tauri::Config) -> bool {
    let key = config.plugins.0.get("updater").and_then(|updater| updater.get("pubkey")).and_then(Value::as_str);
    key.is_some_and(|key| !key.trim().is_empty())
}

/// At start, before the core: install an update the person agreed to (then start the new version), and look for
/// updates from now on. Nothing happens in a build without the public key.
pub fn start(app: &AppHandle) {
    if !configured(app.config()) {
        return;
    }
    install_agreed(app);
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(FIRST_CHECK).await;
        loop {
            check(&app).await;
            tokio::time::sleep(EVERY).await;
        }
    });
}

/// The folder that holds an agreed update until the next start: `package` (the verified download) and
/// `release.json` (the release's manifest entry, to install it from without asking the network again).
fn folder(app: &AppHandle) -> Option<PathBuf> {
    app.path().app_cache_dir().ok().map(|dir| dir.join("update"))
}

/// The version of the agreed update waiting for the next start.
fn agreed(app: &AppHandle) -> Option<String> {
    let text = std::fs::read_to_string(folder(app)?.join("release.json")).ok()?;
    let saved: Value = serde_json::from_str(&text).ok()?;
    saved.get("version").and_then(Value::as_str).map(String::from)
}

fn install_agreed(app: &AppHandle) {
    let Some(dir) = folder(app) else { return };
    let Ok(text) = std::fs::read_to_string(dir.join("release.json")) else { return };
    let package = std::fs::read(dir.join("package"));
    let _ = std::fs::remove_dir_all(&dir); // one attempt: a failed install is not tried again at every start
    let saved: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    let version = saved.get("version").and_then(Value::as_str).unwrap_or("?").to_string();
    let outcome = (|| -> Result<bool, String> {
        let updater = app.updater().map_err(|e| e.to_string())?;
        // the saved manifest is not trusted: the update must carry a signature for exactly this version
        let Some(update) = updater.restore_update(saved["raw"].clone()).map_err(|e| e.to_string())? else {
            return Ok(false); // not newer than this app (installed another way meanwhile)
        };
        let bytes = package.map_err(|e| format!("the download is gone: {e}"))?;
        eprintln!("[aqt desktop] installing the update to {}", update.version);
        // checks the signature again; on Windows the installer takes over and this process ends here
        update.install(bytes).map_err(|e| e.to_string())?;
        Ok(true)
    })();
    match outcome {
        Ok(true) => {
            eprintln!("[aqt desktop] installed {version}; starting it");
            app.restart();
        }
        Ok(false) => eprintln!("[aqt desktop] the agreed update to {version} is not newer than this app: dropped"),
        Err(reason) => {
            eprintln!("[aqt desktop] the update to {version} could not be installed: {reason}");
            STATE.lock().unwrap().failed = Some(json!({"version": version, "reason": reason}));
        }
    }
}

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis())
}

async fn check(app: &AppHandle) {
    let result = match app.updater() {
        Ok(updater) => updater.check().await.map_err(|e| e.to_string()),
        Err(error) => Err(error.to_string()),
    };
    {
        let mut state = STATE.lock().unwrap();
        state.checked = Some(now_ms());
        match result {
            Ok(found) => {
                if let Some(update) = &found {
                    eprintln!("[aqt desktop] update available: {} (this app: {})", update.version, update.current_version);
                }
                state.found = found;
                state.error = None;
            }
            Err(error) => {
                eprintln!("[aqt desktop] could not check for updates: {error}");
                state.error = Some(error);
            }
        }
    }
    tell_page(app);
}

/// The page shows the dot at Settings without asking: `window.aqtUpdate(status)`.
fn tell_page(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        if let Err(error) = window.eval(format!("window.aqtUpdate && window.aqtUpdate({})", status(app))) {
            eprintln!("[aqt desktop] could not tell the page about updates: {error}");
        }
    }
}

/// Download, verify and keep the update to `version`, the one the last check found.
async fn agree(app: &AppHandle, version: &str) -> Result<(), String> {
    let found = STATE.lock().unwrap().found.clone();
    let update = found.filter(|update| update.version == version).ok_or("this update is no longer offered")?;
    let dir = folder(app).ok_or("no cache folder for the update")?;
    STATE.lock().unwrap().busy = true;
    let result = async {
        // download() checks the signature (and the signed version) before it returns the bytes
        let bytes = update.download(|_, _| {}, || {}).await.map_err(|e| format!("download: {e}"))?;
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let part = dir.join("package.part");
        std::fs::write(&part, bytes).map_err(|e| e.to_string())?;
        std::fs::rename(&part, dir.join("package")).map_err(|e| e.to_string())?;
        let saved = json!({"version": update.version, "raw": update.raw_json});
        std::fs::write(dir.join("release.json"), saved.to_string()).map_err(|e| e.to_string())
    }
    .await;
    STATE.lock().unwrap().busy = false;
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    result
}

fn status(app: &AppHandle) -> Value {
    let current = app.package_info().version.to_string();
    if !configured(app.config()) {
        return json!({"enabled": false, "current": current});
    }
    // the release's page, beside the manifest's address (…/releases/latest/download/latest.json)
    let release = |version: &str| {
        let endpoint = app.config().plugins.0.get("updater")?.get("endpoints")?.get(0)?.as_str()?;
        let (repo, _) = endpoint.split_once("/releases/")?;
        Some(format!("{repo}/releases/tag/v{version}"))
    };
    let state = STATE.lock().unwrap();
    json!({
        "enabled": true,
        "current": current,
        "checked": state.checked,
        "available": state.found.as_ref().map(|u| json!({"version": u.version, "notes": release(&u.version)})),
        "ready": agreed(app),
        "busy": state.busy,
        "error": state.error,
        "failed": state.failed,
    })
}

/// The page's view of updates: `{enabled, current}`, and when on also `checked` (ms), `available`
/// (`{version, notes}`: the release page), `ready` (the version that installs at the next start), `busy`, `error`
/// (of the last check) and `failed` (`{version, reason}` of this start's install). `change` may be
/// `{"install": "<version>"}`: the person agrees; the app downloads and verifies the update and installs it at the
/// next start. `{"cancel": true}` drops an agreed update again.
#[tauri::command]
pub async fn updates(app: AppHandle, change: Option<Value>) -> Result<Value, String> {
    let change = change.unwrap_or(Value::Null);
    if !configured(app.config()) && !change.is_null() {
        return Err("this build of the app does not update itself".into());
    }
    if let Some(version) = change.get("install").and_then(Value::as_str) {
        agree(&app, version).await?;
    }
    if change.get("cancel") == Some(&Value::Bool(true)) {
        if let Some(dir) = folder(&app) {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
    Ok(status(&app))
}

#[cfg(test)]
mod tests {
    use super::configured;

    fn config(plugins: serde_json::Value) -> tauri::Config {
        serde_json::from_value(serde_json::json!({"identifier": "x.y.z", "plugins": plugins})).unwrap()
    }

    #[test]
    fn updates_are_off_without_the_public_key() {
        assert!(!configured(&config(serde_json::json!({}))));
        assert!(!configured(&config(serde_json::json!({"updater": {"pubkey": " ", "endpoints": []}}))));
        assert!(configured(&config(serde_json::json!({"updater": {"pubkey": "dW50cnVzdGVk", "endpoints": []}}))));
    }

    #[test]
    fn the_shipped_config_names_the_release_manifest() {
        let shipped: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let updater = &shipped["plugins"]["updater"];
        assert_eq!(
            updater["endpoints"][0],
            "https://github.com/benediktneumayer2-tech/agent-quality-toolkit/releases/latest/download/latest.json"
        );
        assert_eq!(updater["requireSignedVersion"], true);
    }
}
