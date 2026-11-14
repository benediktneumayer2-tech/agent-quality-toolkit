fn main() {
    // The page may call only these app commands, and only as the capabilities in capabilities/ allow.
    let manifest = tauri_build::AppManifest::new().commands(&[
        "core_session",
        "core_request",
        "save_file",
        "desktop_settings",
        "show_notifications",
        "pick_folder",
        "machines",
        "updates",
    ]);
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(manifest)).expect("tauri-build failed");
}
