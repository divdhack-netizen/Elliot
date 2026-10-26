mod proxy;
mod scope;

use std::path::PathBuf;

use tauri::Manager;

pub fn run() {
    tauri::Builder::default()
        .manage(proxy::ProxyState::default())
        .setup(|app| {
            // The project file lives in the app data directory, next to the CA.
            // If that cannot be resolved we fall back to the working directory
            // rather than refusing to start: the path is shown in the Scope tab
            // and can be overridden there.
            let default_path = app
                .path()
                .app_data_dir()
                .map(|dir| dir.join(scope::PROJECT_FILE))
                .unwrap_or_else(|_| PathBuf::from(scope::PROJECT_FILE));
            app.manage(scope::ScopeState::new(default_path));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            proxy::proxy_start,
            proxy::proxy_stop,
            proxy::proxy_set_intercept,
            proxy::proxy_intercept_decide,
            proxy::proxy_get_ca_pem,
            scope::project_status,
            scope::project_create,
            scope::project_open,
            scope::project_close,
            scope::scope_get,
            scope::scope_set,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
