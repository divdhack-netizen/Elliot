mod agent;
mod proxy;
mod replay;
mod scope;
mod socks;

use std::path::PathBuf;

use tauri::Manager;

pub fn run() {
    tauri::Builder::default()
        .manage(proxy::ProxyState::default())
        .manage(socks::SocksState::default())
        .manage(agent::AgentState::default())
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
            // Managed behind an `Arc` because the capture pumps keep it in their
            // own tasks (see `scope::SharedScope`).
            app.manage(scope::SharedScope::new(scope::ScopeState::new(default_path)));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            proxy::proxy_start,
            proxy::proxy_stop,
            proxy::proxy_status,
            proxy::proxy_set_intercept,
            proxy::proxy_intercept_decide,
            proxy::proxy_ws_decide,
            proxy::ws_list,
            proxy::proxy_ca_status,
            proxy::proxy_get_ca_pem,
            scope::project_status,
            scope::project_create,
            scope::project_open,
            scope::project_close,
            scope::scope_get,
            scope::scope_set,
            socks::socks_start,
            socks::socks_stop,
            socks::capture_list,
            socks::capture_messages,
            replay::repeater_send,
            replay::intruder_run,
            replay::send_to_repeater,
            replay::send_to_intruder,
            agent::agent_send,
            agent::agent_propose,
            agent::agent_attach_context,
            agent::agent_context_list,
            agent::agent_context_remove,
            agent::agent_context_clear,
            agent::agent_reset,
            agent::agent_stop,
            agent::agent_execute,
            agent::agent_runs,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
