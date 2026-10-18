mod proxy;

pub fn run() {
    tauri::Builder::default()
        .manage(proxy::ProxyState::default())
        .invoke_handler(tauri::generate_handler![
            proxy::proxy_start,
            proxy::proxy_stop,
            proxy::proxy_set_intercept,
            proxy::proxy_intercept_decide,
            proxy::proxy_get_ca_pem,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
