use std::collections::HashMap;

use netls::{Connection, ConnectionKey};

pub(crate) const NO_PERMISSION: &str = "-";

pub(crate) fn state_str(c: &Connection) -> String {
    c.state
        .map_or_else(|| NO_PERMISSION.to_string(), |s| s.to_string())
}

pub(crate) fn process_display(c: &Connection) -> &str {
    c.process.as_deref().unwrap_or(NO_PERMISSION)
}

pub(crate) fn format_process_text<S: std::hash::BuildHasher>(
    c: &Connection,
    origins: &HashMap<ConnectionKey, String, S>,
) -> String {
    match origins.get(&c.key()) {
        Some(clients) => format!("{} <- {}", c.process.as_deref().unwrap_or("?"), clients),
        None => c
            .process
            .clone()
            .unwrap_or_else(|| NO_PERMISSION.to_string()),
    }
}

pub(crate) fn docker_proxy_label(c: &Connection) -> Option<String> {
    netls::docker_proxy_service(c).map(|s| format!("docker-proxy ({s})"))
}
