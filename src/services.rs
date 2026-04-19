use std::collections::HashMap;
use std::sync::OnceLock;

static SERVICE_MAP: OnceLock<HashMap<u16, &'static str>> = OnceLock::new();
static USER_OVERRIDES: OnceLock<HashMap<u16, String>> = OnceLock::new();
static ETC_SERVICES: OnceLock<HashMap<u16, String>> = OnceLock::new();

/// Curated, developer-friendly port → name pairs. Consulted before
/// `/etc/services` so common dev ports get nicer names than the IANA-assigned
/// ones the system file would yield (e.g. `3000` → `dev-server` instead of
/// the IANA `hbci`).
const BUILTIN: &[(u16, &str)] = &[
    (20, "ftp-data"),
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (53, "dns"),
    (80, "http"),
    (110, "pop3"),
    (143, "imap"),
    (194, "irc"),
    (443, "https"),
    (465, "smtps"),
    (587, "submission"),
    (993, "imaps"),
    (995, "pop3s"),
    (3000, "dev-server"),
    (3306, "mysql"),
    (5432, "postgres"),
    (5672, "amqp"),
    (6379, "redis"),
    (6443, "k8s-api"),
    (8080, "http-alt"),
    (8443, "https-alt"),
    (9200, "elasticsearch"),
    (9300, "elasticsearch"),
    (15672, "rabbitmq-ui"),
    (27017, "mongodb"),
    (27018, "mongodb"),
];

fn load() -> HashMap<u16, &'static str> {
    BUILTIN.iter().map(|&(p, n)| (p, n)).collect()
}

/// Read and parse `/etc/services` once on first request. On non-Unix platforms,
/// when the file is missing (containers, minimal images) or unreadable, returns
/// an empty map so this layer contributes nothing rather than erroring.
fn load_etc_services() -> HashMap<u16, String> {
    #[cfg(unix)]
    if let Ok(content) = std::fs::read_to_string("/etc/services") {
        return parse_etc_services(&content);
    }
    HashMap::new()
}

/// Parse `/etc/services`-format text. Each non-comment line looks like
/// `name port/proto [aliases...]`; everything after `#` is a comment.
///
/// When the same port appears multiple times (typical: a tcp entry followed
/// by an identical udp entry) the first occurrence wins. `/etc/services`
/// lists tcp before udp by convention, which matches what users normally
/// expect to see.
fn parse_etc_services(content: &str) -> HashMap<u16, String> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let trimmed = line.split('#').next().unwrap_or("").trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let Some(name) = parts.next() else { continue };
        let Some(port_proto) = parts.next() else {
            continue;
        };
        let Some((port_str, _proto)) = port_proto.split_once('/') else {
            continue;
        };
        let Ok(port) = port_str.parse::<u16>() else {
            continue;
        };
        map.entry(port).or_insert_with(|| name.to_string());
    }
    map
}

/// Install user-provided port → name overrides loaded from the config file's
/// `[ports]` section.
///
/// **Set-once per process**: only the first call wins. Subsequent calls are
/// silently ignored, so it is safe to call from `main` without coordination
/// but unsuitable as a "live update" hook.
///
/// Overrides take precedence over both the built-in map and `/etc/services`,
/// so a user can rename `3000` from `dev-server` to `vite-dev` or replace any
/// IANA assignment.
pub fn set_user_overrides(overrides: HashMap<u16, String>) {
    let _ = USER_OVERRIDES.set(overrides);
}

/// Resolve a port to a name. Lookup order, first hit wins:
/// 1. caller-supplied `extra` (unit-test seam)
/// 2. user `[ports]` registered via [`set_user_overrides`]
/// 3. curated [`BUILTIN`] map (developer-friendly names)
/// 4. `/etc/services` (Unix only; empty everywhere else)
fn lookup_with(port: u16, extra: Option<&HashMap<u16, String>>) -> Option<String> {
    if let Some(map) = extra
        && let Some(name) = map.get(&port)
    {
        return Some(name.clone());
    }
    if let Some(map) = USER_OVERRIDES.get()
        && let Some(name) = map.get(&port)
    {
        return Some(name.clone());
    }
    if let Some(name) = SERVICE_MAP.get_or_init(load).get(&port).copied() {
        return Some(name.to_string());
    }
    ETC_SERVICES
        .get_or_init(load_etc_services)
        .get(&port)
        .cloned()
}

/// Format an address with optional service name annotation.
/// `"0.0.0.0:5432"` → `"0.0.0.0:5432 (postgres)"`.
///
/// Consults user overrides registered via [`set_user_overrides`] before the
/// built-in service map.
#[must_use]
pub fn annotate_addr(addr: &str) -> String {
    annotate_with(addr, None)
}

/// Like [`annotate_addr`] but takes a caller-local overrides map that wins
/// over the global table. Used by unit tests to avoid depending on the
/// process-global `OnceLock` state.
fn annotate_with(addr: &str, extra: Option<&HashMap<u16, String>>) -> String {
    if let Some(port) = addr
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        && let Some(name) = lookup_with(port, extra)
    {
        return format!("{addr} ({name})");
    }
    addr.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn annotate_known_port() {
        let result = annotate_addr("0.0.0.0:5432");
        assert!(
            result.contains("postgres"),
            "expected postgres annotation, got: {result}"
        );
    }

    #[test]
    fn annotate_unknown_port_unchanged() {
        // Picked from the dynamic/private port range (49152-65535) above any
        // IANA assignment so it is absent from both BUILTIN and /etc/services.
        let addr = "0.0.0.0:60001";
        assert_eq!(annotate_addr(addr), addr);
    }

    #[test]
    fn annotate_wildcard_remote_unchanged() {
        let addr = "0.0.0.0:*";
        assert_eq!(annotate_addr(addr), addr);
    }

    #[test]
    fn user_override_takes_precedence_over_builtin() {
        let mut overrides = HashMap::new();
        overrides.insert(3000, "vite-dev".to_string());
        let result = annotate_with("0.0.0.0:3000", Some(&overrides));
        assert!(
            result.contains("vite-dev") && !result.contains("dev-server"),
            "expected user override 'vite-dev' to win over built-in 'dev-server', got: {result}"
        );
    }

    #[test]
    fn user_override_adds_unknown_port() {
        let mut overrides = HashMap::new();
        overrides.insert(9229, "node-debug".to_string());
        let result = annotate_with("127.0.0.1:9229", Some(&overrides));
        assert!(
            result.contains("node-debug"),
            "expected user override 'node-debug' to apply, got: {result}"
        );
    }

    #[test]
    fn local_overrides_do_not_affect_other_ports() {
        let mut overrides = HashMap::new();
        overrides.insert(9229, "node-debug".to_string());
        // 5432 should still resolve to postgres from built-in
        let result = annotate_with("0.0.0.0:5432", Some(&overrides));
        assert!(result.contains("postgres"));
    }

    #[test]
    fn etc_services_parser_basic_line() {
        let map = parse_etc_services("http  80/tcp  www  # WorldWideWeb HTTP\n");
        assert_eq!(map.get(&80).map(String::as_str), Some("http"));
    }

    #[test]
    fn etc_services_parser_skips_blank_and_comment_lines() {
        let input = "# header\n\n   \nssh   22/tcp\n# another\nhttps 443/tcp\n";
        let map = parse_etc_services(input);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get(&22).map(String::as_str), Some("ssh"));
        assert_eq!(map.get(&443).map(String::as_str), Some("https"));
    }

    #[test]
    fn etc_services_parser_first_entry_wins_per_port() {
        // /etc/services convention lists tcp before udp; the tcp name wins
        // even when the udp entry has a different label.
        let map = parse_etc_services("http  80/tcp\nweird 80/udp\n");
        assert_eq!(map.get(&80).map(String::as_str), Some("http"));
    }

    #[test]
    fn etc_services_parser_skips_malformed_lines() {
        let input = "garbage\nname noslash\nbad notanumber/tcp\nrange 99999/tcp\nok 99/tcp\n";
        let map = parse_etc_services(input);
        assert_eq!(map.len(), 1);
        assert_eq!(map.get(&99).map(String::as_str), Some("ok"));
    }

    #[test]
    fn etc_services_parser_accepts_hyphenated_names() {
        let map = parse_etc_services("ftp-data  20/tcp  ftp-control\n");
        assert_eq!(map.get(&20).map(String::as_str), Some("ftp-data"));
    }
}
