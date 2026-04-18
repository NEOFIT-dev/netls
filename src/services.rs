use std::collections::HashMap;
use std::sync::OnceLock;

static SERVICE_MAP: OnceLock<HashMap<u16, &'static str>> = OnceLock::new();

/// Well-known ports that matter to developers and sysadmins.
/// Used as fallback when /etc/services is unavailable.
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

/// Look up the service name for a port number.
fn lookup(port: u16) -> Option<&'static str> {
    SERVICE_MAP.get_or_init(load).get(&port).copied()
}

/// Format an address with optional service name annotation.
/// `"0.0.0.0:5432"` → `"0.0.0.0:5432 (postgres)"`
pub fn annotate_addr(addr: &str) -> String {
    if let Some(port) = addr
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        && let Some(name) = lookup(port)
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
        let addr = "0.0.0.0:19999";
        assert_eq!(annotate_addr(addr), addr);
    }

    #[test]
    fn annotate_wildcard_remote_unchanged() {
        let addr = "0.0.0.0:*";
        assert_eq!(annotate_addr(addr), addr);
    }
}
