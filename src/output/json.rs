use anyhow::Result;

use crate::Connection;

/// Render `conns` as JSON to stdout - one object per line, or a single
/// pretty-printed object per connection when `pretty` is `true`.
pub fn print_conns(conns: &[Connection], pretty: bool) -> Result<()> {
    for c in conns {
        let s = if pretty {
            serde_json::to_string_pretty(c)?
        } else {
            serde_json::to_string(c)?
        };
        println!("{s}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{Connection, Proto, State};

    fn make_conn() -> Connection {
        Connection {
            proto: Proto::Tcp,
            local: "0.0.0.0:80".to_string(),
            remote: "0.0.0.0:*".to_string(),
            state: Some(State::Listen),
            pid: Some(42),
            process: Some("nginx".to_string()),
            cmdline: None,
            container: None,
            recv_q: None,
            send_q: None,
            inode: None,
            age_secs: None,
            parent_chain: None,
            systemd_unit: None,
            fd_usage: None,
        }
    }

    #[test]
    fn json_serializes_all_fields() {
        let c = make_conn();
        let s = serde_json::to_string(&c).unwrap();
        assert!(s.contains("\"proto\":\"tcp\""));
        assert!(s.contains("\"local\":\"0.0.0.0:80\""));
        assert!(s.contains("\"state\":\"LISTEN\""));
        assert!(s.contains("\"pid\":42"));
        assert!(s.contains("\"process\":\"nginx\""));
    }

    #[test]
    fn json_roundtrip_preserves_state() {
        let c = make_conn();
        let s = serde_json::to_string(&c).unwrap();
        let back: Connection = serde_json::from_str(&s).unwrap();
        assert_eq!(back.state, Some(State::Listen));
        assert_eq!(back.pid, Some(42));
        assert_eq!(back.process.as_deref(), Some("nginx"));
    }

    #[test]
    fn json_omits_recv_send_q_when_none() {
        let c = make_conn();
        let s = serde_json::to_string(&c).unwrap();
        assert!(!s.contains("recv_q"));
        assert!(!s.contains("send_q"));
    }

    #[test]
    fn json_includes_recv_send_q_when_present() {
        let mut c = make_conn();
        c.recv_q = Some(128);
        c.send_q = Some(0);
        let s = serde_json::to_string(&c).unwrap();
        assert!(s.contains("\"recv_q\":128"));
        assert!(s.contains("\"send_q\":0"));
    }
}
