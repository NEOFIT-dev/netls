use anyhow::Result;

use crate::Connection;

pub fn print_conns(conns: &[Connection]) -> Result<()> {
    let mut w = csv::Writer::from_writer(std::io::stdout());
    write_conns(&mut w, conns)?;
    w.flush()?;
    Ok(())
}

fn write_conns<W: std::io::Write>(w: &mut csv::Writer<W>, conns: &[Connection]) -> Result<()> {
    w.write_record(["proto", "local", "remote", "state", "pid", "process"])?;

    for c in conns {
        let proto = c.proto.to_string();
        let state = c.state_str();
        let pid = c.pid.map(|p| p.to_string()).unwrap_or_default();
        w.write_record([
            &proto,
            &c.local,
            &c.remote,
            &state,
            &pid,
            c.process_display(),
        ])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Connection, Proto, State};

    fn make_conn() -> Connection {
        Connection {
            proto: Proto::Tcp,
            local: "127.0.0.1:8080".to_string(),
            remote: "1.2.3.4:443".to_string(),
            state: Some(State::Established),
            pid: Some(1234),
            process: Some("curl".to_string()),
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
    fn csv_header_and_row() {
        let conns = vec![make_conn()];
        let mut w = csv::Writer::from_writer(Vec::new());
        write_conns(&mut w, &conns).unwrap();
        let data = String::from_utf8(w.into_inner().unwrap()).unwrap();
        assert!(data.starts_with("proto,local,remote,state,pid,process\n"));
        assert!(data.contains("tcp,127.0.0.1:8080,1.2.3.4:443,ESTABLISHED,1234,curl"));
    }

    #[test]
    fn csv_empty_input_has_only_header() {
        let mut w = csv::Writer::from_writer(Vec::new());
        write_conns(&mut w, &[]).unwrap();
        let data = String::from_utf8(w.into_inner().unwrap()).unwrap();
        assert_eq!(data.trim(), "proto,local,remote,state,pid,process");
    }

    #[test]
    fn csv_no_pid_no_process() {
        let mut conn = make_conn();
        conn.pid = None;
        conn.process = None;
        let mut w = csv::Writer::from_writer(Vec::new());
        write_conns(&mut w, &[conn]).unwrap();
        let data = String::from_utf8(w.into_inner().unwrap()).unwrap();
        // pid and process columns are empty
        assert!(data.contains("ESTABLISHED,,"));
    }
}
