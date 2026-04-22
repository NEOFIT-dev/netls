use anyhow::Result;

use netls::Connection;

use crate::display;

/// Render `conns` as CSV to stdout.
///
/// # Errors
///
/// Propagates I/O errors writing to stdout (broken pipe, etc.).
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
        let state = display::state_str(c);
        let pid = c.pid.map(|p| p.to_string()).unwrap_or_default();
        w.write_record([
            &proto,
            &c.local,
            &c.remote,
            &state,
            &pid,
            display::process_display(c),
        ])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use netls::{Connection, Proto, State};

    fn make_conn() -> Connection {
        let mut c = Connection::new(Proto::Tcp, "127.0.0.1:8080", "1.2.3.4:443");
        c.state = Some(State::Established);
        c.pid = Some(1234);
        c.process = Some("curl".to_string());
        c
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
