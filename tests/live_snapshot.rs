//! Smoke test against live OS state. Opens a real socket and verifies
//! that `snapshot` sees it. Catches regressions in the `/proc/net`
//! parser (Linux) and `libproc` wiring (macOS) that fixture-based unit
//! tests cannot.

#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::net::{TcpListener, UdpSocket};

use netls::{Filter, Proto, State, snapshot};

#[test]
fn snapshot_sees_a_tcp_listener() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();

    let conns = snapshot(&Filter::default().proto(Proto::Tcp)).unwrap();
    let found = conns
        .iter()
        .any(|c| c.state == Some(State::Listen) && c.local.ends_with(&format!(":{port}")));
    assert!(found, "listener on port {port} not found in snapshot");
}

#[test]
fn snapshot_sees_a_udp_socket() {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind loopback");
    let port = sock.local_addr().unwrap().port();

    let conns = snapshot(&Filter::default().proto(Proto::Udp)).unwrap();
    let found = conns
        .iter()
        .any(|c| c.proto == Proto::Udp && c.local.ends_with(&format!(":{port}")));
    assert!(found, "udp socket on port {port} not found in snapshot");
}
