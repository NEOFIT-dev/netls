use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{Connection, Error, Proto, Result, State};

// ── Public entry point ────────────────────────────────────────────────────────

/// Read the kernel TCP/UDP/Unix tables from `/proc/net/*` and resolve each
/// socket inode back to the owning process by walking `/proc/<pid>/fd/`.
///
/// # Errors
///
/// Returns an [`enum@Error`] if `/proc/net/{tcp,tcp6,udp,udp6,unix}` cannot
/// be read (procfs missing, permissions, etc.).
pub fn get_connections() -> Result<Vec<Connection>> {
    // Build inode → (pid, process_name) map by walking /proc/[pid]/fd/
    let pid_map = build_inode_pid_map()?;

    let mut conns = Vec::new();
    for (path, proto, ipv6) in [
        ("/proc/net/tcp", Proto::Tcp, false),
        ("/proc/net/tcp6", Proto::Tcp, true),
        ("/proc/net/udp", Proto::Udp, false),
        ("/proc/net/udp6", Proto::Udp, true),
        ("/proc/net/raw", Proto::Raw, false),
        ("/proc/net/raw6", Proto::Raw, true),
    ] {
        let mut batch = parse_proc_net(path, proto, ipv6, &pid_map)?;
        // Raw sockets don't follow the TCP state machine; the `st` field is
        // a synthetic placeholder. Clear it so the library reports None.
        if proto == Proto::Raw {
            for c in &mut batch {
                c.state = None;
            }
        }
        conns.extend(batch);
    }

    conns.extend(parse_proc_net_unix(&pid_map)?);

    Ok(conns)
}

// ── /proc/net/tcp* parser ─────────────────────────────────────────────────────

fn parse_proc_net(
    path: &str,
    proto: Proto,
    ipv6: bool,
    pid_map: &HashMap<u64, (u32, String)>,
) -> Result<Vec<Connection>> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        // File missing = protocol not loaded (e.g. no IPv6). Not an error.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(Error::Io(e)),
    };

    let mut conns = Vec::new();

    for line in content.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Fields: sl local_addr rem_addr state tx:rx tr:when retrnsmt uid timeout inode ...
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }

        let local = parse_address(fields[1], ipv6)?;
        let remote = parse_address(fields[2], ipv6)?;
        let state = parse_state(fields[3]);

        // fields[4] = "tx_queue:rx_queue" in hex
        let (send_q, recv_q) = parse_queues(fields[4]);

        let inode: u64 = fields[9]
            .parse()
            .map_err(|_| Error::Parse(format!("bad inode: {}", fields[9])))?;

        let (pid, process) = pid_map
            .get(&inode)
            .map_or((None, None), |(p, n)| (Some(*p), Some(n.clone())));

        conns.push(Connection {
            proto,
            local,
            remote,
            state,
            pid,
            process,
            cmdline: None,
            container: None,
            recv_q,
            send_q,
            inode: Some(inode),
            age_secs: None,
            parent_chain: None,
            systemd_unit: None,
            fd_usage: None,
        });
    }

    Ok(conns)
}

// ── Address parsing ───────────────────────────────────────────────────────────

/// Parse a `XXXXXXXX:PPPP` (IPv4) or `XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:PPPP` (IPv6)
/// address as written by the kernel into a human-readable `addr:port` string.
///
/// The kernel prints addresses as native-endian u32 words, so we use
/// `to_ne_bytes()` to recover the original byte order on both LE and BE hosts.
fn parse_address(s: &str, ipv6: bool) -> Result<String> {
    let (addr_hex, port_hex) = s
        .split_once(':')
        .ok_or_else(|| Error::Parse(format!("bad address field: {s}")))?;

    let port = u16::from_str_radix(port_hex, 16)
        .map_err(|_| Error::Parse(format!("bad port hex: {port_hex}")))?;

    let port_str = if port == 0 {
        "*".to_string()
    } else {
        port.to_string()
    };

    Ok(if ipv6 {
        let ip = parse_ipv6_hex(addr_hex)?;
        format!("[{ip}]:{port_str}")
    } else {
        let ip = parse_ipv4_hex(addr_hex)?;
        format!("{ip}:{port_str}")
    })
}

/// 8 hex chars → Ipv4Addr.
/// The kernel writes the address as a native-endian u32.
fn parse_ipv4_hex(s: &str) -> Result<Ipv4Addr> {
    let n = u32::from_str_radix(s, 16).map_err(|_| Error::Parse(format!("bad ipv4 hex: {s}")))?;
    // to_ne_bytes() gives the bytes in memory order, which matches the IP octets
    // on both little-endian (most Linux systems) and big-endian hosts.
    Ok(Ipv4Addr::from(n.to_ne_bytes()))
}

/// 32 hex chars → Ipv6Addr.
/// Stored as four native-endian u32 words, each covering 4 bytes of the address.
fn parse_ipv6_hex(s: &str) -> Result<Ipv6Addr> {
    if s.len() != 32 {
        return Err(Error::Parse(format!("bad ipv6 hex length: {s}")));
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let word_hex = &s[i * 8..(i + 1) * 8];
        let word = u32::from_str_radix(word_hex, 16)
            .map_err(|_| Error::Parse(format!("bad ipv6 word: {word_hex}")))?;
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_ne_bytes());
    }
    Ok(Ipv6Addr::from(bytes))
}

// ── Queue parsing ─────────────────────────────────────────────────────────────

/// Parse "tx_queue:rx_queue" hex field → (send_q, recv_q) bytes.
fn parse_queues(s: &str) -> (Option<u32>, Option<u32>) {
    let Some((tx, rx)) = s.split_once(':') else {
        return (None, None);
    };
    let send = u32::from_str_radix(tx, 16).ok();
    let recv = u32::from_str_radix(rx, 16).ok();
    (send, recv)
}

// ── State parsing ─────────────────────────────────────────────────────────────

fn parse_state(hex: &str) -> Option<State> {
    let n = u8::from_str_radix(hex, 16).ok()?;
    match n {
        0x01 => Some(State::Established),
        0x02 => Some(State::SynSent),
        0x03 => Some(State::SynRecv),
        0x04 => Some(State::FinWait1),
        0x05 => Some(State::FinWait2),
        0x06 => Some(State::TimeWait),
        0x07 => Some(State::Close),
        0x08 => Some(State::CloseWait),
        0x09 => Some(State::LastAck),
        0x0A => Some(State::Listen),
        0x0B => Some(State::Closing),
        _ => None,
    }
}

// ── inode → PID map ───────────────────────────────────────────────────────────

/// Walk `/proc/[pid]/fd/`, find symlinks of the form `socket:[inode]`,
/// and build a map from inode → (pid, process_name).
///
/// Entries for processes we can't read (no permission, or process exited)
/// are silently skipped - the connection will appear with pid=None.
pub(crate) fn build_inode_pid_map() -> Result<HashMap<u64, (u32, String)>> {
    let mut map: HashMap<u64, (u32, String)> = HashMap::new();

    let proc_dir = fs::read_dir("/proc").map_err(Error::Io)?;

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Only numeric directories are PIDs
        let pid: u32 = match name_str.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue;
        }; // no permission or process already gone

        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };

            // Symlink target looks like: socket:[12345]
            let t = target.to_string_lossy();
            if let Some(inode_str) = t.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']'))
                && let Ok(inode) = inode_str.parse::<u64>()
            {
                // First PID that owns the inode wins
                map.entry(inode).or_insert_with(|| {
                    let comm = read_comm(pid);
                    (pid, comm)
                });
            }
        }
    }

    Ok(map)
}

/// Read the process name from `/proc/[pid]/comm` (max 15 chars, kernel-truncated).
fn read_comm(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim_end_matches('\n').to_string())
        .unwrap_or_default()
}

// ── /proc/net/unix parser ─────────────────────────────────────────────────────

/// Parse /proc/net/unix and return Unix domain socket connections.
///
/// Format (columns): Num RefCount Protocol Flags Type St Inode Path
/// We show the socket path as both local and remote (no remote peer concept).
fn parse_proc_net_unix(pid_map: &HashMap<u64, (u32, String)>) -> Result<Vec<Connection>> {
    let path = "/proc/net/unix";
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(Error::Io(e)),
    };

    let mut conns = Vec::new();

    for line in content.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Fields: Num RefCount Protocol Flags Type St Inode [Path]
        let fields: Vec<&str> = line
            .splitn(8, char::is_whitespace)
            .filter(|s| !s.is_empty())
            .collect();
        if fields.len() < 7 {
            continue;
        }

        let inode: u64 = match fields[6].parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        // St field: 01=ESTABLISHED, 03=LISTEN, others
        let st_hex = fields[5];
        let state = match u8::from_str_radix(st_hex, 16).ok() {
            Some(0x01) => Some(State::Established),
            Some(0x02 | 0x03) => Some(State::Listen),
            _ => None,
        };

        // Path is optional (anonymous sockets have none)
        let socket_path = fields.get(7).copied().unwrap_or("(anonymous)").to_string();

        let (pid, process) = pid_map
            .get(&inode)
            .map_or((None, None), |(p, n)| (Some(*p), Some(n.clone())));

        conns.push(Connection {
            proto: Proto::Unix,
            local: socket_path.clone(),
            remote: socket_path,
            state,
            pid,
            process,
            cmdline: None,
            container: None,
            recv_q: None,
            send_q: None,
            inode: Some(inode),
            age_secs: None,
            parent_chain: None,
            systemd_unit: None,
            fd_usage: None,
        });
    }

    Ok(conns)
}

/// Read TCP/UDP connections from a container's network namespace.
/// `ns_pid` is any host PID running inside the target container.
/// `pid_map` is the global inode→(pid,name) map built from all host processes.
/// `container_name` is set on each returned Connection.
pub(crate) fn get_connections_in_namespace(
    ns_pid: u32,
    container_name: &str,
    pid_map: &HashMap<u64, (u32, String)>,
) -> Result<Vec<Connection>> {
    let protos = [
        ("tcp", Proto::Tcp, false),
        ("tcp6", Proto::Tcp, true),
        ("udp", Proto::Udp, false),
        ("udp6", Proto::Udp, true),
    ];
    let conns = protos.iter().try_fold(
        Vec::<Connection>::new(),
        |mut acc, (suffix, proto, ipv6)| -> Result<_> {
            let path = format!("/proc/{ns_pid}/net/{suffix}");
            let mut batch = parse_proc_net(&path, *proto, *ipv6, pid_map)?;
            for c in &mut batch {
                c.container = Some(container_name.to_string());
            }
            acc.extend(batch);
            Ok(acc)
        },
    )?;
    Ok(conns)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_loopback() {
        // 127.0.0.1 stored as little-endian u32 = 0x0100007F
        let ip = parse_ipv4_hex("0100007F").unwrap();
        assert_eq!(ip, Ipv4Addr::LOCALHOST);
    }

    #[test]
    fn test_parse_ipv4_any() {
        let ip = parse_ipv4_hex("00000000").unwrap();
        assert_eq!(ip, Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn test_parse_address_listen() {
        // 0.0.0.0:22 in /proc/net/tcp format
        let addr = parse_address("00000000:0016", false).unwrap();
        assert_eq!(addr, "0.0.0.0:22");
    }

    #[test]
    fn test_parse_address_zero_port() {
        // remote of a LISTEN socket: 0.0.0.0:0 → 0.0.0.0:*
        let addr = parse_address("00000000:0000", false).unwrap();
        assert_eq!(addr, "0.0.0.0:*");
    }

    #[test]
    fn test_parse_state_listen() {
        assert_eq!(parse_state("0A"), Some(State::Listen));
    }
}
