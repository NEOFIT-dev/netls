use libproc::libproc::file_info::{ListFDs, ProcFDType};
use libproc::libproc::net_info::SocketInfo;
use libproc::libproc::proc_pid;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{compact_addr, Connection, Error, Proto, Result, State};

// proc_pidfdinfo is not wrapped cleanly in libproc 0.14.11 - call it directly.
// proc_fileinfo C layout: fi_openflags(4) + fi_status(4) + fi_offset(8) + fi_type(4) +
// fi_guardflags(4) = 24 bytes. socket_fdinfo = proc_fileinfo + socket_info.
extern "C" {
    fn proc_pidfdinfo(
        pid: libc::c_int,
        fd: libc::c_int,
        flavor: libc::c_int,
        buffer: *mut libc::c_void,
        buffersize: libc::c_int,
    ) -> libc::c_int;
}

const PROC_PIDFDSOCKETINFO: libc::c_int = 3;

#[repr(C)]
struct RawSocketFDInfo {
    _pfi: [u8; 24], // proc_fileinfo (24 bytes on macOS 64-bit)
    psi: SocketInfo,
}

pub fn get_connections() -> Result<Vec<Connection>> {
    #[allow(deprecated)]
    let pids = proc_pid::listpids(proc_pid::ProcType::ProcAllPIDS)
        .map_err(|e| Error::Parse(format!("listpids: {e}")))?;

    let mut conns = Vec::new();

    for pid in pids {
        if pid == 0 {
            continue;
        }

        let name = proc_pid::name(pid as i32).ok();

        let fds = match proc_pid::listpidinfo::<ListFDs>(pid as i32, 1024) {
            Ok(fds) => fds,
            Err(_) => continue, // no permission or process gone
        };

        for fd in &fds {
            if fd.proc_fdtype != ProcFDType::Socket as u32 {
                continue;
            }

            let mut raw = unsafe { std::mem::zeroed::<RawSocketFDInfo>() };
            let ret = unsafe {
                proc_pidfdinfo(
                    pid as libc::c_int,
                    fd.proc_fd,
                    PROC_PIDFDSOCKETINFO,
                    &mut raw as *mut _ as *mut libc::c_void,
                    std::mem::size_of::<RawSocketFDInfo>() as libc::c_int,
                )
            };
            if ret <= 0 {
                continue;
            }

            if let Some(conn) = parse_socket(raw.psi, pid, name.as_deref()) {
                conns.push(conn);
            }
        }
    }

    Ok(conns)
}

fn parse_socket(info: SocketInfo, pid: u32, name: Option<&str>) -> Option<Connection> {
    let si = &info;

    if si.soi_family == libc::AF_UNIX {
        return parse_unix_socket(si, pid, name);
    }

    let ipv6 = match si.soi_family {
        f if f == libc::AF_INET => false,
        f if f == libc::AF_INET6 => true,
        _ => return None,
    };

    let recv_q = Some(si.soi_rcv.sbi_cc);
    let send_q = Some(si.soi_snd.sbi_cc);

    let (proto, local, remote, state) = if si.soi_type == libc::SOCK_STREAM {
        unsafe {
            let tcp = &si.soi_proto.pri_tcp;
            let state = map_tcp_state(tcp.tcpsi_state);
            let local = format_addr(
                ipv6,
                &tcp.tcpsi_ini.insi_laddr as *const _ as *const u8,
                tcp.tcpsi_ini.insi_lport,
            );
            let remote = format_addr(
                ipv6,
                &tcp.tcpsi_ini.insi_faddr as *const _ as *const u8,
                tcp.tcpsi_ini.insi_fport,
            );
            (Proto::Tcp, local, remote, state)
        }
    } else if si.soi_type == libc::SOCK_DGRAM {
        unsafe {
            let udp = &si.soi_proto.pri_in;
            let local = format_addr(
                ipv6,
                &udp.insi_laddr as *const _ as *const u8,
                udp.insi_lport,
            );
            let remote = format_addr(
                ipv6,
                &udp.insi_faddr as *const _ as *const u8,
                udp.insi_fport,
            );
            (Proto::Udp, local, remote, None)
        }
    } else {
        return None;
    };

    Some(Connection {
        proto,
        local,
        remote,
        state,
        pid: Some(pid),
        process: name.map(|s| s.to_string()),
        cmdline: None,
        container: None,
        recv_q,
        send_q,
        inode: None,
        age_secs: None,
        parent_chain: None,
        systemd_unit: None,
        fd_usage: None,
    })
}

fn parse_unix_socket(si: &SocketInfo, pid: u32, name: Option<&str>) -> Option<Connection> {
    if si.soi_type != libc::SOCK_STREAM && si.soi_type != libc::SOCK_DGRAM {
        return None;
    }
    let (local, remote) = unsafe {
        let un = &si.soi_proto.pri_un;
        let local = sun_path_to_str(&un.unsi_addr.ua_sun.sun_path);
        let remote = sun_path_to_str(&un.unsi_caddr.ua_sun.sun_path);
        (local, remote)
    };
    if local == "*" && remote == "*" {
        return None;
    }
    let state = {
        let s = si.soi_state as u16;
        if s & 0x0002 != 0 {
            Some(crate::State::Listen)
        } else if s & 0x0004 != 0 {
            Some(crate::State::Established)
        } else {
            None
        }
    };
    Some(Connection {
        proto: Proto::Unix,
        local,
        remote,
        state,
        pid: Some(pid),
        process: name.map(|s| s.to_string()),
        cmdline: None,
        container: None,
        recv_q: None,
        send_q: None,
        inode: None,
        age_secs: None,
        parent_chain: None,
        systemd_unit: None,
        fd_usage: None,
    })
}

fn sun_path_to_str(path: &[libc::c_char]) -> String {
    let bytes: Vec<u8> = path
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| b as u8)
        .collect();
    if bytes.is_empty() {
        "*".to_string()
    } else {
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

// macOS TCP states (netinet/tcp_fsm.h)
fn map_tcp_state(state: i32) -> Option<State> {
    match state {
        1 => Some(State::Listen),
        2 => Some(State::SynSent),
        3 => Some(State::SynRecv),
        4 => Some(State::Established),
        5 => Some(State::CloseWait),
        6 => Some(State::FinWait1),
        7 => Some(State::Closing),
        8 => Some(State::LastAck),
        9 => Some(State::FinWait2),
        10 => Some(State::TimeWait),
        _ => None,
    }
}

// Ports are stored in network byte order (big-endian) in in_sockinfo.
// in_addr_4in6_t memory layout:
//   IPv4: [u32 pad; 3][u32 s_addr]  → s_addr at byte offset 12
//   IPv6: [u8; 16]                  → bytes at offset 0
unsafe fn format_addr(ipv6: bool, addr_ptr: *const u8, port: i32) -> String {
    let port_u = u16::from_be(port as u16);
    let port_str = if port_u == 0 {
        "*".to_string()
    } else {
        port_u.to_string()
    };

    let raw = if ipv6 {
        let bytes = *(addr_ptr as *const [u8; 16]);
        let ip = Ipv6Addr::from(bytes);
        format!("[{ip}]:{port_str}")
    } else {
        let s_addr = *(addr_ptr.add(12) as *const u32);
        let ip = Ipv4Addr::from(u32::from_be(s_addr));
        format!("{ip}:{port_str}")
    };
    compact_addr(&raw)
}
