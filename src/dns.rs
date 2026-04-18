#[cfg(unix)]
extern crate libc;

use crate::{Connection, Proto};

/// Resolve remote IP addresses to hostnames in-place.
/// Skips wildcard (`*`), loopback, and addresses that fail to resolve.
/// May be slow - each unique remote IP triggers a reverse DNS lookup.
pub fn resolve_dns(conns: &mut [Connection]) {
    use std::collections::HashMap;

    let mut cache: HashMap<String, String> = HashMap::new();

    for c in conns.iter_mut() {
        if c.remote.ends_with(":*") || c.proto == Proto::Unix {
            continue;
        }
        if crate::is_loopback(&c.remote) {
            continue;
        }

        let ip_part = extract_ip(&c.remote);
        if ip_part.is_empty() {
            continue;
        }

        let hostname = cache
            .entry(ip_part.clone())
            .or_insert_with(|| reverse_lookup(&ip_part));

        if hostname != &ip_part {
            c.remote = c.remote.replacen(&ip_part, hostname, 1);
        }
    }
}

fn extract_ip(addr: &str) -> String {
    if addr.starts_with('[') {
        addr.trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or("")
            .to_string()
    } else {
        addr.rsplit_once(':')
            .map(|(ip, _)| ip.to_string())
            .unwrap_or_default()
    }
}

/// Timeout for a single reverse DNS lookup.
const DNS_LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Reverse DNS lookup via getnameinfo (Unix) or no-op (other platforms).
/// Runs in a separate thread with a timeout to avoid blocking indefinitely.
fn reverse_lookup(ip: &str) -> String {
    let ip_owned = ip.to_string();
    let (tx, rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        let result = reverse_lookup_blocking(&ip_owned);
        let _ = tx.send(result);
    });

    rx.recv_timeout(DNS_LOOKUP_TIMEOUT)
        .unwrap_or_else(|_| ip.to_string())
}

/// Blocking reverse DNS lookup - called inside a dedicated thread.
fn reverse_lookup_blocking(ip: &str) -> String {
    #[cfg(unix)]
    {
        use std::ffi::CStr;
        use std::net::IpAddr;

        let Ok(addr) = ip.parse::<IpAddr>() else {
            return ip.to_string();
        };

        let mut host = [0i8; 256];

        let ret = match addr {
            IpAddr::V4(v4) => {
                let sa = libc::sockaddr_in {
                    #[cfg(target_os = "macos")]
                    sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: 0,
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(v4.octets()),
                    },
                    sin_zero: [0; 8],
                };
                // SAFETY: `sa` is a valid, fully-initialized `sockaddr_in` on the stack.
                // The size argument matches `sockaddr_in` exactly. `host` is a
                // 256-byte buffer whose length is passed to getnameinfo. We only
                // read `host` after a successful (ret == 0) return.
                unsafe {
                    call_getnameinfo(
                        std::ptr::addr_of!(sa) as *const libc::sockaddr,
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                        &mut host,
                    )
                }
            }
            IpAddr::V6(v6) => {
                let sa = libc::sockaddr_in6 {
                    #[cfg(target_os = "macos")]
                    sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: libc::in6_addr {
                        s6_addr: v6.octets(),
                    },
                    sin6_scope_id: 0,
                };
                // SAFETY: `sa` is a valid, fully-initialized `sockaddr_in6` on the stack.
                // The size argument matches `sockaddr_in6` exactly. `host` is a
                // 256-byte buffer whose length is passed to getnameinfo. We only
                // read `host` after a successful (ret == 0) return.
                unsafe {
                    call_getnameinfo(
                        std::ptr::addr_of!(sa) as *const libc::sockaddr,
                        std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                        &mut host,
                    )
                }
            }
        };

        if ret == 0 {
            // SAFETY: getnameinfo wrote a valid NUL-terminated C string into
            // `host` on success (ret == 0). The buffer is kept alive for the
            // duration of this block.
            unsafe { CStr::from_ptr(host.as_ptr()) }
                .to_string_lossy()
                .into_owned()
        } else {
            ip.to_string()
        }
    }

    #[cfg(not(unix))]
    ip.to_string()
}

/// Thin wrapper around `libc::getnameinfo` that consolidates the repetitive call.
#[cfg(unix)]
unsafe fn call_getnameinfo(
    sa: *const libc::sockaddr,
    sa_len: libc::socklen_t,
    host: &mut [i8; 256],
) -> libc::c_int {
    unsafe {
        libc::getnameinfo(
            sa,
            sa_len,
            host.as_mut_ptr(),
            host.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    }
}
