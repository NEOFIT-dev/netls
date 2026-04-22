use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(target_os = "linux")]
use crate::{Connection, Result};

const SOCKET_TIMEOUT: Duration = Duration::from_secs(2);

// ── Common (Docker-compatible HTTP API; both runtimes) ────────────────────────

/// Probe well-known socket locations for Docker and Podman, returning every
/// endpoint that currently exists.
fn discover_sockets() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = vec![
        PathBuf::from("/var/run/docker.sock"),
        PathBuf::from("/run/podman/podman.sock"),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        paths.push(PathBuf::from(&home).join(".docker/run/docker.sock"));
    }
    if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
        paths.push(PathBuf::from(&xdg).join("podman/podman.sock"));
    }
    paths.into_iter().filter(|p| p.exists()).collect()
}

fn http_get(socket: &Path, endpoint: &str) -> std::io::Result<String> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(SOCKET_TIMEOUT))?;
    stream.set_write_timeout(Some(SOCKET_TIMEOUT))?;
    let req = format!("GET {endpoint} HTTP/1.0\r\nHost: localhost\r\n\r\n");
    stream.write_all(req.as_bytes())?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    Ok(response.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

// ── Container listing ─────────────────────────────────────────────────────────

struct ContainerInfo {
    #[allow(dead_code)]
    id: String,
    name: String,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    ips: Vec<String>,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    published_ports: Vec<u16>,
}

/// Fetch and parse the container list from a single socket.
/// Both Docker and Podman expose `/containers/json` with the same schema.
fn list_from_socket(socket: &Path) -> std::io::Result<Vec<ContainerInfo>> {
    let body = http_get(socket, "/containers/json")?;
    let containers: Vec<serde_json::Value> = serde_json::from_str(&body)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    Ok(containers
        .iter()
        .filter_map(|c| {
            let id = c["Id"].as_str()?.to_string();
            let name = c["Labels"]["com.docker.compose.service"]
                .as_str()
                .or_else(|| {
                    c["Names"]
                        .as_array()
                        .and_then(|n| n.first())
                        .and_then(|n| n.as_str())
                        .map(|n| n.trim_start_matches('/'))
                })?
                .to_string();

            let ips: Vec<String> = c["NetworkSettings"]["Networks"]
                .as_object()
                .map(|nets| {
                    nets.values()
                        .filter_map(|n| n["IPAddress"].as_str())
                        .filter(|ip| !ip.is_empty())
                        .map(std::string::ToString::to_string)
                        .collect()
                })
                .unwrap_or_default();

            let published_ports: Vec<u16> = c["Ports"]
                .as_array()
                .map(|ports| {
                    ports
                        .iter()
                        .filter_map(|p| {
                            p["PublicPort"].as_u64().and_then(|n| u16::try_from(n).ok())
                        })
                        .collect()
                })
                .unwrap_or_default();

            Some(ContainerInfo {
                id,
                name,
                ips,
                published_ports,
            })
        })
        .collect())
}

/// List containers across every discovered runtime socket, merging results.
/// A failing socket is skipped silently (the others may still succeed).
fn list_containers() -> Vec<(PathBuf, ContainerInfo)> {
    let mut all = Vec::new();
    for socket in discover_sockets() {
        if let Ok(containers) = list_from_socket(&socket) {
            for c in containers {
                all.push((socket.clone(), c));
            }
        }
    }
    all
}

/// Inspect a container and return the host PID of its main process.
/// Uses `/containers/<id>/json -> State.Pid`, which is consistent across
/// Docker and Podman and returns a host-namespace PID (unlike `/top`,
/// which Podman fills with container-internal PIDs).
#[cfg(target_os = "linux")]
fn container_host_pid(socket: &Path, container_id: &str) -> std::io::Result<u32> {
    let body = http_get(socket, &format!("/containers/{container_id}/json"))?;
    let data: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    data["State"]["Pid"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .filter(|&p| p > 0)
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "container has no host PID")
        })
}

// ── Public (crate-internal) API ───────────────────────────────────────────────

/// Build a map of container IP -> compose service name (or container name as fallback).
/// Returns empty map on any error.
#[cfg(target_os = "linux")]
#[must_use]
pub(crate) fn container_ip_to_service() -> HashMap<String, String> {
    list_containers()
        .into_iter()
        .flat_map(|(_, c)| c.ips.into_iter().map(move |ip| (ip, c.name.clone())))
        .collect()
}

/// Build a map of host published port -> container name.
#[cfg(target_os = "macos")]
#[must_use]
pub(crate) fn container_published_ports() -> HashMap<u16, String> {
    list_containers()
        .into_iter()
        .flat_map(|(_, c)| {
            c.published_ports
                .into_iter()
                .map(move |port| (port, c.name.clone()))
        })
        .collect()
}

/// Collect connections from inside every container reported by any
/// discovered runtime (Docker, Podman). Requires permission to read
/// `/proc/<pid>/net/*` for foreign processes.
///
/// # Errors
///
/// Fails only when the host inode-to-PID map cannot be built (procfs
/// unreadable). Per-container failures are silently skipped.
#[cfg(target_os = "linux")]
pub(crate) fn get_container_connections() -> Result<Vec<Connection>> {
    let containers = list_containers();
    if containers.is_empty() {
        return Ok(vec![]);
    }

    let pid_map = crate::platform::linux::build_inode_pid_map()?;
    let mut result = Vec::new();

    for (socket, container) in &containers {
        let Ok(pid) = container_host_pid(socket, &container.id) else {
            continue;
        };
        if let Ok(conns) =
            crate::platform::linux::get_connections_in_namespace(pid, &container.name, &pid_map)
        {
            result.extend(conns);
        }
    }

    Ok(result)
}

// ── Docker-specific helpers ───────────────────────────────────────────────────
// docker-proxy is a Docker-only mechanism for host-port publishing. Podman
// uses slirp4netns / pasta and has no equivalent userland process.

/// Parse `-container-ip <IP>` from a docker-proxy cmdline (null-separated args).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[must_use]
pub(crate) fn parse_docker_proxy_ip(cmdline: &[u8]) -> Option<String> {
    let args: Vec<&str> = cmdline
        .split(|&b| b == 0)
        .filter_map(|s| std::str::from_utf8(s).ok())
        .collect();
    let pos = args.iter().position(|&a| a == "-container-ip")?;
    let ip = args.get(pos + 1)?;
    if ip.is_empty() {
        None
    } else {
        Some((*ip).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmdline(args: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for arg in args {
            out.extend_from_slice(arg.as_bytes());
            out.push(0);
        }
        out
    }

    #[test]
    fn parse_docker_proxy_ip_found() {
        let raw = cmdline(&[
            "/usr/bin/docker-proxy",
            "-container-ip",
            "172.17.0.2",
            "-container-port",
            "80",
        ]);
        assert_eq!(parse_docker_proxy_ip(&raw), Some("172.17.0.2".to_string()));
    }

    #[test]
    fn parse_docker_proxy_ip_missing_flag() {
        let raw = cmdline(&["/usr/bin/docker-proxy", "-host-ip", "0.0.0.0"]);
        assert_eq!(parse_docker_proxy_ip(&raw), None);
    }

    #[test]
    fn parse_docker_proxy_ip_flag_at_end() {
        let raw = cmdline(&["/usr/bin/docker-proxy", "-container-ip"]);
        assert_eq!(parse_docker_proxy_ip(&raw), None);
    }
}
