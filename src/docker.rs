use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use crate::{Connection, Result};

const DOCKER_SOCKET: &str = "/var/run/docker.sock";
const DOCKER_SOCKET_FALLBACK: &str = ".docker/run/docker.sock"; // relative to $HOME

// ── docker-proxy helpers ──────────────────────────────────────────────────────

/// Parse `-container-ip <IP>` from a docker-proxy cmdline (null-separated args).
pub fn parse_container_ip(cmdline: &[u8]) -> Option<String> {
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

/// Build a map of container IP → compose service name (or container name as fallback).
/// Returns empty map on any error.
pub fn container_ip_to_service() -> HashMap<String, String> {
    list_containers()
        .ok()
        .map(|containers| {
            containers
                .into_iter()
                .flat_map(|c| c.ips.into_iter().map(move |ip| (ip, c.name.clone())))
                .collect()
        })
        .unwrap_or_default()
}

/// Build a map of host published port → container name.
/// Used on platforms where container namespaces are not accessible (e.g. macOS).
pub fn container_published_ports() -> HashMap<u16, String> {
    list_containers()
        .ok()
        .map(|containers| {
            containers
                .into_iter()
                .flat_map(|c| {
                    c.published_ports
                        .into_iter()
                        .map(move |port| (port, c.name.clone()))
                })
                .collect()
        })
        .unwrap_or_default()
}

// ── Container listing ─────────────────────────────────────────────────────────

struct ContainerInfo {
    #[allow(dead_code)]
    id: String,
    name: String,
    ips: Vec<String>,
    published_ports: Vec<u16>,
}

fn list_containers() -> std::io::Result<Vec<ContainerInfo>> {
    let body = docker_get("/containers/json")?;
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
                        .filter_map(|p| p["PublicPort"].as_u64().map(|n| n as u16))
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

/// Return the first host PID of any process running inside the container.
#[cfg(target_os = "linux")]
fn container_host_pid(container_id: &str) -> std::io::Result<u32> {
    let body = docker_get(&format!("/containers/{container_id}/top?ps_args=-o%20pid"))?;
    let data: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    data["Processes"]
        .as_array()
        .and_then(|rows| rows.first())
        .and_then(|row| row.as_array())
        .and_then(|cols| cols.first())
        .and_then(|v| v.as_str())
        .and_then(|s| s.trim().parse::<u32>().ok())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "no processes in container")
        })
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Collect connections from all running Docker containers.
/// Requires root to read `/proc/<pid>/net/tcp` for foreign processes.
/// Returns empty vec on any error (Docker not running, no permission, etc.).
#[cfg(target_os = "linux")]
pub fn get_container_connections() -> Result<Vec<Connection>> {
    let Ok(containers) = list_containers() else {
        return Ok(vec![]);
    };

    let pid_map = crate::platform::linux::build_inode_pid_map()?;
    let mut result = Vec::new();

    for container in &containers {
        let Ok(pid) = container_host_pid(&container.id) else {
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

/// Always returns an empty Vec on non-Linux platforms (no `/proc/<pid>/net/`).
#[cfg(not(target_os = "linux"))]
pub fn get_container_connections() -> Result<Vec<Connection>> {
    Ok(vec![])
}

// ── HTTP helper ───────────────────────────────────────────────────────────────

fn docker_socket_path() -> std::path::PathBuf {
    let primary = std::path::Path::new(DOCKER_SOCKET);
    if primary.exists() {
        return primary.to_path_buf();
    }
    if let Some(home) = std::env::var_os("HOME") {
        let fallback = std::path::Path::new(&home).join(DOCKER_SOCKET_FALLBACK);
        if fallback.exists() {
            return fallback;
        }
    }
    primary.to_path_buf()
}

fn docker_get(path: &str) -> std::io::Result<String> {
    let mut stream = UnixStream::connect(docker_socket_path())?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n");
    stream.write_all(req.as_bytes())?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    Ok(response.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
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
    fn parse_container_ip_found() {
        let raw = cmdline(&[
            "/usr/bin/docker-proxy",
            "-container-ip",
            "172.17.0.2",
            "-container-port",
            "80",
        ]);
        assert_eq!(parse_container_ip(&raw), Some("172.17.0.2".to_string()));
    }

    #[test]
    fn parse_container_ip_missing_flag() {
        let raw = cmdline(&["/usr/bin/docker-proxy", "-host-ip", "0.0.0.0"]);
        assert_eq!(parse_container_ip(&raw), None);
    }

    #[test]
    fn parse_container_ip_flag_at_end() {
        let raw = cmdline(&["/usr/bin/docker-proxy", "-container-ip"]);
        assert_eq!(parse_container_ip(&raw), None);
    }
}
