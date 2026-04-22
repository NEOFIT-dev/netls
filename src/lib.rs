#![warn(missing_docs)]

//! `netls` is a network connections viewer for daily use and automation.
//!
//! This crate exposes the same functionality as the `netls` CLI tool through
//! a programmatic API. The entry points are [`snapshot`] (gathered with a
//! [`Filter`]) and the various `enrich_*` functions that populate optional
//! fields on each [`Connection`].

/// Configuration file (TOML) loading: `[defaults]`, `[profiles.<name>]`, `[ports]`.
pub mod config;
/// Reverse-DNS resolution helpers (internal; re-exported as [`resolve_dns`]).
pub(crate) mod dns;
/// Per-platform connection collection; wrapped by [`snapshot`].
pub(crate) mod platform;
/// Container runtime (Docker, Podman) metadata; wrapped by
/// [`snapshot_with_containers`].
pub(crate) mod runtime;

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use thiserror::Error;

pub use dns::resolve_dns;

/// Connection states accepted by `--state` and the `state` config field.
pub const VALID_STATES: &[&str] = &[
    "established",
    "listen",
    "syn_sent",
    "syn_recv",
    "fin_wait1",
    "fin_wait2",
    "time_wait",
    "close",
    "close_wait",
    "last_ack",
    "closing",
];

/// Protocols accepted by `--proto` and the `proto` config field.
pub const VALID_PROTOS: &[&str] = &["tcp", "udp", "unix", "raw", "icmp"];

/// Columns accepted by `--sort` and the `sort` config field.
pub const VALID_SORT: &[&str] = &[
    "proto", "local", "remote", "state", "pid", "process", "port",
];

/// Fields accepted by `--group-by` and the `group_by` config field.
pub const VALID_GROUP_BY: &[&str] = &["remote-ip", "process", "port", "proto"];

/// Populate `cmdline` field for each connection.
/// On Linux: reads `/proc/<pid>/cmdline` (full args joined with spaces).
/// On macOS: uses `pidpath()` to get the full binary path.
#[cfg(target_os = "linux")]
pub fn enrich_cmdline(conns: &mut [Connection]) {
    for c in conns.iter_mut() {
        let Some(pid) = c.pid else { continue };
        let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        let cmdline = raw
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        if !cmdline.is_empty() {
            c.cmdline = Some(cmdline);
        }
    }
}

/// macOS variant: see top-level [`enrich_cmdline`].
#[cfg(target_os = "macos")]
pub fn enrich_cmdline(conns: &mut [Connection]) {
    platform::macos_enrich::enrich_cmdline(conns);
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn enrich_cmdline(_conns: &mut [Connection]) {}

/// Populate `fd_usage` for each connection: (open_fds, soft_limit).
/// On Linux: reads `/proc/<pid>/fd/` and `/proc/<pid>/limits`.
/// On macOS: uses `listpidinfo::<ListFDs>` and `getrlimit`.
#[cfg(target_os = "linux")]
pub fn enrich_fd(conns: &mut [Connection]) {
    let mut cache: std::collections::HashMap<u32, FdUsage> = std::collections::HashMap::new();
    for c in conns.iter_mut() {
        let Some(pid) = c.pid else { continue };
        let usage = cache.entry(pid).or_insert_with(|| {
            let open =
                std::fs::read_dir(format!("/proc/{pid}/fd")).map_or(0, std::iter::Iterator::count);
            FdUsage {
                open,
                soft_limit: read_fd_limit(pid),
            }
        });
        c.fd_usage = Some(*usage);
    }
}

#[cfg(target_os = "linux")]
fn read_fd_limit(pid: u32) -> Option<usize> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/limits")).ok()?;
    for line in content.lines() {
        if line.starts_with("Max open files") {
            // "Max open files          1024  4096  files"
            let mut parts = line.split_whitespace().skip(3);
            return parts.next()?.parse().ok();
        }
    }
    None
}

/// macOS variant: see top-level [`enrich_fd`].
#[cfg(target_os = "macos")]
pub fn enrich_fd(conns: &mut [Connection]) {
    platform::macos_enrich::enrich_fd(conns);
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn enrich_fd(_conns: &mut [Connection]) {}

/// Populate `systemd_unit` for each connection from `/proc/<pid>/cgroup`.
/// Extracts the last path component ending in ".service", ".scope", or ".slice".
/// Not applicable on macOS (uses launchd).
#[cfg(target_os = "linux")]
pub fn enrich_systemd(conns: &mut [Connection]) {
    for c in conns.iter_mut() {
        let Some(pid) = c.pid else { continue };
        c.systemd_unit = read_systemd_unit(pid);
    }
}

#[cfg(target_os = "linux")]
fn read_systemd_unit(pid: u32) -> Option<String> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    // Format: "0::/path/to/unit.service\n" (cgroups v2) or "1:name:/path\n" (v1)
    for line in content.lines() {
        let path = if let Some(rest) = line.strip_prefix("0::") {
            rest
        } else {
            line.splitn(3, ':').nth(2)?
        };
        if let Some(unit) = path.rsplit('/').find(|s| {
            s.ends_with(".service")
                || std::path::Path::new(s)
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("scope"))
                || std::path::Path::new(s)
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("slice"))
        }) {
            return Some(unit.to_string());
        }
    }
    None
}

/// No-op on non-Linux platforms (systemd is Linux-specific).
#[cfg(not(target_os = "linux"))]
pub fn enrich_systemd(_conns: &mut [Connection]) {}

/// Populate `parent_chain` for each connection.
/// On Linux: walks PPid links in `/proc/<pid>/status`.
/// On macOS: uses `BSDInfo.pbi_ppid` via libproc.
/// Result format: "parent <- grandparent <- ..." (up to 4 levels).
#[cfg(target_os = "linux")]
pub fn enrich_process_tree(conns: &mut [Connection]) {
    for c in conns.iter_mut() {
        let Some(pid) = c.pid else { continue };
        let chain = build_parent_chain(pid);
        if !chain.is_empty() {
            c.parent_chain = Some(chain);
        }
    }
}

#[cfg(target_os = "linux")]
fn read_proc_status(pid: u32) -> Option<(u32, String)> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let mut name = String::new();
    let mut ppid: u32 = 0;
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("Name:\t") {
            name = v.to_string();
        }
        if let Some(v) = line.strip_prefix("PPid:\t") {
            ppid = v.trim().parse().unwrap_or(0);
        }
    }
    if ppid == 0 || name.is_empty() {
        None
    } else {
        Some((ppid, name))
    }
}

#[cfg(target_os = "linux")]
fn build_parent_chain(pid: u32) -> String {
    let mut parts = Vec::new();
    // Start from the direct parent of pid, not pid itself
    let Some((mut current, _)) = read_proc_status(pid) else {
        return String::new();
    };
    for _ in 0..4 {
        if current <= 1 {
            break;
        }
        let Some((ppid, name)) = read_proc_status(current) else {
            break;
        };
        parts.push(name);
        current = ppid;
    }
    parts.join(" <- ")
}

/// macOS variant: see top-level [`enrich_process_tree`].
#[cfg(target_os = "macos")]
pub fn enrich_process_tree(conns: &mut [Connection]) {
    platform::macos_enrich::enrich_process_tree(conns);
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn enrich_process_tree(_conns: &mut [Connection]) {}

/// Populate `age_secs` for each connection by reading the mtime of the socket fd
/// in `/proc/<pid>/fd/`. Uses the stored inode to find the exact fd symlink.
/// Linux only - no clean equivalent on macOS.
#[cfg(target_os = "linux")]
pub fn enrich_age(conns: &mut [Connection]) {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    for c in conns.iter_mut() {
        let (Some(pid), Some(inode)) = (c.pid, c.inode) else {
            continue;
        };
        let fd_dir = format!("/proc/{pid}/fd");
        let target_str = format!("socket:[{inode}]");
        let Ok(entries) = std::fs::read_dir(&fd_dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(link) = std::fs::read_link(entry.path()) else {
                continue;
            };
            if link.to_string_lossy() != target_str {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            let Ok(modified) = meta.modified() else {
                continue;
            };
            let Ok(mtime) = modified.duration_since(SystemTime::UNIX_EPOCH) else {
                continue;
            };
            c.age_secs = Some(now.saturating_sub(mtime.as_secs()));
            break;
        }
    }
}

/// No-op on non-Linux platforms (age relies on `/proc/<pid>/fd/` mtime).
#[cfg(not(target_os = "linux"))]
pub fn enrich_age(_conns: &mut [Connection]) {}

/// Format age in seconds as a human-readable string: "5s", "3m12s", "2h34m", "1d3h".
#[must_use]
pub fn fmt_age(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d{}h", secs / 86400, (secs % 86400) / 3600)
    }
}

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors returned by `netls` library functions.
#[non_exhaustive]
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("platform not supported")]
    UnsupportedPlatform,
    /// Failed to parse a byte / text representation of connection data
    /// (e.g. `/proc/net/tcp` line, macOS libproc struct).
    #[error("parse error: {message}")]
    Parse {
        /// Human-readable description of what failed to parse.
        message: String,
    },
}

/// Convenience alias for `std::result::Result<T, netls::Error>`.
pub type Result<T> = std::result::Result<T, Error>;

// ── Types ─────────────────────────────────────────────────────────────────────

/// Transport protocol of a connection.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[allow(missing_docs)]
pub enum Proto {
    Tcp,
    Udp,
    Unix,
    /// Raw IP socket (`SOCK_RAW`). Used by `CAP_NET_RAW` tools like
    /// `tcpdump`, routing daemons (bird, FRR), and nmap. The `state`
    /// field is always `None`.
    Raw,
    /// ICMP datagram socket (`SOCK_DGRAM` + `IPPROTO_ICMP` or `IPPROTO_ICMPV6`).
    /// Used by `blackbox_exporter`, Kubernetes probes, Go `net/icmp`
    /// monitors, and any tool that does unprivileged ICMP without
    /// `CAP_NET_RAW`. The `state` field is always `None`.
    Icmp,
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Proto::Tcp => write!(f, "tcp"),
            Proto::Udp => write!(f, "udp"),
            Proto::Unix => write!(f, "unix"),
            Proto::Raw => write!(f, "raw"),
            Proto::Icmp => write!(f, "icmp"),
        }
    }
}

impl std::str::FromStr for Proto {
    type Err = ParseEnumError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "tcp" => Ok(Proto::Tcp),
            "udp" => Ok(Proto::Udp),
            "unix" => Ok(Proto::Unix),
            "raw" => Ok(Proto::Raw),
            "icmp" => Ok(Proto::Icmp),
            _ => Err(ParseEnumError {
                kind: "proto",
                value: s.to_string(),
                allowed: VALID_PROTOS,
            }),
        }
    }
}

/// TCP connection state. Mirrors the standard TCP state machine
/// (RFC 793). Only meaningful for `Proto::Tcp`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(missing_docs)]
pub enum State {
    Established,
    Listen,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Closing,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            State::Established => "ESTABLISHED",
            State::Listen => "LISTEN",
            State::SynSent => "SYN_SENT",
            State::SynRecv => "SYN_RECV",
            State::FinWait1 => "FIN_WAIT1",
            State::FinWait2 => "FIN_WAIT2",
            State::TimeWait => "TIME_WAIT",
            State::Close => "CLOSE",
            State::CloseWait => "CLOSE_WAIT",
            State::LastAck => "LAST_ACK",
            State::Closing => "CLOSING",
        };
        write!(f, "{s}")
    }
}

impl std::str::FromStr for State {
    type Err = ParseEnumError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "established" => Ok(State::Established),
            "listen" => Ok(State::Listen),
            "syn_sent" => Ok(State::SynSent),
            "syn_recv" => Ok(State::SynRecv),
            "fin_wait1" => Ok(State::FinWait1),
            "fin_wait2" => Ok(State::FinWait2),
            "time_wait" => Ok(State::TimeWait),
            "close" => Ok(State::Close),
            "close_wait" => Ok(State::CloseWait),
            "last_ack" => Ok(State::LastAck),
            "closing" => Ok(State::Closing),
            _ => Err(ParseEnumError {
                kind: "state",
                value: s.to_string(),
                allowed: VALID_STATES,
            }),
        }
    }
}

/// Error returned when a string cannot be parsed into one of the
/// library's enum types (`Proto`, `State`, `SortKey`).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseEnumError {
    /// Name of the target enum (e.g. `"proto"`, `"state"`).
    pub kind: &'static str,
    /// The input string that failed to parse.
    pub value: String,
    /// Accepted lowercase spellings.
    pub allowed: &'static [&'static str],
}

impl fmt::Display for ParseEnumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid {} value {:?}. Valid values: {}",
            self.kind,
            self.value,
            self.allowed.join(", ")
        )
    }
}

impl std::error::Error for ParseEnumError {}

/// A single network connection.
///
/// Marked `#[non_exhaustive]`: additional fields may be added in future
/// minor releases. Construct via [`snapshot`] / [`snapshot_all`] rather
/// than struct literal.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    /// Transport protocol.
    pub proto: Proto,
    /// Local endpoint as `addr:port`, or socket path for Unix sockets.
    ///
    /// Stable format: IPv4 is `1.2.3.4:PORT`, IPv6 is `[::1]:PORT` with
    /// square brackets. No IPv6 scope id / zone suffix. Port `*` marks
    /// wildcards. Use [`compact_addr`] for human-friendly rendering.
    pub local: String,
    /// Remote endpoint, same format as [`local`](Self::local). `0.0.0.0:*`
    /// or `[::]:*` for listening sockets.
    pub remote: String,
    /// TCP state. `None` for UDP and Unix sockets.
    pub state: Option<State>,
    /// Owning process ID, when known.
    pub pid: Option<u32>,
    /// Owning process short name (e.g. `nginx`), when known.
    pub process: Option<String>,
    /// Full command line from `/proc/<pid>/cmdline`. Populated only when --cmdline is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,
    /// Docker container name. Populated only when --containers is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// Receive queue size in bytes (from /proc/net/tcp). None for UDP/Unix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recv_q: Option<u32>,
    /// Send queue size in bytes (from /proc/net/tcp). None for UDP/Unix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub send_q: Option<u32>,
    /// Internal. Not part of the stable public API.
    #[serde(skip)]
    #[doc(hidden)]
    pub inode: Option<u64>,
    /// Approximate connection age in seconds. Populated only with --age.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_secs: Option<u64>,
    /// Parent process chain, e.g. "bash <- tmux". Populated only with --tree.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_chain: Option<String>,
    /// systemd unit name, e.g. "nginx.service". Populated only with --systemd.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub systemd_unit: Option<String>,
    /// Open file-descriptor usage. Populated only with --fd.
    #[serde(skip)]
    pub fd_usage: Option<FdUsage>,
}

/// Stable identity key for a [`Connection`].
/// Internal representation is opaque; only [`Display`](fmt::Display),
/// [`Hash`](std::hash::Hash), and equality are guaranteed.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ConnectionKey(String);

impl fmt::Display for ConnectionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for ConnectionKey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::borrow::Borrow<str> for ConnectionKey {
    fn borrow(&self) -> &str {
        &self.0
    }
}

/// Open file descriptors and the soft limit for a process.
/// Populated on a [`Connection`] by [`enrich_fd`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdUsage {
    /// Currently open file-descriptor count.
    pub open: usize,
    /// Soft limit from `RLIMIT_NOFILE` / `/proc/<pid>/limits`.
    /// `None` when the limit could not be read.
    pub soft_limit: Option<usize>,
}

impl Connection {
    /// Minimal constructor: required identity fields only. All other fields
    /// start as `None` and can be set directly (they are `pub`).
    #[must_use]
    pub fn new(proto: Proto, local: impl Into<String>, remote: impl Into<String>) -> Self {
        Self {
            proto,
            local: local.into(),
            remote: remote.into(),
            state: None,
            pid: None,
            process: None,
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

    /// Stable identity key for this connection. Used as the lookup key in
    /// [`diff_connections`] and [`resolve_proxy_origins`].
    #[must_use]
    pub fn key(&self) -> ConnectionKey {
        ConnectionKey(format!("{}|{}|{}", self.proto, self.local, self.remote))
    }

    /// Returns true if `query` matches any visible field (case-insensitive).
    #[must_use]
    pub fn text_matches(&self, query: &str) -> bool {
        if query.is_empty() {
            return true;
        }
        let q = query.to_ascii_lowercase();
        self.proto.to_string().contains(&q)
            || self.local.to_ascii_lowercase().contains(&q)
            || self.remote.to_ascii_lowercase().contains(&q)
            || self
                .state
                .is_some_and(|s| s.to_string().to_ascii_lowercase().contains(&q))
            || self
                .process
                .as_deref()
                .is_some_and(|p| p.to_ascii_lowercase().contains(&q))
    }
}

// ── Filter ────────────────────────────────────────────────────────────────────

/// Builder-style filter for [`snapshot`].
///
/// ```
/// use netls::{Filter, Proto, State};
/// let f = Filter::default().proto(Proto::Tcp).state(State::Listen);
/// ```
#[derive(Default)]
pub struct Filter {
    port: Option<u16>,
    pid: Option<u32>,
    process: Option<String>,
    state: Option<State>,
    proto: Option<Proto>,
    no_loopback: bool,
    ipv4_only: bool,
    ipv6_only: bool,
    no_unix: bool,
}

impl Filter {
    /// Filter by local or remote port number.
    #[must_use]
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Filter by owning process ID.
    #[must_use]
    pub fn pid(mut self, pid: u32) -> Self {
        self.pid = Some(pid);
        self
    }

    /// Filter by process name (case-insensitive substring match).
    #[must_use]
    pub fn process(mut self, name: impl Into<String>) -> Self {
        self.process = Some(name.into().to_lowercase());
        self
    }

    /// Filter by connection state.
    #[must_use]
    pub fn state(mut self, state: State) -> Self {
        self.state = Some(state);
        self
    }

    /// Filter by protocol.
    #[must_use]
    pub fn proto(mut self, proto: Proto) -> Self {
        self.proto = Some(proto);
        self
    }

    /// Exclude loopback connections (127.x.x.x and ::1).
    #[must_use]
    pub fn no_loopback(mut self) -> Self {
        self.no_loopback = true;
        self
    }

    /// Restrict output to IPv4 connections.
    #[must_use]
    pub fn ipv4_only(mut self) -> Self {
        self.ipv4_only = true;
        self
    }

    /// Restrict output to IPv6 connections.
    #[must_use]
    pub fn ipv6_only(mut self) -> Self {
        self.ipv6_only = true;
        self
    }

    /// Exclude Unix domain sockets from results.
    #[must_use]
    pub fn no_unix(mut self) -> Self {
        self.no_unix = true;
        self
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Return a snapshot of current network connections, optionally filtered.
///
/// # Errors
///
/// Propagates I/O errors from the platform layer: failure to read
/// `/proc/net/*` on Linux or `proc_listpidinfo` on macOS.
pub fn snapshot(filter: &Filter) -> Result<Vec<Connection>> {
    let all = platform::get_connections()?;
    Ok(apply_filter(all, filter))
}

/// Return all connections without any filtering.
/// Used internally for proxy chain analysis which needs the full picture.
///
/// # Errors
///
/// Same conditions as [`snapshot`].
pub fn snapshot_all() -> Result<Vec<Connection>> {
    platform::get_connections()
}

/// Sort connections in-place by one of the supported keys.
pub fn sort_connections(conns: &mut [Connection], by: SortKey) {
    match by {
        SortKey::Proto => conns.sort_by_key(|c| c.proto),
        SortKey::Local => conns.sort_by(|a, b| a.local.cmp(&b.local)),
        SortKey::Remote => conns.sort_by(|a, b| a.remote.cmp(&b.remote)),
        SortKey::State => conns.sort_by_key(|c| c.state),
        SortKey::Pid => conns.sort_by_key(|c| c.pid),
        SortKey::Process => conns.sort_by(|a, b| {
            a.process
                .as_deref()
                .unwrap_or("")
                .cmp(b.process.as_deref().unwrap_or(""))
        }),
        SortKey::Port => conns.sort_by_key(|c| extract_port(&c.local).unwrap_or(0)),
    }
}

/// Column key accepted by [`sort_connections`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum SortKey {
    Proto,
    Local,
    Remote,
    State,
    Pid,
    Process,
    Port,
}

impl std::str::FromStr for SortKey {
    type Err = ParseEnumError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "proto" => Ok(SortKey::Proto),
            "local" => Ok(SortKey::Local),
            "remote" => Ok(SortKey::Remote),
            "state" => Ok(SortKey::State),
            "pid" => Ok(SortKey::Pid),
            "process" => Ok(SortKey::Process),
            "port" => Ok(SortKey::Port),
            _ => Err(ParseEnumError {
                kind: "sort",
                value: s.to_string(),
                allowed: VALID_SORT,
            }),
        }
    }
}

/// A single entry returned by [`top_connections`].
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopProcess {
    /// Process name, or `"-"` if unknown.
    pub name: String,
    /// Number of connections owned by this process in the snapshot.
    pub count: usize,
}

/// Return top N processes by connection count, descending.
/// Ties are broken by name (ascending).
#[must_use]
pub fn top_connections(conns: &[Connection], n: usize) -> Vec<TopProcess> {
    use std::collections::HashMap;
    let counts = conns
        .iter()
        .fold(HashMap::<String, usize>::new(), |mut acc, c| {
            let name = c.process.as_deref().unwrap_or("-").to_owned();
            *acc.entry(name).or_insert(0) += 1;
            acc
        });
    let mut sorted: Vec<TopProcess> = counts
        .into_iter()
        .map(|(name, count)| TopProcess { name, count })
        .collect();
    sorted.sort_by(|a, b| b.count.cmp(&a.count).then(a.name.cmp(&b.name)));
    sorted.truncate(n);
    sorted
}

/// Return a summary of connections grouped by proto and state.
#[must_use]
pub fn summary(conns: &[Connection]) -> Summary {
    let mut s = Summary::default();
    for c in conns {
        match c.proto {
            Proto::Tcp => {
                s.tcp_total += 1;
                match c.state {
                    Some(State::Established) => s.tcp_established += 1,
                    Some(State::Listen) => s.tcp_listen += 1,
                    Some(State::TimeWait) => s.tcp_timewait += 1,
                    Some(State::CloseWait) => s.tcp_closewait += 1,
                    _ => s.tcp_other += 1,
                }
            }
            Proto::Udp => s.udp_total += 1,
            Proto::Unix => s.unix_total += 1,
            Proto::Raw => s.raw_total += 1,
            Proto::Icmp => s.icmp_total += 1,
        }
    }
    s
}

/// Aggregated counts of connections by protocol and TCP state.
/// Returned by [`summary`].
#[non_exhaustive]
#[derive(Default)]
#[allow(missing_docs)]
pub struct Summary {
    pub tcp_total: usize,
    pub tcp_established: usize,
    pub tcp_listen: usize,
    pub tcp_timewait: usize,
    pub tcp_closewait: usize,
    pub tcp_other: usize,
    pub udp_total: usize,
    pub unix_total: usize,
    pub raw_total: usize,
    pub icmp_total: usize,
}

/// For each external connection that passes through a local proxy, return the
/// list of originating process names (one or more).
///
/// Example: firefox → sing-box → 8.8.8.8:443
/// The key is for the sing-box connection, the value is `["firefox"]`.
/// Multiple clients on the same local port produce multiple entries.
pub fn resolve_proxy_origins(conns: &[Connection]) -> HashMap<ConnectionKey, Vec<String>> {
    let pid_listen_ports = build_listen_ports_map(conns);
    let port_clients = build_port_clients_map(conns);

    let mut result = HashMap::new();
    for c in conns {
        if c.state != Some(State::Established) {
            continue;
        }
        if is_loopback(&c.remote) || c.remote.ends_with(":*") {
            continue;
        }
        let Some(pid) = c.pid else {
            continue;
        };
        let Some(listen_ports) = pid_listen_ports.get(&pid) else {
            continue;
        };

        let proxy_name = c.process.as_deref().unwrap_or("");
        for &port in listen_ports {
            let Some(clients) = port_clients.get(&port) else {
                continue;
            };
            let origins: Vec<String> = clients
                .iter()
                .filter(|n| n.as_str() != proxy_name)
                .cloned()
                .collect();
            if !origins.is_empty() {
                result.insert(c.key(), origins);
                break;
            }
        }
    }

    result
}

/// Build a map: pid → ports the process listens on.
fn build_listen_ports_map(conns: &[Connection]) -> HashMap<u32, Vec<u16>> {
    let mut map: HashMap<u32, Vec<u16>> = HashMap::new();
    conns
        .iter()
        .filter(|c| c.state == Some(State::Listen))
        .filter_map(|c| c.pid.zip(extract_port(&c.local)))
        .for_each(|(pid, port)| map.entry(pid).or_default().push(port));
    map
}

/// Build a map: listen_port → set of client process names connecting to it on loopback.
fn build_port_clients_map(conns: &[Connection]) -> HashMap<u16, HashSet<String>> {
    let mut map: HashMap<u16, HashSet<String>> = HashMap::new();
    conns
        .iter()
        .filter(|c| c.state == Some(State::Established) && is_loopback(&c.remote))
        .filter_map(|c| {
            let port = extract_port(&c.remote)?;
            let name = c.process.as_ref()?.clone();
            Some((port, name))
        })
        .for_each(|(port, name)| {
            map.entry(port).or_default().insert(name);
        });
    map
}

/// Result of [`snapshot_with_containers`]: connections plus any non-fatal
/// warnings that occurred while enriching from container runtimes.
#[non_exhaustive]
#[derive(Debug, Default)]
pub struct SnapshotResult {
    /// Collected connections.
    pub connections: Vec<Connection>,
    /// Non-fatal problems (e.g. Docker socket unreachable, a single
    /// container's netns not accessible). One string per occurrence.
    pub warnings: Vec<String>,
}

/// Collect connections from the host plus all running Docker containers.
/// Linux only - Docker runs in a VM on macOS; namespace trick does not apply.
///
/// # Errors
///
/// Propagates [`snapshot`] failures from host-side collection. Docker-side
/// failures surface in [`SnapshotResult::warnings`] rather than as errors.
#[cfg(target_os = "linux")]
pub fn snapshot_with_containers(filter: &Filter) -> Result<SnapshotResult> {
    let mut connections = snapshot(filter)?;
    let mut warnings = Vec::new();
    match runtime::get_container_connections() {
        Ok(container_conns) => {
            let filtered = apply_filter(container_conns, filter);
            connections.extend(filtered);
        }
        Err(e) => warnings.push(format!("failed to read container connections: {e}")),
    }
    Ok(SnapshotResult {
        connections,
        warnings,
    })
}

/// macOS variant: see top-level [`snapshot_with_containers`].
#[cfg(target_os = "macos")]
pub fn snapshot_with_containers(filter: &Filter) -> Result<SnapshotResult> {
    let mut connections = snapshot(filter)?;
    let port_map = runtime::container_published_ports();
    if !port_map.is_empty() {
        for c in connections.iter_mut() {
            if let Some(port) = extract_port(&c.local)
                && let Some(name) = port_map.get(&port)
            {
                c.container = Some(name.clone());
                continue;
            }
            if let Some(port) = extract_port(&c.remote)
                && let Some(name) = port_map.get(&port)
            {
                c.container = Some(name.clone());
            }
        }
    }
    Ok(SnapshotResult {
        connections,
        warnings: Vec::new(),
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn snapshot_with_containers(_filter: &Filter) -> Result<SnapshotResult> {
    Err(Error::UnsupportedPlatform)
}

/// For a `docker-proxy` connection, resolve the compose/container service
/// name behind it. Returns `None` if the connection is not `docker-proxy`
/// or if resolution fails (no PID, cmdline unreadable, daemon unreachable).
#[cfg(target_os = "linux")]
#[must_use]
pub fn docker_proxy_service(c: &Connection) -> Option<String> {
    if c.process.as_deref() != Some("docker-proxy") {
        return None;
    }
    let pid = c.pid?;
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let container_ip = runtime::parse_docker_proxy_ip(&cmdline)?;
    let map = runtime::container_ip_to_service();
    map.get(&container_ip).cloned()
}

/// Always `None` on non-Linux platforms (Docker namespace lookup is Linux-only).
#[cfg(not(target_os = "linux"))]
pub fn docker_proxy_service(_c: &Connection) -> Option<String> {
    None
}

/// Result of [`diff_connections`].
#[non_exhaustive]
#[derive(Debug, Default, Clone)]
pub struct ConnectionDiff {
    /// Keys present in `curr` but not in `prev` (newly opened).
    pub new: HashSet<ConnectionKey>,
    /// Full connection records present in `prev` but not in `curr` (closed).
    pub closed: Vec<Connection>,
}

/// Compute the diff between two connection snapshots.
#[must_use]
pub fn diff_connections(prev: &[Connection], curr: &[Connection]) -> ConnectionDiff {
    let curr_keys: HashSet<ConnectionKey> = curr.iter().map(Connection::key).collect();
    let prev_keys: HashSet<ConnectionKey> = prev.iter().map(Connection::key).collect();
    let new = curr_keys.difference(&prev_keys).cloned().collect();
    let closed = prev
        .iter()
        .filter(|c| !curr_keys.contains(&c.key()))
        .cloned()
        .collect();
    ConnectionDiff { new, closed }
}

fn extract_port(addr: &str) -> Option<u16> {
    // Works for both "1.2.3.4:8080" and "[::1]:8080"
    addr.rsplit_once(':')?.1.parse().ok()
}

pub(crate) fn is_loopback(addr: &str) -> bool {
    addr.starts_with("127.") || addr.starts_with("[::1]")
}

fn apply_filter(connections: Vec<Connection>, filter: &Filter) -> Vec<Connection> {
    connections
        .into_iter()
        .filter(|c| {
            if filter.no_unix && c.proto == Proto::Unix {
                return false;
            }
            if filter.no_loopback && is_loopback(&c.local) {
                return false;
            }
            if filter.ipv4_only && (is_ipv6_addr(&c.local) || c.proto == Proto::Unix) {
                return false;
            }
            if filter.ipv6_only && (!is_ipv6_addr(&c.local) || c.proto == Proto::Unix) {
                return false;
            }
            if let Some(port) = filter.port
                && !c.local.ends_with(&format!(":{port}"))
                && !c.remote.ends_with(&format!(":{port}"))
            {
                return false;
            }
            if let Some(pid) = filter.pid
                && c.pid != Some(pid)
            {
                return false;
            }
            if let Some(ref name) = filter.process {
                match &c.process {
                    Some(p) if p.to_lowercase().contains(name.as_str()) => {}
                    _ => return false,
                }
            }
            if let Some(proto) = filter.proto
                && c.proto != proto
            {
                return false;
            }
            if let Some(state) = filter.state
                && c.state != Some(state)
            {
                return false;
            }
            true
        })
        .collect()
}

fn is_ipv6_addr(addr: &str) -> bool {
    addr.starts_with('[')
}

/// Replace verbose IPv6 addresses with human-friendly aliases.
/// `[::1]:port` → `localhost:port`, `[::]:port` / `[0:…:0]:port` → `*:port`
#[must_use]
pub fn compact_addr(addr: &str) -> String {
    if let Some(rest) = addr.strip_prefix("[::1]:") {
        return format!("localhost:{rest}");
    }
    // Any all-zero IPv6: [::], [0000:0000:…:0000]
    if addr.starts_with("[::]:") || addr.starts_with("[0000:0000:0000:0000:0000:0000:0000:0000]:") {
        let port = addr.rsplit_once(':').map_or("*", |(_, p)| p);
        return format!("*:{port}");
    }
    addr.to_string()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_conn(
        proto: Proto,
        local: &str,
        remote: &str,
        state: Option<State>,
        pid: Option<u32>,
    ) -> Connection {
        Connection {
            proto,
            local: local.to_string(),
            remote: remote.to_string(),
            state,
            pid,
            process: pid.map(|_| "test".to_string()),
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

    fn sample() -> Vec<Connection> {
        vec![
            make_conn(
                Proto::Tcp,
                "0.0.0.0:80",
                "0.0.0.0:*",
                Some(State::Listen),
                None,
            ),
            make_conn(
                Proto::Tcp,
                "0.0.0.0:443",
                "0.0.0.0:*",
                Some(State::Listen),
                Some(1000),
            ),
            make_conn(
                Proto::Tcp,
                "127.0.0.1:80",
                "127.0.0.1:54321",
                Some(State::Established),
                Some(42),
            ),
            make_conn(Proto::Udp, "0.0.0.0:53", "0.0.0.0:*", None, Some(99)),
        ]
    }

    #[test]
    fn filter_by_proto_tcp() {
        let conns = apply_filter(sample(), &Filter::default().proto(Proto::Tcp));
        assert_eq!(conns.len(), 3);
        assert!(conns.iter().all(|c| c.proto == Proto::Tcp));
    }

    #[test]
    fn filter_by_port_local() {
        let conns = apply_filter(sample(), &Filter::default().port(80));
        assert_eq!(conns.len(), 2);
    }

    #[test]
    fn filter_by_state_listen() {
        let conns = apply_filter(sample(), &Filter::default().state(State::Listen));
        assert_eq!(conns.len(), 2);
        assert!(conns.iter().all(|c| c.state == Some(State::Listen)));
    }

    #[test]
    fn filter_combined_proto_and_state() {
        let conns = apply_filter(
            sample(),
            &Filter::default().proto(Proto::Tcp).state(State::Listen),
        );
        assert_eq!(conns.len(), 2);
    }

    #[test]
    fn state_display() {
        assert_eq!(State::Listen.to_string(), "LISTEN");
        assert_eq!(State::Established.to_string(), "ESTABLISHED");
        assert_eq!(State::TimeWait.to_string(), "TIME_WAIT");
    }

    #[test]
    fn proto_display() {
        assert_eq!(Proto::Tcp.to_string(), "tcp");
        assert_eq!(Proto::Udp.to_string(), "udp");
    }

    // ── fmt_age ───────────────────────────────────────────────────────────────

    #[test]
    fn fmt_age_seconds() {
        assert_eq!(fmt_age(0), "0s");
        assert_eq!(fmt_age(45), "45s");
    }

    #[test]
    fn fmt_age_minutes() {
        assert_eq!(fmt_age(90), "1m30s");
        assert_eq!(fmt_age(3599), "59m59s");
    }

    #[test]
    fn fmt_age_hours() {
        assert_eq!(fmt_age(3600), "1h0m");
        assert_eq!(fmt_age(7384), "2h3m");
    }

    #[test]
    fn fmt_age_days() {
        assert_eq!(fmt_age(86400), "1d0h");
        assert_eq!(fmt_age(90000), "1d1h");
    }

    // ── compact_addr ──────────────────────────────────────────────────────────

    #[test]
    fn compact_addr_loopback_ipv6() {
        assert_eq!(compact_addr("[::1]:443"), "localhost:443");
    }

    #[test]
    fn compact_addr_any_ipv6() {
        assert_eq!(compact_addr("[::]:80"), "*:80");
    }

    #[test]
    fn compact_addr_leaves_regular_addresses_untouched() {
        assert_eq!(compact_addr("0.0.0.0:80"), "0.0.0.0:80");
        assert_eq!(compact_addr("127.0.0.1:443"), "127.0.0.1:443");
        assert_eq!(compact_addr("[fe80::1]:22"), "[fe80::1]:22");
    }

    // ── FromStr for Proto / State / SortKey ───────────────────────────────────

    #[test]
    fn proto_from_str_case_insensitive_and_error() {
        assert_eq!("tcp".parse::<Proto>().unwrap(), Proto::Tcp);
        assert_eq!("TCP".parse::<Proto>().unwrap(), Proto::Tcp);
        assert_eq!("Udp".parse::<Proto>().unwrap(), Proto::Udp);
        assert_eq!("raw".parse::<Proto>().unwrap(), Proto::Raw);
        assert_eq!("ICMP".parse::<Proto>().unwrap(), Proto::Icmp);
        let err = "sctp".parse::<Proto>().unwrap_err();
        assert_eq!(err.kind, "proto");
        assert_eq!(err.value, "sctp");
        assert!(err.allowed.contains(&"tcp"));
        assert!(err.allowed.contains(&"icmp"));
    }

    #[test]
    fn summary_counts_icmp_and_raw_separately() {
        let conns = vec![
            make_conn(
                Proto::Tcp,
                "0.0.0.0:80",
                "0.0.0.0:*",
                Some(State::Listen),
                None,
            ),
            make_conn(Proto::Icmp, "*:49152", "*:*", None, Some(100)),
            make_conn(Proto::Icmp, "*:49153", "*:*", None, Some(200)),
            make_conn(Proto::Raw, "*:58", "*:*", None, None),
        ];
        let s = summary(&conns);
        assert_eq!(s.tcp_total, 1);
        assert_eq!(s.icmp_total, 2);
        assert_eq!(s.raw_total, 1);
    }

    #[test]
    fn state_from_str_handles_underscored_and_case() {
        assert_eq!("TIME_WAIT".parse::<State>().unwrap(), State::TimeWait);
        assert_eq!("time_wait".parse::<State>().unwrap(), State::TimeWait);
        assert_eq!("established".parse::<State>().unwrap(), State::Established);
        assert!("unknown".parse::<State>().is_err());
    }

    #[test]
    fn sort_key_from_str_basic() {
        assert_eq!("port".parse::<SortKey>().unwrap(), SortKey::Port);
        assert_eq!("PROTO".parse::<SortKey>().unwrap(), SortKey::Proto);
        let err = "bogus".parse::<SortKey>().unwrap_err();
        assert_eq!(err.kind, "sort");
    }

    // ── text_matches case-insensitivity ───────────────────────────────────────

    #[test]
    fn text_matches_ignores_case_of_query_and_fields() {
        let mut c = make_conn(
            Proto::Tcp,
            "0.0.0.0:80",
            "Registry.Local:443",
            Some(State::Established),
            Some(1),
        );
        c.process = Some("Nginx".to_string());
        assert!(c.text_matches("nginx"));
        assert!(c.text_matches("NGINX"));
        assert!(c.text_matches("registry.local"));
        assert!(c.text_matches("ESTABLISHED"));
    }

    // ── ConnectionKey Borrow<str> contract ────────────────────────────────────

    #[test]
    fn connection_key_can_be_borrowed_as_str() {
        use std::collections::HashMap;
        let c = make_conn(
            Proto::Tcp,
            "1.2.3.4:80",
            "5.6.7.8:443",
            Some(State::Established),
            Some(1),
        );
        let key = c.key();
        let as_str: &str = key.as_ref();
        assert!(as_str.starts_with("tcp|"));

        let mut map: HashMap<ConnectionKey, i32> = HashMap::new();
        map.insert(key.clone(), 42);
        assert_eq!(map.get(as_str), Some(&42));
    }

    // ── diff_connections ──────────────────────────────────────────────────────

    #[test]
    fn diff_new_connection() {
        let prev = vec![make_conn(
            Proto::Tcp,
            "0.0.0.0:80",
            "0.0.0.0:*",
            Some(State::Listen),
            None,
        )];
        let curr = vec![
            make_conn(
                Proto::Tcp,
                "0.0.0.0:80",
                "0.0.0.0:*",
                Some(State::Listen),
                None,
            ),
            make_conn(
                Proto::Tcp,
                "0.0.0.0:443",
                "0.0.0.0:*",
                Some(State::Listen),
                None,
            ),
        ];
        let diff = diff_connections(&prev, &curr);
        assert_eq!(diff.new.len(), 1);
        assert!(diff.new.contains("tcp|0.0.0.0:443|0.0.0.0:*"));
        assert!(diff.closed.is_empty());
    }

    #[test]
    fn diff_closed_connection() {
        let prev = vec![
            make_conn(
                Proto::Tcp,
                "0.0.0.0:80",
                "0.0.0.0:*",
                Some(State::Listen),
                None,
            ),
            make_conn(
                Proto::Tcp,
                "0.0.0.0:443",
                "0.0.0.0:*",
                Some(State::Listen),
                None,
            ),
        ];
        let curr = vec![make_conn(
            Proto::Tcp,
            "0.0.0.0:80",
            "0.0.0.0:*",
            Some(State::Listen),
            None,
        )];
        let diff = diff_connections(&prev, &curr);
        assert!(diff.new.is_empty());
        assert_eq!(diff.closed.len(), 1);
        assert_eq!(diff.closed[0].local, "0.0.0.0:443");
    }

    // ── top_connections ───────────────────────────────────────────────────────

    #[test]
    fn top_connections_order() {
        let mut c1 = make_conn(
            Proto::Tcp,
            "0.0.0.0:8080",
            "1.2.3.4:50000",
            Some(State::Established),
            Some(1),
        );
        c1.process = Some("nginx".to_string());
        let mut c2 = make_conn(
            Proto::Tcp,
            "0.0.0.0:8080",
            "1.2.3.5:50001",
            Some(State::Established),
            Some(1),
        );
        c2.process = Some("nginx".to_string());
        let mut c3 = make_conn(
            Proto::Tcp,
            "0.0.0.0:8080",
            "1.2.3.6:50002",
            Some(State::Established),
            Some(1),
        );
        c3.process = Some("nginx".to_string());
        let mut c4 = make_conn(
            Proto::Tcp,
            "127.0.0.1:9000",
            "127.0.0.1:55000",
            Some(State::Established),
            Some(2),
        );
        c4.process = Some("curl".to_string());
        let top = top_connections(&[c1, c2, c3, c4], 1);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].name, "nginx");
        assert_eq!(top[0].count, 3);
    }

    // ── filter extras ─────────────────────────────────────────────────────────

    #[test]
    fn filter_no_loopback() {
        let conns = apply_filter(sample(), &Filter::default().no_loopback());
        assert!(conns.iter().all(|c| !c.local.starts_with("127.")));
        assert_eq!(conns.len(), 3);
    }

    #[test]
    fn filter_by_process_substring() {
        let mut conns = sample();
        conns[1].process = Some("nginx".to_string());
        conns[2].process = Some("nginx-worker".to_string());
        let filtered = apply_filter(conns, &Filter::default().process("nginx"));
        assert_eq!(filtered.len(), 2);
    }

    // ── summary ───────────────────────────────────────────────────────────────

    #[test]
    fn summary_counts() {
        let s = summary(&sample());
        assert_eq!(s.tcp_total, 3);
        assert_eq!(s.tcp_listen, 2);
        assert_eq!(s.tcp_established, 1);
        assert_eq!(s.udp_total, 1);
    }

    // ── text_matches ──────────────────────────────────────────────────────────

    #[test]
    fn text_matches_by_process() {
        let c = make_conn(
            Proto::Tcp,
            "0.0.0.0:80",
            "0.0.0.0:*",
            Some(State::Listen),
            Some(1),
        );
        assert!(c.text_matches("test"));
        assert!(!c.text_matches("nginx"));
    }

    #[test]
    fn text_matches_by_port() {
        let c = make_conn(
            Proto::Tcp,
            "0.0.0.0:8080",
            "0.0.0.0:*",
            Some(State::Listen),
            None,
        );
        assert!(c.text_matches("8080"));
        assert!(!c.text_matches("443"));
    }

    #[test]
    fn text_matches_empty_query_always_true() {
        let c = make_conn(
            Proto::Tcp,
            "0.0.0.0:80",
            "0.0.0.0:*",
            Some(State::Listen),
            None,
        );
        assert!(c.text_matches(""));
    }

    // ── sort_connections ──────────────────────────────────────────────────────

    #[test]
    fn sort_by_port() {
        let mut conns = vec![
            make_conn(
                Proto::Tcp,
                "0.0.0.0:443",
                "0.0.0.0:*",
                Some(State::Listen),
                None,
            ),
            make_conn(
                Proto::Tcp,
                "0.0.0.0:80",
                "0.0.0.0:*",
                Some(State::Listen),
                None,
            ),
            make_conn(
                Proto::Tcp,
                "0.0.0.0:22",
                "0.0.0.0:*",
                Some(State::Listen),
                None,
            ),
        ];
        sort_connections(&mut conns, SortKey::Port);
        assert_eq!(conns[0].local, "0.0.0.0:22");
        assert_eq!(conns[1].local, "0.0.0.0:80");
        assert_eq!(conns[2].local, "0.0.0.0:443");
    }

    #[test]
    fn sort_by_proto() {
        let mut conns = vec![
            make_conn(Proto::Udp, "0.0.0.0:53", "0.0.0.0:*", None, None),
            make_conn(
                Proto::Tcp,
                "0.0.0.0:80",
                "0.0.0.0:*",
                Some(State::Listen),
                None,
            ),
        ];
        sort_connections(&mut conns, SortKey::Proto);
        assert_eq!(conns[0].proto, Proto::Tcp);
        assert_eq!(conns[1].proto, Proto::Udp);
    }

    #[test]
    fn sort_key_rejects_unknown_column() {
        assert!("nonexistent".parse::<SortKey>().is_err());
    }

    // ── filter ipv4/ipv6/no_unix ──────────────────────────────────────────────

    #[test]
    fn filter_no_unix() {
        let conns = vec![
            make_conn(
                Proto::Tcp,
                "0.0.0.0:80",
                "0.0.0.0:*",
                Some(State::Listen),
                None,
            ),
            make_conn(
                Proto::Unix,
                "/run/app.sock",
                "/run/app.sock",
                Some(State::Listen),
                None,
            ),
        ];
        let filtered = apply_filter(conns, &Filter::default().no_unix());
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].proto, Proto::Tcp);
    }

    #[test]
    fn filter_ipv6_only() {
        let conns = vec![
            make_conn(
                Proto::Tcp,
                "0.0.0.0:80",
                "0.0.0.0:*",
                Some(State::Listen),
                None,
            ),
            make_conn(Proto::Tcp, "[::]:443", "[::]:*", Some(State::Listen), None),
        ];
        let filtered = apply_filter(conns, &Filter::default().ipv6_only());
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].local.starts_with('['));
    }

    // ── resolve_proxy_origins ─────────────────────────────────────────────────

    #[test]
    fn resolve_proxy_origins_detects_chain() {
        // firefox (pid=100) → 127.0.0.1:1080 (xray's listen port)
        // xray (pid=200) listens on 1080 AND connects to 8.8.8.8:443
        let mut browser = make_conn(
            Proto::Tcp,
            "127.0.0.1:55000",
            "127.0.0.1:1080",
            Some(State::Established),
            Some(100),
        );
        browser.process = Some("firefox".to_string());

        let mut proxy_listen = make_conn(
            Proto::Tcp,
            "0.0.0.0:1080",
            "0.0.0.0:*",
            Some(State::Listen),
            Some(200),
        );
        proxy_listen.process = Some("xray".to_string());

        let mut proxy_out = make_conn(
            Proto::Tcp,
            "10.0.0.1:44000",
            "8.8.8.8:443",
            Some(State::Established),
            Some(200),
        );
        proxy_out.process = Some("xray".to_string());

        let proxy_key = proxy_out.key();
        let conns = vec![browser, proxy_listen, proxy_out];
        let origins = resolve_proxy_origins(&conns);

        assert!(origins.contains_key(&proxy_key));
        assert!(origins[&proxy_key].iter().any(|n| n == "firefox"));
    }
}
