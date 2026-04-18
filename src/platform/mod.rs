use crate::{Connection, Result};

/// Linux connection collection via `/proc/net/{tcp,udp,unix}` plus
/// `/proc/<pid>/fd/` for inode → PID resolution.
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
mod macos;
/// macOS-only enrichment helpers (full cmdline, fd usage, parent chain).
#[cfg(target_os = "macos")]
pub mod macos_enrich;

/// Collect all current network connections from the running OS.
/// Dispatches to the platform-specific implementation.
pub fn get_connections() -> Result<Vec<Connection>> {
    #[cfg(target_os = "linux")]
    return linux::get_connections();

    #[cfg(target_os = "macos")]
    return macos::get_connections();

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    Err(crate::Error::UnsupportedPlatform)
}
