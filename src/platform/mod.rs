use crate::{Connection, Result};

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub mod macos_enrich;
pub fn get_connections() -> Result<Vec<Connection>> {
    #[cfg(target_os = "linux")]
    return linux::get_connections();

    #[cfg(target_os = "macos")]
    return macos::get_connections();

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    Err(crate::Error::UnsupportedPlatform)
}
