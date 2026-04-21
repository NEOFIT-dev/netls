//! Configuration file support.
//!
//! netls reads its config from (first match wins):
//! 1. `--config PATH` CLI flag
//! 2. `NETLS_CONFIG` environment variable
//! 3. `~/.config/netls/config.toml` (or the platform-appropriate location via [`dirs::config_dir`])
//!
//! Sections:
//! - `[defaults]`: default values for long-form CLI flags; applied unless the flag
//!   was given on the command line
//! - `[profiles.<name>]`: named overlays activated by `--profile <name>`, applied
//!   on top of `[defaults]`
//! - `[ports]`: extends the built-in port -> service-name map used by `--service-names`

use figment::{
    Figment,
    providers::{Format, Toml},
};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// ── Types ─────────────────────────────────────────────────────────────────────

/// Top-level configuration schema. All sections are optional.
#[derive(Deserialize, Default, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Values applied at every invocation (unless a CLI flag overrides them).
    #[serde(default)]
    pub defaults: Defaults,

    /// Extension of the built-in `port → service-name` map. Keys are TOML
    /// strings (TOML does not allow integer keys in tables) but must parse
    /// to `u16` (validated by [`Config::validate`]).
    #[serde(default)]
    pub ports: HashMap<String, String>,

    /// Named overlays activated via `--profile <name>`.
    #[serde(default)]
    pub profiles: HashMap<String, Defaults>,
}

/// Default values for long-form CLI flags.
///
/// Field names mirror CLI flag names with `-` replaced by `_`. Every field is
/// `Option<T>` so the config can express "unset" (fall through to the CLI /
/// built-in default) distinctly from "explicitly set to false / empty string".
#[derive(Deserialize, Default, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct Defaults {
    // Output format
    pub json: Option<bool>,
    pub pretty: Option<bool>,
    pub csv: Option<bool>,

    // Filters
    pub proto: Option<String>,
    pub state: Option<String>,
    pub port: Option<u16>,
    pub pid: Option<u32>,
    pub process: Option<String>,
    pub ipv4: Option<bool>,
    pub ipv6: Option<bool>,
    pub no_loopback: Option<bool>,
    pub listen: Option<bool>,
    pub all: Option<bool>,

    // Sort / aggregate
    pub sort: Option<String>,
    pub group_by: Option<String>,

    // Extra columns
    pub queues: Option<bool>,
    pub service_names: Option<bool>,
    pub age: Option<bool>,
    pub tree: Option<bool>,
    pub systemd: Option<bool>,
    pub fd: Option<bool>,
    pub cmdline: Option<bool>,
    pub containers: Option<bool>,

    // Resolution
    pub resolve_dns: Option<bool>,
    pub resolve_proxy: Option<bool>,
}

// ── Loading ───────────────────────────────────────────────────────────────────

/// Result of [`load`]: the parsed config plus the path it came from (when a
/// file was actually read). `source_path` is `None` when no file was loaded
/// (XDG default missing, or the platform has no config dir).
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    /// The parsed configuration. [`Config::default`] when no file was found.
    pub config: Config,
    /// Path the config was read from. `None` if nothing was loaded.
    pub source_path: Option<PathBuf>,
}

/// Load the configuration.
///
/// `explicit_path` comes from the `--config` CLI flag and takes priority over
/// the `NETLS_CONFIG` env var, which in turn beats the XDG default.
///
/// **Missing-file behaviour depends on how the path was chosen.** When the user
/// asked for a specific file (`--config` or `NETLS_CONFIG`) and it does not
/// exist, this returns [`ConfigError::NotFound`]: silent fallback there would
/// hide typos. The XDG default falling through to [`Config::default`] is
/// expected: most users will not have a config file at all.
///
/// # Errors
///
/// - [`ConfigError::NotFound`] if `explicit_path` (or `NETLS_CONFIG`) points
///   at a missing file.
/// - [`ConfigError::Parse`] if the TOML fails to parse, has unknown fields,
///   or fails [`Config::validate`] (bad enum value, non-numeric `[ports]` key).
pub fn load(explicit_path: Option<&Path>) -> Result<LoadedConfig, ConfigError> {
    let Some((path, source)) = resolve_path(explicit_path) else {
        return Ok(LoadedConfig {
            config: Config::default(),
            source_path: None,
        });
    };
    if !path.exists() {
        return match source {
            PathSource::Default => Ok(LoadedConfig {
                config: Config::default(),
                source_path: None,
            }),
            PathSource::Cli => Err(ConfigError::NotFound {
                path,
                origin: "--config",
            }),
            PathSource::Env => Err(ConfigError::NotFound {
                path,
                origin: "NETLS_CONFIG",
            }),
        };
    }
    let cfg = Figment::new()
        .merge(Toml::file(&path))
        .extract::<Config>()
        .map_err(|e| ConfigError::Parse(path.clone(), e.to_string()))?;
    cfg.validate()
        .map_err(|msg| ConfigError::Parse(path.clone(), msg))?;
    Ok(LoadedConfig {
        config: cfg,
        source_path: Some(path),
    })
}

/// Where the config path came from. Drives the missing-file policy: explicit
/// sources hard-fail, the implicit XDG default falls back to an empty config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathSource {
    /// `--config PATH`
    Cli,
    /// `NETLS_CONFIG` env var
    Env,
    /// Platform default (e.g. `~/.config/netls/config.toml`)
    Default,
}

fn resolve_path(explicit: Option<&Path>) -> Option<(PathBuf, PathSource)> {
    if let Some(p) = explicit {
        return Some((p.to_path_buf(), PathSource::Cli));
    }
    if let Ok(p) = std::env::var("NETLS_CONFIG") {
        return Some((expand_tilde(&p), PathSource::Env));
    }
    dirs::config_dir().map(|d| (d.join("netls").join("config.toml"), PathSource::Default))
}

/// Path used by write operations (e.g. `--init-config`) when no explicit
/// `--config PATH` was given. Falls back through the same chain as [`load`]:
/// `NETLS_CONFIG` (with leading `~` expanded), then the platform default.
/// Returns `None` only on platforms with no detectable config directory.
#[must_use]
pub fn default_write_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("NETLS_CONFIG") {
        return Some(expand_tilde(&p));
    }
    dirs::config_dir().map(|d| d.join("netls").join("config.toml"))
}

/// Expand a leading `~` or `~/` to the user's home directory. Anything else
/// (including `~user`) is returned untouched. Shells normally do this for
/// interactive args, but env vars set programmatically are passed verbatim.
fn expand_tilde(raw: &str) -> PathBuf {
    if raw == "~" {
        return dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"));
    }
    if let Some(rest) = raw.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(rest);
    }
    PathBuf::from(raw)
}

// ── Effective defaults (defaults + profile overlay) ───────────────────────────

impl Config {
    /// Compute the effective [`Defaults`] for an optional profile name.
    ///
    /// Applies `[defaults]` first, then overlays `[profiles.<name>]` on top.
    ///
    /// # Errors
    ///
    /// [`ConfigError::ProfileNotFound`] if `profile` is `Some` but the named
    /// profile is absent. The error carries the list of defined profile names.
    pub fn effective(&self, profile: Option<&str>) -> Result<Defaults, ConfigError> {
        let mut eff = self.defaults.clone();
        if let Some(name) = profile {
            let overlay = self.profiles.get(name).ok_or_else(|| {
                let mut names: Vec<&str> = self.profiles.keys().map(String::as_str).collect();
                names.sort_unstable();
                ConfigError::ProfileNotFound {
                    requested: name.to_string(),
                    available: names.into_iter().map(String::from).collect(),
                }
            })?;
            eff.overlay(overlay);
        }
        Ok(eff)
    }

    /// Return an iterator of validated `(port, name)` pairs from `[ports]`.
    /// Invalid port keys (non-numeric or out of range) are skipped; validity
    /// is enforced at load time by [`Self::validate`].
    pub fn port_overrides(&self) -> impl Iterator<Item = (u16, &str)> {
        self.ports
            .iter()
            .filter_map(|(k, v)| k.parse::<u16>().ok().map(|p| (p, v.as_str())))
    }

    /// Validate constraints that serde cannot express:
    /// - every `[ports]` key parses as `u16`
    /// - enum-like fields (`proto`, `state`, `sort`, `group_by`) in
    ///   `[defaults]` and every `[profiles.*]` use a recognised value
    ///
    /// Called automatically from [`load`]; user-constructed configs may
    /// call it explicitly.
    ///
    /// # Errors
    ///
    /// Returns the first failing rule as a string prefixed with the section
    /// (`[defaults]`, `[profiles.<name>]`, or `[ports]`) and the bad value.
    pub fn validate(&self) -> Result<(), String> {
        for key in self.ports.keys() {
            if key.parse::<u16>().is_err() {
                return Err(format!(
                    "[ports] key {key:?} is not a valid port number (0-65535)"
                ));
            }
        }
        self.defaults.validate("[defaults]")?;
        for (name, profile) in &self.profiles {
            profile.validate(&format!("[profiles.{name}]"))?;
        }
        Ok(())
    }
}

impl Defaults {
    /// Reject enum-like values that the CLI would later refuse anyway, but
    /// surface the error pointing at the config section instead of a generic
    /// `--proto` complaint.
    fn validate(&self, section: &str) -> Result<(), String> {
        check_enum(section, "proto", self.proto.as_deref(), crate::VALID_PROTOS)?;
        check_enum(section, "state", self.state.as_deref(), crate::VALID_STATES)?;
        check_enum(section, "sort", self.sort.as_deref(), crate::VALID_SORT)?;
        check_enum(
            section,
            "group_by",
            self.group_by.as_deref(),
            crate::VALID_GROUP_BY,
        )?;
        Ok(())
    }

    /// Merge `other` on top of `self`: every field set in `other` overrides
    /// the corresponding field in `self`. Unset fields in `other` are ignored.
    fn overlay(&mut self, other: &Defaults) {
        macro_rules! overlay_fields {
            ($($field:ident),* $(,)?) => {
                $(
                    if other.$field.is_some() {
                        self.$field = other.$field.clone();
                    }
                )*
            };
        }
        overlay_fields!(
            json,
            pretty,
            csv,
            proto,
            state,
            port,
            pid,
            process,
            ipv4,
            ipv6,
            no_loopback,
            listen,
            all,
            sort,
            group_by,
            queues,
            service_names,
            age,
            tree,
            systemd,
            fd,
            cmdline,
            containers,
            resolve_dns,
            resolve_proxy,
        );
    }
}

fn check_enum(
    section: &str,
    field: &str,
    value: Option<&str>,
    valid: &[&str],
) -> Result<(), String> {
    let Some(raw) = value else { return Ok(()) };
    if valid.contains(&raw.to_lowercase().as_str()) {
        return Ok(());
    }
    Err(format!(
        "{section}: invalid {field} {raw:?}. Valid values: {}",
        valid.join(", ")
    ))
}

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors returned by the config loader.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// TOML failed to parse or did not match the schema.
    #[error("invalid config {0:?}: {1}")]
    Parse(PathBuf, String),

    /// The user asked for a specific config file (via `--config` or
    /// `NETLS_CONFIG`) but the file does not exist. The XDG default falling
    /// through silently is intentional and never produces this error.
    #[error("config file not found at {path:?} (from {origin})")]
    NotFound {
        /// The resolved path that was checked.
        path: PathBuf,
        /// Origin label, currently `"--config"` or `"NETLS_CONFIG"`.
        origin: &'static str,
    },

    /// `--profile <name>` was given but `[profiles.<name>]` is missing.
    /// `available` lists every profile defined in the config (sorted), so the
    /// user can copy-paste a valid name without inspecting the file.
    #[error("{}", fmt_profile_not_found(.requested, .available))]
    ProfileNotFound {
        /// The name passed to `--profile`.
        requested: String,
        /// All profile names actually present in the config (sorted).
        available: Vec<String>,
    },
}

fn fmt_profile_not_found(requested: &str, available: &[String]) -> String {
    if available.is_empty() {
        format!("profile '{requested}' not found: no profiles are defined in the config")
    } else {
        format!(
            "profile '{requested}' not found. Available: {}",
            available.join(", ")
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_toml(content: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(file, "{content}").unwrap();
        file
    }

    #[test]
    fn missing_explicit_config_path_is_error() {
        // When the user types --config /typo.toml we must not silently load an
        // empty config: they would think their settings just "did not apply".
        let err = load(Some(Path::new("/nonexistent/netls.toml"))).unwrap_err();
        match err {
            ConfigError::NotFound { ref path, origin } => {
                assert_eq!(path, Path::new("/nonexistent/netls.toml"));
                assert_eq!(origin, "--config");
                assert!(err.to_string().contains("--config"));
            }
            other => panic!("expected ConfigError::NotFound, got {other:?}"),
        }
    }

    #[test]
    fn resolve_path_marks_explicit_cli_source() {
        let (path, source) = resolve_path(Some(Path::new("/some/path.toml"))).unwrap();
        assert_eq!(path, Path::new("/some/path.toml"));
        assert_eq!(source, PathSource::Cli);
    }

    // Env-var mutating cases live in one test: cargo runs unit tests in
    // parallel by default and `NETLS_CONFIG` is process-global, so splitting
    // would race (one body sets, another unsets, both observe wrong state).
    #[test]
    fn netls_config_env_var_path_resolution() {
        // SAFETY: the function restores the prior value before returning.
        let prior = std::env::var("NETLS_CONFIG").ok();

        // resolve_path: with NETLS_CONFIG unset and no explicit arg the source
        // is the platform default.
        unsafe { std::env::remove_var("NETLS_CONFIG") };
        if let Some((_, source)) = resolve_path(None) {
            assert_eq!(source, PathSource::Default);
        }

        // default_write_path: env set wins over the XDG fallback.
        unsafe { std::env::set_var("NETLS_CONFIG", "/tmp/from-env.toml") };
        let env_path = default_write_path().unwrap();
        assert_eq!(env_path, Path::new("/tmp/from-env.toml"));

        // default_write_path: env unset falls back to "<dir>/netls/config.toml".
        unsafe { std::env::remove_var("NETLS_CONFIG") };
        if let Some(p) = default_write_path() {
            assert!(p.ends_with("netls/config.toml"));
        }

        // Restore prior env so we do not leak state.
        match prior {
            Some(prev) => unsafe { std::env::set_var("NETLS_CONFIG", prev) },
            None => unsafe { std::env::remove_var("NETLS_CONFIG") },
        }
    }

    #[test]
    fn parses_defaults_section() {
        let f = write_toml(
            r#"
[defaults]
proto = "tcp"
sort = "port"
no_loopback = true
"#,
        );
        let cfg = load(Some(f.path())).unwrap().config;
        assert_eq!(cfg.defaults.proto.as_deref(), Some("tcp"));
        assert_eq!(cfg.defaults.sort.as_deref(), Some("port"));
        assert_eq!(cfg.defaults.no_loopback, Some(true));
    }

    #[test]
    fn parses_ports_section() {
        let f = write_toml(
            r#"
[ports]
3000 = "vite-dev"
9229 = "node-debug"
"#,
        );
        let cfg = load(Some(f.path())).unwrap().config;
        let overrides: HashMap<u16, &str> = cfg.port_overrides().collect();
        assert_eq!(overrides.get(&3000).copied(), Some("vite-dev"));
        assert_eq!(overrides.get(&9229).copied(), Some("node-debug"));
    }

    #[test]
    fn invalid_port_key_is_rejected() {
        let f = write_toml(
            r#"
[ports]
"not-a-number" = "nope"
"#,
        );
        let err = load(Some(f.path())).unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_, ref msg) if msg.contains("not a valid port")));
    }

    #[test]
    fn profile_overlays_defaults() {
        let f = write_toml(
            r#"
[defaults]
proto = "tcp"
sort = "port"

[profiles.k8s]
all = true
containers = true
"#,
        );
        let cfg = load(Some(f.path())).unwrap().config;
        let eff = cfg.effective(Some("k8s")).unwrap();
        assert_eq!(
            eff.proto.as_deref(),
            Some("tcp"),
            "proto inherited from [defaults]"
        );
        assert_eq!(
            eff.sort.as_deref(),
            Some("port"),
            "sort inherited from [defaults]"
        );
        assert_eq!(eff.all, Some(true), "all added by [profiles.k8s]");
        assert_eq!(
            eff.containers,
            Some(true),
            "containers added by [profiles.k8s]"
        );
    }

    #[test]
    fn profile_overrides_defaults_for_same_field() {
        let f = write_toml(
            r#"
[defaults]
proto = "tcp"

[profiles.udp-debug]
proto = "udp"
"#,
        );
        let cfg = load(Some(f.path())).unwrap().config;
        let eff = cfg.effective(Some("udp-debug")).unwrap();
        assert_eq!(
            eff.proto.as_deref(),
            Some("udp"),
            "profile wins over defaults"
        );
    }

    #[test]
    fn unknown_profile_lists_available() {
        let f = write_toml(
            r#"[defaults]
proto = "tcp"

[profiles.k8s]
all = true

[profiles.dev]
listen = true
"#,
        );
        let cfg = load(Some(f.path())).unwrap().config;
        let err = cfg.effective(Some("missing")).unwrap_err();
        match err {
            ConfigError::ProfileNotFound {
                ref requested,
                ref available,
            } => {
                assert_eq!(requested, "missing");
                assert_eq!(available, &["dev".to_string(), "k8s".to_string()]);
                let msg = err.to_string();
                assert!(msg.contains("Available: dev, k8s"), "got: {msg}");
            }
            other => panic!("expected ProfileNotFound, got {other:?}"),
        }
    }

    #[test]
    fn unknown_profile_with_no_profiles_defined() {
        let f = write_toml(
            r#"[defaults]
proto = "tcp"
"#,
        );
        let cfg = load(Some(f.path())).unwrap().config;
        let err = cfg.effective(Some("any")).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("no profiles are defined"),
            "expected hint about empty profiles, got: {msg}"
        );
    }

    #[test]
    fn invalid_proto_in_defaults_is_rejected() {
        let f = write_toml(
            r#"[defaults]
proto = "garbage"
"#,
        );
        let err = load(Some(f.path())).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("[defaults]") && msg.contains("proto") && msg.contains("garbage"),
            "expected section + field + bad value in error, got: {msg}"
        );
    }

    #[test]
    fn invalid_state_in_profile_is_rejected() {
        let f = write_toml(
            r#"
[profiles.bad]
state = "bogus"
"#,
        );
        let err = load(Some(f.path())).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("[profiles.bad]") && msg.contains("state") && msg.contains("bogus"),
            "expected profile section in error, got: {msg}"
        );
    }

    #[test]
    fn invalid_sort_or_group_by_is_rejected() {
        let f = write_toml(
            r#"[defaults]
sort = "nonsense"
"#,
        );
        let err = load(Some(f.path())).unwrap_err();
        assert!(err.to_string().contains("sort"));

        let g = write_toml(
            r#"[defaults]
group_by = "nonsense"
"#,
        );
        let err = load(Some(g.path())).unwrap_err();
        assert!(err.to_string().contains("group_by"));
    }

    #[test]
    fn tilde_expansion() {
        if let Some(home) = dirs::home_dir() {
            assert_eq!(expand_tilde("~"), home);
            assert_eq!(expand_tilde("~/foo.toml"), home.join("foo.toml"));
        }
        // Non-tilde paths are passed through unchanged.
        assert_eq!(
            expand_tilde("/etc/netls.toml"),
            PathBuf::from("/etc/netls.toml")
        );
        assert_eq!(
            expand_tilde("relative.toml"),
            PathBuf::from("relative.toml")
        );
        // ~user is not expanded; shells normally handle this, we deliberately don't.
        assert_eq!(expand_tilde("~root/x"), PathBuf::from("~root/x"));
    }

    #[test]
    fn proto_is_case_insensitive() {
        let f = write_toml(
            r#"[defaults]
proto = "TCP"
"#,
        );
        // Should not error: "TCP" lowercases to "tcp".
        let cfg = load(Some(f.path())).unwrap().config;
        assert_eq!(cfg.defaults.proto.as_deref(), Some("TCP"));
    }

    #[test]
    fn no_profile_returns_defaults_only() {
        let f = write_toml(
            r#"
[defaults]
proto = "tcp"

[profiles.k8s]
all = true
"#,
        );
        let cfg = load(Some(f.path())).unwrap().config;
        let eff = cfg.effective(None).unwrap();
        assert_eq!(eff.proto.as_deref(), Some("tcp"));
        assert_eq!(eff.all, None, "profile not applied when not requested");
    }

    #[test]
    fn unknown_fields_in_defaults_are_rejected() {
        let f = write_toml(
            r#"
[defaults]
proto = "tcp"
typo_field = "oops"
"#,
        );
        let err = load(Some(f.path())).unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_, _)));
    }

    #[test]
    fn invalid_toml_syntax_is_error() {
        let f = write_toml("[defaults]\nproto = \n");
        let err = load(Some(f.path())).unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_, _)));
    }
}
