mod display;
mod output;
mod services;
mod tui;
mod tui_common;
mod watch;

use anyhow::Result;
use clap::{CommandFactory, FromArgMatches, Parser, parser::ValueSource};
use netls::{Filter, config};

use crate::watch::WatchOutput;

#[cfg(unix)]
use std::process;

#[derive(Parser)]
#[command(
    name = "netls",
    about = "Fast cross-platform replacement for netstat / ss / lsof",
    version
)]
struct Cli {
    /// Output as JSON (one object per line)
    #[arg(long)]
    json: bool,

    /// Pretty-print JSON (use with --json)
    #[arg(long)]
    pretty: bool,

    /// Output as CSV
    #[arg(long)]
    csv: bool,

    /// Refresh every N seconds with diff (default: 2)
    #[arg(long, value_name = "N", default_missing_value = "2", num_args = 0..=1)]
    watch: Option<u64>,

    /// Interactive TUI mode
    #[arg(long)]
    tui: bool,

    /// Show only listening sockets (shorthand for --state listen)
    #[arg(long)]
    listen: bool,

    /// Show a summary of connections by protocol and state
    #[arg(long)]
    summary: bool,

    /// Show top N processes by connection count (default: 10)
    #[arg(long, value_name = "N", default_missing_value = "10", num_args = 0..=1)]
    top: Option<usize>,

    /// Print only the count of matching connections
    #[arg(long)]
    count: bool,

    /// Sort output by column: proto, local, remote, state, pid, port, process
    #[arg(long, value_name = "COL")]
    sort: Option<String>,

    /// Filter by port
    #[arg(long)]
    port: Option<u16>,

    /// Filter by PID
    #[arg(long)]
    pid: Option<u32>,

    /// Filter by process name (case-insensitive substring match)
    #[arg(long, value_name = "NAME")]
    process: Option<String>,

    /// Filter by state (e.g. listen, established)
    #[arg(long)]
    state: Option<String>,

    /// Filter by protocol (tcp, udp, unix, raw, icmp)
    #[arg(long)]
    proto: Option<String>,

    /// Show only IPv4 connections
    #[arg(long)]
    ipv4: bool,

    /// Show only IPv6 connections
    #[arg(long)]
    ipv6: bool,

    /// Hide loopback connections (127.x.x.x and ::1)
    #[arg(long)]
    no_loopback: bool,

    /// Show Recv-Q and Send-Q columns (socket buffer sizes in bytes)
    #[arg(long)]
    queues: bool,

    /// Resolve remote IP addresses to hostnames (may be slow)
    #[arg(long)]
    resolve_dns: bool,

    /// Resolve proxy chains: show the real originating process for proxied connections
    #[arg(long)]
    resolve_proxy: bool,

    /// Show all connections including Unix domain sockets (default: TCP and UDP only)
    #[arg(long, short = 'a')]
    all: bool,

    /// Show full command line instead of short process name
    #[arg(long)]
    cmdline: bool,

    /// Annotate port numbers with service names (e.g. :5432 -> :5432 (postgres))
    #[arg(long)]
    service_names: bool,

    /// Include connections from inside Docker containers (requires root)
    #[arg(long)]
    containers: bool,

    /// Check if a port is free. Exits 0 if free, 1 if in use
    #[arg(long, value_name = "PORT")]
    check_port: Option<u16>,

    /// Kill the process listening on PORT (sends SIGTERM, asks for confirmation)
    #[arg(long, value_name = "PORT")]
    kill: Option<u16>,

    /// Skip confirmation prompt for --kill
    #[arg(long)]
    force: bool,

    /// Show approximate connection age (AGE column)
    #[arg(long)]
    age: bool,

    /// Show parent process chain (PARENT CHAIN column): "bash <- tmux"
    #[arg(long)]
    tree: bool,

    /// Show systemd unit name (UNIT column): "nginx.service"
    #[arg(long)]
    systemd: bool,

    /// Warn if TIME_WAIT count exceeds N (use with --summary, default threshold: 500)
    #[arg(long, value_name = "N", default_missing_value = "500", num_args = 0..=1)]
    warn_timewait: Option<usize>,

    /// Block until PORT is listening. Exits 0 when up, 1 on timeout
    #[arg(long, value_name = "PORT")]
    wait_for: Option<u16>,

    /// Timeout in seconds for --wait-for (default: 30)
    #[arg(long, value_name = "SECS", default_value = "30")]
    timeout: u64,

    /// Save current snapshot to FILE (JSON)
    #[arg(long, value_name = "FILE")]
    save: Option<std::path::PathBuf>,

    /// Compare current snapshot with FILE saved by --save
    #[arg(long, value_name = "FILE")]
    diff: Option<std::path::PathBuf>,

    /// Show fd usage per process (FD column), warn when near limit
    #[arg(long)]
    fd: bool,

    /// Group connections by field: remote-ip, process, port, proto
    #[arg(long, value_name = "FIELD")]
    group_by: Option<String>,

    /// Path to config file (default: ~/.config/netls/config.toml)
    #[arg(long, value_name = "PATH")]
    config: Option<std::path::PathBuf>,

    /// Apply named profile from config file (`[profiles.<NAME>]`)
    #[arg(long, value_name = "NAME")]
    profile: Option<String>,

    /// Write a starter config file to ~/.config/netls/config.toml and exit.
    /// Refuses to overwrite an existing file unless --force is also given.
    #[arg(long)]
    init_config: bool,

    /// Print the resolved effective config and exit. Shows which file loaded,
    /// the active profile, and the origin of every set value (CLI flag,
    /// `[profiles.X]`, or `[defaults]`).
    #[arg(long)]
    show_config: bool,
}

/// Apply effective config defaults to `cli` for any field that was *not* set on
/// the command line. Uses `ArgMatches::value_source` to distinguish CLI-supplied
/// values (which always win) from clap-supplied defaults (which the config can
/// override).
fn apply_config(cli: &mut Cli, eff: &config::Defaults, matches: &clap::ArgMatches) {
    let from_cli = |name: &str| matches.value_source(name) == Some(ValueSource::CommandLine);

    // Option<T> fields: take config value only if CLI left it unset.
    macro_rules! apply_opt {
        ($field:ident) => {
            if cli.$field.is_none() {
                cli.$field = eff.$field.clone();
            }
        };
    }
    apply_opt!(proto);
    apply_opt!(state);
    apply_opt!(port);
    apply_opt!(pid);
    apply_opt!(process);
    apply_opt!(sort);
    apply_opt!(group_by);

    // bool fields: clap defaults them to `false`; config overrides only when
    // the CLI did not set the flag explicitly.
    macro_rules! apply_bool {
        ($field:ident) => {
            if !from_cli(stringify!($field)) {
                if let Some(v) = eff.$field {
                    cli.$field = v;
                }
            }
        };
    }
    apply_bool!(json);
    apply_bool!(pretty);
    apply_bool!(csv);
    apply_bool!(ipv4);
    apply_bool!(ipv6);
    apply_bool!(no_loopback);
    apply_bool!(listen);
    apply_bool!(all);
    apply_bool!(queues);
    apply_bool!(service_names);
    apply_bool!(age);
    apply_bool!(tree);
    apply_bool!(systemd);
    apply_bool!(fd);
    apply_bool!(cmdline);
    apply_bool!(containers);
    apply_bool!(resolve_dns);
    apply_bool!(resolve_proxy);
}

/// Starter config template written by `--init-config`. `service_names = true`
/// is the only active default; everything else is commented out so the user
/// opts in explicitly by uncommenting.
const STARTER_CONFIG: &str = r#"# netls config file generated by `netls --init-config`.
# Uncomment what you want. CLI flags always override these values.

[defaults]
# Annotate ports with service names like (postgres), (kafka), (redis).
# Uses /etc/services plus a curated built-in map.
service_names = true

# Hide loopback (127.x and ::1) connections.
# no_loopback = true

# Sort table rows by port number.
# sort = "port"

# A profile activated with `netls --profile dev`. Overlays on [defaults].
[profiles.dev]
listen = true
no_loopback = true

# Profile for inspecting Kubernetes / container hosts.
[profiles.k8s]
all = true
containers = true

# Profile for security audits: listening sockets only, no loopback.
[profiles.audit]
state = "listen"
no_loopback = true

# Custom port to service-name overrides. Win over /etc/services and the
# built-in map. A non-empty section auto-enables --service-names.
[ports]
# 3000 = "vite-dev"
# 9229 = "node-debug"
# 4321 = "astro-dev"
"#;

/// Print the resolved effective config to stdout, one line per set field,
/// annotated with its origin (CLI flag, `[profiles.X]`, or `[defaults]`).
/// Skips fields left at their CLI default to keep the output focused on
/// what actually overrides defaults.
fn cmd_show_config(loaded: &netls::config::LoadedConfig, cli: &Cli, matches: &clap::ArgMatches) {
    match &loaded.source_path {
        Some(p) => println!("config:  {}", p.display()),
        None => println!("config:  (no file loaded; using built-in defaults)"),
    }
    if let Some(p) = &cli.profile {
        println!("profile: {p}");
    }
    println!();

    let active_profile = cli
        .profile
        .as_deref()
        .and_then(|n| loaded.config.profiles.get(n));
    let defaults_section = &loaded.config.defaults;
    let from_cli = |name: &str| matches.value_source(name) == Some(ValueSource::CommandLine);
    let profile_label = || format!("[profiles.{}]", cli.profile.as_deref().unwrap_or("?"));

    println!("effective settings:");
    let mut emitted = 0u32;

    macro_rules! show_opt {
        ($field:ident) => {
            if let Some(v) = &cli.$field {
                let origin = if from_cli(stringify!($field)) {
                    format!("--{}", stringify!($field).replace('_', "-"))
                } else if active_profile.and_then(|p| p.$field.as_ref()).is_some() {
                    profile_label()
                } else if defaults_section.$field.is_some() {
                    "[defaults]".to_string()
                } else {
                    "(default)".to_string()
                };
                let value_str = format!("{v:?}");
                println!("  {:15} = {value_str:<20}  ({origin})", stringify!($field));
                emitted += 1;
            }
        };
    }

    macro_rules! show_bool {
        ($field:ident) => {
            if cli.$field {
                let origin = if from_cli(stringify!($field)) {
                    format!("--{}", stringify!($field).replace('_', "-"))
                } else if active_profile.and_then(|p| p.$field).is_some() {
                    profile_label()
                } else if defaults_section.$field.is_some() {
                    "[defaults]".to_string()
                } else {
                    "(auto)".to_string()
                };
                println!("  {:15} = {:<20}  ({origin})", stringify!($field), "true");
                emitted += 1;
            }
        };
    }

    show_opt!(proto);
    show_opt!(state);
    show_opt!(port);
    show_opt!(pid);
    show_opt!(process);
    show_opt!(sort);
    show_opt!(group_by);

    show_bool!(json);
    show_bool!(pretty);
    show_bool!(csv);
    show_bool!(ipv4);
    show_bool!(ipv6);
    show_bool!(no_loopback);
    show_bool!(listen);
    show_bool!(all);
    show_bool!(queues);
    show_bool!(service_names);
    show_bool!(age);
    show_bool!(tree);
    show_bool!(systemd);
    show_bool!(fd);
    show_bool!(cmdline);
    show_bool!(containers);
    show_bool!(resolve_dns);
    show_bool!(resolve_proxy);

    if emitted == 0 {
        println!("  (none, all at built-in defaults)");
    }

    if !loaded.config.ports.is_empty() {
        println!();
        let count = loaded.config.ports.len();
        println!("[ports]: {count} entries");
        let mut entries: Vec<_> = loaded.config.ports.iter().collect();
        entries.sort_by_key(|(k, _)| k.parse::<u16>().unwrap_or(0));
        for (port, name) in entries {
            println!("  {port} = {name:?}");
        }
    }
}

fn cmd_init_config(target: Option<&std::path::Path>, force: bool) -> Result<()> {
    let path = match target {
        Some(p) => p.to_path_buf(),
        None => netls::config::default_write_path().ok_or_else(|| {
            anyhow::anyhow!("could not determine config directory; pass --config PATH explicitly")
        })?,
    };

    if path.exists() && !force {
        anyhow::bail!(
            "{} already exists. Re-run with --force to overwrite.",
            path.display()
        );
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("could not create directory {}: {e}", parent.display()))?;
    }

    std::fs::write(&path, STARTER_CONFIG)
        .map_err(|e| anyhow::anyhow!("could not write {}: {e}", path.display()))?;

    println!("created {}", path.display());
    println!("edit it to enable more defaults, profiles, or [ports] overrides.");
    Ok(())
}

fn cmd_kill_port(port: u16, force: bool) -> Result<()> {
    let filter = Filter::default().port(port).state(netls::State::Listen);
    let listeners: Vec<_> = netls::snapshot(&filter)?
        .into_iter()
        .filter(|c| c.local.ends_with(&format!(":{port}")))
        .collect();

    if listeners.is_empty() {
        println!("port {port}: nothing is listening");
        return Ok(());
    }

    for c in &listeners {
        let process = c.process.as_deref().unwrap_or("-");
        let Some(pid) = c.pid else {
            eprintln!("port {port}: process found but PID is not accessible (try sudo)");
            #[cfg(unix)]
            process::exit(1);
            #[cfg(not(unix))]
            return Ok(());
        };

        if !force {
            eprint!("kill {process} (pid {pid}) listening on port {port}? [y/N] ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if !matches!(input.trim().to_lowercase().as_str(), "y" | "yes") {
                println!("aborted");
                return Ok(());
            }
        }

        #[cfg(unix)]
        unsafe {
            let pid_t = libc::pid_t::try_from(pid).unwrap_or(libc::pid_t::MAX);
            if libc::kill(pid_t, libc::SIGTERM) != 0 {
                anyhow::bail!("kill({pid}) failed: {}", std::io::Error::last_os_error());
            }
        }
        println!("sent SIGTERM to {process} (pid {pid})");
    }
    Ok(())
}

fn cmd_check_port(port: u16) -> Result<()> {
    let filter = Filter::default().port(port).state(netls::State::Listen);
    let listeners: Vec<_> = netls::snapshot(&filter)?
        .into_iter()
        .filter(|c| c.local.ends_with(&format!(":{port}")))
        .collect();

    if listeners.is_empty() {
        println!("port {port}: free");
        return Ok(());
    }

    for c in &listeners {
        let process = c.process.as_deref().unwrap_or("-");
        let pid = c.pid.map_or_else(|| "-".to_string(), |p| p.to_string());
        println!(
            "port {port}: in use  proto={}  pid={pid}  process={process}",
            c.proto
        );
    }
    #[cfg(unix)]
    process::exit(1);
    #[cfg(not(unix))]
    Ok(())
}

fn cmd_wait_for(port: u16, timeout_secs: u64) -> Result<()> {
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let filter = Filter::default().port(port).state(netls::State::Listen);
    eprint!("waiting for port {port}");
    loop {
        let listeners: Vec<_> = netls::snapshot(&filter)?
            .into_iter()
            .filter(|c| c.local.ends_with(&format!(":{port}")))
            .collect();
        if !listeners.is_empty() {
            eprintln!(" - up");
            return Ok(());
        }
        if Instant::now() >= deadline {
            eprintln!(" - timeout after {timeout_secs}s");
            #[cfg(unix)]
            std::process::exit(1);
            #[cfg(not(unix))]
            return Ok(());
        }
        eprint!(".");
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn cmd_diff(path: &std::path::Path, filter: &Filter) -> Result<()> {
    use std::collections::HashSet;
    let saved_json = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
    let saved: Vec<netls::Connection> = serde_json::from_str(&saved_json)
        .map_err(|e| anyhow::anyhow!("invalid snapshot file: {e}"))?;
    let current = netls::snapshot(filter)?;

    let saved_keys: HashSet<netls::ConnectionKey> =
        saved.iter().map(netls::Connection::key).collect();
    let curr_keys: HashSet<netls::ConnectionKey> =
        current.iter().map(netls::Connection::key).collect();

    let added: Vec<&netls::Connection> = current
        .iter()
        .filter(|c| !saved_keys.contains(&c.key()))
        .collect();
    let removed: Vec<&netls::Connection> = saved
        .iter()
        .filter(|c| !curr_keys.contains(&c.key()))
        .collect();

    if added.is_empty() && removed.is_empty() {
        println!("no changes");
        return Ok(());
    }

    // Group key: proto + stable endpoint (non-ephemeral port).
    // Process is included only when the local port is stable (i.e. we know which service it is).
    // Ephemeral ports (≥32768) are folded to *, and process is dropped - otherwise
    // the same service port splits into multiple groups (one per unknown client process).
    let group_key = |c: &netls::Connection| -> String {
        let local_port = extract_port_num(&c.local).unwrap_or(0);
        let remote_port = extract_port_num(&c.remote).unwrap_or(0);
        let local_ephemeral = is_ephemeral(local_port);
        let remote_ephemeral = is_ephemeral(remote_port);
        let (stable, proc) = if local_ephemeral && !remote_ephemeral {
            // client side - group by the remote service, drop process (unknown on client)
            (stable_addr(&c.remote), "-".to_string())
        } else if !local_ephemeral && remote_ephemeral {
            // server side - group by local service port, include process
            let p = c.process.as_deref().unwrap_or("-").to_string();
            (stable_addr(&c.local), p)
        } else if local_ephemeral && remote_ephemeral {
            // both high ports - treat the lower one as the service side
            let service = if local_port <= remote_port {
                &c.local
            } else {
                &c.remote
            };
            (stable_addr(service), "-".to_string())
        } else {
            // both low ports (server↔server) - include both + process
            let p = c.process.as_deref().unwrap_or("-").to_string();
            (format!("{} -> {}", c.local, stable_addr(&c.remote)), p)
        };
        format!("{}|{}|{}", c.proto, stable, proc)
    };

    print_diff_grouped("+", &added, &group_key);
    print_diff_grouped("-", &removed, &group_key);
    Ok(())
}

fn print_diff_grouped(
    sign: &str,
    conns: &[&netls::Connection],
    key_fn: &dyn Fn(&netls::Connection) -> String,
) {
    use std::collections::HashMap;
    if conns.is_empty() {
        return;
    }

    // group key -> (count, representative connection)
    let mut groups: HashMap<String, (usize, &netls::Connection)> = HashMap::new();
    for c in conns {
        let k = key_fn(c);
        let e = groups.entry(k).or_insert((0, c));
        e.0 += 1;
    }

    let mut rows: Vec<(usize, &netls::Connection, String)> = groups
        .into_iter()
        .map(|(k, (count, c))| (count, c, k))
        .collect();
    rows.sort_by(|a, b| b.0.cmp(&a.0).then(a.2.cmp(&b.2)));

    for (count, c, _) in &rows {
        let proc = c.process.as_deref().unwrap_or("-");
        let local_port = extract_port_num(&c.local).unwrap_or(0);
        let remote_port = extract_port_num(&c.remote).unwrap_or(0);
        let endpoint = if is_ephemeral(local_port) && !is_ephemeral(remote_port) {
            stable_addr(&c.remote)
        } else {
            stable_addr(&c.local)
        };
        if *count == 1 {
            println!(
                "{sign}    1x  {} {} -> {} {}  ({})",
                c.proto,
                netls::compact_addr(&c.local),
                netls::compact_addr(&c.remote),
                display::state_str(c),
                proc
            );
        } else {
            println!(
                "{sign} {:>4}x  {} {}  {}  ({})",
                count,
                c.proto,
                endpoint,
                display::state_str(c),
                proc
            );
        }
    }
}

fn extract_port_num(addr: &str) -> Option<u16> {
    addr.rsplit_once(':')?.1.trim_end_matches('*').parse().ok()
}

fn is_ephemeral(port: u16) -> bool {
    port >= 32768
}

fn stable_addr(addr: &str) -> String {
    if let Some((host, port)) = addr.rsplit_once(':')
        && let Ok(p) = port.parse::<u16>()
        && is_ephemeral(p)
    {
        return format!("{host}:*");
    }
    addr.to_string()
}

fn build_filter(cli: &Cli) -> Result<Filter> {
    let mut f = Filter::default();
    if let Some(port) = cli.port {
        f = f.port(port);
    }
    if let Some(pid) = cli.pid {
        f = f.pid(pid);
    }
    if let Some(ref n) = cli.process {
        f = f.process(n.as_str());
    }
    if let Some(ref s) = cli.state {
        f = f.state(s.parse().map_err(anyhow::Error::from)?);
    }
    if let Some(ref p) = cli.proto {
        f = f.proto(p.parse().map_err(anyhow::Error::from)?);
    }
    if cli.no_loopback {
        f = f.no_loopback();
    }
    if cli.ipv4 {
        f = f.ipv4_only();
    }
    if cli.ipv6 {
        f = f.ipv6_only();
    }
    if cli.listen {
        f = f.state(netls::State::Listen);
    }
    // By default hide Unix sockets - they dominate the output and are rarely useful.
    // Show them with --all or --proto unix.
    if !cli.all && cli.proto.is_none() {
        f = f.no_unix();
    }
    Ok(f)
}

#[allow(clippy::too_many_lines)]
fn main() -> Result<()> {
    // Broken pipe (e.g. `netls | head`) should exit silently, not panic.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let matches = Cli::command().get_matches();
    let mut cli = Cli::from_arg_matches(&matches).expect("clap should accept its own matches");

    // --init-config bootstraps a brand-new config file; running config::load
    // first would defeat the purpose (and would hard-fail if the user pointed
    // --config at a file that does not yet exist).
    if cli.init_config {
        return cmd_init_config(cli.config.as_deref(), cli.force);
    }

    let loaded = config::load(cli.config.as_deref())?;
    let effective = loaded.config.effective(cli.profile.as_deref())?;
    let pretty_from_cli = matches.value_source("pretty") == Some(ValueSource::CommandLine);
    let service_names_from_cli =
        matches.value_source("service_names") == Some(ValueSource::CommandLine);
    let service_names_set_in_config = effective.service_names.is_some();
    apply_config(&mut cli, &effective, &matches);

    // Install [ports] from config as service-name overrides (consulted by
    // services::annotate_addr when --service-names is on).
    let port_overrides: std::collections::HashMap<u16, String> = loaded
        .config
        .port_overrides()
        .map(|(p, n)| (p, n.to_string()))
        .collect();
    let has_port_overrides = !port_overrides.is_empty();
    if has_port_overrides {
        services::set_user_overrides(port_overrides);
    }

    // [ports] without --service-names is dead weight: the overrides load but
    // nothing displays them. If the user defined entries and made no explicit
    // choice about service_names anywhere, turn it on. An explicit
    // `service_names = false` in config still wins (we only auto-flip when
    // truly unset).
    if has_port_overrides && !service_names_from_cli && !service_names_set_in_config {
        cli.service_names = true;
    }

    // Diagnostic hint: when the user activated a profile, remind them on stderr
    // which sections were applied and from where. Stdout stays clean for pipes.
    // Skipped for one-shot subcommands (those usually feed scripts) and TUI
    // (the redraw would bury the hint anyway).
    let skip_hint = cli.tui
        || cli.check_port.is_some()
        || cli.kill.is_some()
        || cli.wait_for.is_some()
        || cli.save.is_some()
        || cli.diff.is_some();
    if !skip_hint
        && let Some(ref profile_name) = cli.profile
        && let Some(ref path) = loaded.source_path
    {
        let has_defaults = loaded.config.defaults != netls::config::Defaults::default();
        let sections = if has_defaults {
            format!("[defaults] + [profiles.{profile_name}]")
        } else {
            format!("[profiles.{profile_name}]")
        };
        eprintln!("applied: {sections} from {}", path.display());
    }

    // --show-config wins over every subcommand: it is purely diagnostic and
    // the user explicitly asked for it.
    if cli.show_config {
        cmd_show_config(&loaded, &cli, &matches);
        return Ok(());
    }

    let cli = cli; // freeze

    if let Some(port) = cli.check_port {
        return cmd_check_port(port);
    }

    if let Some(port) = cli.kill {
        return cmd_kill_port(port, cli.force);
    }

    if let Some(port) = cli.wait_for {
        return cmd_wait_for(port, cli.timeout);
    }

    let filter = build_filter(&cli)?;
    let rp = cli.resolve_proxy;

    // Validate flag combinations that would silently do nothing.
    if cli.pretty && !cli.json {
        if pretty_from_cli {
            anyhow::bail!("--pretty requires --json");
        }
        anyhow::bail!(
            "config sets pretty = true but json is not enabled; either set json = true in the same section or remove pretty"
        );
    }
    if cli.watch.is_some() {
        if cli.csv {
            anyhow::bail!("--csv is not supported with --watch");
        }
        if cli.sort.is_some() {
            anyhow::bail!("--sort is not supported with --watch");
        }
        if cli.resolve_dns {
            anyhow::bail!("--resolve-dns is not supported with --watch");
        }
        if cli.pretty {
            anyhow::bail!("--pretty is not supported with --watch");
        }
        if cli.queues && cli.json {
            anyhow::bail!("--queues is not supported with --watch --json");
        }
    }
    if cli.tui {
        if cli.sort.is_some() {
            anyhow::bail!("--sort is not supported with --tui");
        }
        if cli.resolve_dns {
            anyhow::bail!("--resolve-dns is not supported with --tui");
        }
        if cli.json {
            anyhow::bail!("--json is not supported with --tui");
        }
        if cli.csv {
            anyhow::bail!("--csv is not supported with --tui");
        }
        if cli.queues {
            anyhow::bail!("--queues is not supported with --tui");
        }
    }

    // Flags not supported on this platform.
    #[cfg(not(target_os = "linux"))]
    if cli.systemd {
        anyhow::bail!("--systemd is not supported on this platform (Linux only)");
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    if cli.containers {
        anyhow::bail!("--containers is not supported on this platform");
    }

    if let Some(ref path) = cli.save {
        let conns = netls::snapshot(&filter)?;
        let json = serde_json::to_string_pretty(&conns)?;
        std::fs::write(path, json)?;
        println!("saved {} connections to {}", conns.len(), path.display());
        return Ok(());
    }

    if let Some(ref path) = cli.diff {
        return cmd_diff(path, &filter);
    }

    if cli.summary {
        let conns = netls::snapshot(&filter)?;
        output::summary::print(&conns);
        if let Some(threshold) = cli.warn_timewait {
            let tw = conns
                .iter()
                .filter(|c| c.state == Some(netls::State::TimeWait))
                .count();
            if tw >= threshold {
                eprintln!(
                    "WARNING: {tw} TIME_WAIT connections (threshold: {threshold}). Check keep-alive settings or ephemeral port exhaustion."
                );
            }
        }
        return Ok(());
    }

    if let Some(n) = cli.top {
        let conns = netls::snapshot(&filter)?;
        output::summary::print_top(&conns, n);
        return Ok(());
    }

    if cli.count {
        let conns = netls::snapshot(&filter)?;
        println!("{}", conns.len());
        return Ok(());
    }

    if cli.tui {
        tui::run(filter, rp)?;
    } else if let Some(interval) = cli.watch {
        let mode = if cli.json {
            WatchOutput::Json
        } else {
            WatchOutput::Table
        };
        watch::run(&filter, interval, &mode, rp, cli.containers)?;
    } else {
        let mut conns = if cli.containers {
            let r = netls::snapshot_with_containers(&filter)?;
            for w in &r.warnings {
                eprintln!("netls: warning: {w}");
            }
            r.connections
        } else {
            netls::snapshot(&filter)?
        };
        if cli.resolve_dns {
            netls::resolve_dns(&mut conns);
        }
        if cli.cmdline {
            netls::enrich_cmdline(&mut conns);
        }
        if cli.age {
            netls::enrich_age(&mut conns);
        }
        if cli.tree {
            netls::enrich_process_tree(&mut conns);
        }
        if cli.systemd {
            netls::enrich_systemd(&mut conns);
        }
        if cli.fd {
            netls::enrich_fd(&mut conns);
        }
        if let Some(ref col) = cli.sort {
            let key: netls::SortKey = col.parse().map_err(anyhow::Error::from)?;
            netls::sort_connections(&mut conns, key);
        }

        if let Some(ref field) = cli.group_by {
            output::grouped::print_conns(&conns, field)?;
        } else if cli.json {
            output::json::print_conns(&conns, cli.pretty)?;
        } else if cli.csv {
            output::csv::print_conns(&conns)?;
        } else {
            output::table::print_conns(
                &conns,
                output::table::TableOptions {
                    resolve_proxy: rp,
                    show_queues: cli.queues,
                    service_names: cli.service_names,
                    show_container: cli.containers,
                    show_age: cli.age,
                    show_tree: cli.tree,
                    show_systemd: cli.systemd,
                    show_fd: cli.fd,
                },
            )?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use netls::config::Defaults;

    /// Run clap on a synthetic argv, then apply the supplied config defaults.
    /// Returns the resulting `Cli` so tests can assert on field values.
    fn run(argv: &[&str], defaults: Defaults) -> Cli {
        let matches = Cli::command()
            .try_get_matches_from(argv)
            .expect("argv should parse");
        let mut cli = Cli::from_arg_matches(&matches).expect("clap should accept its own matches");
        apply_config(&mut cli, &defaults, &matches);
        cli
    }

    #[test]
    fn cli_option_wins_over_config() {
        let mut defaults = Defaults::default();
        defaults.proto = Some("udp".into());
        let cli = run(&["netls", "--proto", "tcp"], defaults);
        assert_eq!(
            cli.proto.as_deref(),
            Some("tcp"),
            "CLI --proto must override config defaults.proto"
        );
    }

    #[test]
    fn config_option_applies_when_cli_unset() {
        let mut defaults = Defaults::default();
        defaults.proto = Some("udp".into());
        defaults.sort = Some("port".into());
        let cli = run(&["netls"], defaults);
        assert_eq!(cli.proto.as_deref(), Some("udp"));
        assert_eq!(cli.sort.as_deref(), Some("port"));
    }

    #[test]
    fn cli_bool_flag_wins_when_config_says_false() {
        // Config explicitly sets no_loopback = false; CLI passes the flag.
        // The CLI form is a presence flag that defaults to false, so we rely
        // on value_source to detect that the user actually typed it.
        let mut defaults = Defaults::default();
        defaults.no_loopback = Some(false);
        let cli = run(&["netls", "--no-loopback"], defaults);
        assert!(cli.no_loopback, "CLI flag must beat config bool=false");
    }

    #[test]
    fn config_bool_applies_when_cli_did_not_pass_flag() {
        let mut defaults = Defaults::default();
        defaults.no_loopback = Some(true);
        defaults.service_names = Some(true);
        let cli = run(&["netls"], defaults);
        assert!(cli.no_loopback, "config-set bool must apply");
        assert!(cli.service_names);
    }

    #[test]
    fn unset_config_field_does_not_clobber_cli_default() {
        // No defaults at all: every field stays at its clap-default value.
        let cli = run(&["netls"], Defaults::default());
        assert!(cli.proto.is_none());
        assert!(!cli.no_loopback);
        assert!(!cli.json);
    }

    #[test]
    fn init_config_creates_file_at_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        cmd_init_config(Some(&target), false).unwrap();
        let content = std::fs::read_to_string(&target).unwrap();
        // Active recommendation that the template ships uncommented.
        assert!(content.contains("service_names = true"));
        // Sample profile header is present (uncommented, but only activated
        // when the user passes --profile dev).
        assert!(content.contains("[profiles.dev]"));
        // [ports] examples are commented out so they don't change behaviour
        // until the user opts in.
        assert!(content.contains("# 3000 = \"vite-dev\""));
    }

    #[test]
    fn init_config_refuses_to_overwrite_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        std::fs::write(&target, "existing content").unwrap();
        let err = cmd_init_config(Some(&target), false).unwrap_err();
        assert!(err.to_string().contains("already exists"));
        // File should still be the original.
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "existing content"
        );
    }

    #[test]
    fn init_config_force_overwrites_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        std::fs::write(&target, "stale content").unwrap();
        cmd_init_config(Some(&target), true).unwrap();
        let content = std::fs::read_to_string(&target).unwrap();
        assert!(content.contains("service_names = true"));
        assert!(!content.contains("stale content"));
    }

    #[test]
    fn init_config_creates_parent_directory() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("sub1").join("sub2").join("config.toml");
        cmd_init_config(Some(&nested), false).unwrap();
        assert!(nested.exists());
    }
}
