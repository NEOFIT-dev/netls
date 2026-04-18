use anyhow::Result;
use clap::Parser;
use netls::{watch::WatchOutput, Filter};

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

    /// Filter by protocol (tcp, udp)
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

    /// Annotate port numbers with service names (e.g. :5432 → :5432 (postgres))
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
}

fn cmd_kill_port(port: u16, force: bool) -> Result<()> {
    let filter = Filter::default().port(port).state("listen");
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
    let filter = Filter::default().port(port).state("listen");
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
    let filter = Filter::default().port(port).state("listen");
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

    let saved_keys: HashSet<String> = saved.iter().map(netls::Connection::key).collect();
    let curr_keys: HashSet<String> = current.iter().map(netls::Connection::key).collect();

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
            (format!("{} → {}", c.local, stable_addr(&c.remote)), p)
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

    // group key → (count, representative connection)
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
                "{sign}    1x  {} {} → {} {}  ({})",
                c.proto,
                c.local,
                c.remote,
                c.state_str(),
                proc
            );
        } else {
            println!(
                "{sign} {:>4}x  {} {}  {}  ({})",
                count,
                c.proto,
                endpoint,
                c.state_str(),
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
    if let Some((host, port)) = addr.rsplit_once(':') {
        if let Ok(p) = port.parse::<u16>() {
            if is_ephemeral(p) {
                return format!("{host}:*");
            }
        }
    }
    addr.to_string()
}

const VALID_STATES: &[&str] = &[
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

const VALID_PROTOS: &[&str] = &["tcp", "udp", "unix"];

fn build_filter(cli: &Cli) -> Result<Filter> {
    if let Some(ref s) = cli.state {
        let lower = s.to_lowercase();
        if !VALID_STATES.contains(&lower.as_str()) {
            anyhow::bail!(
                "invalid --state value {:?}. Valid values: {}",
                s,
                VALID_STATES.join(", ")
            );
        }
    }
    if let Some(ref p) = cli.proto {
        let lower = p.to_lowercase();
        if !VALID_PROTOS.contains(&lower.as_str()) {
            anyhow::bail!(
                "invalid --proto value {:?}. Valid values: {}",
                p,
                VALID_PROTOS.join(", ")
            );
        }
    }

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
        f = f.state(s.as_str());
    }
    if let Some(ref p) = cli.proto {
        f = f.proto(p.as_str());
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
        f = f.state("listen");
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

    let cli = Cli::parse();

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
        anyhow::bail!("--pretty requires --json");
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
        netls::output::summary::print(&conns);
        if let Some(threshold) = cli.warn_timewait {
            let tw = conns
                .iter()
                .filter(|c| c.state == Some(netls::State::TimeWait))
                .count();
            if tw >= threshold {
                eprintln!("WARNING: {tw} TIME_WAIT connections (threshold: {threshold}). Check keep-alive settings or ephemeral port exhaustion.");
            }
        }
        return Ok(());
    }

    if let Some(n) = cli.top {
        let conns = netls::snapshot(&filter)?;
        netls::output::summary::print_top(&conns, n);
        return Ok(());
    }

    if cli.count {
        let conns = netls::snapshot(&filter)?;
        println!("{}", conns.len());
        return Ok(());
    }

    if cli.tui {
        netls::tui::run(filter, rp)?;
    } else if let Some(interval) = cli.watch {
        let mode = if cli.json {
            WatchOutput::Json
        } else {
            WatchOutput::Table
        };
        netls::watch::run(&filter, interval, &mode, rp, cli.containers)?;
    } else {
        let mut conns = if cli.containers {
            netls::snapshot_with_containers(&filter)?
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
            netls::sort_connections(&mut conns, col);
        }

        if let Some(ref field) = cli.group_by {
            netls::output::grouped::print_conns(&conns, field)?;
        } else if cli.json {
            netls::output::json::print_conns(&conns, cli.pretty)?;
        } else if cli.csv {
            netls::output::csv::print_conns(&conns)?;
        } else {
            netls::output::table::print_conns(
                &conns,
                netls::output::table::TableOptions {
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
