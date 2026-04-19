#[cfg(unix)]
extern crate libc;
use anyhow::Result;
use owo_colors::OwoColorize;
use std::collections::HashMap;
use std::io::IsTerminal;
use tabled::builder::Builder;
use tabled::settings::Modify;
use tabled::settings::Style;
use tabled::settings::object::Columns;
use tabled::settings::width::Truncate;

use crate::{
    Connection, NO_PERMISSION, State, fmt_age, format_process_text, resolve_docker_name,
    resolve_proxy_origins, services, snapshot_all,
};

// ── Options ───────────────────────────────────────────────────────────────────

/// Toggles for optional table columns.
#[derive(Clone, Copy)]
#[allow(missing_docs)]
pub struct TableOptions {
    pub resolve_proxy: bool,
    pub show_queues: bool,
    pub service_names: bool,
    pub show_container: bool,
    pub show_age: bool,
    pub show_tree: bool,
    pub show_systemd: bool,
    pub show_fd: bool,
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Render `conns` as a table to stdout.
///
/// # Errors
///
/// Propagates errors from the `tabled` renderer and stdout writes.
pub fn print_conns(conns: &[Connection], opts: TableOptions) -> Result<()> {
    let output = render_conns(conns, opts)?;
    print!("{output}");
    Ok(())
}

fn render_conns(conns: &[Connection], opts: TableOptions) -> Result<String> {
    let TableOptions {
        resolve_proxy,
        show_queues,
        service_names,
        show_container,
        show_age,
        show_tree,
        show_systemd,
        show_fd,
    } = opts;
    if conns.is_empty() {
        return Ok("No connections found.\n".to_string());
    }

    let color = std::io::stdout().is_terminal();
    let origins = if resolve_proxy {
        let all = snapshot_all()?;
        resolve_proxy_origins(&all)
    } else {
        HashMap::new()
    };

    // Build header
    let mut header: Vec<String> = vec![
        "PROTO".into(),
        "LOCAL".into(),
        "REMOTE".into(),
        "STATE".into(),
    ];
    if show_age {
        header.push("AGE".into());
    }
    if show_queues {
        header.push("RECV-Q".into());
        header.push("SEND-Q".into());
    }
    header.push("PID".into());
    header.push("PROCESS".into());
    if show_fd {
        header.push("FD".into());
    }
    if show_container {
        header.push("CONTAINER".into());
    }
    if show_tree {
        header.push("PARENT CHAIN".into());
    }
    if show_systemd {
        header.push("UNIT".into());
    }

    let mut builder = Builder::new();
    builder.push_record(header);

    let fmt_queue = |q: Option<u32>| q.map_or_else(|| "-".to_string(), |v| v.to_string());

    for c in conns {
        let base = build_base(c, color, &origins, service_names);
        let mut row: Vec<String> = vec![base.proto, base.local, base.remote, base.state];
        if show_age {
            row.push(c.age_secs.map_or_else(|| "-".to_string(), fmt_age));
        }
        if show_queues {
            row.push(fmt_queue(c.recv_q));
            row.push(fmt_queue(c.send_q));
        }
        row.push(base.pid);
        row.push(base.process);
        if show_fd {
            let fd_str = match c.fd_usage {
                Some((open, limit)) if limit != usize::MAX => {
                    let pct = open * 100 / limit.max(1);
                    if pct >= 90 {
                        format!("{open}/{limit}").bright_red().to_string()
                    } else if pct >= 75 {
                        format!("{open}/{limit}").yellow().to_string()
                    } else {
                        format!("{open}/{limit}")
                    }
                }
                Some((open, _)) => open.to_string(),
                None => "-".to_string(),
            };
            row.push(fd_str);
        }
        if show_container {
            row.push(c.container.clone().unwrap_or_default());
        }
        if show_tree {
            row.push(c.parent_chain.clone().unwrap_or_else(|| "-".to_string()));
        }
        if show_systemd {
            row.push(c.systemd_unit.clone().unwrap_or_else(|| "-".to_string()));
        }
        builder.push_record(row);
    }

    let term_width = terminal_width();
    let mut tbl = builder.build();
    tbl.with(Style::blank());
    if let Some(w) = term_width {
        // Reserve ~60 chars for fixed columns (PROTO, STATE, PID, PROCESS, spacing).
        // Split the rest evenly between LOCAL (col 1) and REMOTE (col 2).
        let addr_width = ((w.saturating_sub(60)) / 2).max(20);
        tbl.with(Modify::new(Columns::single(1)).with(Truncate::new(addr_width).suffix("…")));
        tbl.with(Modify::new(Columns::single(2)).with(Truncate::new(addr_width).suffix("…")));
        // Final safety: cap total table width so nothing wraps.
        tbl.with(Truncate::new(w).suffix("…"));
    }
    Ok(format!("{tbl}\n"))
}

// ── Row builder ───────────────────────────────────────────────────────────────

struct BaseRow {
    proto: String,
    local: String,
    remote: String,
    state: String,
    pid: String,
    process: String,
}

fn build_base(
    c: &Connection,
    color: bool,
    origins: &HashMap<String, String>,
    service_names: bool,
) -> BaseRow {
    let no_perm = no_permission(color);
    let key = c.key();
    let process = if origins.contains_key(&key) {
        let text = format_process_text(c, origins);
        if color {
            text.bright_yellow().to_string()
        } else {
            text
        }
    } else if let Some(docker_name) = resolve_docker_name(c) {
        docker_name
    } else if let Some(ref cl) = c.cmdline {
        cl.to_owned()
    } else {
        c.process.as_deref().unwrap_or(&no_perm).to_owned()
    };
    let fmt_remote = |addr: &str| {
        if service_names {
            services::annotate_addr(addr)
        } else {
            addr.to_string()
        }
    };
    let is_container = c.container.is_some();
    let fmt_loc = |addr: &str| {
        let base = fmt_local(addr, color, is_container);
        if service_names {
            services::annotate_addr(&base)
        } else {
            base
        }
    };
    BaseRow {
        proto: c.proto.to_string(),
        local: fmt_loc(&c.local),
        remote: fmt_remote(&c.remote),
        state: fmt_state(c.state.as_ref(), color),
        pid: c.pid.map(|p| p.to_string()).unwrap_or(no_perm),
        process,
    }
}

// ── Terminal width ────────────────────────────────────────────────────────────

fn terminal_width() -> Option<usize> {
    #[cfg(unix)]
    {
        let mut ws = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let ret = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
        if ret == 0 && ws.ws_col > 0 {
            return Some(ws.ws_col as usize);
        }
    }
    None
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn no_permission(color: bool) -> String {
    if color {
        NO_PERMISSION.truecolor(80, 80, 80).to_string()
    } else {
        NO_PERMISSION.to_string()
    }
}

/// Highlight local addresses bound to all interfaces - these are externally reachable.
fn fmt_local(local: &str, color: bool, is_container: bool) -> String {
    if color && !is_container && (local.starts_with("0.0.0.0:") || local.starts_with("*:")) {
        local.yellow().to_string()
    } else {
        local.to_string()
    }
}

fn fmt_state(state: Option<&State>, color: bool) -> String {
    let Some(s) = state else {
        return "-".to_string();
    };
    let text = s.to_string();
    if !color {
        return text;
    }
    match s {
        State::Listen => text.bright_blue().to_string(),
        State::Established => text.bright_green().to_string(),
        State::TimeWait | State::CloseWait | State::FinWait1 | State::FinWait2 | State::LastAck => {
            text.yellow().to_string()
        }
        _ => text,
    }
}
