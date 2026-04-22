use std::collections::HashMap;
use std::io::{self, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use crossterm::{
    cursor::MoveTo,
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{Clear, ClearType, EnterAlternateScreen, enable_raw_mode},
};
use owo_colors::OwoColorize;

use netls::{
    Connection, Filter, compact_addr, diff_connections, resolve_proxy_origins, snapshot,
    snapshot_all, snapshot_with_containers,
};

use crate::display::{format_process_text, state_str};
use crate::tui_common::TerminalGuard;

// ── Entry point ───────────────────────────────────────────────────────────────

/// Output style for the [`run`] watch loop.
#[non_exhaustive]
#[allow(missing_docs)]
pub enum WatchOutput {
    Table,
    Json,
}

/// Launch the live `--watch` loop. Refreshes every `interval_secs` and
/// renders the diff between successive snapshots. Blocks until interrupted.
///
/// # Errors
///
/// Fails if stdout is not a TTY (table mode cannot enable raw mode for the
/// alternate screen) or if [`netls::snapshot`] errors on a refresh.
pub fn run(
    filter: &Filter,
    interval_secs: u64,
    output: &WatchOutput,
    resolve_proxy: bool,
    containers: bool,
) -> Result<()> {
    match output {
        WatchOutput::Json => run_json(filter, interval_secs, resolve_proxy, containers),
        WatchOutput::Table => run_table(filter, interval_secs, resolve_proxy, containers),
    }
}

fn snapshot_for(filter: &Filter, containers: bool) -> netls::Result<Vec<Connection>> {
    if containers {
        let r = snapshot_with_containers(filter)?;
        for w in &r.warnings {
            eprintln!("netls: warning: {w}");
        }
        Ok(r.connections)
    } else {
        snapshot(filter)
    }
}

// ── JSON streaming mode ───────────────────────────────────────────────────────

fn run_json(
    filter: &Filter,
    interval_secs: u64,
    resolve_proxy: bool,
    containers: bool,
) -> Result<()> {
    let mut prev_conns: Vec<Connection> = Vec::new();

    loop {
        match snapshot_for(filter, containers) {
            Err(e) => {
                eprintln!("netls: warning: snapshot failed: {e}");
            }
            Ok(curr) => {
                let origins = if resolve_proxy {
                    match snapshot_all() {
                        Ok(all) => resolve_proxy_origins(&all),
                        Err(e) => {
                            eprintln!("netls: warning: failed to resolve proxy origins: {e}");
                            std::collections::HashMap::new()
                        }
                    }
                } else {
                    std::collections::HashMap::new()
                };

                let diff = diff_connections(&prev_conns, &curr);

                for c in curr.iter().filter(|c| diff.new.contains(&c.key())) {
                    emit_event("new", c, &origins);
                }
                for c in &diff.closed {
                    emit_event("closed", c, &origins);
                }
                io::stdout().flush()?;
                prev_conns = curr;
            }
        }
        std::thread::sleep(Duration::from_secs(interval_secs));
    }
}

// ── Table mode (alternate screen) ─────────────────────────────────────────────

fn run_table(
    filter: &Filter,
    interval_secs: u64,
    resolve_proxy: bool,
    containers: bool,
) -> Result<()> {
    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    let _guard = TerminalGuard;

    table_loop(filter, interval_secs, resolve_proxy, containers)
}

// ── Column layout ─────────────────────────────────────────────────────────────

const COL_PROTO: usize = 4;
const COL_LOCAL: usize = 22;
const COL_REMOTE: usize = 22;
const COL_STATE: usize = 11;
const COL_PID: usize = 6;
const COL_CONTAINER: usize = 16;
const SEP: usize = 2; // column separator width
const COL_FIXED: usize =
    COL_PROTO + SEP + COL_LOCAL + SEP + COL_REMOTE + SEP + COL_STATE + SEP + COL_PID + SEP;
const MIN_PROC_COL_WIDTH: usize = 10;

/// Fallback terminal dimensions used when the real size cannot be queried.
const FALLBACK_TERM_COLS: u16 = 200;
const FALLBACK_TERM_ROWS: u16 = 50;

/// Number of non-data lines rendered per frame (header rows + footer + safety margin).
const OVERHEAD_LINES: usize = 7;

enum RowKind {
    Normal,
    New,
    Closed,
}

// ── Watch state ───────────────────────────────────────────────────────────────

struct WatchState {
    prev_conns: Vec<Connection>,
    last_refresh: Instant,
    entries: Vec<(Connection, RowKind)>,
    origins: HashMap<netls::ConnectionKey, Vec<String>>,
    scroll: usize,
    max_visible: usize,
    needs_redraw: bool,
    filter_query: String,
    editing_filter: bool,
    containers: bool,
}

impl WatchState {
    fn new(interval_secs: u64, containers: bool) -> Self {
        Self {
            prev_conns: Vec::new(),
            last_refresh: Instant::now()
                .checked_sub(Duration::from_secs(interval_secs + 1))
                .unwrap_or_else(Instant::now),
            entries: Vec::new(),
            origins: HashMap::new(),
            scroll: 0,
            max_visible: 40,
            needs_redraw: true,
            filter_query: String::new(),
            editing_filter: false,
            containers,
        }
    }

    fn max_scroll(&self) -> usize {
        self.visible_entries()
            .len()
            .saturating_sub(self.max_visible)
    }

    fn visible_entries(&self) -> Vec<&(Connection, RowKind)> {
        if self.filter_query.is_empty() {
            self.entries.iter().collect()
        } else {
            self.entries
                .iter()
                .filter(|(c, _)| c.text_matches(&self.filter_query))
                .collect()
        }
    }
}

// ── Main loop ─────────────────────────────────────────────────────────────────

fn table_loop(
    filter: &Filter,
    interval_secs: u64,
    resolve_proxy: bool,
    containers: bool,
) -> Result<()> {
    let mut state = WatchState::new(interval_secs, containers);

    loop {
        if handle_input(&mut state)? {
            return Ok(());
        }
        refresh_data(&mut state, filter, resolve_proxy, interval_secs, containers);
        render(&mut state, interval_secs)?;
    }
}

/// Process pending keyboard events. Returns `true` if the user requested quit.
fn handle_input(state: &mut WatchState) -> Result<bool> {
    if !event::poll(Duration::from_millis(50))? {
        return Ok(false);
    }
    let Event::Key(k) = event::read()? else {
        return Ok(false);
    };

    if state.editing_filter {
        match k.code {
            KeyCode::Enter | KeyCode::Esc => {
                if k.code == KeyCode::Esc {
                    state.filter_query.clear();
                }
                state.editing_filter = false;
                state.scroll = 0;
                state.needs_redraw = true;
            }
            KeyCode::Backspace => {
                state.filter_query.pop();
                state.scroll = 0;
                state.needs_redraw = true;
            }
            KeyCode::Char(c) => {
                state.filter_query.push(c);
                state.scroll = 0;
                state.needs_redraw = true;
            }
            _ => {}
        }
        return Ok(false);
    }

    let max_scroll = state.max_scroll();
    match (k.code, k.modifiers) {
        (KeyCode::Char('q'), _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => return Ok(true),

        (KeyCode::Char('/'), _) => {
            state.editing_filter = true;
            state.needs_redraw = true;
        }

        (KeyCode::Down | KeyCode::Char('j'), _) => {
            state.scroll = (state.scroll + 1).min(max_scroll);
            state.needs_redraw = true;
        }
        (KeyCode::Up | KeyCode::Char('k'), _) => {
            state.scroll = state.scroll.saturating_sub(1);
            state.needs_redraw = true;
        }
        (KeyCode::PageDown, _) => {
            state.scroll = (state.scroll + state.max_visible).min(max_scroll);
            state.needs_redraw = true;
        }
        (KeyCode::PageUp, _) => {
            state.scroll = state.scroll.saturating_sub(state.max_visible);
            state.needs_redraw = true;
        }
        (KeyCode::Home, _) => {
            state.scroll = 0;
            state.needs_redraw = true;
        }
        (KeyCode::End, _) => {
            state.scroll = max_scroll;
            state.needs_redraw = true;
        }
        _ => {}
    }
    Ok(false)
}

/// Refresh connection data if the interval has elapsed.
fn refresh_data(
    state: &mut WatchState,
    filter: &Filter,
    resolve_proxy: bool,
    interval_secs: u64,
    containers: bool,
) {
    if state.last_refresh.elapsed() < Duration::from_secs(interval_secs) {
        return;
    }

    let curr = match snapshot_for(filter, containers) {
        Ok(c) => c,
        Err(e) => {
            // Transient errors (e.g. permissions on /proc) should not kill watch mode.
            eprintln!("netls: warning: snapshot failed: {e}");
            state.last_refresh = std::time::Instant::now();
            return;
        }
    };
    let diff = diff_connections(&state.prev_conns, &curr);

    if resolve_proxy {
        match snapshot_all() {
            Ok(all) => state.origins = resolve_proxy_origins(&all),
            Err(e) => eprintln!("netls: warning: failed to resolve proxy origins: {e}"),
        }
    }

    state.entries = curr
        .iter()
        .map(|c| {
            let kind = if diff.new.contains(&c.key()) {
                RowKind::New
            } else {
                RowKind::Normal
            };
            (c.clone(), kind)
        })
        .collect();
    for c in diff.closed {
        state.entries.push((c, RowKind::Closed));
    }

    // Clamp scroll so it stays valid after the list shrinks
    state.scroll = if state.entries.is_empty() {
        0
    } else {
        state.scroll.min(state.entries.len() - 1)
    };

    state.prev_conns = curr;
    state.last_refresh = Instant::now();
    state.needs_redraw = true;
}

/// Render the current state to the terminal if a redraw is needed.
fn render(state: &mut WatchState, interval_secs: u64) -> Result<()> {
    if !state.needs_redraw {
        return Ok(());
    }

    let (term_cols, term_rows) =
        crossterm::terminal::size().unwrap_or((FALLBACK_TERM_COLS, FALLBACK_TERM_ROWS));
    state.max_visible = (term_rows as usize).saturating_sub(OVERHEAD_LINES);

    // Re-clamp scroll after terminal resize or list shrink
    state.scroll = state.scroll.min(state.max_scroll());

    execute!(io::stdout(), Clear(ClearType::All), MoveTo(0, 0))?;
    let visible = state.visible_entries();
    print_header(
        interval_secs,
        visible.len(),
        state.scroll,
        state.max_visible,
        &state.filter_query,
    );
    print_table(
        &visible,
        &state.origins,
        term_cols as usize,
        state.max_visible,
        state.scroll,
        state.containers,
    );
    print_footer(state.editing_filter, &state.filter_query);
    io::stdout().flush()?;
    state.needs_redraw = false;
    Ok(())
}

// ── Table rendering ───────────────────────────────────────────────────────────

fn print_table(
    entries: &[&(Connection, RowKind)],
    origins: &HashMap<netls::ConnectionKey, Vec<String>>,
    term_cols: usize,
    max_visible: usize,
    scroll: usize,
    containers: bool,
) {
    let extra = if containers { COL_CONTAINER + 1 } else { 0 };
    let max_available = term_cols
        .saturating_sub(COL_FIXED + extra)
        .max(MIN_PROC_COL_WIDTH);
    let w_proc = if containers {
        // Use actual max process name width so CONTAINER column stays close
        let actual = entries
            .iter()
            .map(|(c, _)| format_process_text(c, origins).chars().count())
            .max()
            .unwrap_or(MIN_PROC_COL_WIDTH)
            .max(MIN_PROC_COL_WIDTH);
        actual.min(max_available)
    } else {
        max_available
    };

    let hdr = if containers {
        format!(
            "{:<COL_PROTO$}  {:<COL_LOCAL$}  {:<COL_REMOTE$}  {:<COL_STATE$}  {:<COL_PID$}  {:<w_proc$}  CONTAINER",
            "PROTO", "LOCAL", "REMOTE", "STATE", "PID", "PROCESS",
        )
    } else {
        format!(
            "{:<COL_PROTO$}  {:<COL_LOCAL$}  {:<COL_REMOTE$}  {:<COL_STATE$}  {:<COL_PID$}  PROCESS",
            "PROTO", "LOCAL", "REMOTE", "STATE", "PID",
        )
    };
    rprint(&hdr.bold().to_string());

    if entries.is_empty() {
        rprint("  (no connections)");
        return;
    }

    for (c, kind) in entries.iter().skip(scroll).take(max_visible) {
        let line = fmt_row(c, origins, w_proc, containers);
        let colored = match kind {
            RowKind::New => line.bright_green().to_string(),
            RowKind::Closed => line.bright_red().to_string(),
            RowKind::Normal => line,
        };
        rprint(&colored);
    }
}

fn fmt_row(
    c: &Connection,
    origins: &HashMap<netls::ConnectionKey, Vec<String>>,
    w_proc: usize,
    containers: bool,
) -> String {
    let process_text = format_process_text(c, origins);
    let base = format!(
        "{}  {}  {}  {}  {}  {}",
        fit(&c.proto.to_string(), COL_PROTO),
        fit(&compact_addr(&c.local), COL_LOCAL),
        fit(&compact_addr(&c.remote), COL_REMOTE),
        fit(&state_str(c), COL_STATE),
        fit(
            &c.pid.map_or_else(|| "?".to_string(), |p| p.to_string()),
            COL_PID
        ),
        fit(&process_text, w_proc),
    );
    if containers {
        let name = c.container.as_deref().unwrap_or("");
        format!("{base}  {}", fit(name, COL_CONTAINER))
    } else {
        base
    }
}

/// Left-align `s` in a field of `width` chars, truncating with '…' if too long.
fn fit(s: &str, width: usize) -> String {
    let n = s.chars().count();
    if n <= width {
        format!("{s:<width$}")
    } else if width > 1 {
        let t: String = s.chars().take(width - 1).collect();
        format!("{t}…")
    } else {
        s.chars().take(width).collect()
    }
}

/// Print a line with \r\n - required in raw mode so cursor returns to column 0.
fn rprint(s: &str) {
    print!("{s}\r\n");
}

// ── Header / footer ───────────────────────────────────────────────────────────

fn print_header(
    interval_secs: u64,
    total: usize,
    scroll: usize,
    max_visible: usize,
    filter_query: &str,
) {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).map_or_else(
        |_| "??:??:??".to_string(),
        |d| {
            let s = d.as_secs();
            format!(
                "{:02}:{:02}:{:02}",
                (s % 86400) / 3600,
                (s % 3600) / 60,
                s % 60
            )
        },
    );

    let end = (scroll + max_visible).min(total);
    let count_str = if total == 0 {
        "0 connections".to_string()
    } else {
        format!("{}-{} of {}", scroll + 1, end, total)
    };

    let label = format!("netls --watch {interval_secs}");
    let filter_part = if filter_query.is_empty() {
        String::new()
    } else {
        format!("  filter:{}", filter_query.yellow())
    };
    let line = format!(
        "{}  {}{}  {}  q=quit",
        label.dimmed(),
        count_str.bold(),
        filter_part,
        ts.dimmed()
    );
    rprint(&line);
    rprint("");
}

fn print_footer(editing: bool, filter_query: &str) {
    if editing {
        rprint(&format!("  /{}█", filter_query.yellow()));
    } else {
        rprint(&format!(
            "{}",
            "  q quit   ↑↓/jk scroll   PgUp/PgDn page   Home/End   / filter".dimmed()
        ));
    }
}

// ── JSON event emitter ────────────────────────────────────────────────────────

fn emit_event(event: &str, c: &Connection, origins: &HashMap<netls::ConnectionKey, Vec<String>>) {
    let proxy_origin = origins.get(&c.key());
    let result = match proxy_origin {
        Some(origin) => {
            let joined = origin.join(", ");
            serde_json::to_string(c).map(|json| {
                format!(
                    "{{\"event\":\"{event}\",\"proxy_origin\":\"{joined}\",\"connection\":{json}}}"
                )
            })
        }
        None => serde_json::to_string(c)
            .map(|json| format!("{{\"event\":\"{event}\",\"connection\":{json}}}")),
    };
    match result {
        Ok(line) => println!("{line}"),
        Err(e) => eprintln!("netls: failed to serialize connection: {e}"),
    }
}
