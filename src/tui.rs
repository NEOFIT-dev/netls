use std::collections::HashSet;
use std::io;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
};

use crate::{
    Connection, Filter, NO_PERMISSION, State, diff_connections, format_process_text, snapshot,
    tui_common::TerminalGuard,
};

const REFRESH_SECS: u64 = 2;

// ── State ─────────────────────────────────────────────────────────────────────

struct App {
    filter: Filter,
    resolve_proxy: bool,
    conns: Vec<Connection>,
    origins: std::collections::HashMap<String, String>,
    new_keys: HashSet<String>,
    closed_conns: Vec<Connection>,
    table_state: TableState,
    // Inline filter
    filter_mode: bool,
    filter_input: String,
    last_refresh: Instant,
}

impl App {
    fn new(filter: Filter, resolve_proxy: bool) -> Result<Self> {
        let mut app = Self {
            filter,
            resolve_proxy,
            conns: Vec::new(),
            origins: std::collections::HashMap::new(),
            new_keys: HashSet::new(),
            closed_conns: Vec::new(),
            table_state: TableState::default(),
            filter_mode: false,
            filter_input: String::new(),
            last_refresh: Instant::now()
                .checked_sub(Duration::from_secs(REFRESH_SECS + 1))
                .unwrap_or_else(Instant::now),
        };
        app.refresh()?;
        Ok(app)
    }

    fn refresh(&mut self) -> Result<()> {
        let curr = snapshot(&self.filter)?;
        let (new_keys, closed_conns) = diff_connections(&self.conns, &curr);
        self.new_keys = new_keys;
        self.closed_conns = closed_conns;

        if self.resolve_proxy {
            match crate::snapshot_all() {
                Ok(all) => self.origins = crate::resolve_proxy_origins(&all),
                Err(e) => eprintln!("netls: warning: failed to resolve proxy origins: {e}"),
            }
        }
        self.conns = curr;
        self.last_refresh = Instant::now();
        Ok(())
    }

    fn visible_rows(&self) -> Vec<&Connection> {
        let q = self.filter_input.to_lowercase();
        let mut rows: Vec<&Connection> = self.conns.iter().filter(|c| c.text_matches(&q)).collect();
        rows.extend(self.closed_conns.iter().filter(|c| c.text_matches(&q)));
        rows
    }

    fn select_next(&mut self) {
        let len = self.visible_rows().len();
        if len == 0 {
            return;
        }
        let i = self.table_state.selected().map_or(0, |i| (i + 1) % len);
        self.table_state.select(Some(i));
    }

    fn select_prev(&mut self) {
        let len = self.visible_rows().len();
        if len == 0 {
            return;
        }
        let i = self
            .table_state
            .selected()
            .map_or(0, |i| if i == 0 { len - 1 } else { i - 1 });
        self.table_state.select(Some(i));
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Launch the interactive TUI (`--tui`). Blocks until the user quits.
///
/// # Errors
///
/// Fails if stdout is not a TTY (cannot enable raw mode), if the terminal
/// backend errors out, or if the underlying [`crate::snapshot`] call fails.
pub fn run(filter: Filter, resolve_proxy: bool) -> Result<()> {
    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    let _guard = TerminalGuard;

    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    run_loop(&mut terminal, filter, resolve_proxy)
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    filter: Filter,
    resolve_proxy: bool,
) -> Result<()> {
    let mut app = App::new(filter, resolve_proxy)?;

    loop {
        terminal.draw(|f| draw(f, &mut app))?;

        // Poll events with a short timeout so refresh still happens
        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
        {
            if app.filter_mode {
                match key.code {
                    KeyCode::Esc => {
                        app.filter_mode = false;
                        app.filter_input.clear();
                    }
                    KeyCode::Enter => {
                        app.filter_mode = false;
                    }
                    KeyCode::Backspace => {
                        app.filter_input.pop();
                    }
                    KeyCode::Char(c) => {
                        app.filter_input.push(c);
                    }
                    _ => {}
                }
            } else {
                match (key.code, key.modifiers) {
                    (KeyCode::Char('q'), _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                        return Ok(());
                    }
                    (KeyCode::Down | KeyCode::Char('j'), _) => app.select_next(),
                    (KeyCode::Up | KeyCode::Char('k'), _) => app.select_prev(),
                    (KeyCode::Char('/'), _) => {
                        app.filter_mode = true;
                        app.filter_input.clear();
                    }
                    (KeyCode::Esc, _) => {
                        app.filter_input.clear();
                    }
                    (KeyCode::Char('r'), _) => app.refresh()?,
                    _ => {}
                }
            }
        }

        // Auto-refresh every REFRESH_SECS seconds
        if app.last_refresh.elapsed() >= Duration::from_secs(REFRESH_SECS) {
            app.refresh()?;
        }
    }
}

// ── Drawing ───────────────────────────────────────────────────────────────────

fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // header
            Constraint::Min(0),    // table
            Constraint::Length(1), // footer / filter bar
        ])
        .split(area);

    draw_header(f, app, chunks[0]);
    draw_table(f, app, chunks[1]);
    draw_footer(f, app, chunks[2]);
}

fn draw_header(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let rows = app.visible_rows().len();
    let mut spans = vec![
        Span::styled(
            " netls --tui",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("  {rows} connections")),
    ];
    if !app.filter_input.is_empty() && !app.filter_mode {
        spans.push(Span::styled(
            format!("  [filter: {}]", app.filter_input),
            Style::default().fg(Color::Yellow),
        ));
    }
    spans.push(Span::styled(
        format!(
            "  (refresh in {}s)",
            REFRESH_SECS.saturating_sub(app.last_refresh.elapsed().as_secs())
        ),
        Style::default().fg(Color::DarkGray),
    ));
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_table(f: &mut Frame, app: &mut App, area: ratatui::layout::Rect) {
    let header = Row::new(["PROTO", "LOCAL", "REMOTE", "STATE", "PID", "PROCESS"])
        .style(Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED));

    let visible = app.visible_rows();
    let closed_keys: HashSet<String> = app
        .closed_conns
        .iter()
        .map(super::Connection::key)
        .collect();

    let rows: Vec<Row> = visible
        .iter()
        .map(|c| build_tui_row(c, &app.origins, &closed_keys, &app.new_keys))
        .collect();

    let widths = [
        Constraint::Length(6),
        Constraint::Length(25),
        Constraint::Length(25),
        Constraint::Length(13),
        Constraint::Length(8),
        Constraint::Min(10),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::NONE))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_stateful_widget(table, area, &mut app.table_state);
}

/// Map a TCP/UDP state to its display color.
fn state_color(state: State) -> Color {
    match state {
        State::Listen => Color::Blue,
        State::Established => Color::Green,
        _ => Color::Yellow,
    }
}

/// Build the "no permission" placeholder cell.
fn no_permission_cell() -> Cell<'static> {
    Cell::from(NO_PERMISSION).style(Style::default().fg(Color::DarkGray))
}

/// Build a single table row for the given connection.
fn build_tui_row(
    c: &Connection,
    origins: &std::collections::HashMap<String, String>,
    closed_keys: &HashSet<String>,
    new_keys: &HashSet<String>,
) -> Row<'static> {
    let key = c.key();

    let row_style = if closed_keys.contains(&key) {
        Style::default().fg(Color::Red)
    } else if new_keys.contains(&key) {
        Style::default().fg(Color::Green)
    } else {
        Style::default()
    };

    let state_cell = if closed_keys.contains(&key) || new_keys.contains(&key) {
        Cell::from(c.state_str()).style(row_style)
    } else {
        match c.state {
            Some(s) => Cell::from(s.to_string()).style(Style::default().fg(state_color(s))),
            None => Cell::from("-"),
        }
    };

    let process_text = format_process_text(c, origins);
    let process_style = if origins.contains_key(&key) {
        Style::default().fg(Color::Yellow)
    } else {
        row_style
    };

    Row::new(vec![
        Cell::from(c.proto.to_string()).style(row_style),
        Cell::from(c.local.clone()).style(row_style),
        Cell::from(c.remote.clone()).style(row_style),
        state_cell,
        c.pid.map_or_else(no_permission_cell, |p| {
            Cell::from(p.to_string()).style(row_style)
        }),
        Cell::from(process_text).style(process_style),
    ])
}

fn draw_footer(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let text = if app.filter_mode {
        Line::from(vec![
            Span::styled(
                " Filter: ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(&app.filter_input),
            Span::styled("█", Style::default().fg(Color::Yellow)),
            Span::styled(
                "  (Enter to confirm, Esc to cancel)",
                Style::default().fg(Color::DarkGray),
            ),
        ])
    } else {
        Line::from(vec![
            Span::styled(" q", Style::default().fg(Color::Cyan)),
            Span::raw(" quit  "),
            Span::styled("↑↓ / j k", Style::default().fg(Color::Cyan)),
            Span::raw(" navigate  "),
            Span::styled("/", Style::default().fg(Color::Cyan)),
            Span::raw(" filter  "),
            Span::styled("r", Style::default().fg(Color::Cyan)),
            Span::raw(" refresh now"),
        ])
    };
    f.render_widget(Paragraph::new(text), area);
}
