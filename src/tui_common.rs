use crossterm::{
    execute,
    terminal::{disable_raw_mode, LeaveAlternateScreen},
};
use std::io;

/// RAII guard that restores the terminal to its original state when dropped.
/// Works for both watch (raw crossterm) and TUI (ratatui) modes.
pub struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, crossterm::cursor::Show);
    }
}
