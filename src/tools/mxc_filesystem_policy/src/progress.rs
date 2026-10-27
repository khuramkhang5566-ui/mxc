// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Throttled, single-line stderr progress without an assumed scan total.

use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::ValueEnum;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum ProgressMode {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ScanProgress<'a> {
    pub(crate) current: Option<&'a Path>,
    pub(crate) scanned: usize,
    pub(crate) unknown: usize,
    pub(crate) pending: usize,
}

#[derive(Debug)]
pub(crate) struct Progress {
    enabled: bool,
    visible: bool,
    started: Instant,
    last_draw: Option<Instant>,
    frame: usize,
    stage: &'static str,
    scanned: usize,
    unknown: usize,
    pending: usize,
}

impl Progress {
    pub(crate) fn new(mode: ProgressMode) -> Self {
        Self {
            enabled: match mode {
                ProgressMode::Auto => io::stderr().is_terminal(),
                ProgressMode::Always => true,
                ProgressMode::Never => false,
            },
            visible: false,
            started: Instant::now(),
            last_draw: None,
            frame: 0,
            stage: "Starting",
            scanned: 0,
            unknown: 0,
            pending: 0,
        }
    }

    pub(crate) fn phase(&mut self, stage: &'static str, path: Option<&Path>) -> Result<()> {
        self.stage = stage;
        self.draw(path, true)
    }

    pub(crate) fn counts(&mut self, scanned: usize, unknown: usize) {
        self.scanned = scanned;
        self.unknown = unknown;
        self.pending = 0;
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn update(&mut self, state: ScanProgress<'_>) -> Result<()> {
        self.scanned = state.scanned;
        self.unknown = state.unknown;
        self.pending = state.pending;
        self.draw(state.current, state.current.is_none())
    }

    fn draw(&mut self, path: Option<&Path>, force: bool) -> Result<()> {
        if !self.enabled
            || (!force
                && self
                    .last_draw
                    .is_some_and(|last| last.elapsed() < Duration::from_millis(100)))
        {
            return Ok(());
        }
        let columns = display_columns();
        let line = render(
            self.stage,
            self.started.elapsed(),
            self.frame,
            ScanProgress {
                current: path,
                scanned: self.scanned,
                unknown: self.unknown,
                pending: self.pending,
            },
            columns,
        );
        let mut stderr = io::stderr().lock();
        write!(stderr, "\r{:columns$}\r{line}", "").context("cannot write scan progress")?;
        stderr.flush().context("cannot flush scan progress")?;
        self.visible = true;
        self.last_draw = Some(Instant::now());
        self.frame = (self.frame + 1) % 8;
        Ok(())
    }

    pub(crate) fn finish(&mut self) -> Result<()> {
        if self.visible {
            let columns = display_columns();
            let mut stderr = io::stderr().lock();
            write!(stderr, "\r{:columns$}\r", "").context("cannot clear scan progress")?;
            stderr.flush().context("cannot flush scan progress")?;
            self.visible = false;
        }
        Ok(())
    }
}

fn display_columns() -> usize {
    // Forced output to a pipe has no terminal dimensions; use a bounded log line.
    console_columns()
        .unwrap_or(80)
        .saturating_sub(1)
        .clamp(1, 120)
}

#[cfg(target_os = "windows")]
fn console_columns() -> Option<usize> {
    use windows::Win32::System::Console::{
        GetConsoleScreenBufferInfo, GetStdHandle, CONSOLE_SCREEN_BUFFER_INFO, STD_ERROR_HANDLE,
    };

    let mut information = CONSOLE_SCREEN_BUFFER_INFO::default();
    // SAFETY: the standard handle is borrowed, and information is a live output buffer.
    unsafe {
        let handle = GetStdHandle(STD_ERROR_HANDLE).ok()?;
        GetConsoleScreenBufferInfo(handle, &mut information).ok()?;
    }
    usize::try_from(
        i32::from(information.srWindow.Right) - i32::from(information.srWindow.Left) + 1,
    )
    .ok()
    .filter(|columns| *columns > 0)
}

#[cfg(unix)]
fn console_columns() -> Option<usize> {
    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: ioctl writes a winsize to the live buffer; stderr remains borrowed.
    let result = unsafe { libc::ioctl(libc::STDERR_FILENO, libc::TIOCGWINSZ, &mut size) };
    (result == 0 && size.ws_col > 0).then_some(usize::from(size.ws_col))
}

#[cfg(not(any(target_os = "windows", unix)))]
fn console_columns() -> Option<usize> {
    None
}

fn render(
    stage: &str,
    elapsed: Duration,
    frame: usize,
    state: ScanProgress<'_>,
    columns: usize,
) -> String {
    let mut bar = [b' '; 10];
    let position = frame % 8;
    bar[position..position + 3].copy_from_slice(b"==>");
    let bar = String::from_utf8_lossy(&bar);
    let seconds = elapsed.as_secs();
    let mut line = format!(
        "[{bar}] {:02}:{:02} {stage} | {} paths | {} unknown | {} queued",
        seconds / 60,
        seconds % 60,
        state.scanned,
        state.unknown,
        state.pending
    );
    if line.len() > columns {
        let mut end = columns;
        while !line.is_char_boundary(end) {
            end -= 1;
        }
        line.truncate(end);
    }
    let available = columns.saturating_sub(line.len() + 3);
    if let Some(path) = state.current.filter(|_| available >= 4) {
        let mut label = String::new();
        for character in path.display().to_string().chars() {
            if character.is_control() || matches!(character, '\u{2028}' | '\u{2029}') {
                label.extend(character.escape_default());
            } else {
                label.push(character);
            }
        }
        line.push_str(" | ");
        if label.len() > available {
            let mut start = label.len().saturating_sub(available - 3);
            while !label.is_char_boundary(start) {
                start += 1;
            }
            line.push_str("...");
            line.push_str(&label[start..]);
        } else {
            line.push_str(&label);
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_preserves_counts_and_fits_long_unicode_paths() {
        let line = render(
            "Scanning",
            Duration::from_secs(61),
            3,
            ScanProgress {
                current: Some(Path::new("C:\\Windows\\a-very-long-directory\\文件\\最后")),
                scanned: 42,
                unknown: 2,
                pending: 8,
            },
            80,
        );
        assert!(line.len() <= 80);
        assert!(line.contains("01:01 Scanning"));
        assert!(line.contains("42 paths"));
        assert!(line.contains("2 unknown"));
        assert!(line.ends_with("最后"));
    }

    #[test]
    fn path_control_characters_cannot_change_terminal_layout() {
        let line = render(
            "Scanning",
            Duration::ZERO,
            0,
            ScanProgress {
                current: Some(Path::new("C:\\bad\n\u{1b}[2J")),
                scanned: 1,
                unknown: 0,
                pending: 0,
            },
            120,
        );
        assert!(!line.chars().any(char::is_control));
        assert!(line.contains("\\n"));
        assert!(line.contains("\\u{1b}"));
    }
}
