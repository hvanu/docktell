use serde::Serialize;

use crate::trace::Trace;

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Exited,
    TimedOut,
    Interrupted,
    Failed,
}

#[derive(Debug, Serialize)]
pub struct FileChange {
    pub path: String,
    pub kind: String,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub container_id: String,
    pub image: String,
    pub image_id: String,
    pub command: Vec<String>,
    pub network_enabled: bool,
    pub outcome: Outcome,
    pub exit_code: Option<i64>,
    pub duration_ms: u128,
    pub oom_killed: bool,
    pub container_removed: bool,
    pub stdout: String,
    pub stderr: String,
    pub output_truncated: bool,
    pub raw_trace: String,
    pub trace: Trace,
    pub filesystem_changes: Vec<FileChange>,
    pub warnings: Vec<String>,
}

impl Report {
    pub fn status(&self) -> u8 {
        if !self.container_removed {
            return 125;
        }
        match self.outcome {
            Outcome::TimedOut => 124,
            Outcome::Interrupted => 130,
            Outcome::Failed => 125,
            Outcome::Exited => self
                .exit_code
                .and_then(|code| u8::try_from(code).ok())
                .unwrap_or(125),
        }
    }

    pub fn print(&self) {
        println!(
            "Outcome: {:?}; exit: {:?}; network: {}",
            self.outcome,
            self.exit_code,
            if self.network_enabled {
                "enabled (bridge)"
            } else {
                "disabled"
            }
        );
        println!(
            "\nFinal filesystem changes ({} paths; first 100 shown; not content diffs):",
            self.filesystem_changes.len()
        );
        if self.filesystem_changes.is_empty() {
            println!("  None observed.");
        }
        for change in self.filesystem_changes.iter().take(100) {
            println!("  {} {:?}", change.kind, change.path);
        }
        println!(
            "\nObserved actions ({} total; first 100 shown):",
            self.trace.actions.len()
        );
        for action in self.trace.actions.iter().take(100) {
            println!(
                "  time={:?} duration_seconds={:?} pid={:?} {:?} {}({:?}) -> {:?}",
                action.timestamp,
                action.duration_seconds,
                action.pid,
                action.category,
                action.syscall,
                action.arguments,
                action.result
            );
        }
        if !self.stdout.is_empty() {
            println!("\nGuest stdout (escaped): {:?}", preview(&self.stdout));
        }
        if !self.stderr.is_empty() {
            println!("Guest stderr (escaped): {:?}", preview(&self.stderr));
        }
        for warning in &self.warnings {
            println!("Warning: {warning:?}");
        }
    }
}

fn preview(text: &str) -> &str {
    let mut end = text.len().min(4096);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_preserves_utf8_boundaries() {
        let text = "€".repeat(2000);
        assert_eq!(preview(&text).len(), 4095);
    }
}
