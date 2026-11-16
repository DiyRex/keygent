//! `state/broker.log` (SPEC §5.4 "Logging"): owner-only, rotated at 1 MB × 3. Holds events, error codes and timings —
//! **never values, commands or prompts**. The API only accepts `&'static str` event names plus numbers, so a value
//! can't be formatted into a log line by accident.

use crate::platform;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const MAX_LOG: u64 = 1024 * 1024;
const KEEP: u32 = 3;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}

impl Level {
    pub fn from_u8(b: u8) -> Level {
        match b {
            0 => Level::Error,
            1 => Level::Warn,
            3 => Level::Debug,
            _ => Level::Info,
        }
    }
}

pub struct Log {
    path: PathBuf,
    level: Level,
    file: Mutex<Option<File>>,
}

fn open_append(path: &Path) -> Option<File> {
    platform::ipc::open_private_rw(path, true).ok()
}

impl Log {
    pub fn open(state: &Path, level: Level) -> Log {
        let path = state.join("broker.log");
        Log {
            file: Mutex::new(open_append(&path)),
            path,
            level,
        }
    }

    /// `event` is a fixed identifier; `n` an optional number (code, count, milliseconds).
    pub fn event(&self, level: Level, event: &'static str, n: Option<u64>) {
        if level > self.level {
            return;
        }
        let Ok(mut g) = self.file.lock() else { return };
        if g.as_ref()
            .and_then(|f| f.metadata().ok())
            .is_some_and(|m| m.len() > MAX_LOG)
        {
            *g = None;
            for i in (1..KEEP).rev() {
                let _ = std::fs::rename(
                    self.path.with_extension(format!("log.{i}")),
                    self.path
                        .with_extension(format!("log.{}", i.saturating_add(1))),
                );
            }
            let _ = std::fs::rename(&self.path, self.path.with_extension("log.1"));
            *g = open_append(&self.path);
        }
        if let Some(f) = g.as_mut() {
            let ts = crate::vault::now();
            let lvl = ["error", "warn", "info", "debug"]
                .get(level as usize)
                .copied()
                .unwrap_or("info");
            let line = match n {
                Some(n) => format!("{ts} {lvl} {event} {n}\n"),
                None => format!("{ts} {lvl} {event}\n"),
            };
            let _ = f.write_all(line.as_bytes());
        }
    }
}
