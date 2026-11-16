//! Human console for auth flows (SPEC §5.1, §5.3, PLATFORMS "Passphrase input").
//!
//! - Prompts and secrets go through the controlling terminal (`/dev/tty`), never stdin/stdout, so a piped agent
//!   can't feed or read them. Under the `test-profile` feature with `KEYGENT_TEST_ROOT` set, stdin/stderr are used
//!   instead (test isolation only; compiled out of release builds).
//! - Agent markers and a missing terminal refuse auth commands — **UX only**, not a security boundary (ADR 0003);
//!   the passphrase is the real gate.
//! - Secret input is read into pre-sized zeroizing buffers (no reallocation copies) with a hard cap.
//! - Secrets shown to the human use the alternate screen and are cleared afterwards, so they don't stay in scrollback.

use crate::crypto::Secret;
use crate::error::{Error, Result};
use crate::platform::{self, Platform};
use std::fs::File;
use std::io::{Read, Write};
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_SECRET_INPUT: usize = 64 * 1024;
const MAX_LINE: usize = 4096;

/// Agent environment markers (SPEC §5.3, ADR 0001). UX only.
const AGENT_MARKERS: &[(&str, &str)] = &[("CLAUDECODE", "1")];

pub fn agent_marker_present() -> bool {
    AGENT_MARKERS
        .iter()
        .any(|(k, v)| std::env::var(k).is_ok_and(|x| x == *v))
}

pub struct Console {
    tty: Option<File>,
}

impl Console {
    /// Open the human console, or refuse with `NeedsAuth`.
    pub fn open() -> Result<Console> {
        if agent_marker_present() {
            return Err(Error::NeedsAuth);
        }
        if platform::test_console() {
            return Ok(Console { tty: None });
        }
        let tty = platform::os().open_tty().ok_or(Error::NeedsAuth)?;
        Ok(Console { tty: Some(tty) })
    }

    fn out(&mut self, b: &[u8]) {
        let _ = match &mut self.tty {
            Some(t) => t.write_all(b).and_then(|()| t.flush()),
            None => std::io::stderr().write_all(b),
        };
    }

    pub fn say(&mut self, s: &str) {
        self.out(s.as_bytes());
        self.out(b"\n");
    }

    /// Read bytes up to `\n` (excluded) into a pre-sized zeroizing buffer; `cap` bytes max.
    fn read_until_newline(&mut self, cap: usize) -> Result<Zeroizing<Vec<u8>>> {
        let mut buf = Zeroizing::new(Vec::with_capacity(cap.saturating_add(1)));
        let mut byte = [0u8; 1];
        loop {
            let n = match &mut self.tty {
                Some(t) => t.read(&mut byte)?,
                None => std::io::stdin().lock().read(&mut byte)?,
            };
            if n == 0 {
                if buf.is_empty() {
                    return Err(Error::Cancelled);
                }
                break;
            }
            if byte[0] == b'\n' {
                break;
            }
            if buf.len() >= cap {
                byte.zeroize();
                // drain the rest of the line so it can't become the next answer
                self.drain_line();
                return Err(Error::TooLarge("64 KiB"));
            }
            buf.push(byte[0]);
        }
        byte.zeroize();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
        Ok(buf)
    }

    fn drain_line(&mut self) {
        let mut b = [0u8; 1];
        loop {
            let r = match &mut self.tty {
                Some(t) => t.read(&mut b),
                None => std::io::stdin().lock().read(&mut b),
            };
            if !matches!(r, Ok(1)) || b[0] == b'\n' {
                break;
            }
        }
    }

    /// Visible line (handles, confirmations).
    pub fn read_line(&mut self, prompt: &str) -> Result<String> {
        self.out(prompt.as_bytes());
        let b = self.read_until_newline(MAX_LINE)?;
        if self.tty.is_none() {
            // the test console has no echo; keep one prompt per line like a terminal would
            self.out(b"\n");
        }
        String::from_utf8(b.to_vec()).map_err(|_| Error::Usage("input must be UTF-8"))
    }

    /// One hidden line (echo off).
    pub fn read_hidden(&mut self, prompt: &str) -> Result<Secret> {
        self.out(prompt.as_bytes());
        let _guard = match &self.tty {
            Some(t) => Some(platform::os().term_mode(t, false)?),
            None => None,
        };
        let r = self.read_until_newline(MAX_SECRET_INPUT);
        drop(_guard);
        self.out(b"\n");
        Ok(Secret::new(r?.to_vec()))
    }

    /// Hidden multi-line input until a line containing only `.` (PEM keys, JSON).
    pub fn read_multiline_hidden(&mut self, prompt: &str) -> Result<Secret> {
        self.say(prompt);
        let _guard = match &self.tty {
            Some(t) => Some(platform::os().term_mode(t, false)?),
            None => None,
        };
        let mut all = Zeroizing::new(Vec::with_capacity(
            MAX_SECRET_INPUT.saturating_add(MAX_LINE),
        ));
        loop {
            let line = self.read_until_newline(MAX_SECRET_INPUT)?;
            if line.as_slice() == b"." {
                break;
            }
            if all.len().saturating_add(line.len()).saturating_add(1) > MAX_SECRET_INPUT {
                return Err(Error::ValueSize);
            }
            all.extend_from_slice(&line);
            all.push(b'\n');
        }
        drop(_guard);
        if all.last() == Some(&b'\n') {
            all.pop();
        }
        Ok(Secret::new(all.to_vec()))
    }

    pub fn confirm(&mut self, prompt: &str) -> Result<bool> {
        let a = self.read_line(&format!("{prompt} [y/N] "))?;
        Ok(matches!(a.trim(), "y" | "Y" | "yes"))
    }

    /// Show a secret on the alternate screen until a keypress or `timeout`, then clear it (SPEC §5.1 `reveal`).
    pub fn show_secret(&mut self, header: &str, secret: &[u8], timeout: Duration) -> Result<()> {
        let mut screen = Zeroizing::new(Vec::with_capacity(
            secret.len().saturating_add(header.len()).saturating_add(64),
        ));
        screen.extend_from_slice(b"\x1b[?1049h\x1b[H\x1b[2J");
        screen.extend_from_slice(header.as_bytes());
        screen.extend_from_slice(b"\r\n\r\n");
        for &b in secret {
            if b == b'\n' {
                screen.extend_from_slice(b"\r\n");
            } else {
                screen.push(b);
            }
        }
        screen.extend_from_slice(b"\r\n\r\n(press any key to clear)");
        match &self.tty {
            Some(t) => {
                let guard = platform::os().term_mode(t, true)?;
                self.out(&screen);
                if let Some(t) = &self.tty
                    && platform::os().wait_readable(t, timeout)?
                {
                    let mut k = [0u8; 16];
                    let _ = (&*t).read(&mut k);
                    k.zeroize();
                }
                self.out(b"\x1b[2J\x1b[H\x1b[?1049l");
                drop(guard);
            }
            None => {
                self.out(&screen);
                self.out(b"\x1b[2J\x1b[H\x1b[?1049l\n");
            }
        }
        Ok(())
    }
}
