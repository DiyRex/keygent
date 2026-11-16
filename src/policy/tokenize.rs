//! POSIX shell tokenizer (SPEC §5.7 step 1, §5.5.2 "Executable binding"). Total and capped: never panics, any input
//! up to `MAX_CMD` bytes. It finds every simple command (across `|`, `&&`, `||`, `;`, `&`, newlines), its words and
//! their literal values where they have no expansions, every placeholder with its quote context and position
//! (argv vs assignment / redirect / heredoc body), and flags shell features that make a command ineligible for
//! allow rules (metacharacters, globs, `~`, `$`, substitutions, subshells).
//!
//! It works on commands, never on values (SPEC §4.2: `policy/` holds no plaintext).

pub const MAX_CMD: usize = 64 * 1024;
const OPEN: &str = "{{keygent:";
const OPEN_FILE: &str = "{{keygent-file:";
const CLOSE: &str = "}}";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Quote {
    None,
    Double,
    Single,
    /// Heredoc body; `quoted` = the delimiter was quoted (no expansion inside).
    Heredoc {
        quoted: bool,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// argv[0] or an argument: visible to other local users via the process list (SPEC §3.2.6).
    Argv,
    /// `NAME=value` before the command word: stays in the environment.
    Assign,
    /// A redirect target or here-string: never in argv.
    Redirect,
    HereString,
    HeredocBody,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Placeholder {
    pub handle: String,
    pub file: bool,
    pub quote: Quote,
    pub role: Role,
    /// Byte span of `{{keygent…}}` in the original command.
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct SimpleCmd {
    /// Words after assignments: literal value when the word has no expansions/placeholders, else `None`.
    pub argv: Vec<Option<String>>,
    /// Byte span of each argv word in the original command (same order as `argv`).
    pub spans: Vec<(usize, usize)>,
    pub assigns: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Parsed {
    pub commands: Vec<SimpleCmd>,
    pub placeholders: Vec<Placeholder>,
    /// Any operator, redirect, subshell, substitution, glob, `~` or `$` (allow rules never match these).
    pub metachar: bool,
    pub substitution: bool,
    pub subshell: bool,
    pub heredoc: bool,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TokError {
    TooLong,
    Unterminated,
    /// `{{keygent:` without a valid handle and `}}`.
    BadPlaceholder,
}

struct Lex<'a> {
    s: &'a [u8],
    i: usize,
    out: Parsed,
    cur: SimpleCmd,
    /// Current word: literal so far (None once it contains an expansion), whether it started, its role.
    word: Option<String>,
    word_started: bool,
    word_role: Role,
    word_assign: bool,
    word_start: usize,
    pending_heredocs: Vec<(String, bool)>,
    next_role: Option<Role>,
    paren_depth: usize,
}

fn is_name_byte(b: u8, first: bool) -> bool {
    b == b'_' || b.is_ascii_alphabetic() || (!first && b.is_ascii_digit())
}

impl<'a> Lex<'a> {
    fn peek(&self, k: usize) -> Option<u8> {
        self.s.get(self.i.saturating_add(k)).copied()
    }

    fn starts(&self, p: &str) -> bool {
        self.s
            .get(self.i..)
            .is_some_and(|r| r.starts_with(p.as_bytes()))
    }

    fn begin(&mut self) {
        if !self.word_started {
            self.word_start = self.i;
            self.word_started = true;
        }
    }

    fn push_lit(&mut self, b: u8) {
        self.begin();
        if let Some(w) = &mut self.word {
            w.push(char::from(b));
        }
    }

    fn taint(&mut self) {
        self.begin();
        self.word = None;
    }

    fn end_word(&mut self) {
        if !self.word_started {
            return;
        }
        let role = self.word_role;
        let lit = self.word.take();
        if role == Role::Assign {
            self.cur.assigns.push(lit.unwrap_or_default());
        } else if role == Role::Argv {
            self.cur.argv.push(lit);
            self.cur.spans.push((self.word_start, self.i));
        }
        self.word = Some(String::new());
        self.word_started = false;
        self.word_assign = false;
        self.word_role = self.next_role.take().unwrap_or(Role::Argv);
    }

    fn end_cmd(&mut self) {
        self.end_word();
        if !self.cur.argv.is_empty() || !self.cur.assigns.is_empty() {
            self.out.commands.push(std::mem::take(&mut self.cur));
        }
        self.word_role = Role::Argv;
    }

    /// At a word start (in argv role, before any argv word): `NAME=` makes it an assignment.
    fn maybe_assignment(&mut self) {
        if self.word_started || self.word_role != Role::Argv || !self.cur.argv.is_empty() {
            return;
        }
        let rest = self.s.get(self.i..).unwrap_or_default();
        let n = rest.iter().take_while(|&&b| is_name_byte(b, false)).count();
        if n > 0
            && rest.first().is_some_and(|&b| is_name_byte(b, true))
            && rest.get(n) == Some(&b'=')
        {
            self.word_role = Role::Assign;
        }
    }

    /// `{{keygent:h}}` / `{{keygent-file:h}}` at the cursor.
    fn placeholder(&mut self, quote: Quote) -> Result<bool, TokError> {
        let (file, open) = if self.starts(OPEN_FILE) {
            (true, OPEN_FILE)
        } else if self.starts(OPEN) {
            (false, OPEN)
        } else {
            return Ok(false);
        };
        let start = self.i;
        self.begin();
        let body = self
            .s
            .get(start.saturating_add(open.len())..)
            .unwrap_or_default();
        let end_rel = body
            .windows(2)
            .position(|w| w == CLOSE.as_bytes())
            .ok_or(TokError::BadPlaceholder)?;
        let handle = std::str::from_utf8(body.get(..end_rel).unwrap_or_default())
            .map_err(|_| TokError::BadPlaceholder)?;
        if !crate::vault::names::valid_handle(handle) {
            return Err(TokError::BadPlaceholder);
        }
        let end = start
            .saturating_add(open.len())
            .saturating_add(end_rel)
            .saturating_add(CLOSE.len());
        let role = match quote {
            Quote::Heredoc { .. } => Role::HeredocBody,
            _ => self.word_role,
        };
        self.out.placeholders.push(Placeholder {
            handle: handle.to_owned(),
            file,
            quote,
            role,
            start,
            end,
        });
        self.taint();
        self.i = end;
        Ok(true)
    }

    fn dollar(&mut self) -> Result<(), TokError> {
        // `$` expansion of any kind: never literal. `$(…)` and `${…}` are read whole (nesting-aware).
        self.out.metachar = true;
        self.taint();
        match self.peek(1) {
            Some(b'(') => {
                self.out.substitution = true;
                self.i = self.i.saturating_add(2);
                self.skip_nested(b'(', b')')
            }
            Some(b'{') => {
                self.i = self.i.saturating_add(2);
                self.skip_nested(b'{', b'}')
            }
            _ => {
                self.i = self.i.saturating_add(1);
                Ok(())
            }
        }
    }

    /// Skip a nested `open … close` region (quotes respected). Placeholders inside run as part of a nested command,
    /// so they are recorded conservatively as argv uses.
    fn skip_nested(&mut self, open: u8, close: u8) -> Result<(), TokError> {
        let mut depth = 1usize;
        let saved_role = self.word_role;
        self.word_role = Role::Argv;
        let r = loop {
            match self.peek(0) {
                None => break Err(TokError::Unterminated),
                Some(b'\\') => self.i = self.i.saturating_add(2),
                Some(b'\'') => {
                    self.i = self.i.saturating_add(1);
                    while !matches!(self.peek(0), None | Some(b'\'')) {
                        if !self.placeholder(Quote::Single)? {
                            self.i = self.i.saturating_add(1);
                        }
                    }
                    self.i = self.i.saturating_add(1);
                }
                Some(b'{') if self.starts(OPEN) || self.starts(OPEN_FILE) => {
                    self.placeholder(Quote::None)?;
                }
                Some(c) if c == close => {
                    depth = depth.saturating_sub(1);
                    self.i = self.i.saturating_add(1);
                    if depth == 0 {
                        break Ok(());
                    }
                }
                Some(c) if c == open => {
                    depth = depth.saturating_add(1);
                    self.i = self.i.saturating_add(1);
                }
                Some(_) => {
                    if !self.placeholder(Quote::None)? {
                        self.i = self.i.saturating_add(1);
                    }
                }
            }
        };
        self.word_role = saved_role;
        self.taint();
        r
    }

    fn backtick(&mut self) -> Result<(), TokError> {
        self.out.substitution = true;
        self.out.metachar = true;
        self.taint();
        self.i = self.i.saturating_add(1);
        let saved_role = self.word_role;
        self.word_role = Role::Argv;
        let r = loop {
            match self.peek(0) {
                None => break Err(TokError::Unterminated),
                Some(b'\\') => self.i = self.i.saturating_add(2),
                Some(b'`') => {
                    self.i = self.i.saturating_add(1);
                    break Ok(());
                }
                Some(_) => {
                    if !self.placeholder(Quote::None)? {
                        self.i = self.i.saturating_add(1);
                    }
                }
            }
        };
        self.word_role = saved_role;
        self.taint();
        r
    }

    fn single(&mut self) -> Result<(), TokError> {
        self.begin();
        self.i = self.i.saturating_add(1);
        loop {
            match self.peek(0) {
                None => return Err(TokError::Unterminated),
                Some(b'\'') => {
                    self.i = self.i.saturating_add(1);
                    return Ok(());
                }
                Some(_) => {
                    if self.placeholder(Quote::Single)? {
                        continue;
                    }
                    let b = self.peek(0).unwrap_or(0);
                    self.push_lit(b);
                    self.i = self.i.saturating_add(1);
                }
            }
        }
    }

    fn double(&mut self) -> Result<(), TokError> {
        self.begin();
        self.i = self.i.saturating_add(1);
        loop {
            match self.peek(0) {
                None => return Err(TokError::Unterminated),
                Some(b'"') => {
                    self.i = self.i.saturating_add(1);
                    return Ok(());
                }
                Some(b'\\') => {
                    match self.peek(1) {
                        Some(c @ (b'$' | b'`' | b'"' | b'\\')) => self.push_lit(c),
                        Some(b'\n') => {}
                        Some(c) => {
                            self.push_lit(b'\\');
                            self.push_lit(c);
                        }
                        None => return Err(TokError::Unterminated),
                    }
                    self.i = self.i.saturating_add(2);
                }
                Some(b'$') => self.dollar()?,
                Some(b'`') => self.backtick()?,
                Some(_) => {
                    if self.placeholder(Quote::Double)? {
                        continue;
                    }
                    let b = self.peek(0).unwrap_or(0);
                    self.push_lit(b);
                    self.i = self.i.saturating_add(1);
                }
            }
        }
    }

    /// After a newline: consume pending heredoc bodies.
    fn heredoc_bodies(&mut self) -> Result<(), TokError> {
        let docs = std::mem::take(&mut self.pending_heredocs);
        for (delim, quoted) in docs {
            loop {
                let rest = self.s.get(self.i..).unwrap_or_default();
                if rest.is_empty() {
                    return Err(TokError::Unterminated);
                }
                let line_len = rest.iter().position(|&b| b == b'\n').unwrap_or(rest.len());
                let line = rest.get(..line_len).unwrap_or_default();
                let trimmed = line
                    .iter()
                    .skip_while(|&&b| b == b'\t')
                    .copied()
                    .collect::<Vec<u8>>();
                if trimmed == delim.as_bytes() {
                    self.i = self
                        .i
                        .saturating_add(line_len)
                        .saturating_add(1)
                        .min(self.s.len());
                    break;
                }
                // scan the line for placeholders
                let line_end = self.i.saturating_add(line_len);
                while self.i < line_end {
                    if !self.placeholder(Quote::Heredoc { quoted })? {
                        self.i = self.i.saturating_add(1);
                    }
                }
                self.i = line_end.saturating_add(1).min(self.s.len());
            }
        }
        Ok(())
    }

    fn redirect(&mut self) {
        self.end_word();
        self.out.metachar = true;
        // here-doc / here-string
        if self.starts("<<<") {
            self.i = self.i.saturating_add(3);
            self.word_role = Role::HereString;
            return;
        }
        if self.starts("<<") {
            self.out.heredoc = true;
            self.i = self.i.saturating_add(2);
            if self.peek(0) == Some(b'-') {
                self.i = self.i.saturating_add(1);
            }
            while matches!(self.peek(0), Some(b' ' | b'\t')) {
                self.i = self.i.saturating_add(1);
            }
            // delimiter word (quoted delimiter disables expansion in the body)
            let mut delim = String::new();
            let mut quoted = false;
            while let Some(b) = self.peek(0) {
                match b {
                    b'\'' | b'"' => {
                        quoted = true;
                        self.i = self.i.saturating_add(1);
                    }
                    b'\\' => {
                        quoted = true;
                        self.i = self.i.saturating_add(1);
                    }
                    b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'<' | b'>' | b'(' | b')' => break,
                    _ => {
                        delim.push(char::from(b));
                        self.i = self.i.saturating_add(1);
                    }
                }
            }
            self.pending_heredocs.push((delim, quoted));
            return;
        }
        // <, >, >>, <&, >&, <>, >|
        self.i = self.i.saturating_add(1);
        while matches!(self.peek(0), Some(b'>' | b'&' | b'|')) {
            self.i = self.i.saturating_add(1);
        }
        self.word_role = Role::Redirect;
    }

    fn run(mut self) -> Result<Parsed, TokError> {
        while let Some(b) = self.peek(0) {
            if !self.word_started {
                self.maybe_assignment();
            }
            match b {
                b' ' | b'\t' => {
                    self.end_word();
                    self.i = self.i.saturating_add(1);
                }
                b'\n' => {
                    self.end_cmd();
                    self.i = self.i.saturating_add(1);
                    self.heredoc_bodies()?;
                }
                b';' | b'&' | b'|' => {
                    self.out.metachar = true;
                    self.end_cmd();
                    self.i = self.i.saturating_add(1);
                    if matches!(self.peek(0), Some(b'&' | b'|' | b';')) {
                        self.i = self.i.saturating_add(1);
                    }
                }
                b'(' | b')' => {
                    self.out.metachar = true;
                    self.out.subshell = true;
                    if b == b'(' {
                        self.paren_depth = self.paren_depth.saturating_add(1);
                    } else {
                        self.paren_depth = self.paren_depth.saturating_sub(1);
                    }
                    self.end_cmd();
                    self.i = self.i.saturating_add(1);
                }
                b'<' | b'>' => self.redirect(),
                b'#' if !self.word_started => {
                    while !matches!(self.peek(0), None | Some(b'\n')) {
                        self.i = self.i.saturating_add(1);
                    }
                }
                b'\'' => self.single()?,
                b'"' => self.double()?,
                b'\\' => {
                    self.begin();
                    match self.peek(1) {
                        Some(b'\n') => {}
                        Some(c) => self.push_lit(c),
                        None => return Err(TokError::Unterminated),
                    }
                    self.i = self.i.saturating_add(2);
                }
                b'$' => self.dollar()?,
                b'`' => self.backtick()?,
                b'*' | b'?' | b'[' => {
                    self.out.metachar = true;
                    self.taint();
                    self.i = self.i.saturating_add(1);
                }
                b'~' if !self.word_started => {
                    self.out.metachar = true;
                    self.taint();
                    self.i = self.i.saturating_add(1);
                }
                _ => {
                    if self.placeholder(Quote::None)? {
                        continue;
                    }
                    self.push_lit(b);
                    self.i = self.i.saturating_add(1);
                }
            }
        }
        if !self.pending_heredocs.is_empty() {
            return Err(TokError::Unterminated);
        }
        self.end_cmd();
        Ok(self.out)
    }
}

pub fn parse(cmd: &str) -> Result<Parsed, TokError> {
    if cmd.len() > MAX_CMD {
        return Err(TokError::TooLong);
    }
    Lex {
        s: cmd.as_bytes(),
        i: 0,
        out: Parsed::default(),
        cur: SimpleCmd::default(),
        word: Some(String::new()),
        word_started: false,
        word_role: Role::Argv,
        word_assign: false,
        word_start: 0,
        pending_heredocs: Vec::new(),
        next_role: None,
        paren_depth: 0,
    }
    .run()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation
    )]
    use super::*;

    fn ph(cmd: &str) -> Vec<(String, Quote, Role)> {
        parse(cmd)
            .unwrap()
            .placeholders
            .into_iter()
            .map(|p| (p.handle, p.quote, p.role))
            .collect()
    }

    #[test]
    fn simple_commands_and_literals() {
        let p = parse("stripe customers list --limit 3").unwrap();
        assert_eq!(p.commands.len(), 1);
        assert_eq!(
            p.commands[0].argv,
            vec![
                Some("stripe".into()),
                Some("customers".into()),
                Some("list".into()),
                Some("--limit".into()),
                Some("3".into())
            ]
        );
        assert!(!p.metachar);
        let p = parse("a 'b c' \"d\\\"e\" f\\ g && h | i; j").unwrap();
        assert_eq!(p.commands.len(), 4);
        assert_eq!(
            p.commands[0].argv,
            vec![
                Some("a".into()),
                Some("b c".into()),
                Some("d\"e".into()),
                Some("f g".into())
            ]
        );
        assert!(p.metachar);
    }

    #[test]
    fn placeholder_contexts_and_roles() {
        assert_eq!(
            ph("X={{keygent:a/b}} tool"),
            vec![("a/b".into(), Quote::None, Role::Assign)]
        );
        assert_eq!(
            ph("tool --key {{keygent:a/b}}"),
            vec![("a/b".into(), Quote::None, Role::Argv)]
        );
        assert_eq!(
            ph("tool \"--key={{keygent:a/b}}\""),
            vec![("a/b".into(), Quote::Double, Role::Argv)]
        );
        assert_eq!(
            ph("tool '{{keygent:a/b}}'"),
            vec![("a/b".into(), Quote::Single, Role::Argv)]
        );
        assert_eq!(
            ph("tool <<< \"{{keygent:a/b}}\""),
            vec![("a/b".into(), Quote::Double, Role::HereString)]
        );
        assert_eq!(
            ph("psql <<EOF\nselect '{{keygent:a/b}}';\nEOF\n"),
            vec![(
                "a/b".into(),
                Quote::Heredoc { quoted: false },
                Role::HeredocBody
            )]
        );
        assert_eq!(
            ph("psql <<'EOF'\n{{keygent:a/b}}\nEOF"),
            vec![(
                "a/b".into(),
                Quote::Heredoc { quoted: true },
                Role::HeredocBody
            )]
        );
        let p = parse("curl -H @{{keygent-file:stripe/hdr}} x").unwrap();
        assert!(p.placeholders[0].file);
    }

    #[test]
    fn features_flagged() {
        for (c, sub, shell) in [
            ("echo $(id)", true, false),
            ("echo `id`", true, false),
            ("(cd x; y)", false, true),
        ] {
            let p = parse(c).unwrap();
            assert!(p.metachar);
            assert_eq!((p.substitution, p.subshell), (sub, shell), "{c}");
        }
        for c in ["ls *.rs", "ls ~/x", "echo $HOME", "a > f", "a 2>&1"] {
            assert!(parse(c).unwrap().metachar, "{c}");
        }
        // an expansion makes the word non-literal
        assert_eq!(parse("$CMD arg").unwrap().commands[0].argv[0], None);
        // a placeholder inside a substitution is a (nested) argv use
        assert_eq!(
            ph("x=$(echo {{keygent:a}})"),
            vec![("a".into(), Quote::None, Role::Argv)]
        );
        assert_eq!(ph("echo `cat {{keygent-file:a}}`")[0].2, Role::Argv);
        assert_eq!(parse("echo $(a (b) c) d").unwrap().commands.len(), 1);
        assert_eq!(ph("echo ${X:-{{keygent:a}}}").len(), 1);
    }

    #[test]
    fn errors() {
        assert_eq!(parse("echo 'x").err(), Some(TokError::Unterminated));
        assert_eq!(parse("echo \"x").err(), Some(TokError::Unterminated));
        assert_eq!(parse("cat <<EOF\nx\n").err(), Some(TokError::Unterminated));
        assert_eq!(
            parse("t {{keygent:Bad Handle}}").err(),
            Some(TokError::BadPlaceholder)
        );
        assert_eq!(parse("t {{keygent:x").err(), Some(TokError::BadPlaceholder));
        assert_eq!(
            parse(&"a".repeat(MAX_CMD + 1)).err(),
            Some(TokError::TooLong)
        );
    }

    #[test]
    fn word_spans() {
        let c = "python3  './my script.py' --x=1";
        let p = parse(c).unwrap();
        let words: Vec<&str> = p.commands[0].spans.iter().map(|&(a, b)| &c[a..b]).collect();
        assert_eq!(words, vec!["python3", "'./my script.py'", "--x=1"]);
        assert_eq!(p.commands[0].argv[1].as_deref(), Some("./my script.py"));
    }

    #[test]
    fn spans_point_at_placeholders() {
        let c = "A={{keygent:x/y}} b \"{{keygent-file:z}}\"";
        for p in parse(c).unwrap().placeholders {
            assert!(c[p.start..p.end].starts_with("{{keygent"));
            assert!(c[p.start..p.end].ends_with("}}"));
        }
    }

    #[test]
    fn never_panics_on_noise() {
        let alphabet = b"ab {}$'\"\\|&;()<>\n#*~`=keygent:/-";
        let mut x: u64 = 7;
        for _ in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let n = (x % 40) as usize;
            let s: String = (0..n)
                .map(|i| alphabet[((x >> (i % 60)) as usize) % alphabet.len()] as char)
                .collect();
            let _ = parse(&s);
        }
    }
}
