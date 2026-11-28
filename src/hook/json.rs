//! Minimal JSON for hook I/O and `settings.json` (DEPENDENCIES: hand-rolled instead of serde). Total and capped:
//! malformed input, depth > 64 or input > 1 MiB is `None`, never a panic. Object key order is kept, so a user's
//! settings file round-trips without reordering. Numbers are kept as their source text.

pub const MAX_INPUT: usize = 1 << 20;
const MAX_DEPTH: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<Value>),
    Obj(Vec<(String, Value)>),
}

impl Value {
    pub fn get(&self, k: &str) -> Option<&Value> {
        match self {
            Value::Obj(m) => m.iter().find(|(x, _)| x == k).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn get_mut(&mut self, k: &str) -> Option<&mut Value> {
        match self {
            Value::Obj(m) => m.iter_mut().find(|(x, _)| x == k).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    /// Set `k` on an object (replacing in place, or appending). No-op on non-objects.
    pub fn set(&mut self, k: &str, v: Value) {
        if let Value::Obj(m) = self {
            match m.iter_mut().find(|(x, _)| x == k) {
                Some((_, slot)) => *slot = v,
                None => m.push((k.to_owned(), v)),
            }
        }
    }
    pub fn str(s: &str) -> Value {
        Value::Str(s.to_owned())
    }
    pub fn compact(&self) -> String {
        let mut o = String::new();
        write(self, &mut o, None, 0);
        o
    }
    /// Two-space indented, for files a human edits.
    pub fn pretty(&self) -> String {
        let mut o = String::new();
        write(self, &mut o, Some(2), 0);
        o.push('\n');
        o
    }
}

pub fn parse(s: &[u8]) -> Option<Value> {
    if s.len() > MAX_INPUT {
        return None;
    }
    let mut p = Parser { s, i: 0 };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    (p.i == s.len()).then_some(v)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn bump(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.i = self.i.checked_add(1)?;
        Some(c)
    }
    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i = self.i.saturating_add(1);
        }
    }
    fn lit(&mut self, word: &[u8], v: Value) -> Option<Value> {
        let end = self.i.checked_add(word.len())?;
        (self.s.get(self.i..end)? == word).then(|| {
            self.i = end;
            v
        })
    }
    fn value(&mut self, depth: usize) -> Option<Value> {
        if depth > MAX_DEPTH {
            return None;
        }
        match self.peek()? {
            b'n' => self.lit(b"null", Value::Null),
            b't' => self.lit(b"true", Value::Bool(true)),
            b'f' => self.lit(b"false", Value::Bool(false)),
            b'"' => self.string().map(Value::Str),
            b'[' => {
                self.bump()?;
                let mut a = Vec::new();
                self.ws();
                if self.peek()? == b']' {
                    self.bump()?;
                    return Some(Value::Arr(a));
                }
                loop {
                    self.ws();
                    a.push(self.value(depth.checked_add(1)?)?);
                    self.ws();
                    match self.bump()? {
                        b',' => {}
                        b']' => return Some(Value::Arr(a)),
                        _ => return None,
                    }
                }
            }
            b'{' => {
                self.bump()?;
                let mut m: Vec<(String, Value)> = Vec::new();
                self.ws();
                if self.peek()? == b'}' {
                    self.bump()?;
                    return Some(Value::Obj(m));
                }
                loop {
                    self.ws();
                    let k = self.string()?;
                    self.ws();
                    if self.bump()? != b':' {
                        return None;
                    }
                    self.ws();
                    let v = self.value(depth.checked_add(1)?)?;
                    if m.iter().any(|(x, _)| *x == k) {
                        return None; // duplicate keys are ambiguous: refuse
                    }
                    m.push((k, v));
                    self.ws();
                    match self.bump()? {
                        b',' => {}
                        b'}' => return Some(Value::Obj(m)),
                        _ => return None,
                    }
                }
            }
            b'-' | b'0'..=b'9' => self.number(),
            _ => None,
        }
    }
    fn number(&mut self) -> Option<Value> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.bump()?;
        }
        let digits = |p: &mut Self| {
            let s = p.i;
            while matches!(p.peek(), Some(b'0'..=b'9')) {
                p.i = p.i.saturating_add(1);
            }
            p.i > s
        };
        if !digits(self) {
            return None;
        }
        if self.peek() == Some(b'.') {
            self.bump()?;
            if !digits(self) {
                return None;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.bump()?;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.bump()?;
            }
            if !digits(self) {
                return None;
            }
        }
        let txt = std::str::from_utf8(self.s.get(start..self.i)?).ok()?;
        Some(Value::Num(txt.to_owned()))
    }
    fn hex4(&mut self) -> Option<u32> {
        let mut n = 0u32;
        for _ in 0..4 {
            let d = char::from(self.bump()?).to_digit(16)?;
            n = n.checked_mul(16)?.checked_add(d)?;
        }
        Some(n)
    }
    fn string(&mut self) -> Option<String> {
        if self.bump()? != b'"' {
            return None;
        }
        let mut out: Vec<u8> = Vec::new();
        loop {
            match self.bump()? {
                b'"' => return String::from_utf8(out).ok(),
                b'\\' => {
                    let c = match self.bump()? {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let code = if (0xd800..0xdc00).contains(&hi) {
                                if self.bump()? != b'\\' || self.bump()? != b'u' {
                                    return None;
                                }
                                let lo = self.hex4()?;
                                if !(0xdc00..0xe000).contains(&lo) {
                                    return None;
                                }
                                0x10000u32
                                    .checked_add((hi.checked_sub(0xd800)?) << 10)?
                                    .checked_add(lo.checked_sub(0xdc00)?)?
                            } else {
                                hi
                            };
                            char::from_u32(code)?
                        }
                        _ => return None,
                    };
                    let mut b = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
                }
                c if c < 0x20 => return None,
                c => out.push(c),
            }
        }
    }
}

fn esc(s: &str, o: &mut String) {
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if u32::from(c) < 0x20 => o.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => o.push(c),
        }
    }
    o.push('"');
}

fn indent(o: &mut String, ind: Option<usize>, level: usize) {
    if let Some(n) = ind {
        o.push('\n');
        o.push_str(&" ".repeat(n.saturating_mul(level)));
    }
}

fn write(v: &Value, o: &mut String, ind: Option<usize>, level: usize) {
    match v {
        Value::Null => o.push_str("null"),
        Value::Bool(b) => o.push_str(if *b { "true" } else { "false" }),
        Value::Num(n) => o.push_str(n),
        Value::Str(s) => esc(s, o),
        Value::Arr(a) if a.is_empty() => o.push_str("[]"),
        Value::Obj(m) if m.is_empty() => o.push_str("{}"),
        Value::Arr(a) => {
            o.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    o.push(',');
                }
                indent(o, ind, level.saturating_add(1));
                write(x, o, ind, level.saturating_add(1));
            }
            indent(o, ind, level);
            o.push(']');
        }
        Value::Obj(m) => {
            o.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    o.push(',');
                }
                indent(o, ind, level.saturating_add(1));
                esc(k, o);
                o.push(':');
                if ind.is_some() {
                    o.push(' ');
                }
                write(x, o, ind, level.saturating_add(1));
            }
            indent(o, ind, level);
            o.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        reason = "tests: a panic is the failure report"
    )]
    use super::*;

    #[test]
    fn roundtrip_keeps_order_and_escapes() {
        let src =
            r#"{"b":1,"a":[true,false,null,-1.5e3],"s":"x\"y\\z\n\u00e9\ud83d\ude00","o":{}}"#;
        let v = parse(src.as_bytes()).unwrap();
        assert_eq!(v.get("s").unwrap().as_str().unwrap(), "x\"y\\z\né😀");
        let again = parse(v.compact().as_bytes()).unwrap();
        assert_eq!(again, v);
        assert!(v.compact().starts_with(r#"{"b":1,"a":"#));
        assert_eq!(parse(v.pretty().as_bytes()).unwrap(), v);
    }

    #[test]
    fn refuses_bad_input_without_panicking() {
        for bad in [
            &b""[..],
            b"{",
            b"{\"a\":1,}",
            b"[1 2]",
            b"\"\x01\"",
            b"{\"a\":1,\"a\":2}",
            b"01x",
            b"\"\\ud800\"",
            b"nul",
            b"{\"a\":1} x",
        ] {
            assert!(parse(bad).is_none(), "{}", String::from_utf8_lossy(bad));
        }
        let deep = "[".repeat(100) + &"]".repeat(100);
        assert!(parse(deep.as_bytes()).is_none());
        // every prefix of a valid document fails cleanly
        let ok = br#"{"tool_input":{"command":"echo {{keygent:a/b}}","n":[1,2.5,{"x":null}]}}"#;
        for n in 0..ok.len() {
            let _ = parse(&ok[..n]);
        }
    }

    #[test]
    fn set_replaces_in_place() {
        let mut v = parse(br#"{"a":1,"b":2}"#).unwrap();
        v.set("a", Value::str("x"));
        v.set("c", Value::Bool(true));
        assert_eq!(v.compact(), r#"{"a":"x","b":2,"c":true}"#);
    }
}
