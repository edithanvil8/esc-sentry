//! Scans text for terminal escape sequences and decides what to do with them.
//!
//! Anything printed to a terminal that came from outside the program - a
//! filename, a chat message, a log line pulled from somewhere else - can
//! contain escape sequences of its own. Those sequences can rewrite the
//! window title, move the cursor, hide or overwrite text that comes after
//! them, or (on terminals that support it) push data onto the clipboard.
//! None of that requires a vulnerability in the terminal; it is the
//! sequences behaving exactly as specified.
//!
//! [`scan`] walks a string and classifies every escape sequence it finds.
//! With [`Policy::strict`] (the default), only plain SGR sequences (colors
//! and text attributes, e.g. `\x1b[1;31m`) are let through; everything else
//! is reported as a [`Violation`] and dropped from the sanitized output.
//! With [`Policy::lenient`], any well-formed sequence is passed through -
//! but sequences that are simply broken (an escape with no valid body, or a
//! string sequence with no terminator) are always dropped, in both modes,
//! since a dangling sequence is what lets injected text swallow whatever
//! comes after it.

use std::fmt;

/// Controls how [`scan`] treats escape sequences that are not plain SGR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Policy {
    /// When true, any well-formed escape sequence is passed through.
    /// When false (the default), only SGR sequences survive.
    pub lenient: bool,
}

impl Policy {
    pub fn strict() -> Self {
        Policy { lenient: false }
    }

    pub fn lenient() -> Self {
        Policy { lenient: true }
    }
}

/// The family a detected escape sequence belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceKind {
    /// Control Sequence Introducer: `ESC [ ... final-byte`.
    Csi,
    /// Operating System Command: `ESC ] ... terminator`.
    Osc,
    /// Device Control String: `ESC P ... terminator`.
    Dcs,
    /// Start of String: `ESC X ... terminator`.
    Sos,
    /// Privacy Message: `ESC ^ ... terminator`.
    Pm,
    /// Application Program Command: `ESC _ ... terminator`.
    Apc,
    /// A two-byte escape with no parameters, e.g. `ESC c` (reset) or `ESC 7`.
    Simple,
}

impl fmt::Display for SequenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            SequenceKind::Csi => "CSI",
            SequenceKind::Osc => "OSC",
            SequenceKind::Dcs => "DCS",
            SequenceKind::Sos => "SOS",
            SequenceKind::Pm => "PM",
            SequenceKind::Apc => "APC",
            SequenceKind::Simple => "simple",
        };
        write!(f, "{s}")
    }
}

/// Something [`scan`] found and did not consider safe to pass through
/// unconditionally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    /// A well-formed sequence that strict mode does not allow. Passed
    /// through only under [`Policy::lenient`].
    DisallowedSequence {
        kind: SequenceKind,
        offset: usize,
        bytes: String,
    },
    /// A sequence that started but never reached its terminator before the
    /// input ended (or before the next escape began). Always dropped.
    UnterminatedSequence { kind: SequenceKind, offset: usize },
    /// An ESC byte followed by something that is not the start of any
    /// recognized sequence. Always dropped.
    BareEscape { offset: usize },
    /// A raw C1 control character (U+0080-U+009F), the 8-bit encoding of
    /// what ESC + a byte would otherwise spell out. Dropped in strict mode.
    RawC1Control { offset: usize, codepoint: u32 },
}

/// Output of [`scan`]: the cleaned text plus everything that was flagged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    pub sanitized: String,
    pub violations: Vec<Violation>,
}

impl ScanResult {
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Scans `input` and returns the sanitized text plus a report of every
/// escape sequence that was not passed through untouched.
pub fn scan(input: &str, policy: &Policy) -> ScanResult {
    let chars: Vec<(usize, char)> = input.char_indices().collect();
    let mut out = String::with_capacity(input.len());
    let mut violations = Vec::new();
    let mut i = 0;

    while i < chars.len() {
        let (offset, ch) = chars[i];
        match ch {
            '\u{1b}' => {
                i = handle_escape(&chars, i, offset, &mut out, &mut violations, policy);
            }
            '\u{80}'..='\u{9f}' => {
                violations.push(Violation::RawC1Control {
                    offset,
                    codepoint: ch as u32,
                });
                if policy.lenient {
                    out.push(ch);
                }
                i += 1;
            }
            _ => {
                out.push(ch);
                i += 1;
            }
        }
    }

    ScanResult {
        sanitized: out,
        violations,
    }
}

fn is_param_byte(c: char) -> bool {
    matches!(c as u32, 0x30..=0x3f)
}

fn is_intermediate(c: char) -> bool {
    matches!(c as u32, 0x20..=0x2f)
}

fn is_csi_final(c: char) -> bool {
    matches!(c as u32, 0x40..=0x7e)
}

fn is_simple_final(c: char) -> bool {
    matches!(c as u32, 0x30..=0x7e) && !matches!(c, '[' | ']' | 'P' | 'X' | '^' | '_')
}

fn slice_to_string(chars: &[(usize, char)], start: usize, end: usize) -> String {
    chars[start..end].iter().map(|&(_, c)| c).collect()
}

// Precondition: chars[i] is ESC. Returns the index of the char right after
// the sequence that was consumed.
fn handle_escape(
    chars: &[(usize, char)],
    i: usize,
    offset: usize,
    out: &mut String,
    violations: &mut Vec<Violation>,
    policy: &Policy,
) -> usize {
    match chars.get(i + 1).map(|&(_, c)| c) {
        Some('[') => parse_csi(chars, i, offset, out, violations, policy),
        Some(']') => parse_string_sequence(chars, i, offset, SequenceKind::Osc, out, violations, policy),
        Some('P') => parse_string_sequence(chars, i, offset, SequenceKind::Dcs, out, violations, policy),
        Some('X') => parse_string_sequence(chars, i, offset, SequenceKind::Sos, out, violations, policy),
        Some('^') => parse_string_sequence(chars, i, offset, SequenceKind::Pm, out, violations, policy),
        Some('_') => parse_string_sequence(chars, i, offset, SequenceKind::Apc, out, violations, policy),
        Some(c) if is_simple_final(c) => {
            let raw = slice_to_string(chars, i, i + 2);
            violations.push(Violation::DisallowedSequence {
                kind: SequenceKind::Simple,
                offset,
                bytes: raw.clone(),
            });
            if policy.lenient {
                out.push_str(&raw);
            }
            i + 2
        }
        _ => {
            violations.push(Violation::BareEscape { offset });
            i + 1
        }
    }
}

// Precondition: chars[i] is ESC, chars[i + 1] is '['.
fn parse_csi(
    chars: &[(usize, char)],
    i: usize,
    offset: usize,
    out: &mut String,
    violations: &mut Vec<Violation>,
    policy: &Policy,
) -> usize {
    let mut j = i + 2;
    let mut private = false;
    let mut first = true;
    let mut final_byte = None;

    while let Some(&(_, c)) = chars.get(j) {
        if is_param_byte(c) {
            if first && matches!(c, '<' | '=' | '>' | '?') {
                private = true;
            }
            first = false;
            j += 1;
        } else if is_intermediate(c) {
            first = false;
            j += 1;
        } else if is_csi_final(c) {
            final_byte = Some(c);
            j += 1;
            break;
        } else {
            break;
        }
    }

    let raw = slice_to_string(chars, i, j);

    match final_byte {
        Some('m') if !private => {
            out.push_str(&raw);
        }
        Some(_) => {
            violations.push(Violation::DisallowedSequence {
                kind: SequenceKind::Csi,
                offset,
                bytes: raw.clone(),
            });
            if policy.lenient {
                out.push_str(&raw);
            }
        }
        None => {
            violations.push(Violation::UnterminatedSequence {
                kind: SequenceKind::Csi,
                offset,
            });
        }
    }

    j
}

// Precondition: chars[i] is ESC, chars[i + 1] is the sequence's introducer
// byte (']', 'P', 'X', '^', or '_'). Terminated by BEL, C1 ST (U+009C), or
// the two-char 7-bit ST (ESC \).
fn parse_string_sequence(
    chars: &[(usize, char)],
    i: usize,
    offset: usize,
    kind: SequenceKind,
    out: &mut String,
    violations: &mut Vec<Violation>,
    policy: &Policy,
) -> usize {
    let mut j = i + 2;
    let mut terminated = false;

    while let Some(&(_, c)) = chars.get(j) {
        match c {
            '\u{07}' | '\u{9c}' => {
                j += 1;
                terminated = true;
                break;
            }
            '\u{1b}' => {
                if let Some(&(_, '\\')) = chars.get(j + 1) {
                    j += 2;
                    terminated = true;
                    break;
                }
                // Not a valid ST: this ESC starts a new token. Stop here
                // without consuming it.
                break;
            }
            _ => j += 1,
        }
    }

    let raw = slice_to_string(chars, i, j);

    if terminated {
        violations.push(Violation::DisallowedSequence {
            kind,
            offset,
            bytes: raw.clone(),
        });
        if policy.lenient {
            out.push_str(&raw);
        }
    } else {
        violations.push(Violation::UnterminatedSequence { kind, offset });
    }

    j
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_allows_sgr() {
        let input = "\x1b[1;31mred\x1b[0m plain";
        let result = scan(input, &Policy::strict());
        assert_eq!(result.sanitized, input);
        assert!(result.is_clean());
    }

    #[test]
    fn strict_strips_private_mode_csi() {
        // ESC [ ? 1049 h switches to the alternate screen buffer.
        let input = "before\x1b[?1049hafter";
        let result = scan(input, &Policy::strict());
        assert_eq!(result.sanitized, "beforeafter");
        assert_eq!(result.violations.len(), 1);
    }

    #[test]
    fn strict_strips_osc_and_lenient_keeps_it() {
        let input = "\x1b]0;window title\x07rest";
        let strict = scan(input, &Policy::strict());
        assert_eq!(strict.sanitized, "rest");
        assert_eq!(strict.violations.len(), 1);

        let lenient = scan(input, &Policy::lenient());
        assert_eq!(lenient.sanitized, input);
    }

    #[test]
    fn unterminated_osc_is_always_dropped() {
        let input = "\x1b]0;never closes";
        let strict = scan(input, &Policy::strict());
        let lenient = scan(input, &Policy::lenient());
        assert_eq!(strict.sanitized, "");
        assert_eq!(lenient.sanitized, "");
        assert_eq!(strict.violations.len(), 1);
        assert_eq!(lenient.violations.len(), 1);
    }

    #[test]
    fn bare_trailing_escape_is_dropped() {
        let input = "hello\x1b";
        let result = scan(input, &Policy::lenient());
        assert_eq!(result.sanitized, "hello");
        assert!(matches!(
            result.violations.as_slice(),
            [Violation::BareEscape { offset: 5 }]
        ));
    }

    #[test]
    fn raw_c1_control_is_dropped_in_strict_mode() {
        let input = "a\u{9b}b"; // U+009B is the C1 form of CSI
        let strict = scan(input, &Policy::strict());
        assert_eq!(strict.sanitized, "ab");
        let lenient = scan(input, &Policy::lenient());
        assert_eq!(lenient.sanitized, input);
    }
}
