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
//!
//! [`scan_bytes`] applies the same rules to `&[u8]` for input that isn't
//! guaranteed to be valid UTF-8, such as a log file with mixed encodings.

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

/// Output of [`scan_bytes`]: the same report as [`ScanResult`], but over
/// bytes that were never required to be valid UTF-8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytesScanResult {
    pub sanitized: Vec<u8>,
    pub violations: Vec<Violation>,
}

impl BytesScanResult {
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

/// Byte-oriented counterpart to [`scan`] for input that isn't guaranteed to
/// be valid UTF-8 - a log file that mixes encodings, or text truncated mid
/// character. Every byte that matters to escape-sequence syntax (`ESC` and
/// the CSI/OSC/DCS/SOS/PM/APC introducer, parameter, intermediate, and final
/// bytes) is plain ASCII, so this scans byte by byte using the same rules as
/// [`scan`]. A raw C1 control is reported either as a bare byte in the
/// 0x80-0x9F range (its meaning under an 8-bit encoding) or as that byte's
/// two-byte UTF-8 encoding, `0xC2 0x80`-`0xC2 0x9F`; anything else, valid
/// UTF-8 or not, is copied through untouched, since it isn't part of any
/// escape mechanism this tool understands.
pub fn scan_bytes(input: &[u8], policy: &Policy) -> BytesScanResult {
    let mut out = Vec::with_capacity(input.len());
    let mut violations = Vec::new();
    let mut i = 0;

    while i < input.len() {
        let b = input[i];
        if b == 0x1b {
            i = handle_escape_bytes(input, i, &mut out, &mut violations, policy);
            continue;
        }

        match decode_utf8_char(input, i) {
            Some((c, len)) if matches!(c as u32, 0x80..=0x9f) => {
                violations.push(Violation::RawC1Control {
                    offset: i,
                    codepoint: c as u32,
                });
                if policy.lenient {
                    out.extend_from_slice(&input[i..i + len]);
                }
                i += len;
            }
            Some((_, len)) => {
                out.extend_from_slice(&input[i..i + len]);
                i += len;
            }
            None if matches!(b, 0x80..=0x9f) => {
                violations.push(Violation::RawC1Control {
                    offset: i,
                    codepoint: b as u32,
                });
                if policy.lenient {
                    out.push(b);
                }
                i += 1;
            }
            None => {
                out.push(b);
                i += 1;
            }
        }
    }

    BytesScanResult {
        sanitized: out,
        violations,
    }
}

// Reads one full UTF-8 scalar value starting at `input[i]`. Returns the
// decoded char and its width in bytes, or None if `input[i]` is not the
// start of a well-formed sequence - which includes a lone continuation byte,
// so callers never mistake the middle of a multi-byte character (e.g. the
// 0x9C in the "e2 80 9c" encoding of a curly left quote) for a standalone
// control byte.
fn decode_utf8_char(input: &[u8], i: usize) -> Option<(char, usize)> {
    let len = match input[i] {
        0x00..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return None,
    };
    let slice = input.get(i..i + len)?;
    let s = std::str::from_utf8(slice).ok()?;
    s.chars().next().map(|c| (c, len))
}

fn is_param_byte_u8(b: u8) -> bool {
    matches!(b, 0x30..=0x3f)
}

fn is_intermediate_u8(b: u8) -> bool {
    matches!(b, 0x20..=0x2f)
}

fn is_csi_final_u8(b: u8) -> bool {
    matches!(b, 0x40..=0x7e)
}

fn is_simple_final_byte(b: u8) -> bool {
    matches!(b, 0x30..=0x7e) && !matches!(b, b'[' | b']' | b'P' | b'X' | b'^' | b'_')
}

// Lossy on purpose: this only feeds the human-readable `bytes` field on a
// Violation. The bytes actually written to output go through untouched.
fn bytes_to_display_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

// Precondition: input[i] is ESC. Returns the index right after the sequence
// that was consumed.
fn handle_escape_bytes(
    input: &[u8],
    i: usize,
    out: &mut Vec<u8>,
    violations: &mut Vec<Violation>,
    policy: &Policy,
) -> usize {
    match input.get(i + 1).copied() {
        Some(b'[') => parse_csi_bytes(input, i, out, violations, policy),
        Some(b']') => {
            parse_string_sequence_bytes(input, i, SequenceKind::Osc, out, violations, policy)
        }
        Some(b'P') => {
            parse_string_sequence_bytes(input, i, SequenceKind::Dcs, out, violations, policy)
        }
        Some(b'X') => {
            parse_string_sequence_bytes(input, i, SequenceKind::Sos, out, violations, policy)
        }
        Some(b'^') => {
            parse_string_sequence_bytes(input, i, SequenceKind::Pm, out, violations, policy)
        }
        Some(b'_') => {
            parse_string_sequence_bytes(input, i, SequenceKind::Apc, out, violations, policy)
        }
        Some(c) if is_simple_final_byte(c) => {
            let raw = input[i..i + 2].to_vec();
            violations.push(Violation::DisallowedSequence {
                kind: SequenceKind::Simple,
                offset: i,
                bytes: bytes_to_display_string(&raw),
            });
            if policy.lenient {
                out.extend_from_slice(&raw);
            }
            i + 2
        }
        _ => {
            violations.push(Violation::BareEscape { offset: i });
            i + 1
        }
    }
}

// Precondition: input[i] is ESC, input[i + 1] is '['.
fn parse_csi_bytes(
    input: &[u8],
    i: usize,
    out: &mut Vec<u8>,
    violations: &mut Vec<Violation>,
    policy: &Policy,
) -> usize {
    let mut j = i + 2;
    let mut private = false;
    let mut first = true;
    let mut final_byte = None;

    while let Some(&b) = input.get(j) {
        if is_param_byte_u8(b) {
            if first && matches!(b, b'<' | b'=' | b'>' | b'?') {
                private = true;
            }
            first = false;
            j += 1;
        } else if is_intermediate_u8(b) {
            first = false;
            j += 1;
        } else if is_csi_final_u8(b) {
            final_byte = Some(b);
            j += 1;
            break;
        } else {
            break;
        }
    }

    let raw = input[i..j].to_vec();

    match final_byte {
        Some(b'm') if !private => {
            out.extend_from_slice(&raw);
        }
        Some(_) => {
            violations.push(Violation::DisallowedSequence {
                kind: SequenceKind::Csi,
                offset: i,
                bytes: bytes_to_display_string(&raw),
            });
            if policy.lenient {
                out.extend_from_slice(&raw);
            }
        }
        None => {
            violations.push(Violation::UnterminatedSequence {
                kind: SequenceKind::Csi,
                offset: i,
            });
        }
    }

    j
}

// Precondition: input[i] is ESC, input[i + 1] is the sequence's introducer
// byte (']', 'P', 'X', '^', or '_'). Terminated by BEL, C1 ST (0x9C), or the
// two-byte 7-bit ST (ESC \). Multi-byte UTF-8 characters in the payload are
// skipped as whole units so a continuation byte that happens to equal 0x07,
// 0x1B, or 0x9C is never mistaken for a terminator.
fn parse_string_sequence_bytes(
    input: &[u8],
    i: usize,
    kind: SequenceKind,
    out: &mut Vec<u8>,
    violations: &mut Vec<Violation>,
    policy: &Policy,
) -> usize {
    let mut j = i + 2;
    let mut terminated = false;

    while j < input.len() {
        let b = input[j];
        match b {
            0x07 | 0x9c => {
                j += 1;
                terminated = true;
                break;
            }
            0x1b => {
                if input.get(j + 1) == Some(&b'\\') {
                    j += 2;
                    terminated = true;
                    break;
                }
                // Not a valid ST: this ESC starts a new token. Stop here
                // without consuming it.
                break;
            }
            _ => match decode_utf8_char(input, j) {
                Some((_, len)) => j += len,
                None => j += 1,
            },
        }
    }

    let raw = input[i..j].to_vec();

    if terminated {
        violations.push(Violation::DisallowedSequence {
            kind,
            offset: i,
            bytes: bytes_to_display_string(&raw),
        });
        if policy.lenient {
            out.extend_from_slice(&raw);
        }
    } else {
        violations.push(Violation::UnterminatedSequence { kind, offset: i });
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

    #[test]
    fn scan_bytes_matches_scan_on_valid_utf8() {
        let input = "safe \x1b[32mgreen\x1b[0m, \x1b]0;title\x07 dropped";
        for policy in [Policy::strict(), Policy::lenient()] {
            let by_char = scan(input, &policy);
            let by_byte = scan_bytes(input.as_bytes(), &policy);
            assert_eq!(by_byte.sanitized, by_char.sanitized.as_bytes());
            assert_eq!(by_byte.violations, by_char.violations);
        }
    }

    #[test]
    fn scan_bytes_passes_through_invalid_utf8() {
        // 0xff is not a valid UTF-8 lead byte anywhere; it isn't an escape
        // sequence or a C1 control, so it should survive unexamined.
        let input: &[u8] = b"lat\xffn-1";
        let result = scan_bytes(input, &Policy::strict());
        assert_eq!(result.sanitized, input);
        assert!(result.is_clean());
    }

    #[test]
    fn scan_bytes_does_not_mistake_curly_quote_for_a_terminator() {
        // U+201C ("open curly quote") encodes as 0xE2 0x80 0x9C. The last
        // byte equals the C1 ST byte and falls in the main-loop
        // RawC1Control range; a scanner that isn't UTF-8-aware would
        // misfire on it and cut the OSC payload short.
        let mut input = Vec::new();
        input.extend_from_slice(b"before \x1b]0;titlewith");
        input.extend_from_slice("\u{201c}".as_bytes());
        input.extend_from_slice(b"quote\x07 after");

        let strict = scan_bytes(&input, &Policy::strict());
        assert_eq!(strict.sanitized, b"before  after");
        assert_eq!(strict.violations.len(), 1);

        let lenient = scan_bytes(&input, &Policy::lenient());
        assert_eq!(lenient.sanitized, input);
    }

    #[test]
    fn scan_bytes_flags_bare_c1_control_byte() {
        // A lone 0x9b with no valid UTF-8 lead byte before it: the raw
        // 8-bit encoding of CSI, not a continuation byte.
        let input: &[u8] = b"a\x9bb";
        let strict = scan_bytes(input, &Policy::strict());
        assert_eq!(strict.sanitized, b"ab");
        assert_eq!(
            strict.violations,
            vec![Violation::RawC1Control {
                offset: 1,
                codepoint: 0x9b
            }]
        );

        let lenient = scan_bytes(input, &Policy::lenient());
        assert_eq!(lenient.sanitized, input);
    }

    #[test]
    fn scan_bytes_drops_unterminated_sequence() {
        let input: &[u8] = b"\x1b]0;never closes";
        let strict = scan_bytes(input, &Policy::strict());
        let lenient = scan_bytes(input, &Policy::lenient());
        assert_eq!(strict.sanitized, b"");
        assert_eq!(lenient.sanitized, b"");
        assert_eq!(strict.violations.len(), 1);
        assert_eq!(lenient.violations.len(), 1);
    }
}
