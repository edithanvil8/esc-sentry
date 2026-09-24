use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::process::ExitCode;

use esc_sentry::{scan, Policy, Violation};

#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
}

fn main() -> ExitCode {
    let mut lenient = false;
    let mut quiet = false;
    let mut format = OutputFormat::Text;
    let mut path: Option<String> = None;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--lenient" => lenient = true,
            "--quiet" => quiet = true,
            "--format" => match args.next().as_deref() {
                Some("text") => format = OutputFormat::Text,
                Some("json") => format = OutputFormat::Json,
                Some(other) => {
                    eprintln!("esc-sentry: unknown format {other} (expected text or json)");
                    return ExitCode::from(2);
                }
                None => {
                    eprintln!("esc-sentry: --format requires a value (text or json)");
                    return ExitCode::from(2);
                }
            },
            "-h" | "--help" => {
                print_help();
                return ExitCode::SUCCESS;
            }
            other if !other.starts_with('-') => path = Some(other.to_string()),
            other => {
                eprintln!("esc-sentry: unknown flag {other}");
                return ExitCode::from(2);
            }
        }
    }

    let input = match path {
        Some(p) => match fs::read_to_string(&p) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("esc-sentry: cannot read {p}: {e}");
                return ExitCode::from(2);
            }
        },
        None => {
            let mut buf = String::new();
            if let Err(e) = io::stdin().read_to_string(&mut buf) {
                eprintln!("esc-sentry: cannot read stdin: {e}");
                return ExitCode::from(2);
            }
            buf
        }
    };

    let policy = Policy { lenient };
    let result = scan(&input, &policy);

    match format {
        OutputFormat::Text => {
            if io::stdout().write_all(result.sanitized.as_bytes()).is_err() {
                return ExitCode::from(2);
            }
            if !quiet {
                for v in &result.violations {
                    eprintln!("esc-sentry: {}", describe(v));
                }
            }
        }
        OutputFormat::Json => {
            let report = render_json_report(&result, quiet);
            if io::stdout().write_all(report.as_bytes()).is_err() {
                return ExitCode::from(2);
            }
            if io::stdout().write_all(b"\n").is_err() {
                return ExitCode::from(2);
            }
        }
    }

    if result.is_clean() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// Builds a single-line JSON report: `sanitized` is the cleaned text and
/// `violations` mirrors what the text format prints to stderr, so scripts
/// don't have to scrape `describe`'s human-readable strings.
fn render_json_report(result: &esc_sentry::ScanResult, quiet: bool) -> String {
    let mut out = String::new();
    out.push_str(r#"{"clean":"#);
    out.push_str(if result.is_clean() { "true" } else { "false" });
    out.push_str(r#","sanitized":""#);
    out.push_str(&json_escape(&result.sanitized));
    out.push_str(r#"","violations":["#);
    if !quiet {
        for (idx, v) in result.violations.iter().enumerate() {
            if idx > 0 {
                out.push(',');
            }
            out.push_str(&violation_to_json(v));
        }
    }
    out.push_str("]}");
    out
}

fn violation_to_json(v: &Violation) -> String {
    match v {
        Violation::DisallowedSequence { kind, offset, bytes } => format!(
            r#"{{"type":"disallowed_sequence","kind":"{kind}","offset":{offset},"bytes":"{}"}}"#,
            json_escape(bytes)
        ),
        Violation::UnterminatedSequence { kind, offset } => {
            format!(r#"{{"type":"unterminated_sequence","kind":"{kind}","offset":{offset}}}"#)
        }
        Violation::BareEscape { offset } => {
            format!(r#"{{"type":"bare_escape","offset":{offset}}}"#)
        }
        Violation::RawC1Control { offset, codepoint } => {
            format!(r#"{{"type":"raw_c1_control","offset":{offset},"codepoint":{codepoint}}}"#)
        }
    }
}

// Escapes a string for embedding in a JSON string literal. This also covers
// DEL and the C1 control range (0x7f-0x9f): those bytes are exactly what
// this tool exists to neutralize, so a JSON report that let them through
// raw would be re-introducing the same problem in its own output.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || matches!(c as u32, 0x7f..=0x9f) => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out
}

fn describe(v: &Violation) -> String {
    match v {
        Violation::DisallowedSequence { kind, offset, bytes } => {
            format!(
                "byte {offset}: disallowed {kind} sequence ({})",
                escape_for_display(bytes)
            )
        }
        Violation::UnterminatedSequence { kind, offset } => {
            format!("byte {offset}: unterminated {kind} sequence")
        }
        Violation::BareEscape { offset } => {
            format!("byte {offset}: bare escape with no valid sequence following")
        }
        Violation::RawC1Control { offset, codepoint } => {
            format!("byte {offset}: raw C1 control character U+{codepoint:04X}")
        }
    }
}

fn escape_for_display(s: &str) -> String {
    s.chars()
        .map(|c| {
            let code = c as u32;
            if code < 0x20 || code == 0x7f {
                format!("\\x{code:02x}")
            } else {
                c.to_string()
            }
        })
        .collect()
}

fn print_help() {
    println!("esc-sentry [--lenient] [--quiet] [--format text|json] [file]");
    println!();
    println!("Reads text (from a file, or stdin if no file is given), strips");
    println!("terminal escape sequences that are not on the strict allowlist,");
    println!("and writes the sanitized text to stdout. Anything flagged is");
    println!("reported on stderr, one line per finding.");
    println!();
    println!("  --lenient        allow any well-formed escape sequence through");
    println!("                   (sequences that never terminate are still dropped)");
    println!("  --quiet          suppress the violation report");
    println!("  --format json    write one JSON object to stdout instead - {{clean,");
    println!("                   sanitized, violations}} - and skip the stderr report");
    println!();
    println!("Exit status is 1 if anything was flagged, 0 otherwise.");
}
