use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::process::ExitCode;

use esc_sentry::{scan, Policy, Violation};

fn main() -> ExitCode {
    let mut lenient = false;
    let mut quiet = false;
    let mut path: Option<String> = None;

    for arg in env::args().skip(1) {
        match arg.as_str() {
            "--lenient" => lenient = true,
            "--quiet" => quiet = true,
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

    if io::stdout().write_all(result.sanitized.as_bytes()).is_err() {
        return ExitCode::from(2);
    }

    if !quiet {
        for v in &result.violations {
            eprintln!("esc-sentry: {}", describe(v));
        }
    }

    if result.is_clean() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
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
    println!("esc-sentry [--lenient] [--quiet] [file]");
    println!();
    println!("Reads text (from a file, or stdin if no file is given), strips");
    println!("terminal escape sequences that are not on the strict allowlist,");
    println!("and writes the sanitized text to stdout. Anything flagged is");
    println!("reported on stderr, one line per finding.");
    println!();
    println!("  --lenient   allow any well-formed escape sequence through");
    println!("              (sequences that never terminate are still dropped)");
    println!("  --quiet     suppress the violation report on stderr");
    println!();
    println!("Exit status is 1 if anything was flagged, 0 otherwise.");
}
