# esc-sentry

A library and small CLI for dealing with terminal escape sequences that show
up in text you didn't generate yourself.

## the problem

If your program ever prints text it didn't fully control - a filename, a
commit message, a chat message, a log line forwarded from somewhere else -
that text can contain ANSI/VT escape sequences. Terminals will happily obey
them. A crafted string can:

- rewrite the window title
- move the cursor and overwrite earlier output
- switch to the alternate screen buffer, or turn on/off bracketed paste
- on some terminal emulators, push arbitrary data onto the system clipboard
  (OSC 52) or set a hyperlink whose target is invisible in plain text (OSC 8)

None of this needs a bug in the terminal. It's the sequences doing exactly
what they're specified to do, just triggered by data the terminal's owner
never asked to run.

`esc-sentry` scans text, classifies every escape sequence it finds, and
gives you sanitized output plus a report of what it removed.

## the default is strict

Out of the box, only plain SGR sequences survive - the ones that set colors
and text attributes, like `\x1b[1;31m` or `\x1b[0m`. Everything else (cursor
movement, private mode toggles, OSC/DCS/APC/PM strings, raw C1 control
bytes, single-byte escapes like `ESC c`) is stripped and reported.

Sequences that are simply broken - an `ESC` with nothing valid after it, or
a string sequence that never reaches its terminator - are always dropped,
in strict mode and lenient mode alike. Letting a dangling sequence through
is exactly what lets injected text swallow whatever gets printed after it.

If you know your input can contain more than colors - say you're rendering
trusted output from another program that also moves the cursor - pass
`--lenient` (CLI) or `Policy::lenient()` (library) to let any *well-formed*
sequence through instead of just SGR.

## library usage

```rust
use esc_sentry::{scan, Policy};

let untrusted = "user: \x1b]0;pwned\x07 hey check this out";
let result = scan(untrusted, &Policy::strict());

println!("{}", result.sanitized); // "user:  hey check this out"
for v in &result.violations {
    eprintln!("{v:?}");
}
```

## CLI usage

```
$ printf 'safe \x1b[32mgreen\x1b[0m text' | esc-sentry
safe green text

$ printf 'title trick \x1b]0;evil\x07 rest' | esc-sentry
title trick  rest
esc-sentry: byte 12: disallowed OSC sequence (\x1b]0;evil\x07)

$ printf 'title trick \x1b]0;evil\x07 rest' | esc-sentry --lenient
title trick \x1b]0;evil\x07 rest
```

(That last line, once actually printed to a terminal, would set the window
title - which is the point: `--lenient` is an explicit choice, not the
default.)

Exit status is `1` if anything was flagged, `0` if the input was clean.
Pass `--quiet` to suppress the stderr report and just get the sanitized
output and exit code.

Pass `--format json` to get a single JSON object on stdout instead of
sanitized text plus a separate stderr report:

```
$ printf 'title trick \x1b]0;evil\x07 rest' | esc-sentry --format json
{"clean":false,"sanitized":"title trick  rest","violations":[{"type":"disallowed_sequence","kind":"OSC","offset":12,"bytes":"\u001b]0;evil\u0007"}]}
```

`--quiet` still applies: the report keeps `clean` and `sanitized` but the
`violations` array is empty.

## what's not here yet

This is a first cut of the scanner and CLI, covering CSI, OSC, DCS, SOS,
PM, APC, two-byte simple escapes, and raw C1 control bytes. See the roadmap
in the issue tracker / commit history for what's planned next.

## license

MIT, see [LICENSE](LICENSE).
