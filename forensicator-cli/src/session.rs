//! Interactive session: load one dump or trace, run commands against it
//! repeatedly. Hand-rolled REPL over std::io — no line-editing dependencies.

use std::io::Write;

use clap::{Parser, Subcommand};
use forensicator_core::model::trace::{Position, Trace};
use forensicator_core::parse::ttfx::{TTFX_MAGIC, decode_ttfx};
use forensicator_core::pipeline::{Forensicator, S1Output};

use crate::{basename, kind_str, match_dump, print_inspect, run_analyze, supplement_images};

/// What the session is pointed at: a frozen dump, or a trace with a cursor.
enum Target {
    Dump(Box<S1Output>),
    Trace(TraceCursor),
}

struct TraceCursor {
    trace: Trace,
    cursor: Position,
}

pub struct Session {
    path: String,
    target: Target,
    symbols: Option<String>,
    images: usize,
}

#[derive(Parser)]
#[command(name = "forensicator", no_binary_name = true)]
#[command(about = "session commands — type 'help' for details")]
struct SessionCli {
    #[command(subcommand)]
    command: SessionCommands,
}

#[derive(Subcommand)]
enum SessionCommands {
    /// Structural inventory of the loaded dump (trace mode: snapshot at cursor)
    Inspect {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        quiet: bool,
    },
    /// Run analyzers (trace mode: against the snapshot at the cursor)
    Analyze {
        #[arg(long)]
        plugin: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Verify the dump matches given build artifacts (RSDS GUID/age, checksum)
    Match {
        #[arg(long)]
        exe: Vec<String>,
        #[arg(long)]
        pdb: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// List registered analyzers
    ListPlugins,
    /// Load a different dump (.dmp) or trace (.ttfx) into this session
    Load { path: String },
    /// Set PDB directory ('symbols <dir>'), clear it ('symbols off'), or show it ('symbols')
    Symbols { path: Option<String> },
    /// Jump to a trace position (decimal, or hex with 0x prefix)
    Seek { pos: String },
    /// Step one position forward
    #[command(alias = "t+")]
    Forward,
    /// Step one position backward
    #[command(alias = "t-")]
    Back,
    /// Show current trace position and frontier
    Position,
    /// Recorded writes overlapping [va, va+len) up to the cursor
    Writes { va: String, len: String },
    /// Trace threads and call spans at the cursor
    Intervals,
    /// Exit the session
    Quit,
}

/// Parse a u64: decimal, or hex with a 0x prefix.
pub(crate) fn parse_u64(s: &str) -> Result<u64, String> {
    let hex = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"));
    match hex {
        Some(h) => u64::from_str_radix(h, 16).map_err(|e| format!("bad hex value '{s}': {e}")),
        None => s
            .parse::<u64>()
            .map_err(|e| format!("bad value '{s}': {e}")),
    }
}

fn sniff_magic(path: &str) -> Option<u32> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut b = [0u8; 4];
    f.read_exact(&mut b).ok()?;
    Some(u32::from_le_bytes(b))
}

impl Session {
    fn open(path: &str, symbols: Option<String>) -> Result<Session, Box<dyn std::error::Error>> {
        if sniff_magic(path) == Some(TTFX_MAGIC) {
            let data = std::fs::read(path)?;
            let trace = decode_ttfx(&data).map_err(|a| a.description)?;
            for a in &trace.anomalies {
                eprintln!("warning: {a}");
            }
            let cursor = trace.frontier;
            return Ok(Session {
                path: path.to_string(),
                target: Target::Trace(TraceCursor { trace, cursor }),
                symbols,
                images: 0,
            });
        }
        let mut s1 = Forensicator::open(path)?;
        let images = supplement_images(&mut s1, path);
        Ok(Session {
            path: path.to_string(),
            target: Target::Dump(Box::new(s1)),
            symbols,
            images,
        })
    }

    fn banner(&self) -> String {
        match &self.target {
            Target::Dump(s1) => format!(
                "{}: {}, {} image(s) supplemented, symbols: {}",
                basename(&self.path),
                kind_str(s1),
                self.images,
                self.symbols.as_deref().unwrap_or("<none>")
            ),
            Target::Trace(tc) => format!(
                "{}: trace, frontier {:#X}, {} writes, {} events, symbols: {}",
                basename(&self.path),
                tc.trace.frontier,
                tc.trace.writes.len(),
                tc.trace.events.len(),
                self.symbols.as_deref().unwrap_or("<none>")
            ),
        }
    }

    fn prompt(&self) -> String {
        match &self.target {
            Target::Dump(_) => format!("forensicator[{}]> ", basename(&self.path)),
            Target::Trace(tc) => format!(
                "forensicator[{} @ {:#X}/{:#X}]> ",
                basename(&self.path),
                tc.cursor,
                tc.trace.frontier
            ),
        }
    }

    /// Snapshot view for commands that consume (Dump, AddressSpace):
    /// the dump itself, or the trace materialized at the cursor.
    fn current_s1(&self) -> Result<S1Output, Box<dyn std::error::Error>> {
        match &self.target {
            Target::Dump(s1) => Ok(S1Output {
                dump: s1.dump.clone(),
                space: s1.space.clone(),
                kind: s1.kind,
            }),
            Target::Trace(tc) => {
                let snap = tc
                    .trace
                    .snapshot(tc.cursor)
                    .ok_or("cursor out of recorded range")?;
                let kind = Forensicator::classify_dump(&snap.dump);
                Ok(S1Output {
                    dump: snap.dump,
                    space: snap.space,
                    kind,
                })
            }
        }
    }

    fn trace_mut(&mut self) -> Result<&mut TraceCursor, Box<dyn std::error::Error>> {
        match &mut self.target {
            Target::Trace(tc) => Ok(tc),
            Target::Dump(_) => Err("not a trace session (load a .ttfx file)".into()),
        }
    }

    fn dispatch(&mut self, cmd: SessionCommands) -> Result<bool, Box<dyn std::error::Error>> {
        match cmd {
            SessionCommands::Inspect { json, quiet } => {
                let s1 = self.current_s1()?;
                if let Target::Trace(tc) = &self.target {
                    println!(
                        "position {:#X} / frontier {:#X}",
                        tc.cursor, tc.trace.frontier
                    );
                }
                print_inspect(&s1.dump, json, quiet)?
            }
            SessionCommands::Analyze { plugin, json } => {
                let s1 = self.current_s1()?;
                if let Target::Trace(tc) = &self.target
                    && !json
                {
                    eprintln!(
                        "position {:#X} / frontier {:#X}, dump: {}",
                        tc.cursor,
                        tc.trace.frontier,
                        kind_str(&s1)
                    );
                }
                run_analyze(&s1, plugin.as_deref(), json, self.symbols.as_deref())?
            }
            SessionCommands::Match { exe, pdb, json } => {
                let s1 = self.current_s1()?;
                match_dump(&s1.dump, &exe, &pdb, json)?;
            }
            SessionCommands::ListPlugins => crate::cmd_list_plugins(),
            SessionCommands::Load { path } => {
                let symbols = self.symbols.take();
                *self = Session::open(&path, symbols)?;
                println!("loaded {}", self.banner());
            }
            SessionCommands::Symbols { path } => match path.as_deref() {
                None => println!("symbols: {}", self.symbols.as_deref().unwrap_or("<none>")),
                Some("off") => {
                    self.symbols = None;
                    println!("symbols cleared");
                }
                Some(dir) => {
                    self.symbols = Some(dir.to_string());
                    println!("symbols: {dir}");
                }
            },
            SessionCommands::Seek { pos } => {
                let pos = parse_u64(&pos)?;
                let tc = self.trace_mut()?;
                // CursorBounded: no travel beyond the recorded range.
                if pos > tc.trace.frontier {
                    return Err(format!(
                        "position {pos:#X} beyond frontier {:#X}",
                        tc.trace.frontier
                    )
                    .into());
                }
                tc.cursor = pos;
            }
            SessionCommands::Forward => {
                let tc = self.trace_mut()?;
                if tc.cursor < tc.trace.frontier {
                    tc.cursor += 1;
                }
                println!("position {:#X}", tc.cursor);
            }
            SessionCommands::Back => {
                let tc = self.trace_mut()?;
                if tc.cursor > 0 {
                    tc.cursor -= 1;
                }
                println!("position {:#X}", tc.cursor);
            }
            SessionCommands::Position => {
                let tc = self.trace_mut()?;
                println!(
                    "position {:#X} / frontier {:#X}",
                    tc.cursor, tc.trace.frontier
                );
            }
            SessionCommands::Writes { va, len } => {
                let (va, len) = (parse_u64(&va)?, parse_u64(&len)?);
                let tc = self.trace_mut()?;
                let last = tc.trace.last_writer(va, tc.cursor);
                let writes = tc.trace.writes_between(va, len, 0, tc.cursor);
                if writes.is_empty() {
                    println!("no writes to [0x{va:X}, 0x{:X}) up to cursor", va + len);
                }
                for (i, w) in writes.iter().enumerate() {
                    let marker = if last == Some(writes_index(tc, va, tc.cursor, i)) {
                        "  <-- last writer"
                    } else {
                        ""
                    };
                    let _ = i;
                    println!(
                        "  @{:#X}  [0x{:X}, 0x{:X})  {:02X?}{}",
                        w.pos,
                        w.va,
                        w.end_va(),
                        w.data,
                        marker
                    );
                }
            }
            SessionCommands::Intervals => {
                let tc = self.trace_mut()?;
                for (id, iv) in &tc.trace.threads {
                    let alive = match iv.end {
                        None => "alive".to_string(),
                        Some(e) => format!("ended {e:#X}"),
                    };
                    let here = if iv.contains(tc.cursor) { "*" } else { " " };
                    println!("  {here}thread {id}: start {:#X}, {alive}", iv.start);
                }
                for c in &tc.trace.calls {
                    let state = match c.interval.end {
                        None => "open".to_string(),
                        Some(e) => format!("end {e:#X}"),
                    };
                    println!(
                        "   call on {}: [{:#X}, {})",
                        c.thread_id, c.interval.start, state
                    );
                }
            }
            SessionCommands::Quit => return Ok(false),
        }
        Ok(true)
    }
}

/// Map the i-th writes_between result back to its index in the log, for the
/// "last writer" marker. Small helper to keep the display loop readable.
fn writes_index(tc: &TraceCursor, va: u64, cursor: Position, i: usize) -> usize {
    tc.trace
        .writes
        .iter()
        .enumerate()
        .filter(|(_, w)| w.pos <= cursor && w.va <= va && va < w.end_va())
        .map(|(idx, _)| idx)
        .nth(i)
        .unwrap_or(usize::MAX)
}

pub fn run(path: &str, symbols: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::open(path, symbols.map(|s| s.to_string()))?;
    println!("loaded {}", session.banner());
    println!("type 'help' for commands, 'quit' to exit");

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    loop {
        print!("{}", session.prompt());
        stdout.flush()?;
        let mut line = String::new();
        if stdin.read_line(&mut line)? == 0 {
            println!();
            break;
        }
        let argv = tokenize(&line);
        if argv.is_empty() {
            continue;
        }
        match SessionCli::try_parse_from(&argv) {
            Ok(cli) => match session.dispatch(cli.command) {
                Ok(true) => {}
                Ok(false) => break,
                Err(e) => eprintln!("error: {e}"),
            },
            Err(e) => e.print()?,
        }
    }
    Ok(())
}

/// Split a command line into argv, honoring double quotes.
fn tokenize(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for c in line.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            c if c.is_whitespace() && !in_quotes => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_plain() {
        assert_eq!(
            tokenize("analyze --plugin v8 --json"),
            ["analyze", "--plugin", "v8", "--json"]
        );
    }

    #[test]
    fn tokenize_quoted_path_with_spaces() {
        assert_eq!(
            tokenize("load \"my dumps/a.dmp\""),
            ["load", "my dumps/a.dmp"]
        );
    }

    #[test]
    fn tokenize_empty_and_blank() {
        assert!(tokenize("").is_empty());
        assert!(tokenize("   \t ").is_empty());
    }

    #[test]
    fn parse_u64_decimal_and_hex() {
        assert_eq!(parse_u64("42"), Ok(42));
        assert_eq!(parse_u64("0x2A"), Ok(42));
        assert_eq!(parse_u64("0X2a"), Ok(42));
        assert!(parse_u64("2A").is_err());
        assert!(parse_u64("0x").is_err());
    }

    #[test]
    fn session_cli_parses_analyze() {
        let cli = SessionCli::try_parse_from(["analyze", "--plugin", "v8", "--json"]).unwrap();
        match cli.command {
            SessionCommands::Analyze { plugin, json } => {
                assert_eq!(plugin.as_deref(), Some("v8"));
                assert!(json);
            }
            _ => panic!("wrong command"),
        }
    }

    #[test]
    fn session_cli_parses_trace_commands() {
        assert!(matches!(
            SessionCli::try_parse_from(["seek", "0x1A3F"])
                .unwrap()
                .command,
            SessionCommands::Seek { .. }
        ));
        assert!(matches!(
            SessionCli::try_parse_from(["t+"]).unwrap().command,
            SessionCommands::Forward
        ));
        assert!(matches!(
            SessionCli::try_parse_from(["t-"]).unwrap().command,
            SessionCommands::Back
        ));
        assert!(matches!(
            SessionCli::try_parse_from(["writes", "0x1000", "8"])
                .unwrap()
                .command,
            SessionCommands::Writes { .. }
        ));
    }

    #[test]
    fn session_cli_rejects_unknown() {
        assert!(SessionCli::try_parse_from(["frobnicate"]).is_err());
    }
}
