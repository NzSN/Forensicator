//! Interactive session: load one dump, run commands against it repeatedly.
//! Hand-rolled REPL over std::io — no line-editing dependencies.

use std::io::Write;

use clap::{Parser, Subcommand};
use forensicator_core::pipeline::{Forensicator, S1Output};

use crate::{basename, kind_str, match_dump, print_inspect, run_analyze, supplement_images};

pub struct Session {
    path: String,
    s1: S1Output,
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
    /// Structural inventory of the loaded dump
    Inspect {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        quiet: bool,
    },
    /// Run analyzers against the loaded dump
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
    /// Load a different dump into this session
    Load { path: String },
    /// Set PDB directory ('symbols <dir>'), clear it ('symbols off'), or show it ('symbols')
    Symbols { path: Option<String> },
    /// Exit the session
    Quit,
}

impl Session {
    fn open(path: &str, symbols: Option<String>) -> Result<Session, Box<dyn std::error::Error>> {
        let mut s1 = Forensicator::open(path)?;
        let images = supplement_images(&mut s1, path);
        Ok(Session {
            path: path.to_string(),
            s1,
            symbols,
            images,
        })
    }

    fn banner(&self) -> String {
        format!(
            "{}: {}, {} image(s) supplemented, symbols: {}",
            basename(&self.path),
            kind_str(&self.s1),
            self.images,
            self.symbols.as_deref().unwrap_or("<none>")
        )
    }

    fn prompt(&self) -> String {
        format!("forensicator[{}]> ", basename(&self.path))
    }

    fn dispatch(&mut self, cmd: SessionCommands) -> Result<bool, Box<dyn std::error::Error>> {
        match cmd {
            SessionCommands::Inspect { json, quiet } => print_inspect(&self.s1.dump, json, quiet)?,
            SessionCommands::Analyze { plugin, json } => {
                run_analyze(&self.s1, plugin.as_deref(), json, self.symbols.as_deref())?
            }
            SessionCommands::Match { exe, pdb, json } => {
                match_dump(&self.s1.dump, &exe, &pdb, json)?;
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
            SessionCommands::Quit => return Ok(false),
        }
        Ok(true)
    }
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
    fn session_cli_rejects_unknown() {
        assert!(SessionCli::try_parse_from(["frobnicate"]).is_err());
    }
}
