use std::process;

use clap::{Parser, Subcommand};
use forensicator_core::analyzer::Pipeline;
use forensicator_core::model::{CpuArch, Dump, OsPlatform};
use forensicator_core::parse::dump;
use forensicator_core::pipeline::{Forensicator, S1Output};

mod session;

#[derive(Parser)]
#[command(name = "forensicator")]
#[command(version = "0.1.0")]
#[command(about = "Forensic analysis of Windows minidumps")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Inspect {
        path: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        quiet: bool,
    },
    Analyze {
        path: String,
        #[arg(long)]
        plugin: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        symbols: Option<String>,
    },
    /// Verify a dump matches given build artifacts (RSDS GUID/age, checksum)
    Match {
        path: String,
        /// PE image (.exe/.dll) to check; matched to a dump module by basename
        #[arg(long)]
        exe: Vec<String>,
        /// PDB file to check; matched to a dump module by pdb_name
        #[arg(long)]
        pdb: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    ListPlugins,
    /// Interactive session: load one dump, run commands against it repeatedly
    Shell {
        path: String,
        #[arg(long)]
        symbols: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Inspect { path, json, quiet } => {
            if let Err(e) = inspect(&path, json, quiet) {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }
        Commands::Analyze {
            path,
            plugin,
            json,
            symbols,
        } => {
            if let Err(e) = cmd_analyze(&path, plugin.as_deref(), json, symbols.as_deref()) {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }
        Commands::ListPlugins => cmd_list_plugins(),
        Commands::Match {
            path,
            exe,
            pdb,
            json,
        } => match cmd_match(&path, &exe, &pdb, json) {
            Ok(code) => process::exit(code),
            Err(e) => {
                eprintln!("error: {e}");
                process::exit(1);
            }
        },
        Commands::Shell { path, symbols } => {
            if let Err(e) = session::run(&path, symbols.as_deref()) {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }
    }
}

fn inspect(path: &str, json: bool, quiet: bool) -> Result<(), Box<dyn std::error::Error>> {
    let dump = dump::open(path)?;
    print_inspect(&dump, json, quiet)
}

fn print_inspect(dump: &Dump, json: bool, quiet: bool) -> Result<(), Box<dyn std::error::Error>> {
    if json {
        let diagnosis = if dump.exception.is_some() {
            let space = Forensicator::build_address_space(dump);
            let d = forensicator_core::analyzer::cause::diagnose(&dump, &space);
            serde_json::json!({
                "verdict": format!("{:?}", d.verdict),
                "confidence": format!("{:?}", d.confidence),
                "evidence": d.evidence,
                "fault_va": d.fault_va.map(|v| format!("0x{v:X}")),
                "fatal_message": d.fatal_message,
            })
        } else {
            serde_json::Value::Null
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "file_size": dump.file_size,
                "system_info": dump.system_info.as_ref().map(|si| serde_json::json!({
                    "os": os_name(si.os), "cpu": cpu_name(si.cpu),
                    "version": format!("{}.{}.{}.{}", si.version.0, si.version.1, si.version.2, si.version.3),
                })),
                "module_count": dump.modules.len(),
                "modules": dump.modules.iter().map(|m| serde_json::json!({
                    "name": m.name,
                    "base_va": format!("0x{:016X}", m.base_va),
                    "size": m.size,
                    "checksum": format!("0x{:08X}", m.checksum),
                    "codeview_guid": m.codeview_uuid().map(|u| u.to_string()),
                    "pdb_name": m.pdb_name,
                })).collect::<Vec<_>>(),
                "thread_count": dump.threads.len(),
                "memory_regions": dump.memory_regions.len(),
                "exception": dump.exception.is_some(),
                "diagnosis": diagnosis,
                "anomaly_count": dump.anomalies.len(),
                "annotation_count": dump.annotations.len(),
                "annotations": dump.annotations.iter().map(|(k, v)| serde_json::json!({ k: v })).collect::<Vec<_>>(),
            }))?
        );
        return Ok(());
    }
    if quiet {
        println!(
            "modules: {}  threads: {}  memory_regions: {}  anomalies: {}",
            dump.modules.len(),
            dump.threads.len(),
            dump.memory_regions.len(),
            dump.anomalies.len()
        );
        return Ok(());
    }
    println!("Dump ({:.1} KB)", dump.file_size as f64 / 1024.0);
    if let Some(ref si) = dump.system_info {
        println!(
            "├── SystemInfo: {} on {} v{}.{}.{}.{}",
            cpu_name(si.cpu),
            os_name(si.os),
            si.version.0,
            si.version.1,
            si.version.2,
            si.version.3
        );
    } else {
        println!("├── SystemInfo: <missing>");
    }
    println!("├── Modules: {} loaded", dump.modules.len());
    for m in &dump.modules {
        println!(
            "│   ├── {} @ 0x{:016X} ({:.1} KB)",
            m.name,
            m.base_va,
            m.size as f64 / 1024.0
        );
    }
    println!("├── Threads: {}", dump.threads.len());
    for t in &dump.threads {
        println!(
            "│   ├── TID {}  stack @ 0x{:016X} ({:.1} KB)  TEB @ 0x{:016X}  RIP 0x{:016X}",
            t.id,
            t.stack_va,
            t.stack_size as f64 / 1024.0,
            t.teb_va,
            t.registers.rip()
        );
    }
    println!("├── Memory regions: {}", dump.memory_regions.len());
    if let Some(ref exc) = dump.exception {
        println!(
            "├── Exception: code 0x{:08X} at 0x{:016X} (thread {})",
            exc.code, exc.address, exc.thread_id
        );
        let space = Forensicator::build_address_space(dump);
        let d = forensicator_core::analyzer::cause::diagnose(&dump, &space);
        let detail = d
            .fatal_message
            .clone()
            .or_else(|| d.evidence.first().cloned())
            .unwrap_or_default();
        println!(
            "├── Diagnosis: {:?} ({:?}){}",
            d.verdict,
            d.confidence,
            if detail.is_empty() {
                String::new()
            } else {
                format!(" — {detail}")
            }
        );
    }
    if !dump.anomalies.is_empty() {
        println!("├── Anomalies: {}", dump.anomalies.len());
        for a in &dump.anomalies {
            println!(
                "│   ├── [stream 0x{:08X} @ +0x{:X}] {}",
                a.provenance.stream_type, a.provenance.file_offset, a.description
            );
        }
    }
    if !dump.annotations.is_empty() {
        println!("└── Crash annotations: {}", dump.annotations.len());
        for (k, v) in &dump.annotations {
            println!("    ├── {} = {}", k, v);
        }
    }
    Ok(())
}

fn basename(p: &str) -> &str {
    p.rsplit(['/', '\\']).next().unwrap_or(p)
}

#[derive(PartialEq, Clone, Copy)]
enum CheckResult {
    Match,
    Mismatch,
    Unknown,
}

impl CheckResult {
    fn as_str(self) -> &'static str {
        match self {
            CheckResult::Match => "match",
            CheckResult::Mismatch => "mismatch",
            CheckResult::Unknown => "unknown",
        }
    }
}

struct Check {
    field: &'static str,
    result: CheckResult,
    file_value: String,
    dump_value: String,
    note: Option<String>,
}

struct MatchItem {
    kind: &'static str,
    path: String,
    module: Option<String>,
    checks: Vec<Check>,
}

impl MatchItem {
    fn result(&self) -> CheckResult {
        if self.module.is_none()
            || self
                .checks
                .iter()
                .any(|c| c.result == CheckResult::Mismatch)
        {
            return CheckResult::Mismatch;
        }
        if self.checks.iter().any(|c| c.result == CheckResult::Match) {
            CheckResult::Match
        } else {
            CheckResult::Unknown
        }
    }
}

fn compare<T: PartialEq + ToString>(
    field: &'static str,
    dump_side: Option<T>,
    file_side: Option<T>,
    absent_note: &'static str,
) -> Check {
    let mk = |r: CheckResult, f: Option<T>, d: Option<T>, note: Option<String>| Check {
        field,
        result: r,
        file_value: f.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
        dump_value: d.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
        note,
    };
    match (dump_side, file_side) {
        (Some(d), Some(f)) => mk(
            if d == f {
                CheckResult::Match
            } else {
                CheckResult::Mismatch
            },
            Some(f),
            Some(d),
            None,
        ),
        (None, f) => mk(CheckResult::Unknown, f, None, Some(absent_note.to_string())),
        (d, None) => mk(
            CheckResult::Unknown,
            None,
            d,
            Some("not present in file".to_string()),
        ),
    }
}

fn cmd_match(
    path: &str,
    exes: &[String],
    pdbs: &[String],
    json: bool,
) -> Result<i32, Box<dyn std::error::Error>> {
    if exes.is_empty() && pdbs.is_empty() {
        return Err("nothing to match: pass --exe and/or --pdb".into());
    }
    let dump = dump::open(path)?;
    match_dump(&dump, exes, pdbs, json)
}

fn match_dump(
    dump: &Dump,
    exes: &[String],
    pdbs: &[String],
    json: bool,
) -> Result<i32, Box<dyn std::error::Error>> {
    use forensicator_core::model::codeview_guid_to_uuid;

    let mut items: Vec<MatchItem> = Vec::new();

    for exe in exes {
        let img =
            forensicator_core::image::ImageFile::open(exe, 0).map_err(|e| format!("{exe}: {e}"))?;
        let rsds = img.rsds();
        let pe_checksum = img.pe_checksum();
        let want = basename(exe);
        let module = dump
            .modules
            .iter()
            .find(|m| basename(&m.name).eq_ignore_ascii_case(want));
        let Some(module) = module else {
            items.push(MatchItem {
                kind: "exe",
                path: exe.clone(),
                module: None,
                checks: vec![],
            });
            continue;
        };
        let checks = vec![
            compare(
                "guid",
                module.codeview_guid.map(|g| codeview_guid_to_uuid(&g)),
                rsds.as_ref().map(|r| codeview_guid_to_uuid(&r.guid)),
                "module has no RSDS record",
            ),
            compare(
                "age",
                module.codeview_age,
                rsds.as_ref().map(|r| r.age),
                "module has no RSDS record",
            ),
            if module.checksum != 0 {
                compare(
                    "checksum",
                    Some(module.checksum),
                    pe_checksum,
                    "module has no RSDS record",
                )
            } else {
                Check {
                    field: "checksum",
                    result: CheckResult::Unknown,
                    file_value: pe_checksum
                        .map(|c| format!("0x{c:08X}"))
                        .unwrap_or_else(|| "-".into()),
                    dump_value: "-".into(),
                    note: Some("dump module checksum is 0".into()),
                }
            },
        ];
        items.push(MatchItem {
            kind: "exe",
            path: exe.clone(),
            module: Some(module.name.clone()),
            checks,
        });
    }

    for pdb in pdbs {
        let (guid, age) = forensicator_core::symbolizer::pdb_identity(std::path::Path::new(pdb))
            .map_err(|e| format!("{pdb}: {e}"))?;
        let want = basename(pdb);
        let module = dump.modules.iter().find(|m| {
            m.pdb_name
                .as_deref()
                .is_some_and(|n| basename(n).eq_ignore_ascii_case(want))
        });
        let Some(module) = module else {
            items.push(MatchItem {
                kind: "pdb",
                path: pdb.clone(),
                module: None,
                checks: vec![],
            });
            continue;
        };
        let checks = vec![
            compare(
                "guid",
                module.codeview_guid.map(|g| codeview_guid_to_uuid(&g)),
                Some(guid),
                "module has no RSDS record",
            ),
            compare(
                "age",
                module.codeview_age,
                Some(age),
                "module has no RSDS record",
            ),
        ];
        items.push(MatchItem {
            kind: "pdb",
            path: pdb.clone(),
            module: Some(module.name.clone()),
            checks,
        });
    }

    let failed = items.iter().any(|i| i.result() == CheckResult::Mismatch);
    let overall = if failed {
        CheckResult::Mismatch
    } else if items.iter().all(|i| i.result() == CheckResult::Unknown) {
        CheckResult::Unknown
    } else {
        CheckResult::Match
    };

    if json {
        let items_json: Vec<_> = items
            .iter()
            .map(|i| {
                serde_json::json!({
                    "kind": i.kind,
                    "path": i.path,
                    "module": i.module,
                    "result": i.result().as_str(),
                    "checks": i.checks.iter().map(|c| serde_json::json!({
                        "field": c.field,
                        "result": c.result.as_str(),
                        "file": c.file_value,
                        "dump": c.dump_value,
                        "note": c.note,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({ "items": items_json, "overall": overall.as_str() })
            )?
        );
    } else {
        for i in &items {
            match &i.module {
                Some(m) => println!("{} {} ↔ module {}", i.kind.to_uppercase(), i.path, m),
                None => {
                    println!(
                        "{} {} ↔ no matching module in dump",
                        i.kind.to_uppercase(),
                        i.path
                    );
                    continue;
                }
            }
            for c in &i.checks {
                let note = c
                    .note
                    .as_ref()
                    .map(|n| format!("  ({n})"))
                    .unwrap_or_default();
                println!(
                    "  {:<9} {:<9} file={}  dump={}{}",
                    c.field,
                    c.result.as_str().to_uppercase(),
                    c.file_value,
                    c.dump_value,
                    note
                );
            }
        }
        println!("overall: {}", overall.as_str().to_uppercase());
    }

    Ok(if failed { 2 } else { 0 })
}

fn cmd_analyze(
    path: &str,
    plugin: Option<&str>,
    json: bool,
    symbols: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut s1 = Forensicator::open(path)?;
    let image_count = supplement_images(&mut s1, path);
    if !json {
        eprintln!(
            "dump: {}, {} image(s) supplemented",
            kind_str(&s1),
            image_count
        );
    }
    run_analyze(&s1, plugin, json, symbols)
}

/// Stack-only minidumps: supplement module bytes (.pdata/.text) from
/// on-disk images discovered next to the dump. Returns images found.
fn supplement_images(s1: &mut S1Output, path: &str) -> usize {
    let dir = std::path::Path::new(path)
        .parent()
        .unwrap_or(std::path::Path::new("."));
    let names: Vec<String> = s1.dump.modules.iter().map(|m| m.name.clone()).collect();
    let bases: Vec<u64> = s1.dump.modules.iter().map(|m| m.base_va).collect();
    let images = forensicator_core::image::ImageSet::discover(dir, &names, &bases);
    let n = images.len();
    if !images.is_empty() {
        s1.space.set_backing(images);
    }
    n
}

fn kind_str(s1: &S1Output) -> &'static str {
    match s1.kind {
        forensicator_core::pipeline::DumpKind::FullMemory => "full-memory",
        forensicator_core::pipeline::DumpKind::StackOnly => "stack-only",
    }
}

fn run_analyze(
    s1: &S1Output,
    plugin: Option<&str>,
    json: bool,
    symbols: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let pipeline = if let Some(pdb_dir) = symbols {
        let mut p = Pipeline::new();
        p.register(forensicator_core::analyzer::cause::CrashCauseAnalyzer);
        p.register(forensicator_core::analyzer::strings::StringAnalyzer::default());
        p.register(forensicator_core::analyzer::vtables::VTableAnalyzer::default());
        p.register(forensicator_core::analyzer::lists::ListAnalyzer::default());
        p.register(forensicator_core::analyzer::arrays::ArrayAnalyzer::default());
        p.register(forensicator_core::analyzer::chunks::ChunkAnalyzer::default());
        p.register(forensicator_core::analyzer::shapes::ShapeAnalyzer);
        p.register(forensicator_core::analyzer::v8::V8Analyzer::new().with_pdb_dir(pdb_dir));
        p
    } else {
        Pipeline::default_pipeline()
    };
    let filter: Vec<&str> = plugin
        .map(|p| p.split(',').map(|s| s.trim()).collect())
        .unwrap_or_default();
    let catalog = Forensicator::analyze(s1, &pipeline, &filter);

    if json {
        let outputs: Vec<serde_json::Value> = catalog
            .outputs
            .iter()
            .map(|o| {
                serde_json::json!({
                    "name": o.plugin_name,
                    "count": o.strings.len() + o.vtables.len() + o.linked_lists.len()
                        + o.arrays.len() + o.chunks.len() + o.shape_clusters.len(),
                    "strings": if !o.strings.is_empty() {
                        serde_json::Value::Array(
                            o.strings.iter().map(|s| serde_json::json!({
                                "va": format!("0x{:X}", s.va),
                                "encoding": format!("{:?}", s.encoding),
                                "content": s.content,
                                "confidence": s.confidence,
                            })).collect()
                        )
                    } else { serde_json::Value::Null },
                    "vtables": if !o.vtables.is_empty() {
                        serde_json::Value::Array(o.vtables.iter().map(|v| serde_json::json!({
                            "va": format!("0x{:X}", v.va),
                            "method_count": v.method_count,
                            "confidence": v.confidence,
                        })).collect())
                    } else { serde_json::Value::Null },
                    "linked_lists": if !o.linked_lists.is_empty() {
                        serde_json::Value::Array(o.linked_lists.iter().map(|l| serde_json::json!({
                            "head_va": format!("0x{:X}", l.head_va),
                            "length": l.length,
                            "stride": l.stride,
                        })).collect())
                    } else { serde_json::Value::Null },
                    "arrays": if !o.arrays.is_empty() {
                        serde_json::Value::Array(o.arrays.iter().map(|a| serde_json::json!({
                            "start_va": format!("0x{:X}", a.start_va),
                            "element_size": a.element_size,
                            "count": a.count,
                            "confidence": a.confidence,
                        })).collect())
                    } else { serde_json::Value::Null },
                    "chunks": if !o.chunks.is_empty() {
                        serde_json::Value::Array(o.chunks.iter().map(|c| serde_json::json!({
                            "va_start": format!("0x{:X}", c.va_start),
                            "size": c.size,
                            "is_free": c.is_free,
                            "confidence": c.confidence,
                        })).collect())
                    } else { serde_json::Value::Null },
                    "shape_clusters": if !o.shape_clusters.is_empty() {
                        serde_json::Value::Array(o.shape_clusters.iter().map(|g| serde_json::json!({
                            "id": g.id,
                            "member_count": g.member_count,
                        })).collect())
                    } else { serde_json::Value::Null },
                    "custom": if !o.custom.is_empty() {
                        serde_json::Value::Array(o.custom.iter().map(|(k, v)| serde_json::json!({ k: v })).collect())
                    } else { serde_json::Value::Null },
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "plugins": outputs }))?
        );
    } else {
        println!("Analysis results:");
        for output in &catalog.outputs {
            let total = output.strings.len()
                + output.vtables.len()
                + output.linked_lists.len()
                + output.arrays.len()
                + output.chunks.len()
                + output.shape_clusters.len();
            println!("  {}: {} results", output.plugin_name, total);
            if output.plugin_name == "v8" {
                print_v8_frames(output);
                continue;
            }
            if !output.strings.is_empty() {
                println!("    strings: {}", output.strings.len());
            }
            if !output.vtables.is_empty() {
                println!("    vtables: {}", output.vtables.len());
            }
            if !output.linked_lists.is_empty() {
                println!("    linked_lists: {}", output.linked_lists.len());
            }
            if !output.arrays.is_empty() {
                println!("    arrays: {}", output.arrays.len());
            }
            if !output.chunks.is_empty() {
                println!("    chunks: {}", output.chunks.len());
            }
            if !output.shape_clusters.is_empty() {
                println!("    shape_clusters: {} groups", output.shape_clusters.len());
            }
            if !output.custom.is_empty() {
                println!("    custom: {} entries", output.custom.len());
            }
        }
    }
    Ok(())
}

fn cmd_list_plugins() {
    println!("Available analyzers:");
    let pipeline = Pipeline::default_pipeline();
    for (name, desc) in pipeline.list_analyzers() {
        println!("  {name}: {desc}");
    }
}

fn print_v8_frames(output: &forensicator_core::analyzer::AnalyzerOutput) {
    // Extract v8_frames from custom
    let frames_json = output
        .custom
        .iter()
        .find(|(k, _)| k == "v8_frames")
        .map(|(_, v)| v);

    let frame_count = output
        .custom
        .iter()
        .find(|(k, _)| k == "v8_frame_count")
        .and_then(|(_, v)| v.as_u64())
        .unwrap_or(0);

    let Some(frames) = frames_json.and_then(|v| v.as_array()) else {
        println!("    v8: no frames");
        return;
    };

    // Crash-site disassembly, when present
    if let Some(disasm) = output
        .custom
        .iter()
        .find(|(k, _)| k == "crash_disasm")
        .and_then(|(_, v)| v.as_array())
    {
        println!("  Crash site:");
        for insn in disasm {
            let va = insn.get("va").and_then(|v| v.as_str()).unwrap_or("");
            let text = insn.get("text").and_then(|v| v.as_str()).unwrap_or("");
            println!("    {va}  {text}");
        }
    }

    // Group frames by thread
    let mut by_thread: std::collections::BTreeMap<u32, Vec<&serde_json::Value>> =
        std::collections::BTreeMap::new();
    for frame in frames {
        if let Some(tid) = frame.get("thread_id").and_then(|v| v.as_u64()) {
            by_thread.entry(tid as u32).or_default().push(frame);
        }
    }

    for (tid, thread_frames) in &by_thread {
        println!("  Thread {}: {} frames", tid, thread_frames.len());
        for frame in thread_frames {
            let depth = frame.get("depth").and_then(|v| v.as_u64()).unwrap_or(0);
            let symbol = frame
                .get("native_symbol")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let offset = frame
                .get("native_offset")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let addr = frame
                .get("return_address")
                .and_then(|v| v.as_str())
                .unwrap_or("0x0");
            let ftype = frame
                .get("frame_type")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let js_name = frame
                .get("js_function_name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let script = frame.get("script_name").and_then(|v| v.as_str());
            let line = frame.get("script_line").and_then(|v| v.as_u64());

            let type_short = match ftype {
                "OptimizedJavaScript" => "Opt JS",
                "JavaScript" => "JS",
                "WasmCompiled" => "Wasm",
                "Cpp" => "C++",
                other => other,
            };

            // Shorten long symbols
            let short_sym = if symbol.len() > 80 {
                let bytes = symbol.as_bytes();
                if let Some(pos) = bytes.iter().position(|&b| b == b'@') {
                    &symbol[..pos.min(75)]
                } else {
                    &symbol[..75]
                }
            } else {
                symbol
            };

            // Description: JS function + source location, or native symbol.
            let desc = if !js_name.is_empty() {
                let loc = match (script, line) {
                    (Some(s), Some(l)) => format!(" @ {}:{l}", shorten_script(s)),
                    (Some(s), None) => format!(" @ {}", shorten_script(s)),
                    (None, Some(l)) => format!(" @ <script>:{l}"),
                    _ => String::new(),
                };
                let sym_part = if symbol.starts_with("0x") {
                    String::new()
                } else if offset > 0 {
                    format!("  ({short_sym} +0x{offset:X})")
                } else {
                    format!("  ({short_sym})")
                };
                format!("{js_name}{loc}{sym_part}")
            } else if offset > 0 {
                format!("{short_sym} +0x{offset:X}")
            } else {
                short_sym.to_string()
            };

            println!("    #{:<3} {:<10} {:<66} {addr}", depth, type_short, desc);
        }
    }
    println!(
        "  Total: {} frames across {} threads",
        frame_count,
        by_thread.len()
    );
}

/// Display form of a script name: basename for URLs/paths, `<dynamic script>`
/// for code snippets (eval/`new Function` sources), truncated otherwise.
fn shorten_script(s: &str) -> String {
    if s.contains([';', '{', '\n']) {
        return "<dynamic script>".to_string();
    }
    if s.contains('/')
        && let Some(base) = s.rsplit('/').next()
    {
        // Only treat as a path when the basename looks like a filename.
        if base.contains('.') && !base.contains(' ') && base.len() <= 128 {
            return base.to_string();
        }
    }
    if s.chars().count() > 30 {
        let mut t: String = s.chars().take(27).collect();
        t.push('…');
        t
    } else {
        s.to_string()
    }
}

fn os_name(os: OsPlatform) -> &'static str {
    match os {
        OsPlatform::Windows => "Windows",
        OsPlatform::Linux => "Linux",
        OsPlatform::MacOs => "macOS",
    }
}

fn cpu_name(cpu: CpuArch) -> &'static str {
    match cpu {
        CpuArch::X86 => "x86",
        CpuArch::X64 => "x64",
        CpuArch::Arm64 => "ARM64",
    }
}
