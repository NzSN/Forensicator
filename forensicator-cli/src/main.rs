use std::process;

use clap::{Parser, Subcommand};
use forensicator_core::analyzer::Pipeline;
use forensicator_core::model::{CpuArch, OsPlatform};
use forensicator_core::parse::dump;
use forensicator_core::pipeline::Forensicator;

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
    ListPlugins,
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
    }
}

fn inspect(path: &str, json: bool, quiet: bool) -> Result<(), Box<dyn std::error::Error>> {
    let dump = dump::open(path)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "file_size": dump.file_size,
                "system_info": dump.system_info.as_ref().map(|si| serde_json::json!({
                    "os": os_name(si.os), "cpu": cpu_name(si.cpu),
                    "version": format!("{}.{}.{}.{}", si.version.0, si.version.1, si.version.2, si.version.3),
                })),
                "module_count": dump.modules.len(),
                "thread_count": dump.threads.len(),
                "memory_regions": dump.memory_regions.len(),
                "exception": dump.exception.is_some(),
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

fn cmd_analyze(
    path: &str,
    plugin: Option<&str>,
    json: bool,
    symbols: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut s1 = Forensicator::open(path)?;

    // Stack-only minidumps: supplement module bytes (.pdata/.text) from
    // on-disk images discovered next to the dump.
    let image_count = {
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
    };
    if !json {
        let kind = match s1.kind {
            forensicator_core::pipeline::DumpKind::FullMemory => "full-memory",
            forensicator_core::pipeline::DumpKind::StackOnly => "stack-only",
        };
        eprintln!("dump: {kind}, {image_count} image(s) supplemented");
    }

    let pipeline = if let Some(pdb_dir) = symbols {
        let mut p = Pipeline::new();
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
    let catalog = Forensicator::analyze(&s1, &pipeline, &filter);

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
