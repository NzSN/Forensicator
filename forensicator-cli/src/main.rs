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
        Commands::Analyze { path, plugin, json, symbols } => {
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
    let s1 = Forensicator::open(path)?;
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
