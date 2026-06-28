use std::process;

use clap::{Parser, Subcommand};
use forensicator_core::graph;
use forensicator_core::model::{CpuArch, OsPlatform};
use forensicator_core::parse::dump;
use forensicator_core::pattern::PointerPattern;
use forensicator_core::query::GraphQuery;
use forensicator_core::scan;

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
    /// Inspect a minidump file and print its structural inventory.
    Inspect {
        path: String,
        #[arg(long)] json: bool,
        #[arg(long)] quiet: bool,
    },
    /// Scan for pointer candidates using configured patterns.
    Scan {
        path: String,
        #[arg(long)] pattern: Option<String>,
        #[arg(long)] json: bool,
    },
    /// Build and export the pointer graph.
    Graph {
        path: String,
        #[arg(long)] pattern: Option<String>,
        #[arg(long, default_value = "0.5")] min_conf: f64,
        #[arg(long)] dot: bool,
        #[arg(long)] json: bool,
    },
    /// Query the pointer graph.
    Query {
        path: String,
        #[arg(long)] reachable: Option<String>,
        #[arg(long)] stats: bool,
    },
    /// List or show pointer patterns.
    Patterns {
        #[command(subcommand)]
        action: PatternsAction,
    },
    /// Recover structures from a minidump.
    Recover {
        path: String,
        #[arg(long)] strings: bool,
        #[arg(long)] vtables: bool,
        #[arg(long)] lists: bool,
        #[arg(long)] arrays: bool,
        #[arg(long)] chunks: bool,
        #[arg(long)] shapes: bool,
        #[arg(long)] all: bool,
        #[arg(long)] json: bool,
        #[arg(long)] pattern: Option<String>,
    },
}

#[derive(Subcommand)]
enum PatternsAction {
    List,
    Show { name: String },
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
        Commands::Scan { path, pattern, json } => {
            if let Err(e) = cmd_scan(&path, pattern.as_deref(), json) {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }
        Commands::Graph { path, pattern, min_conf, dot, json } => {
            if let Err(e) = cmd_graph(&path, pattern.as_deref(), min_conf, dot, json) {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }
        Commands::Query { path, reachable, stats } => {
            if let Err(e) = cmd_query(&path, reachable.as_deref(), stats) {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }
        Commands::Patterns { action } => match action {
            PatternsAction::List => cmd_patterns_list(),
            PatternsAction::Show { name } => cmd_patterns_show(&name),
        },
        Commands::Recover { path, strings, vtables, lists, arrays, chunks, shapes, all, json, pattern } => {
            if let Err(e) = cmd_recover(&path, strings, vtables, lists, arrays, chunks, shapes, all, json, pattern.as_deref()) {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }
    }
}

fn inspect(path: &str, json: bool, quiet: bool) -> Result<(), Box<dyn std::error::Error>> {
    let dump = dump::open(path)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
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
        }))?);
        return Ok(());
    }
    if quiet {
        println!("modules: {}  threads: {}  memory_regions: {}  anomalies: {}",
            dump.modules.len(), dump.threads.len(), dump.memory_regions.len(), dump.anomalies.len());
        return Ok(());
    }
    println!("Dump ({:.1} KB)", dump.file_size as f64 / 1024.0);
    if let Some(ref si) = dump.system_info {
        println!("├── SystemInfo: {} on {} v{}.{}.{}.{}",
            cpu_name(si.cpu), os_name(si.os), si.version.0, si.version.1, si.version.2, si.version.3);
    } else { println!("├── SystemInfo: <missing>"); }
    println!("├── Modules: {} loaded", dump.modules.len());
    for m in &dump.modules {
        println!("│   ├── {} @ 0x{:016X} ({:.1} KB)", m.name, m.base_va, m.size as f64 / 1024.0);
    }
    println!("├── Threads: {}", dump.threads.len());
    for t in &dump.threads {
        println!("│   ├── TID {}  stack @ 0x{:016X} ({:.1} KB)  TEB @ 0x{:016X}  RIP 0x{:016X}",
            t.id, t.stack_va, t.stack_size as f64 / 1024.0, t.teb_va, t.registers.rip());
    }
    println!("├── Memory regions: {}", dump.memory_regions.len());
    if let Some(ref exc) = dump.exception {
        println!("├── Exception: code 0x{:08X} at 0x{:016X} (thread {})", exc.code, exc.address, exc.thread_id);
    }
    if !dump.anomalies.is_empty() {
        println!("└── Anomalies: {}", dump.anomalies.len());
        for a in &dump.anomalies {
            println!("    ├── [stream 0x{:08X} @ +0x{:X}] {}", a.provenance.stream_type, a.provenance.file_offset, a.description);
        }
    }
    Ok(())
}

fn cmd_scan(path: &str, pattern_name: Option<&str>, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let dump = dump::open(path)?;
    let space = forensicator_core::space::AddressSpace::new(1_000_000);
    let patterns = select_patterns(pattern_name);
    let registers: Vec<(u32, Vec<(String, u64)>)> = dump.threads.iter().map(|t| {
        vec![("RIP".into(), t.registers.rip()), ("RSP".into(), t.registers.rsp()), ("RBP".into(), t.registers.rbp())]
    }).enumerate().map(|(i, r)| (i as u32, r)).collect();
    let stack_ranges: Vec<(u32, u64, u64)> = dump.threads.iter().map(|t| (t.id, t.stack_va, t.stack_size)).collect();
    let reg_refs: Vec<(u32, &[(String, u64)])> = registers.iter().map(|(tid, r)| (*tid, r.as_slice())).collect();
    let result = scan::scan(&space, &reg_refs, &stack_ranges, &patterns)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "candidate_count": result.candidates.len(), "root_count": result.roots.len(),
            "candidates": result.candidates.iter().map(|c| serde_json::json!({
                "source_va": format!("0x{:X}", c.source_va), "target_va": format!("0x{:X}", c.target_va),
                "confidence": c.confidence, "evidence": c.evidence,
            })).collect::<Vec<_>>(),
        }))?);
    } else {
        println!("Pointer scan: {} candidates, {} roots", result.candidates.len(), result.roots.len());
        for c in &result.candidates {
            println!("  0x{:016X} -> 0x{:016X}  conf={:.2}", c.source_va, c.target_va, c.confidence);
        }
    }
    Ok(())
}

fn cmd_graph(path: &str, pattern_name: Option<&str>, _min_conf: f64, dot: bool, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let dump = dump::open(path)?;
    let space = forensicator_core::space::AddressSpace::new(1_000_000);
    let patterns = select_patterns(pattern_name);
    let registers: Vec<(u32, Vec<(String, u64)>)> = dump.threads.iter().map(|t| {
        vec![("RIP".into(), t.registers.rip()), ("RSP".into(), t.registers.rsp()), ("RBP".into(), t.registers.rbp())]
    }).enumerate().map(|(i, r)| (i as u32, r)).collect();
    let stack_ranges: Vec<(u32, u64, u64)> = dump.threads.iter().map(|t| (t.id, t.stack_va, t.stack_size)).collect();
    let reg_refs: Vec<(u32, &[(String, u64)])> = registers.iter().map(|(tid, r)| (*tid, r.as_slice())).collect();
    let scan_result = scan::scan(&space, &reg_refs, &stack_ranges, &patterns)?;
    let pointer_graph = graph::build_graph(&scan_result)?;
    let query = GraphQuery::new(&pointer_graph);
    if dot { println!("{}", query.to_dot()); }
    else if json { println!("{}", serde_json::to_string_pretty(&query.to_json())?); }
    else {
        println!("Pointer graph: {} nodes, {} edges, {} roots",
            pointer_graph.node_count(), pointer_graph.edge_count(), pointer_graph.root_nodes().len());
        for (rc, nodes, edges) in query.region_breakdown() {
            println!("  {:?}: {} nodes, {} edges", rc, nodes, edges);
        }
    }
    Ok(())
}

fn cmd_query(path: &str, reachable: Option<&str>, stats: bool) -> Result<(), Box<dyn std::error::Error>> {
    let dump = dump::open(path)?;
    let space = forensicator_core::space::AddressSpace::new(1_000_000);
    let patterns = PointerPattern::presets();
    let registers: Vec<(u32, Vec<(String, u64)>)> = dump.threads.iter().map(|t| {
        vec![("RIP".into(), t.registers.rip()), ("RSP".into(), t.registers.rsp()), ("RBP".into(), t.registers.rbp())]
    }).enumerate().map(|(i, r)| (i as u32, r)).collect();
    let stack_ranges: Vec<(u32, u64, u64)> = dump.threads.iter().map(|t| (t.id, t.stack_va, t.stack_size)).collect();
    let reg_refs: Vec<(u32, &[(String, u64)])> = registers.iter().map(|(tid, r)| (*tid, r.as_slice())).collect();
    let scan_result = scan::scan(&space, &reg_refs, &stack_ranges, &patterns)?;
    let pointer_graph = graph::build_graph(&scan_result)?;
    let query = GraphQuery::new(&pointer_graph);
    if let Some(va_str) = reachable {
        let va = u64::from_str_radix(va_str.trim_start_matches("0x"), 16)?;
        let nodes = query.reachable_from(va);
        println!("Reachable from 0x{:X}: {} nodes", va, nodes.len());
        for n in nodes { println!("  0x{:X}", pointer_graph.nodes[n.0].va); }
    }
    if stats {
        println!("Degree distribution:");
        for (deg, count) in query.degree_distribution() { println!("  {} -> {} nodes", deg, count); }
        println!("Confidence distribution:");
        for (bucket, count) in query.confidence_distribution() { println!("  bucket {} -> {} edges", bucket, count); }
    }
    Ok(())
}

fn cmd_recover(
    path: &str, strings: bool, vtables: bool, lists: bool, arrays: bool, chunks: bool, shapes: bool,
    all: bool, json: bool, pattern_name: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    use forensicator_core::recover;
    let dump = dump::open(path)?;
    let space = forensicator_core::space::AddressSpace::new(1_000_000);
    let patterns = if let Some(n) = pattern_name {
        PointerPattern::presets().into_iter().filter(|p| p.name == n).collect()
    } else { PointerPattern::presets() };
    let registers: Vec<(u32, Vec<(String, u64)>)> = dump.threads.iter().map(|t| {
        vec![("RIP".into(), t.registers.rip()), ("RSP".into(), t.registers.rsp()), ("RBP".into(), t.registers.rbp())]
    }).enumerate().map(|(i, r)| (i as u32, r)).collect();
    let stack_ranges: Vec<(u32, u64, u64)> = dump.threads.iter().map(|t| (t.id, t.stack_va, t.stack_size)).collect();
    let reg_refs: Vec<(u32, &[(String, u64)])> = registers.iter().map(|(tid, r)| (*tid, r.as_slice())).collect();
    let scan_result = scan::scan(&space, &reg_refs, &stack_ranges, &patterns)?;
    let pointer_graph = graph::build_graph(&scan_result)?;
    let query = GraphQuery::new(&pointer_graph);
    let run_all = all || (!strings && !vtables && !lists && !arrays && !chunks && !shapes);
    let catalog = recover::recover_all(&space, &pointer_graph, &query);
    if json {
        let output = serde_json::json!({
            "strings": if run_all || strings { catalog.strings.len() } else { 0 },
            "vtables": if run_all || vtables { catalog.vtables.len() } else { 0 },
            "linked_lists": if run_all || lists { catalog.linked_lists.len() } else { 0 },
            "arrays": if run_all || arrays { catalog.arrays.len() } else { 0 },
            "chunks": if run_all || chunks { catalog.chunks.len() } else { 0 },
            "shape_groups": catalog.shape_clusters.groups.len(),
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Structure recovery results:");
        if run_all || strings { println!("  Strings: {}", catalog.strings.len()); }
        if run_all || vtables { println!("  VTables: {}", catalog.vtables.len()); }
        if run_all || lists { println!("  Linked lists: {}", catalog.linked_lists.len()); }
        if run_all || arrays { println!("  Arrays: {}", catalog.arrays.len()); }
        if run_all || chunks { println!("  Chunks: {}", catalog.chunks.len()); }
        if run_all || shapes { println!("  Shape groups: {}", catalog.shape_clusters.groups.len()); }
    }
    Ok(())
}

fn cmd_patterns_list() {
    println!("Pointer patterns:");
    for p in PointerPattern::presets() {
        println!("  {} (min_conf={:.2})", p.name, p.min_confidence);
    }
}

fn cmd_patterns_show(name: &str) {
    for p in PointerPattern::presets() {
        if p.name == name {
            println!("Pattern: {}", p.name);
            println!("  min_confidence: {:.2}", p.min_confidence);
            println!("  value_matchers: {:?}", p.value_matchers);
            println!("  source: {:?}", p.source);
            println!("  target: {:?}", p.target);
            return;
        }
    }
    println!("Pattern '{}' not found", name);
}

fn select_patterns(name: Option<&str>) -> Vec<PointerPattern> {
    match name {
        Some(n) => PointerPattern::presets().into_iter().filter(|p| p.name == n).collect(),
        None => PointerPattern::presets(),
    }
}

fn os_name(os: OsPlatform) -> &'static str {
    match os { OsPlatform::Windows => "Windows", OsPlatform::Linux => "Linux", OsPlatform::MacOs => "macOS" }
}

fn cpu_name(cpu: CpuArch) -> &'static str {
    match cpu { CpuArch::X86 => "x86", CpuArch::X64 => "x64", CpuArch::Arm64 => "ARM64" }
}
