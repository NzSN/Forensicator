use std::process;

use clap::{Parser, Subcommand};
use forensicator_core::model::{CpuArch, OsPlatform};
use forensicator_core::parse::dump;

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
        /// Path to the .dmp file.
        path: String,

        /// Emit JSON output instead of tree text.
        #[arg(long)]
        json: bool,

        /// Print only summary (module/thread/region counts).
        #[arg(long)]
        quiet: bool,
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
    }
}

fn inspect(path: &str, json: bool, quiet: bool) -> Result<(), Box<dyn std::error::Error>> {
    let dump = dump::open(path)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "file_size": dump.file_size,
            "system_info": dump.system_info.as_ref().map(|si| serde_json::json!({
                "os": os_name(si.os),
                "cpu": cpu_name(si.cpu),
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
            dump.modules.len(), dump.threads.len(),
            dump.memory_regions.len(), dump.anomalies.len());
        return Ok(());
    }

    println!("Dump ({:.1} KB)", dump.file_size as f64 / 1024.0);

    if let Some(ref si) = dump.system_info {
        println!("├── SystemInfo: {} on {} v{}.{}.{}.{}",
            cpu_name(si.cpu), os_name(si.os),
            si.version.0, si.version.1, si.version.2, si.version.3);
    } else {
        println!("├── SystemInfo: <missing>");
    }

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
        println!("├── Exception: code 0x{:08X} at 0x{:016X} (thread {})",
            exc.code, exc.address, exc.thread_id);
    }

    if !dump.anomalies.is_empty() {
        println!("└── Anomalies: {}", dump.anomalies.len());
        for a in &dump.anomalies {
            println!("    ├── [stream 0x{:08X} @ +0x{:X}] {}",
                a.provenance.stream_type, a.provenance.file_offset, a.description);
        }
    }

    Ok(())
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
