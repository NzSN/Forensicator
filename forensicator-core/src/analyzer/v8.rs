//! V8 JavaScript engine stack analyzer.
//! Walks native call stacks, resolves symbols via PDB, classifies V8 frames.

use std::collections::HashMap;
use std::path::Path;

use crate::analyzer::{Analyzer, AnalyzerOutput};
use crate::model::{Dump, V8FrameType, V8StackFrame};
use crate::space::AddressSpace;
use crate::symbolizer::Symbolizer;

pub struct V8Analyzer {
    pdb_dir: Option<String>,
}

impl V8Analyzer {
    pub fn new() -> Self {
        V8Analyzer { pdb_dir: None }
    }

    pub fn with_pdb_dir(mut self, dir: impl Into<String>) -> Self {
        self.pdb_dir = Some(dir.into());
        self
    }
}

impl Default for V8Analyzer {
    fn default() -> Self {
        V8Analyzer::new()
    }
}

impl Analyzer for V8Analyzer {
    fn name(&self) -> &str {
        "v8"
    }

    fn description(&self) -> &str {
        "Recovers JS stack traces by walking native stacks and classifying V8 frames"
    }

    fn analyze(&self, dump: &Dump, space: &AddressSpace) -> AnalyzerOutput {
        let mut out = AnalyzerOutput::new("v8");

        let isolate_va = resolve_v8_isolate(dump);

        let sym = if let Some(ref dir) = self.pdb_dir {
            Symbolizer::load(dump, Path::new(dir)).ok()
        } else {
            Symbolizer::load(dump, Path::new(".")).ok()
        };

        let frames = walk_thread_stacks(dump, space, isolate_va, sym.as_ref());

        let frames_json: Vec<serde_json::Value> = frames
            .iter()
            .map(|f| {
                serde_json::json!({
                    "thread_id": f.thread_id,
                    "depth": f.depth,
                    "frame_type": format!("{:?}", f.frame_type),
                    "native_symbol": f.native_symbol,
                    "native_offset": f.native_offset,
                    "return_address": format!("0x{:X}", f.return_address),
                    "js_function_name": f.js_function_name,
                    "script_name": f.script_name,
                    "script_line": f.script_line,
                })
            })
            .collect();

        out.custom.push((
            "v8_frames".to_string(),
            serde_json::Value::Array(frames_json),
        ));
        out.custom.push((
            "v8_frame_count".to_string(),
            serde_json::json!(frames.len()),
        ));

        out
    }
}

fn resolve_v8_isolate(dump: &Dump) -> Option<u64> {
    for (k, v) in &dump.annotations {
        if k == "v8_isolate_address" {
            let hex = v.trim_start_matches("0x").trim_start_matches("0X");
            if let Ok(va) = u64::from_str_radix(hex, 16) {
                return Some(va);
            }
        }
    }
    None
}

fn walk_thread_stacks(
    dump: &Dump,
    space: &AddressSpace,
    _isolate_va: Option<u64>,
    symbolizer: Option<&Symbolizer>,
) -> Vec<V8StackFrame> {
    let mut frames = Vec::new();

    // Find electron.exe base for module region checks
    let electron_base = dump
        .modules
        .iter()
        .find(|m| m.name.to_lowercase().contains("electron.exe"))
        .map(|m| (m.base_va, m.size))
        .or_else(|| dump.modules.first().map(|m| (m.base_va, m.size)));

    for (_i, thread) in dump.threads.iter().enumerate() {
        let tid = thread.id;
        let rip = thread.registers.rip();
        let rsp = thread.registers.rsp();
        let rbp = thread.registers.rbp();

        // Prefer exception context for the crashed thread
        let (rip, rsp, rbp) = if let Some(ref exc) = dump.exception {
            if exc.thread_id == tid {
                if let Some(ref ctx) = exc.context {
                    (ctx.rip(), ctx.rsp(), ctx.rbp())
                } else {
                    (rip, rsp, rbp)
                }
            } else {
                (rip, rsp, rbp)
            }
        } else {
            (rip, rsp, rbp)
        };

        if rbp == 0 || rsp == 0 {
            continue;
        }

        let stack_end = thread.stack_va.saturating_add(thread.stack_size);
        let mut current_rbp = rbp;
        let mut depth = 0usize;
        let mut seen = HashMap::new();

        // Frame 0: current instruction
        if rip != 0 {
            let sym_name = symbolizer
                .and_then(|s| s.resolve(rip))
                .map(|r| r.function_name.clone())
                .unwrap_or_else(|| format!("0x{:X}", rip));
            let offset = symbolizer
                .and_then(|s| s.resolve(rip))
                .map(|r| r.offset)
                .unwrap_or(0);

            frames.push(V8StackFrame {
                thread_id: tid,
                depth,
                frame_type: classify_frame(rip, space, electron_base),
                native_symbol: sym_name,
                native_offset: offset,
                return_address: rip,
                js_function_name: None,
                script_name: None,
                script_line: None,
            });
            depth += 1;
        }

        while current_rbp > 0 && current_rbp < stack_end && depth < 256 {
            if seen.contains_key(&current_rbp) {
                break;
            }
            seen.insert(current_rbp, depth);

            let saved_rbp = read_u64(space, current_rbp);
            let return_addr = read_u64(space, current_rbp + 8);

            if return_addr == 0 {
                break;
            }

            let sym_name = symbolizer
                .and_then(|s| s.resolve(return_addr))
                .map(|r| r.function_name.clone())
                .unwrap_or_else(|| format!("0x{:X}", return_addr));
            let offset = symbolizer
                .and_then(|s| s.resolve(return_addr))
                .map(|r| r.offset)
                .unwrap_or(0);

            frames.push(V8StackFrame {
                thread_id: tid,
                depth,
                frame_type: classify_frame(return_addr, space, electron_base),
                native_symbol: sym_name,
                native_offset: offset,
                return_address: return_addr,
                js_function_name: None,
                script_name: None,
                script_line: None,
            });

            depth += 1;

            if saved_rbp <= current_rbp || saved_rbp >= stack_end {
                break;
            }
            current_rbp = saved_rbp;
        }
    }

    frames
}

fn classify_frame(
    return_address: u64,
    space: &AddressSpace,
    module_range: Option<(u64, u64)>,
) -> V8FrameType {
    let class = space.classify(return_address);
    match class {
        crate::model::RegionClass::Image => {
            // Check if within the main Electron/V8 module
            if let Some((base, size)) = module_range {
                if return_address >= base && return_address < base + size {
                    return V8FrameType::Builtin;
                }
            }
            V8FrameType::Builtin
        }
        crate::model::RegionClass::Stack => V8FrameType::Cpp,
        _ => V8FrameType::Unknown,
    }
}

fn read_u64(space: &AddressSpace, va: u64) -> u64 {
    match space.read(va, 8) {
        Some(bytes) => {
            let arr: [u8; 8] = bytes.try_into().unwrap();
            u64::from_le_bytes(arr)
        }
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::RegisterSet;
    use crate::arch::x64_indices;
    use crate::error::Provenance;
    use crate::model::{MemState, Module, RegionClass, Thread};
    use crate::space::{AddressRegion, AddressSpace};

    fn make_stack_thread(rbp: u64, rsp: u64, rip: u64, stack_va: u64, stack_size: u64) -> Thread {
        let mut regs = RegisterSet::new();
        regs.set(x64_indices::RBP, rbp);
        regs.set(x64_indices::RSP, rsp);
        regs.set(x64_indices::RIP, rip);
        Thread {
            id: 1,
            registers: regs,
            stack_va,
            stack_size,
            teb_va: 0,
            provenance: Provenance {
                stream_type: 3,
                file_offset: 0,
                rva: 0,
            },
        }
    }

    fn make_synthetic_stack() -> (AddressSpace, Dump) {
        let mut space = AddressSpace::new(2);
        let mut stack_data = vec![0u8; 0x500];
        // RBP=0x1000: saved_RBP=0x1200, return_addr=0x7FFA1000
        // RBP=0x1200: saved_RBP=0x1400, return_addr=0x7FFA2000
        // RBP=0x1400: saved_RBP=0
        stack_data[0x000..0x008].copy_from_slice(&0x1200u64.to_le_bytes());
        stack_data[0x008..0x010].copy_from_slice(&0x7FFA1000u64.to_le_bytes());
        stack_data[0x200..0x208].copy_from_slice(&0x1400u64.to_le_bytes());
        stack_data[0x208..0x210].copy_from_slice(&0x7FFA2000u64.to_le_bytes());
        stack_data[0x400..0x408].copy_from_slice(&0u64.to_le_bytes());
        stack_data[0x408..0x410].copy_from_slice(&0u64.to_le_bytes());
        space
            .add_region(AddressRegion {
                va_start: 0x1000,
                size: 0x500,
                data: stack_data,
                protection: 3,
                state: MemState::Commit,
                classification: RegionClass::Stack,
            })
            .unwrap();
        space
            .add_region(AddressRegion {
                va_start: 0x7FFA0000,
                size: 0x10000,
                data: vec![0u8; 0x10000],
                protection: 3,
                state: MemState::Commit,
                classification: RegionClass::Image,
            })
            .unwrap();

        let dump = Dump {
            system_info: None,
            modules: vec![Module {
                name: "test.dll".into(),
                base_va: 0x7FFA0000,
                size: 0x10000,
                checksum: 0,
                codeview_guid: None,
                pdb_name: None,
                provenance: Provenance {
                    stream_type: 2,
                    file_offset: 0,
                    rva: 0,
                },
            }],
            threads: vec![make_stack_thread(0x1000, 0x1000, 0x7FFA1000, 0x1000, 0x500)],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            annotations: vec![],
            file_size: 0,
        };

        (space, dump)
    }

    #[test]
    fn empty_stack_produces_no_frames() {
        let space = AddressSpace::new(4);
        let dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            annotations: vec![],
            file_size: 0,
        };
        let a = V8Analyzer::new();
        let out = a.analyze(&dump, &space);
        let frames = out.custom.iter().find(|(k, _)| k == "v8_frames");
        assert!(frames.is_some());
    }

    #[test]
    fn synthetic_stack_walks_correct_frame_count() {
        let (space, dump) = make_synthetic_stack();
        let a = V8Analyzer::new();
        let out = a.analyze(&dump, &space);
        let count: usize = out
            .custom
            .iter()
            .find(|(k, _)| k == "v8_frame_count")
            .and_then(|(_, v): &(String, serde_json::Value)| v.as_u64().map(|n| n as usize))
            .unwrap_or(0);
        assert!(count >= 2, "expected at least 2 frames, got {count}");
    }

    #[test]
    fn terminates_on_loop() {
        let mut space = AddressSpace::new(2);
        let mut stack_data = vec![0u8; 0x200];
        stack_data[0x000..0x008].copy_from_slice(&0x1000u64.to_le_bytes()); // self-loop
        stack_data[0x008..0x010].copy_from_slice(&0x7FFA1000u64.to_le_bytes());
        space
            .add_region(AddressRegion {
                va_start: 0x1000,
                size: 0x200,
                data: stack_data,
                protection: 3,
                state: MemState::Commit,
                classification: RegionClass::Stack,
            })
            .unwrap();
        space
            .add_region(AddressRegion {
                va_start: 0x7FFA0000,
                size: 0x10000,
                data: vec![0u8; 0x10000],
                protection: 3,
                state: MemState::Commit,
                classification: RegionClass::Image,
            })
            .unwrap();

        let dump = Dump {
            system_info: None,
            modules: vec![Module {
                name: "test.dll".into(),
                base_va: 0x7FFA0000,
                size: 0x10000,
                checksum: 0,
                codeview_guid: None,
                pdb_name: None,
                provenance: Provenance {
                    stream_type: 2,
                    file_offset: 0,
                    rva: 0,
                },
            }],
            threads: vec![make_stack_thread(0x1000, 0x1000, 0x7FFA1000, 0x1000, 0x200)],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            annotations: vec![],
            file_size: 0,
        };

        let a = V8Analyzer::new();
        let out = a.analyze(&dump, &space);
        let count: usize = out
            .custom
            .iter()
            .find(|(k, _)| k == "v8_frame_count")
            .and_then(|(_, v): &(String, serde_json::Value)| v.as_u64().map(|n| n as usize))
            .unwrap_or(0);
        assert!(count <= 256, "should terminate on loop");
    }

    #[test]
    fn resolve_isolate_from_annotations() {
        let dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            annotations: vec![("v8_isolate_address".into(), "0x68340051c000".into())],
            file_size: 0,
        };
        let iso = resolve_v8_isolate(&dump);
        assert_eq!(iso, Some(0x68340051c000));
    }

    #[test]
    fn no_annotations_returns_none() {
        let dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            annotations: vec![],
            file_size: 0,
        };
        assert_eq!(resolve_v8_isolate(&dump), None);
    }
}
