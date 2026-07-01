pub mod error;

use std::collections::HashMap;
use std::path::Path;

use pdb::FallibleIterator;

use crate::model::Dump;
pub use error::SymbolizerError;

#[derive(Debug, Clone)]
pub struct SymbolEntry {
    pub va: u64,
    pub function_name: String,
    pub source_file: Option<String>,
    pub source_line: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct ResolvedSymbol {
    pub function_name: String,
    pub offset: u64,
    pub source_file: Option<String>,
    pub source_line: Option<u32>,
}

struct ModuleSymbols {
    module_name: String,
    base_va: u64,
    size: u64,
    symbols: Vec<SymbolEntry>,
}

pub struct Symbolizer {
    modules: Vec<ModuleSymbols>,
}

impl Symbolizer {
    pub fn load(dump: &Dump, pdb_dir: &Path) -> Result<Self, SymbolizerError> {
        let mut modules: Vec<ModuleSymbols> = Vec::new();

        for module in &dump.modules {
            let Some(guid) = module.codeview_guid else {
                continue;
            };
            let Some(pdb_name) = &module.pdb_name else {
                continue;
            };

            let pdb_path = match find_pdb(pdb_dir, pdb_name, &guid) {
                Ok(path) => path,
                Err(SymbolizerError::Io(_)) => continue,
                Err(SymbolizerError::NoSymbols(_)) => continue,
                Err(e) => return Err(e),
            };

            match load_module_symbols(
                &pdb_path,
                &module.name,
                module.base_va,
                module.size,
            ) {
                Ok(ms) => modules.push(ms),
                Err(SymbolizerError::Io(_)) => continue,
                Err(SymbolizerError::NoSymbols(_)) => continue,
                Err(e) => return Err(e),
            }
        }

        Ok(Symbolizer { modules })
    }

    pub fn resolve(&self, va: u64) -> Option<ResolvedSymbol> {
        let ms = self
            .modules
            .binary_search_by_key(&va, |m| m.base_va)
            .ok()
            .map(|i| &self.modules[i])
            .or_else(|| {
                self.modules
                    .iter()
                    .find(|m| va >= m.base_va && va < m.base_va + m.size)
            })?;

        ms.resolve(va)
    }

    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    pub fn loaded_modules(&self) -> impl Iterator<Item = &str> {
        self.modules.iter().map(|m| m.module_name.as_str())
    }
}

impl ModuleSymbols {
    fn resolve(&self, va: u64) -> Option<ResolvedSymbol> {
        if va < self.base_va || va >= self.base_va + self.size {
            return None;
        }
        let idx = match self.symbols.binary_search_by_key(&va, |s| s.va) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        let entry = &self.symbols[idx];
        let offset = va.wrapping_sub(entry.va);
        Some(ResolvedSymbol {
            function_name: entry.function_name.clone(),
            offset,
            source_file: entry.source_file.clone(),
            source_line: entry.source_line,
        })
    }
}

fn codeview_guid_to_uuid(guid: &[u8; 16]) -> uuid::Uuid {
    let data1 = u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]);
    let data2 = u16::from_le_bytes([guid[4], guid[5]]);
    let data3 = u16::from_le_bytes([guid[6], guid[7]]);
    let data4: [u8; 8] = guid[8..16].try_into().unwrap();
    uuid::Uuid::from_fields(data1, data2, data3, &data4)
}

fn find_pdb(
    pdb_dir: &Path,
    pdb_name: &str,
    _expected_guid: &[u8; 16],
) -> Result<std::path::PathBuf, SymbolizerError> {
    let file_name = Path::new(pdb_name)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| pdb_name.to_string());

    let pdb_path = pdb_dir.join(&file_name);
    if !pdb_path.exists() {
        return Err(SymbolizerError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("PDB file not found: {}", pdb_path.display()),
        )));
    }

    let file = std::fs::File::open(&pdb_path)?;
    let mut pdb = pdb::PDB::open(file).map_err(|e| {
        SymbolizerError::PdbParse(format!("failed to open PDB {}: {e}", pdb_path.display()))
    })?;

    let pdb_info = pdb.pdb_information().map_err(|e| {
        SymbolizerError::PdbParse(format!(
            "failed to read PDB info from {}: {e}",
            pdb_path.display()
        ))
    })?;

    let actual_guid = pdb_info.guid;
    let expected = codeview_guid_to_uuid(_expected_guid);

    if actual_guid != expected {
        return Err(SymbolizerError::PdbParse(format!(
            "GUID mismatch for {}: expected {expected}, got {actual_guid}",
            file_name
        )));
    }

    Ok(pdb_path)
}

fn load_module_symbols(
    pdb_path: &Path,
    module_name: &str,
    base_va: u64,
    size: u64,
) -> Result<ModuleSymbols, SymbolizerError> {
    let file = std::fs::File::open(pdb_path)?;
    let mut pdb = pdb::PDB::open(file).map_err(|e| {
        SymbolizerError::PdbParse(format!("failed to open PDB {}: {e}", pdb_path.display()))
    })?;

    let address_map = pdb.address_map().map_err(|e| {
        SymbolizerError::PdbParse(format!(
            "failed to read address map from {}: {e}",
            pdb_path.display()
        ))
    })?;

    let _string_table = pdb.string_table().map_err(|e| {
        SymbolizerError::PdbParse(format!(
            "failed to read string table from {}: {e}",
            pdb_path.display()
        ))
    })?;

    let mut symbol_map: HashMap<u64, (String, Option<String>, Option<u32>)> = HashMap::new();

    let symbol_table = pdb.global_symbols().map_err(|e| {
        SymbolizerError::PdbParse(format!(
            "failed to read global symbols from {}: {e}",
            pdb_path.display()
        ))
    })?;

    let mut symbols = symbol_table.iter();
    while let Some(symbol) = symbols.next().map_err(|e| {
        SymbolizerError::PdbParse(format!("symbol iteration error: {e}"))
    })? {
        let parsed: Result<pdb::SymbolData<'_>, _> = symbol.parse();
        let Ok(pdb::SymbolData::Public(data)) = parsed else {
            continue;
        };

        if !data.function || data.offset.section == 0 {
            continue;
        }

        let name = data.name.to_string();

        let rva = data.offset.to_rva(&address_map);
        let Some(rva) = rva else {
            continue;
        };

        let va = base_va.wrapping_add(rva.0 as u64);

        if va >= base_va && va < base_va + size {
            symbol_map
                .entry(va)
                .or_insert_with(|| (name.to_string(), None, None));
        }
    }

    if symbol_map.is_empty() {
        return Err(SymbolizerError::NoSymbols(module_name.to_string()));
    }

    if let Ok(dbi) = pdb.debug_information() {
        if let Ok(modules) = dbi.modules() {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut mod_iter = modules;
                while let Some(module) = mod_iter.next().ok().flatten() {
                    if let Ok(Some(info)) = pdb.module_info(&module) {
                        if let Ok(line_program) = info.line_program() {
                            let mut line_iter = line_program.lines();
                            loop {
                                match line_iter.next() {
                                    Ok(Some(line)) => {
                                        let rva = line.offset.to_rva(&address_map);
                                        let Some(rva) = rva else {
                                            continue;
                                        };
                                        let va = base_va.wrapping_add(rva.0 as u64);
                                        if let Some(entry) = symbol_map.get_mut(&va) {
                                            let file = match line_program
                                                .get_file_info(line.file_index)
                                            {
                                                Ok(fi) => fi.name.to_string(),
                                                Err(_) => continue,
                                            };
                                            entry.1 = Some(file);
                                            entry.2 = Some(line.line_start);
                                            break;
                                        }
                                    }
                                    Ok(None) => break,
                                    Err(_) => break,
                                }
                            }
                        }
                    }
                }
            }));
        }
    }

    let mut symbols: Vec<SymbolEntry> = symbol_map
        .into_iter()
        .map(|(va, (name, file, line))| SymbolEntry {
            va,
            function_name: name,
            source_file: file,
            source_line: line,
        })
        .collect();
    symbols.sort_by_key(|s| s.va);

    Ok(ModuleSymbols {
        module_name: module_name.to_string(),
        base_va,
        size,
        symbols,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Provenance;
    use crate::model::{Dump, Module};

    #[test]
    fn empty_dump_produces_empty_symbolizer() {
        let dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            file_size: 0,
        };
        let tmp = std::env::temp_dir();
        let sym = Symbolizer::load(&dump, &tmp).unwrap();
        assert_eq!(sym.module_count(), 0);
        assert!(sym.resolve(0x1000).is_none());
    }

    #[test]
    fn resolve_returns_none_for_empty_symbolizer() {
        let dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            file_size: 0,
        };
        let tmp = std::env::temp_dir();
        let sym = Symbolizer::load(&dump, &tmp).unwrap();
        assert!(sym.resolve(0).is_none());
        assert!(sym.resolve(0x7FFA0000).is_none());
    }

    #[test]
    fn module_without_guid_is_skipped() {
        let dump = Dump {
            system_info: None,
            modules: vec![Module {
                name: "test.dll".into(),
                base_va: 0x1000,
                size: 0x1000,
                checksum: 0,
                codeview_guid: None,
                pdb_name: None,
                provenance: Provenance {
                    stream_type: 2,
                    file_offset: 0,
                    rva: 0,
                },
            }],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            file_size: 0,
        };
        let tmp = std::env::temp_dir();
        let sym = Symbolizer::load(&dump, &tmp).unwrap();
        assert_eq!(sym.module_count(), 0);
    }

    #[test]
    fn missing_pdb_dir_skips_modules() {
        let dump = Dump {
            system_info: None,
            modules: vec![Module {
                name: "test.dll".into(),
                base_va: 0x1000,
                size: 0x1000,
                checksum: 0,
                codeview_guid: Some([0xAA; 16]),
                pdb_name: Some("test.pdb".into()),
                provenance: Provenance {
                    stream_type: 2,
                    file_offset: 0,
                    rva: 0,
                },
            }],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            file_size: 0,
        };
        let sym = Symbolizer::load(&dump, Path::new("/nonexistent/path")).unwrap();
        assert_eq!(sym.module_count(), 0);
    }

    #[test]
    fn loaded_modules_iterator() {
        let dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            file_size: 0,
        };
        let tmp = std::env::temp_dir();
        let sym = Symbolizer::load(&dump, &tmp).unwrap();
        let names: Vec<&str> = sym.loaded_modules().collect();
        assert!(names.is_empty());
    }

    #[test]
    fn pdb_not_found_is_ok_skips_module() {
        let dump = Dump {
            system_info: None,
            modules: vec![Module {
                name: "nonexistent.dll".into(),
                base_va: 0x1000,
                size: 0x1000,
                checksum: 0,
                codeview_guid: Some([0xBB; 16]),
                pdb_name: Some("nonexistent.pdb".into()),
                provenance: Provenance {
                    stream_type: 2,
                    file_offset: 0,
                    rva: 0,
                },
            }],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            file_size: 0,
        };
        let tmp = std::env::temp_dir();
        let sym = Symbolizer::load(&dump, &tmp).unwrap();
        assert_eq!(sym.module_count(), 0);
    }

    #[test]
    fn integrate_real_dump_and_pdb() {
        let dump_path = "D:/Desktop/Workspaces/crash_renderer/20260625/ed633e36-d254-43d4-b30a-23396ebbf6a2.dmp";
        let pdb_dir = "D:/Desktop/Workspaces/crash_renderer/20260625";

        if !Path::new(dump_path).exists() {
            eprintln!("SKIP: dump file not found at {dump_path}");
            return;
        }

        let dump = crate::parse::dump::open(dump_path).expect("failed to parse dump");
        let sym = Symbolizer::load(&dump, Path::new(pdb_dir)).expect("failed to load symbolizer");

        eprintln!("Loaded {} modules with symbols", sym.module_count());
        for name in sym.loaded_modules() {
            eprintln!("  {name}");
        }

        if let Some(ref exc) = dump.exception {
            eprintln!(
                "Exception at 0x{:016X} (code 0x{:08X})",
                exc.address, exc.code
            );
            if let Some(resolved) = sym.resolve(exc.address) {
                eprintln!(
                    "  -> {}!{}+0x{:X}",
                    resolved.function_name,
                    resolved.function_name,
                    resolved.offset
                );
                if let (Some(file), Some(line)) =
                    (resolved.source_file.as_deref(), resolved.source_line)
                {
                    eprintln!("     at {file}:{line}");
                }
            } else {
                eprintln!("  -> (no symbol resolved)");
            }
        }

        if let Some(first_thread) = dump.threads.first() {
            let rip = first_thread.registers.rip();
            eprintln!("Thread TID {} RIP 0x{:016X}", first_thread.id, rip);
            if rip != 0 {
                if let Some(resolved) = sym.resolve(rip) {
                    eprintln!("  -> {}!{}+0x{:X}",
                        resolved.function_name,
                        resolved.function_name,
                        resolved.offset
                    );
                }
            }
        }
    }
}
