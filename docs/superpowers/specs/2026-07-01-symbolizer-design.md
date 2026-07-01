# Symbolizer Module — Design Spec

## Status
Approved, pending implementation plan.

## Summary
Add a standalone `symbolizer/` module to forensicator-core that resolves virtual addresses to symbolic names — function name, source file, and line number — using local PDB files matched against `Module` entries from the minidump parse.

The Symbolizer is a **utility module**, not an `Analyzer`. It is consumed by the CLI and by other analyzers that benefit from symbolic annotation.

## Motivation
The `Module` struct already captures `codeview_guid` and `pdb_name` from the minidump's module list stream. This data is unused beyond storage. Resolving addresses to symbols enables:
- Human-readable crash analysis (exception address → `ntdll!RtlUserThreadStart+0x14`)
- Annotated output from existing analyzers (vtable method pointers get function names)
- Foundation for future analyzers (call stack reconstruction, hotspot profiling)

## Architecture

```
S1: Dump.modules (GUID, pdb_name, base_va, size)
          │
          ▼
Symbolizer::load(dump, "/path/to/pdbs")
          │
          ├── Match each Module by GUID + name → find matching .pdb file
          ├── Parse PDB (via `pdb` crate) → extract public symbols + line info
          ├── Build SymbolTable per module (sorted Vec<SymbolEntry> by VA)
          │
          ▼
  Symbolizer ready
          │
          ▼
Symbolizer::resolve(va) → Option<ResolvedSymbol>
          │
          ├── Binary search → which module contains VA
          ├── Binary search symbol table → nearest function ≤ VA
          └── Return { function_name, offset, source_file, source_line }
```

### Module layout

```
forensicator-core/src/symbolizer/
├── mod.rs      # Symbolizer, SymbolTable, SymbolEntry, ResolvedSymbol,
│               # load(), resolve(), module_count()
└── error.rs    # SymbolizerError enum
```

## Core Types

### Symbolizer

```rust
pub struct Symbolizer {
    tables: Vec<ModuleSymbols>,   // one per loaded module
}

struct ModuleSymbols {
    module_name: String,
    base_va: u64,
    size: u64,
    symbols: Vec<SymbolEntry>,    // sorted by VA ascending
}
```

### SymbolEntry

```rust
pub struct SymbolEntry {
    pub va: u64,
    pub function_name: String,
    pub source_file: Option<String>,
    pub source_line: Option<u32>,
}
```

### ResolvedSymbol

```rust
pub struct ResolvedSymbol {
    pub function_name: String,
    pub offset: u64,                        // bytes from function entry
    pub source_file: Option<String>,
    pub source_line: Option<u32>,
}
```

### Public API

```rust
impl Symbolizer {
    /// Load PDB files from a directory, matching against Dump modules.
    /// Each module's codeview_guid and pdb_name are used to find the
    /// corresponding .pdb file. Modules without a matching PDB are skipped
    /// (recorded as errors but do not block loading of other modules).
    pub fn load(dump: &Dump, pdb_dir: &Path) -> Result<Self, SymbolizerError>;

    /// Resolve a VA to a symbol. Returns None if the VA falls outside
    /// all known loaded modules, or if the module has no symbol table.
    pub fn resolve(&self, va: u64) -> Option<ResolvedSymbol>;

    /// Number of modules that were successfully loaded with symbols.
    pub fn module_count(&self) -> usize;

    /// Iterator over successfully loaded module names.
    pub fn loaded_modules(&self) -> impl Iterator<Item = &str>;
}
```

## PDB Matching

The minidump records for each module:
- `codeview_guid` — a 16-byte GUID from the CodeView debug directory
- `pdb_name` — the PDB filename as embedded in the binary (e.g., `ntdll.pdb`)

The `pdb` crate exposes `pdb.module_info()` which returns the GUID and age from the PDB header. Matching algorithm:

```
For each Module in dump.modules:
    If module.codeview_guid is None → skip
    expected_name = module.pdb_name (e.g., "ntdll.pdb")
    expected_guid = module.codeview_guid

    For each file in pdb_dir matching "*.pdb":
        pdb = PDB::open(file)
        pdb_info = pdb.module_info()?
        actual_guid = pdb_info.guid

        If actual_guid == expected_guid:
            Load symbols from this PDB → build ModuleSymbols
            Break
    If no match found:
        Skip silently (no error — user may not have all PDBs)
```

## PDB Parsing (via `pdb` crate)

The `pdb` crate (`pdb = "0.8"`) provides access to:

| PDB stream | Rust API | What we extract |
|-----------|----------|-----------------|
| PDB header / DBI | `pdb.module_info()` | GUID, age (for matching) |
| Public symbols | `pdb.public_symbols()` | (section, offset, name) for each public function |
| Global symbols | `pdb.global_symbols()` | Function entries with section + offset |
| Section map | `pdb.sections()` | Section VA ranges (translate section:offset → VA) |
| String table | `pdb.string_table()` | Raw name bytes → UTF-8 strings |
| Line program | `pdb.line_program()` | Address → (source_file_id, line_number) |
| Source files | `pdb.source_files()` | File ID → path string |

Building a symbol table from the PDB:

1. Read section contributions → map section:offset pairs to VAs
2. Iterate public symbols → record each function's VA + name
3. For line info: query line program at each function VA → source file + line
4. Sort entries by VA for binary-search lookup

## Error Handling

```rust
pub enum SymbolizerError {
    /// Failed to read a file or directory.
    Io(std::io::Error),
    /// PDB file is malformed, truncated, or unsupported version.
    PdbParse(String),
    /// A PDB file was found but contains no public symbol stream.
    NoSymbols(String),
}

impl fmt::Display for SymbolizerError { ... }
impl std::error::Error for SymbolizerError { ... }
```

`Symbolizer::load()` accumulates per-module errors and continues loading other modules. A single bad PDB does not prevent other modules from being resolved.

## CLI Integration

```
forensicator inspect <dump.dmp> --symbols /path/to/pdbs
```

With `--symbols`, exception address and thread RIPs are annotated:

```
Exception: code 0xC0000005 at 0x7FFA12345678 (ntdll!RtlUserThreadStart+0x14) (thread 1234)
Threads:
  ├── TID 1234  stack @ 0x...  RIP 0x7FFA12345678 (ntdll!RtlUserThreadStart+0x14)
```

`forensicator analyze` could also annotate its output with resolved names when `--symbols` is provided.

## TLA+ Specification (`specs/Symbolizer.tla`)

### State variables

```
VARIABLES
    sym_loaded,      \* set of module names with loaded symbol tables
    sym_base,        \* function: name → base_va
    sym_size,        \* function: name → size
    sym_entries,     \* function: name → Seq of <<va, name_hash, file_hash, line>>
    sym_anomalies    \* loading errors
```

### Actions

- **LoadPdb(module_name, guid_matches)** — Verify GUID match, parse public symbols, build sorted symbol table. Sets `sym_loaded` to include `module_name`.
- **ResolveAddress(va)** — Binary search: find module containing VA, then binary search symbol table for nearest function ≤ VA. Returns (function_name, offset, file, line) or `None`.
- **ResolveAddressError(va)** — VA not in any loaded module → records an anomaly.

### Invariants

```
SymbolizerInvariant ==
    /\ \A name \in sym_loaded:
         \A i \in 1..Len(sym_entries[name])-1:
           sym_entries[name][i][1] <= sym_entries[name][i+1][1]
         \* All symbol tables are sorted by VA
    /\ sym_loaded \subseteq { M!module_names }
         \* Every loaded module corresponds to a dump module
```

### Composition into Forensicator.tla

```
S == INSTANCE Symbolizer

ForensicatorInvariant ==
    /\ M!ModelInvariant
    /\ A!TypeInvariant
    /\ R!ArchInvariant
    /\ S!SymbolizerInvariant
    /\ S1ParseSequence
    /\ S2PipelineInvariant
    /\ CatalogInvariant
```

## Dependencies

Add to `forensicator-core/Cargo.toml`:

```toml
[dependencies]
pdb = "0.8"
```

No new dev-dependencies. The `pdb` crate is pure Rust (no C++ build requirements).

## Testing Strategy

- Unit tests with synthetic PDB files (create minimal valid PDBs in test data)
- Unit tests for module matching logic (GUID comparison, name matching)
- Unit tests for VA resolution (in-bounds, out-of-bounds, edge cases)
- Unit tests for error cases (missing PDB, malformed PDB, no public symbols)
- Integration: `Forensicator::open(dump)` → `Symbolizer::load(&dump, test_pdb_dir)` → `resolve(rip_va)`

## Open Questions

None — all design decisions captured above.
