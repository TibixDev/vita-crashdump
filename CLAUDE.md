# vita-crashdump

PS Vita crashdump analyzer — CLI + GUI.

## Project structure

```
tools/crashdump/
├── src/
│   ├── lib.rs     # Core: coredump parsing, ARM unwinder, address resolution, analysis, text output
│   ├── cli.rs     # CLI binary (trivial — calls run_analysis + format_thread_text)
│   └── gui.rs     # GUI binary (egui + egui-phosphor)
├── Cargo.toml     # gui feature gates eframe/rfd/egui-phosphor
├── .github/workflows/release.yml
└── README.md
```

## Architecture

All analysis logic lives in `lib.rs`. Both `cli.rs` and `gui.rs` call `run_analysis()` which returns an `AnalysisResult` containing pre-computed display data. `format_thread_text()` produces the plain-text output used by both the CLI and the GUI's "Copy to clipboard" button.

The GUI (`gui.rs`) is purely rendering — no analysis logic.

## Key concepts

- **Coredump format**: Vita `.psp2dmp` files are gzip-compressed ELFs containing PT_NOTE segments with structured data (MODULE_INFO, THREAD_INFO, THREAD_REG_INFO, STACK_INFO, TTY_INFO). Each note has a name string and binary payload with fixed-offset fields.

- **Address resolution**: Runtime addresses from the dump are matched against module segment ranges (from MODULE_INFO) to determine which module + segment + offset they belong to.

- **ARM unwinding**: The app ELF's `.ARM.exidx` table maps PC ranges to unwind instructions. We decode these to walk the stack frame-by-frame. Runtime addresses must be translated to ELF addresses (via a relocation offset computed from the module's segment base vs the ELF's RX vaddr) before exidx lookup. Returned LR values from the stack are runtime addresses and must be translated back.

- **Heuristic fallback**: When unwind tables aren't available (no ELF, or PC in a system module with no exidx), we scan the stack for values pointing into RX segments.

- **System module handling**: When PC is outside the app ELF (e.g. SceGxm, SceLibKernel), we can't unwind from PC (no exidx). Instead we start unwinding from LR (which points back into app code) and prepend the system module PC as frame 0. Disassembly is also skipped for system modules since we don't have their binaries.

## Building

```sh
# CLI only
cargo build --release

# CLI + GUI
cargo build --release --features gui

# Run tests against sample dumps
cargo run --release -- dmp/sample_crash/sample_crash.psp2dmp dmp/sample_crash/aquacord.elf
```

VitaSDK tools (`arm-vita-eabi-addr2line`, `arm-vita-eabi-objdump`) must be on PATH or `VITASDK` env var set. Run inside `distrobox-enter fedora` on Bazzite.

## Test dumps

- `dmp/sample_crash/` — clean null deref crash with known call chain (crashdump_test_inner -> middle -> outer -> run). Perfect for validating the unwinder.
- `dmp/sample_crash_sdl/` — crash inside SDL_RenderCopy (corrupted texture). Tests app-code crash with stale stack frames.
- `dmp/sample_crash_dead0000/` — prefetch abort at unmapped address 0xDEAD0000. Tests LR-fallback unwinding when PC is outside all modules.

## Coredump note layouts

Struct offsets are defined as named constants in `lib.rs`:
- `mod module_info` — MODULE_INFO note (0x50-byte entries + 0x14-byte segments)
- `mod thread_info` — THREAD_INFO note (variable-size entries, key offsets: uid@0x04, name@0x08, status@0x30, stop_reason@0x74, pc@0x9C)
- `mod reg_info` — THREAD_REG_INFO note (0x178-byte entries: 16 GPRs + CPSR + NEON + fault registers IFSR/IFAR/DFSR/DFAR)

Reference implementations: [vita-parse-core](https://github.com/xyzz/vita-parse-core) (Python), [vcp](https://github.com/isage/vcp) (C++).

## GUI notes

- Uses egui 0.33 + eframe 0.33 + egui-phosphor 0.11 (Phosphor icons)
- All colors defined as `COLOR_*` constants at the top of `gui.rs`
- Layout constants: `SIDEBAR_WIDTH`, `DROP_ZONE_*`, `WINDOW_SIZE`, `BTN_MIN_SIZE`
- Start screen: two equal file cards (dump + ELF) side by side with hover effects
- Analysis screen: sidebar thread list with custom-painted cards, detail panel with collapsible sections
- `code_frame()` helper wraps content in a dark code block with horizontal scroll
