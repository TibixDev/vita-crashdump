# vita-crashdump

PS Vita crashdump (`.psp2dmp`) analyzer. Parses coredump ELF files produced by the Vita on crash, resolves addresses to modules/symbols, reconstructs stack traces, and disassembles around the crash site.

Both a CLI tool and a GUI (egui) are included. They produce identical analysis output.

## Features

- Parses MODULE_INFO, THREAD_INFO, and THREAD_REG_INFO notes from Vita coredumps
- Handles both gzip-compressed and raw `.psp2dmp` files
- Resolves addresses to module + segment + offset (e.g. `SceGxm@1(RX) + 0xaa2c`)
- Symbol resolution via `arm-vita-eabi-addr2line` (persistent subprocess, demangled)
- Disassembly around crash PC/LR via `arm-vita-eabi-objdump` (ARM + Thumb)
- Only disassembles app code — skips system modules (SceGxm, SceLibKernel, etc.) where we don't have the binary
- Reconstructs a stack trace by scanning the stack for return addresses in executable segments
- Rust symbol demangling with crate hash cleanup (`serde_json[51fcb18d1cbbb693]` -> `serde_json`)
- File path shortening (strips toolchain/registry prefixes)
- GUI: drag & drop, auto ELF detection, copy-to-clipboard for sharing with others or LLMs

## Usage

### CLI

```sh
vita-crashdump <corefile.psp2dmp> <app.elf>
```

Output looks like:

```
=== THREAD "AQCD00001" <0x40010003> ===
Stop reason: 0x30004 (Data abort exception)
Status: 0x1 (Running)
PC: 0xe008efbc (SceGxm@1(RX) + 0xaa2c)

Stack Trace:
>>> #0  SceGxm+0xaa2c
        in SceGxm@1 [0xe008efbc]
    #1  af_glyph_hints_align_weak_points
        at autofit.c.obj:?
        in aquacord.elf@1 [0x81252607]
    #2  <alloc::vec::into_iter::IntoIter<aquacord::markdown::Line> as core::iter::traits::iterator::Iterator>::size_hint
        at alloc/src/vec/into_iter.rs:240
        in aquacord.elf@1 [0x8107280f]

Registers:
    R0   0x0
    R1   0x818035a0 (aquacord.elf@2(RW) + 0x35a0)
    ...
    PC   0xe008efbc (SceGxm@1(RX) + 0xaa2c)
    LR   0x81252607 (aquacord.elf@1(RX) + 0x200607)

Disassembly around LR: 0x81252606 (Thumb):
    812005fc:   69e3        ldr   r3, [r4, #28]
    812005fe:   3428        adds  r4, #40
>>> 81200604:   f844 3c10   str.w r3, [r4, #-16]
    81200608:   d2f8        bcs.n 812005fc
    ...

Stack Memory:
      0x817bda30:  0x00000000
SP => 0x817bda70:  0x00000000
      0x817bdaac:  0x8124d039  : 0x8124d039 (aquacord.elf@1(RX) + 0x1fb039 => T1_Get_Var_Design at type1.c.obj:?)
      ...
```

### GUI

```sh
# Build with GUI support
cargo build --release --features gui --bin vita-crashdump-gui

# Run (optionally pass a dump file to pre-load)
vita-crashdump-gui [corefile.psp2dmp]
```

The GUI auto-detects your ELF from `target/armv7-sony-vita-newlibeabihf/{debug,release}/`. The "Copy to clipboard" button exports the same text format as the CLI.

## Building

Requires VitaSDK tools on PATH (or `VITASDK` env var set) for symbol resolution and disassembly:
- `arm-vita-eabi-addr2line`
- `arm-vita-eabi-objdump`

Without these, the tool still works but won't resolve symbols or show disassembly.

```sh
# CLI only
cargo build --release

# CLI + GUI
cargo build --release --features gui
```

## How the stack trace works

Vita crashdumps don't include a proper backtrace. The tool reconstructs one heuristically:

1. **PC** — where the crash happened
2. **LR** — the return address (who called the function that crashed)
3. **Stack scan** — walks stack memory looking for values that point into executable (RX) segments of loaded modules, deduplicating against PC/LR

This is imperfect — some entries may be stale return addresses from earlier calls, not the actual call chain. But in practice it gives a useful picture of what was happening.

## Based on

Originally based on [vita-parse-core](https://github.com/xyzz/vita-parse-core) (Python), rewritten in Rust with additional features.
