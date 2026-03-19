use flate2::read::GzDecoder;
use goblin::elf::{Elf, program_header::PT_LOAD, program_header::PT_NOTE};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write as IoWrite};
use std::process::{Command, Stdio};

// --- Binary helpers ---

fn u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn c_str(buf: &[u8], off: usize) -> String {
    let end = buf[off..]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(buf.len() - off);
    String::from_utf8_lossy(&buf[off..off + end]).into_owned()
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

// --- Segment attributes ---

pub const SEG_ATTR_R: u32 = 4;
pub const SEG_ATTR_RX: u32 = 5;
pub const SEG_ATTR_RW: u32 = 6;

// --- Coredump structures ---

pub struct ModuleSegment {
    pub num: usize,
    pub attr: u32,
    pub start: u32,
    pub size: u32,
    pub align: u32,
}

pub struct Module {
    pub uid: u32,
    pub name: String,
    pub segments: Vec<ModuleSegment>,
}

pub struct Thread {
    pub uid: u32,
    pub name: String,
    pub stop_reason: u32,
    pub status: u16,
    pub pc: u32,
    pub regs: Option<[u32; 16]>,
}

pub struct MemSegment {
    pub vaddr: u32,
    pub data: Vec<u8>,
}

pub struct Coredump {
    pub modules: Vec<Module>,
    pub threads: Vec<Thread>,
    pub mem_segments: Vec<MemSegment>,
}

// --- Stop reason / status strings ---

pub fn stop_reason_str(code: u32) -> &'static str {
    match code {
        0 => "No reason",
        0x30002 => "Undefined instruction exception",
        0x30003 => "Prefetch abort exception",
        0x30004 => "Data abort exception",
        0x60080 => "Division by zero",
        _ => "Unknown",
    }
}

pub fn seg_attr_str(attr: u32) -> &'static str {
    match attr {
        SEG_ATTR_R => "R",
        SEG_ATTR_RX => "RX",
        SEG_ATTR_RW => "RW",
        _ => "?",
    }
}

pub fn status_str(code: u16) -> &'static str {
    match code {
        1 => "Running",
        8 => "Waiting",
        16 => "Not started",
        _ => "Unknown",
    }
}

// --- ELF note parsing ---

fn parse_notes(data: &[u8]) -> HashMap<String, Vec<u8>> {
    const NOTE_HEADER_SIZE: usize = 12; // namesz + descsz + type

    let mut notes = HashMap::new();
    let mut off = 0;
    while off + NOTE_HEADER_SIZE <= data.len() {
        let namesz = u32_le(data, off) as usize;
        let descsz = u32_le(data, off + 4) as usize;
        // type at off+8 is unused — Vita notes are keyed by name string
        off += NOTE_HEADER_SIZE;

        if off + align4(namesz) > data.len() { break; }
        let name = if namesz > 0 { c_str(data, off) } else { String::new() };
        off += align4(namesz);

        if off + align4(descsz) > data.len() { break; }
        let desc = data[off..off + descsz].to_vec();
        off += align4(descsz);

        notes.insert(name, desc);
    }
    notes
}

// --- Coredump parsing ---

// Vita MODULE_INFO note layout
mod module_info {
    pub const HEADER_SIZE: usize = 8;    // version(4) + count(4)
    pub const ENTRY_SIZE: usize = 0x50;  // fixed module entry
    pub const UID_OFF: usize = 0x04;
    pub const NAME_OFF: usize = 0x24;
    pub const NUM_SEGS_OFF: usize = 0x4C;
    pub const FOOTER_SIZE: usize = 0x10; // post-segments padding

    pub const SEG_SIZE: usize = 0x14;    // per-segment entry
    pub const SEG_ATTR_OFF: usize = 0x04;
    pub const SEG_START_OFF: usize = 0x08;
    pub const SEG_SIZE_OFF: usize = 0x0C;
    pub const SEG_ALIGN_OFF: usize = 0x10;
}

// Vita THREAD_INFO note layout
mod thread_info {
    pub const HEADER_SIZE: usize = 8;
    pub const UID_OFF: usize = 4;
    pub const NAME_OFF: usize = 8;
    pub const STATUS_OFF: usize = 0x30;
    pub const STOP_REASON_OFF: usize = 0x74;
    pub const PC_OFF: usize = 0x9C;
}

// Vita THREAD_REG_INFO layout
mod reg_info {
    pub const HEADER_SIZE: usize = 8;
    pub const TID_OFF: usize = 4;
    pub const GPR_OFF: usize = 8;
    pub const NUM_GPR: usize = 16;
}

fn parse_modules(data: &[u8]) -> Vec<Module> {
    let mut modules = Vec::new();
    let num = u32_le(data, 4) as usize;
    let mut off = module_info::HEADER_SIZE;

    for _ in 0..num {
        if off + module_info::ENTRY_SIZE > data.len() { break; }
        let uid = u32_le(data, off + module_info::UID_OFF);
        let num_segs = u32_le(data, off + module_info::NUM_SEGS_OFF) as usize;
        let name = c_str(data, off + module_info::NAME_OFF);
        off += module_info::ENTRY_SIZE;

        let mut segments = Vec::new();
        for s in 0..num_segs {
            let seg_off = off + s * module_info::SEG_SIZE;
            segments.push(ModuleSegment {
                num: s + 1,
                attr: u32_le(data, seg_off + module_info::SEG_ATTR_OFF),
                start: u32_le(data, seg_off + module_info::SEG_START_OFF),
                size: u32_le(data, seg_off + module_info::SEG_SIZE_OFF),
                align: u32_le(data, seg_off + module_info::SEG_ALIGN_OFF),
            });
        }
        off += num_segs * module_info::SEG_SIZE;
        off += module_info::FOOTER_SIZE;

        modules.push(Module { uid, name, segments });
    }
    modules
}

fn parse_threads(thr_data: &[u8], reg_data: Option<&[u8]>) -> Vec<Thread> {
    let mut threads = Vec::new();
    let mut tid_index: HashMap<u32, usize> = HashMap::new();

    // Parse thread info
    let num = u32_le(thr_data, 4) as usize;
    let mut off = thread_info::HEADER_SIZE;
    for _ in 0..num {
        if off + 4 > thr_data.len() { break; }
        let sz = u32_le(thr_data, off) as usize;
        if sz == 0 || off + sz > thr_data.len() { break; }
        let block = &thr_data[off..off + sz];
        let uid = u32_le(block, thread_info::UID_OFF);
        let thread = Thread {
            uid,
            name: c_str(block, thread_info::NAME_OFF),
            stop_reason: u32_le(block, thread_info::STOP_REASON_OFF),
            status: u16_le(block, thread_info::STATUS_OFF),
            pc: u32_le(block, thread_info::PC_OFF),
            regs: None,
        };
        tid_index.insert(uid, threads.len());
        threads.push(thread);
        off += sz;
    }

    // Merge register data
    if let Some(reg_data) = reg_data {
        let num = u32_le(reg_data, 4) as usize;
        let mut off = reg_info::HEADER_SIZE;
        for _ in 0..num {
            if off + 4 > reg_data.len() { break; }
            let sz = u32_le(reg_data, off) as usize;
            if sz == 0 || off + sz > reg_data.len() { break; }
            let block = &reg_data[off..off + sz];
            let tid = u32_le(block, reg_info::TID_OFF);
            let mut gpr = [0u32; reg_info::NUM_GPR];
            for i in 0..reg_info::NUM_GPR {
                gpr[i] = u32_le(block, reg_info::GPR_OFF + 4 * i);
            }
            if let Some(&idx) = tid_index.get(&tid) {
                threads[idx].regs = Some(gpr);
            }
            off += sz;
        }
    }

    threads
}

pub fn parse_coredump(path: &str) -> Result<Coredump, String> {
    let raw = fs::read(path).map_err(|e| format!("Failed to read coredump: {}", e))?;

    // Try gzip decompression, fall back to raw bytes
    let data = {
        let mut decoder = GzDecoder::new(&raw[..]);
        let mut buf = Vec::new();
        if decoder.read_to_end(&mut buf).is_ok() && !buf.is_empty() {
            buf
        } else {
            raw
        }
    };

    let elf = Elf::parse(&data).map_err(|e| format!("Failed to parse coredump ELF: {}", e))?;

    let mut all_notes = HashMap::new();
    let mut mem_segments = Vec::new();

    for ph in &elf.program_headers {
        let start = ph.p_offset as usize;
        let end = (ph.p_offset + ph.p_filesz) as usize;
        if start > data.len() || end > data.len() { continue; }
        let seg_data = &data[start..end];

        match ph.p_type {
            PT_NOTE => all_notes.extend(parse_notes(seg_data)),
            PT_LOAD => mem_segments.push(MemSegment {
                vaddr: ph.p_vaddr as u32,
                data: seg_data.to_vec(),
            }),
            _ => {}
        }
    }

    let modules = all_notes
        .get("MODULE_INFO")
        .map(|d| parse_modules(d))
        .unwrap_or_default();

    let threads = all_notes.get("THREAD_INFO").map(|thr_data| {
        parse_threads(thr_data, all_notes.get("THREAD_REG_INFO").map(|v| v.as_slice()))
    }).unwrap_or_default();

    Ok(Coredump { modules, threads, mem_segments })
}

// --- Address resolution ---

pub struct ResolvedAddr {
    pub symbol: String,
    pub vaddr: u32,
    pub module_name: Option<String>,
    pub segment_num: Option<usize>,
    pub segment_attr: Option<u32>,
    pub offset: Option<u32>,
}

impl ResolvedAddr {
    pub fn is_located(&self) -> bool {
        self.module_name.is_some()
    }

    /// Returns true if this address is in an executable (RX) segment
    pub fn is_executable(&self) -> bool {
        self.segment_attr == Some(SEG_ATTR_RX)
    }

    /// Returns true if this address is in the user's app ELF code segment
    /// (i.e. we can meaningfully disassemble it with the provided ELF binary).
    /// System modules (SceGxm, SceLibKernel, etc.) are NOT disassemblable.
    pub fn is_in_app_code(&self) -> bool {
        self.module_name.as_deref().map_or(false, |n| n.ends_with(".elf"))
            && self.segment_num == Some(1)
            && self.is_executable()
    }

    /// Format the location part: "module@seg(attr) + 0x offset"
    fn format_location(&self) -> Option<String> {
        let (mod_name, seg, off) = match (&self.module_name, self.segment_num, self.offset) {
            (Some(m), Some(s), Some(o)) => (m, s, o),
            _ => return None,
        };
        let attr_str = self.segment_attr
            .map(|a| format!("({})", seg_attr_str(a)))
            .unwrap_or_default();
        Some(format!("{}@{}{} + 0x{:x}", mod_name, seg, attr_str, off))
    }

    pub fn format(&self, elf_info: Option<&mut ElfInfo>) -> String {
        if let Some(loc) = self.format_location() {
            let mut s = format!("{}: 0x{:x} ({}", self.symbol, self.vaddr, loc);
            if let (Some(info), Some(off)) = (elf_info, self.offset) {
                if self.module_name.as_deref().map_or(false, |n| n.ends_with(".elf"))
                    && self.segment_num == Some(1)
                {
                    if let Some(sym) = info.addr2line(off) {
                        s += &format!(" => {}", sym);
                    }
                }
            }
            s += ")";
            s
        } else {
            format!("{}: 0x{:x}", self.symbol, self.vaddr)
        }
    }

    pub fn format_plain(&self) -> String {
        self.format_location().unwrap_or_default()
    }
}

pub fn resolve_addr(modules: &[Module], symbol: &str, vaddr: u32) -> ResolvedAddr {
    for module in modules {
        for seg in &module.segments {
            if vaddr >= seg.start && vaddr < seg.start + seg.size {
                return ResolvedAddr {
                    symbol: symbol.to_string(),
                    vaddr,
                    module_name: Some(module.name.clone()),
                    segment_num: Some(seg.num),
                    segment_attr: Some(seg.attr),
                    offset: Some(vaddr - seg.start),
                };
            }
        }
    }
    ResolvedAddr {
        symbol: symbol.to_string(),
        vaddr,
        module_name: None,
        segment_num: None,
        segment_attr: None,
        offset: None,
    }
}

pub fn read_vaddr(mem: &[MemSegment], addr: u32, size: usize) -> Option<Vec<u8>> {
    for seg in mem {
        if addr >= seg.vaddr && (addr as usize) < seg.vaddr as usize + seg.data.len() {
            let off = (addr - seg.vaddr) as usize;
            if off + size <= seg.data.len() {
                return Some(seg.data[off..off + size].to_vec());
            }
        }
    }
    None
}

// --- ELF info (app binary) ---

pub struct DisasmLine {
    pub text: String,
    pub is_crash: bool,
}

const DISASM_WINDOW: u64 = 0x10; // bytes before/after crash address to disassemble

pub struct ElfInfo {
    filename: String,
    pub rx_vaddr: u64,
    vitasdk_prefix: String,
    addr2line_proc: Option<(std::process::ChildStdin, BufReader<std::process::ChildStdout>)>,
}

impl ElfInfo {
    pub fn new(filename: &str) -> Result<Self, String> {
        let data = fs::read(filename).map_err(|e| format!("Failed to read ELF: {}", e))?;
        let elf = Elf::parse(&data).map_err(|e| format!("Failed to parse ELF: {}", e))?;

        // Find the RX (code) segment's virtual address
        let rx_vaddr = elf.program_headers.iter()
            .filter(|ph| ph.p_type == PT_LOAD && ph.p_flags == SEG_ATTR_RX)
            .map(|ph| ph.p_vaddr)
            .last()
            .unwrap_or(0);

        let vitasdk_prefix = std::env::var("VITASDK")
            .map(|v| format!("{}/bin/", v))
            .unwrap_or_default();

        let tool = format!("{}arm-vita-eabi-addr2line", vitasdk_prefix);
        let addr2line_proc = Command::new(&tool)
            .args(["-e", filename, "-f", "-p", "-C"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()
            .map(|mut child| {
                let stdin = child.stdin.take().unwrap();
                let stdout = BufReader::new(child.stdout.take().unwrap());
                (stdin, stdout)
            });

        Ok(ElfInfo {
            filename: filename.to_string(),
            rx_vaddr,
            vitasdk_prefix,
            addr2line_proc,
        })
    }

    pub fn addr2line(&mut self, offset: u32) -> Option<String> {
        let addr = offset as u64 + self.rx_vaddr;
        let (stdin, stdout) = self.addr2line_proc.as_mut()?;
        writeln!(stdin, "0x{:x}", addr).ok()?;
        stdin.flush().ok()?;
        let mut line = String::new();
        stdout.read_line(&mut line).ok()?;
        let s = line.trim().to_string();
        // addr2line returns "?? ??:0" for unknown addresses
        if s.is_empty() || (s.contains("??") && s.contains(":0")) {
            None
        } else {
            Some(s)
        }
    }

    pub fn disas_around(&self, offset: u32) -> Option<Vec<DisasmLine>> {
        let is_thumb = offset & 1 != 0;
        let clean_offset = offset & !1;
        let addr = clean_offset as u64 + self.rx_vaddr;
        let start = addr.saturating_sub(DISASM_WINDOW);
        let end = addr + DISASM_WINDOW;

        let tool = format!("{}arm-vita-eabi-objdump", self.vitasdk_prefix);
        let mut args = vec![
            "-d".to_string(),
            "-S".to_string(),
            format!("--start-address=0x{:x}", start),
            format!("--stop-address=0x{:x}", end),
            self.filename.clone(),
        ];
        if is_thumb {
            args.push("-Mforce-thumb".to_string());
        }

        let output = Command::new(&tool)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .ok()?;

        let text = String::from_utf8_lossy(&output.stdout);
        let crash_marker = format!("{:x}:", addr);
        let lines: Vec<DisasmLine> = text
            .lines()
            .skip_while(|l| !l.contains("Disassembly of section"))
            .skip(1) // skip the "Disassembly of section" line itself
            .filter(|l| !l.trim().is_empty())
            .map(|l| DisasmLine {
                is_crash: l.contains(&crash_marker),
                text: l.to_string(),
            })
            .collect();

        if lines.is_empty() { None } else { Some(lines) }
    }
}

// --- Register names ---

const REG_NAMES: [&str; 16] = [
    "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7",
    "R8", "R9", "R10", "R11", "R12", "SP", "LR", "PC",
];

pub fn reg_name(i: usize) -> &'static str {
    REG_NAMES.get(i).copied().unwrap_or("R?")
}

// --- Symbol cleanup ---

/// Strip crate disambiguation hashes like `crate_name[51fcb18d1cbbb693]`
fn strip_crate_hashes(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '[' {
            let mut hash = String::new();
            while hash.len() < 16 {
                match chars.peek() {
                    Some(&ch) if ch.is_ascii_hexdigit() => {
                        hash.push(ch);
                        chars.next();
                    }
                    _ => break,
                }
            }
            if hash.len() >= 8 && chars.peek() == Some(&']') {
                chars.next(); // strip the hash
            } else {
                result.push('[');
                result.push_str(&hash);
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Shorten absolute file paths to crate-relative paths
fn shorten_file_path(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }

    const RUSTLIB_MARKER: &str = "/lib/rustlib/src/rust/library/";
    if let Some(pos) = path.find(RUSTLIB_MARKER) {
        return path[pos + RUSTLIB_MARKER.len()..].to_string();
    }

    const REGISTRY_MARKER: &str = "/registry/src/";
    if let Some(pos) = path.find(REGISTRY_MARKER) {
        let after = &path[pos + REGISTRY_MARKER.len()..];
        if let Some(slash) = after.find('/') {
            let crate_and_rest = &after[slash + 1..];
            if let Some(crate_slash) = crate_and_rest.find('/') {
                let crate_dir = &crate_and_rest[..crate_slash];
                let rest = &crate_and_rest[crate_slash..];
                if let Some(ver_dash) = crate_dir.rfind('-') {
                    if crate_dir[ver_dash + 1..].starts_with(|c: char| c.is_ascii_digit()) {
                        return format!("{}{}", &crate_dir[..ver_dash], rest);
                    }
                }
                return crate_and_rest.to_string();
            }
        }
    }

    if let Ok(cwd) = std::env::current_dir() {
        if let Some(rest) = path.strip_prefix(&*cwd.to_string_lossy()) {
            return rest.strip_prefix('/').unwrap_or(rest).to_string();
        }
    }

    path.to_string()
}

/// Demangle a Rust/C++ symbol and clean up crate hashes
fn demangle_symbol(name: &str) -> String {
    strip_crate_hashes(&rustc_demangle::demangle(name).to_string())
}

/// Split addr2line output "func at file:line" into (func_name, file_location),
/// then demangle and shorten paths.
fn parse_addr2line_output(sym: &str) -> (String, String) {
    let (func, file) = if let Some(at_pos) = sym.find(" at ") {
        (sym[..at_pos].to_string(), sym[at_pos + 4..].to_string())
    } else {
        (sym.to_string(), String::new())
    };
    (demangle_symbol(&func), shorten_file_path(&file))
}

// --- Analysis (pre-computed display data) ---

const STACK_TRACE_DEPTH: i32 = 64;
const STACK_MEM_BEFORE: i32 = 16;
const STACK_MEM_AFTER: i32 = 24;

pub struct ThreadDisplay {
    pub name: String,
    pub uid: u32,
    pub stop_reason_code: u32,
    pub stop_reason: String,
    pub status_code: u16,
    pub status: String,
    pub pc_display: String,
    pub lr_display: Option<String>,
    pub crashed: bool,
    pub crash: Option<CrashDisplay>,
}

pub struct RegisterDisplay {
    pub name: &'static str,
    pub value: String,
    pub resolved: Option<String>,
}

pub struct DisasmBlock {
    pub header: String,
    pub lines: Vec<DisasmLine>,
}

pub struct StackTraceLine {
    pub func_name: String,
    pub file_loc: String,
    pub module: String,
    pub addr: String,
    pub is_crash: bool,
}

pub struct StackLine {
    pub text: String,
    pub resolved: Option<String>,
    pub is_sp: bool,
}

pub struct CrashDisplay {
    pub stack_trace: Vec<StackTraceLine>,
    pub registers: Vec<RegisterDisplay>,
    pub pc_disasm: Option<DisasmBlock>,
    pub lr_disasm: Option<DisasmBlock>,
    pub stack: Vec<StackLine>,
}

pub struct AnalysisResult {
    pub dump_name: String,
    pub elf_name: String,
    pub threads: Vec<ThreadDisplay>,
}

impl AnalysisResult {
    pub fn format_thread_text(&self, thread_idx: usize) -> String {
        let thread = &self.threads[thread_idx];
        let mut s = String::new();

        s.push_str(&format!("=== THREAD \"{}\" <0x{:x}> ===\n", thread.name, thread.uid));
        s.push_str(&format!("Stop reason: 0x{:x} ({})\n", thread.stop_reason_code, thread.stop_reason));
        s.push_str(&format!("Status: 0x{:x} ({})\n", thread.status_code, thread.status));
        s.push_str(&format!("{}\n", thread.pc_display));
        if let Some(ref lr) = thread.lr_display {
            s.push_str(&format!("{}\n", lr));
        }

        let Some(ref crash) = thread.crash else { return s };

        if !crash.stack_trace.is_empty() {
            s.push_str("\nStack Trace:\n");
            for (i, entry) in crash.stack_trace.iter().enumerate() {
                let prefix = if entry.is_crash { ">>>" } else { "   " };
                s.push_str(&format!("{} #{:<2} {}\n", prefix, i, entry.func_name));
                if !entry.file_loc.is_empty() {
                    s.push_str(&format!("        at {}\n", entry.file_loc));
                }
                s.push_str(&format!("        in {} [{}]\n", entry.module, entry.addr));
            }
        }

        s.push_str("\nRegisters:\n");
        for reg in &crash.registers {
            if let Some(ref resolved) = reg.resolved {
                s.push_str(&format!("    {:<4} {} ({})\n", reg.name, reg.value, resolved));
            } else {
                s.push_str(&format!("    {:<4} {}\n", reg.name, reg.value));
            }
        }

        fn fmt_disasm(s: &mut String, block: &DisasmBlock) {
            s.push_str(&format!("\nDisassembly around {}:\n", block.header));
            for line in &block.lines {
                let prefix = if line.is_crash { ">>> " } else { "    " };
                s.push_str(&format!("{}{}\n", prefix, line.text));
            }
        }
        if let Some(ref d) = crash.pc_disasm { fmt_disasm(&mut s, d); }
        if let Some(ref d) = crash.lr_disasm { fmt_disasm(&mut s, d); }

        s.push_str("\nStack Memory:\n");
        for entry in &crash.stack {
            let prefix = if entry.is_sp { "SP =>" } else { "     " };
            if let Some(ref resolved) = entry.resolved {
                s.push_str(&format!("{} {}  {}\n", prefix, entry.text, resolved));
            } else {
                s.push_str(&format!("{} {}\n", prefix, entry.text));
            }
        }

        s
    }
}

fn resolve_stack_trace_line(
    r: &ResolvedAddr,
    elf: &mut Option<ElfInfo>,
    require_rx: bool,
    is_crash: bool,
) -> Option<StackTraceLine> {
    let (mod_name, seg, attr, off) = match (&r.module_name, r.segment_num, r.segment_attr, r.offset) {
        (Some(m), Some(s), Some(a), Some(o)) => (m.clone(), s, a, o),
        _ => return None,
    };
    if require_rx && attr != SEG_ATTR_RX { return None; }

    let (mut func_name, file_loc) = elf.as_mut()
        .and_then(|info| {
            if mod_name.ends_with(".elf") && seg == 1 {
                info.addr2line(off).map(|sym| parse_addr2line_output(&sym))
            } else {
                None
            }
        })
        .unwrap_or_default();

    if func_name.is_empty() {
        func_name = format!("{}+0x{:x}", mod_name, off);
    }

    Some(StackTraceLine {
        func_name,
        file_loc,
        module: format!("{}@{}", mod_name, seg),
        addr: format!("0x{:08x}", r.vaddr),
        is_crash,
    })
}

fn build_disasm_block(
    label: &str,
    addr: u32,
    resolved: &ResolvedAddr,
    elf: &Option<ElfInfo>,
) -> Option<DisasmBlock> {
    if !resolved.is_in_app_code() { return None; }
    let off = resolved.offset?;
    let state = if off & 1 == 0 { "ARM" } else { "Thumb" };
    let display_addr = addr & !1;
    elf.as_ref()
        .and_then(|e| e.disas_around(off))
        .map(|lines| DisasmBlock {
            header: format!("{}: 0x{:x} ({})", label, display_addr, state),
            lines,
        })
}

fn build_crash_display(
    thread: &Thread,
    regs: &[u32; 16],
    core: &Coredump,
    elf: &mut Option<ElfInfo>,
) -> CrashDisplay {
    let pc = resolve_addr(&core.modules, "PC", thread.pc);
    let lr = resolve_addr(&core.modules, "LR", regs[14]);

    let mut registers: Vec<RegisterDisplay> = (0..13)
        .map(|i| {
            let r = resolve_addr(&core.modules, "", regs[i]);
            RegisterDisplay {
                name: reg_name(i),
                value: format!("0x{:x}", regs[i]),
                resolved: if r.is_located() { Some(r.format_plain()) } else { None },
            }
        })
        .collect();
    registers.push(RegisterDisplay { name: "SP", value: format!("0x{:x}", regs[13]), resolved: None });
    registers.push(RegisterDisplay { name: "PC", value: format!("0x{:x}", thread.pc), resolved: Some(pc.format_plain()) });
    registers.push(RegisterDisplay { name: "LR", value: format!("0x{:x}", regs[14]), resolved: Some(lr.format_plain()) });

    let pc_disasm = build_disasm_block("PC", thread.pc, &pc, elf);
    let lr_disasm = build_disasm_block("LR", regs[14], &lr, elf);

    let mut stack_trace = Vec::new();
    let mut seen = HashSet::new();
    seen.insert(thread.pc);
    seen.insert(regs[14]);

    if let Some(line) = resolve_stack_trace_line(&pc, elf, false, true) {
        stack_trace.push(line);
    }
    if let Some(line) = resolve_stack_trace_line(&lr, elf, false, false) {
        stack_trace.push(line);
    }

    let sp = regs[13];
    for x in 0..STACK_TRACE_DEPTH {
        let addr = (sp as i64 + 4 * x as i64) as u32;
        if let Some(data) = read_vaddr(&core.mem_segments, addr, 4) {
            let val = u32_le(&data, 0);
            if seen.contains(&val) { continue; }
            let r = resolve_addr(&core.modules, "", val);
            if let Some(line) = resolve_stack_trace_line(&r, elf, true, false) {
                seen.insert(val);
                stack_trace.push(line);
            }
        }
    }

    let mut stack = Vec::new();
    for x in -STACK_MEM_BEFORE..STACK_MEM_AFTER {
        let addr = (sp as i64 + 4 * x as i64) as u32;
        if let Some(data) = read_vaddr(&core.mem_segments, addr, 4) {
            let val = u32_le(&data, 0);
            let r = resolve_addr(&core.modules, "", val);
            stack.push(StackLine {
                text: format!("0x{:08x}:  0x{:08x}", addr, val),
                resolved: if r.is_located() { Some(r.format(elf.as_mut())) } else { None },
                is_sp: addr == sp,
            });
        }
    }

    CrashDisplay { stack_trace, registers, pc_disasm, lr_disasm, stack }
}

pub fn run_analysis(dump_path: &str, elf_path: &str) -> Result<AnalysisResult, String> {
    let core = parse_coredump(dump_path)?;
    let mut elf = if !elf_path.is_empty() {
        ElfInfo::new(elf_path).ok()
    } else {
        None
    };

    let dump_name = std::path::Path::new(dump_path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| dump_path.to_string());
    let elf_name = if elf_path.is_empty() {
        "no ELF".to_string()
    } else {
        std::path::Path::new(elf_path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| elf_path.to_string())
    };

    let threads: Vec<ThreadDisplay> = core.threads.iter().map(|thread| {
        let crashed = thread.stop_reason != 0;
        let pc = resolve_addr(&core.modules, "PC", thread.pc);
        let pc_display = pc.format(elf.as_mut());
        let lr_display = if !pc.is_located() {
            thread.regs.as_ref().map(|regs| {
                resolve_addr(&core.modules, "LR", regs[14]).format(elf.as_mut())
            })
        } else {
            None
        };
        let crash = if crashed {
            thread.regs.as_ref().map(|regs| build_crash_display(thread, regs, &core, &mut elf))
        } else {
            None
        };
        ThreadDisplay {
            name: thread.name.clone(),
            uid: thread.uid,
            stop_reason_code: thread.stop_reason,
            stop_reason: stop_reason_str(thread.stop_reason).to_string(),
            status_code: thread.status,
            status: status_str(thread.status).to_string(),
            pc_display,
            lr_display,
            crashed,
            crash,
        }
    }).collect();

    Ok(AnalysisResult { dump_name, elf_name, threads })
}
