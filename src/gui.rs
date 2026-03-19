use eframe::egui;
use vita_crashdump::*;

// --- Theme colors ---

const COLOR_RED: egui::Color32 = egui::Color32::from_rgb(255, 80, 80);
const COLOR_GREEN: egui::Color32 = egui::Color32::from_rgb(80, 200, 120);
const COLOR_YELLOW: egui::Color32 = egui::Color32::from_rgb(240, 200, 80);
const COLOR_CYAN: egui::Color32 = egui::Color32::from_rgb(80, 200, 220);
const COLOR_DIM: egui::Color32 = egui::Color32::from_rgb(140, 140, 140);
const COLOR_SUBTLE: egui::Color32 = egui::Color32::from_rgb(80, 80, 100);
const COLOR_TITLE: egui::Color32 = egui::Color32::from_rgb(220, 220, 235);
const COLOR_WIDGET_ACTIVE: egui::Color32 = egui::Color32::from_rgb(60, 45, 100);

const COLOR_BG_DARK: egui::Color32 = egui::Color32::from_rgb(18, 18, 26);
const COLOR_BG_CODE: egui::Color32 = egui::Color32::from_rgb(20, 20, 28);
const COLOR_BG_PANEL: egui::Color32 = egui::Color32::from_rgb(30, 30, 40);
const COLOR_BG_HOVER: egui::Color32 = egui::Color32::from_rgb(25, 30, 45);
const COLOR_BG_DROP: egui::Color32 = egui::Color32::from_rgb(22, 22, 32);
const COLOR_BG_CRASH: egui::Color32 = egui::Color32::from_rgb(60, 20, 20);

const COLOR_ACCENT: egui::Color32 = egui::Color32::from_rgb(100, 80, 160);
const COLOR_BTN: egui::Color32 = egui::Color32::from_rgb(70, 50, 130);
const COLOR_BORDER_LOADED: egui::Color32 = egui::Color32::from_rgb(60, 150, 90);
const COLOR_BORDER_EMPTY: egui::Color32 = egui::Color32::from_rgb(55, 55, 75);

// --- Layout constants ---

const SIDEBAR_WIDTH: f32 = 200.0;
const DROP_ZONE_MIN_W: f32 = 400.0;
const DROP_ZONE_MAX_W: f32 = 600.0;
const DROP_ZONE_RATIO: f32 = 0.6;
const DROP_ZONE_H_EMPTY: f32 = 140.0;
const DROP_ZONE_H_LOADED: f32 = 100.0;
const WINDOW_SIZE: [f32; 2] = [1100.0, 750.0];
const WINDOW_MIN: [f32; 2] = [800.0, 500.0];
const BTN_MIN_SIZE: egui::Vec2 = egui::vec2(200.0, 48.0);

// --- ELF auto-detection ---

const VITA_TARGET_DIR: &str = "target/armv7-sony-vita-newlibeabihf";
const BUILD_PROFILES: &[&str] = &["debug", "release"];

fn find_elf_for_dump(dump_path: &str) -> Option<String> {
    let start = if dump_path.is_empty() {
        std::env::current_dir().ok()?
    } else {
        std::path::Path::new(dump_path).parent()?.to_path_buf()
    };

    let mut dir = start.as_path();
    loop {
        let target_dir = dir.join(VITA_TARGET_DIR);
        if target_dir.is_dir() {
            for profile in BUILD_PROFILES {
                let profile_dir = target_dir.join(profile);
                if let Ok(entries) = std::fs::read_dir(&profile_dir) {
                    let best = entries
                        .flatten()
                        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("elf"))
                        .filter_map(|e| {
                            let mtime = e.metadata().ok()?.modified().ok()?;
                            Some((mtime, e.path()))
                        })
                        .max_by_key(|(t, _)| *t);
                    if let Some((_, path)) = best {
                        return Some(path.to_string_lossy().into_owned());
                    }
                }
            }
        }
        dir = dir.parent()?;
    }
}

// --- App state ---

enum AppState {
    FileSelect(FileSelectState),
    Analysis(AnalysisState),
}

struct FileSelectState {
    dump_path: String,
    elf_path: String,
    elf_auto: bool,
    error: Option<String>,
}

struct AnalysisState {
    result: AnalysisResult,
    selected_thread: usize,
}

struct App {
    state: AppState,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>, initial_dump: Option<String>) -> Self {
        let mut visuals = egui::Visuals::dark();
        visuals.selection.bg_fill = COLOR_ACCENT;
        visuals.widgets.active.bg_fill = COLOR_WIDGET_ACTIVE;
        cc.egui_ctx.set_visuals(visuals);

        let dump_path = initial_dump.unwrap_or_default();
        let (elf_path, elf_auto) = find_elf_for_dump(&dump_path)
            .map(|p| (p, true))
            .unwrap_or_default();

        App {
            state: AppState::FileSelect(FileSelectState {
                dump_path,
                elf_path,
                elf_auto,
                error: None,
            }),
        }
    }

    fn do_analyze(&mut self) {
        let AppState::FileSelect(ref fs) = self.state else { return };
        if fs.dump_path.is_empty() { return; }
        let dump_path = fs.dump_path.clone();
        let elf_path = fs.elf_path.clone();

        match run_analysis(&dump_path, &elf_path) {
            Ok(result) => {
                let sel = result.threads.iter().position(|t| t.crashed).unwrap_or(0);
                self.state = AppState::Analysis(AnalysisState { result, selected_thread: sel });
            }
            Err(e) => {
                if let AppState::FileSelect(ref mut fs) = self.state {
                    fs.error = Some(e);
                }
            }
        }
    }
}

// --- eframe App impl ---

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Handle dropped files
        let dropped: Vec<egui::DroppedFile> = ctx.input(|i| i.raw.dropped_files.clone());
        if let AppState::FileSelect(ref mut fs) = self.state {
            for file in &dropped {
                let path_str = file
                    .path.as_ref().map(|p| p.to_string_lossy().to_string())
                    .or_else(|| Some(file.name.clone()))
                    .unwrap_or_default();

                if path_str.ends_with(".psp2dmp") || path_str.ends_with(".psp2dmp.tmp") {
                    fs.dump_path = path_str;
                    if let Some(elf) = find_elf_for_dump(&fs.dump_path) {
                        fs.elf_path = elf;
                        fs.elf_auto = true;
                    }
                } else if path_str.ends_with(".elf") {
                    fs.elf_path = path_str;
                    fs.elf_auto = false;
                }
            }
        }

        match &self.state {
            AppState::FileSelect(_) => self.draw_file_select(ctx),
            AppState::Analysis(_) => self.draw_analysis(ctx),
        }
    }
}

// --- UI: File select screen ---

impl App {
    fn draw_file_select(&mut self, ctx: &egui::Context) {
        let hovering = ctx.input(|i| !i.raw.hovered_files.is_empty());
        let mut do_analyze = false;

        egui::CentralPanel::default()
            .frame(egui::Frame::central_panel(&ctx.style()).fill(COLOR_BG_DARK))
            .show(ctx, |ui| {
                let available = ui.available_size();

                ui.vertical_centered(|ui| {
                    let content_height = 380.0;
                    let top_pad = ((available.y - content_height) / 2.0).max(30.0);
                    ui.add_space(top_pad);

                    // Title
                    ui.label(egui::RichText::new("VITA CRASHDUMP").size(12.0).color(COLOR_ACCENT).strong());
                    ui.add_space(2.0);
                    ui.heading(egui::RichText::new("Analyzer").size(36.0).strong().color(COLOR_TITLE));
                    ui.add_space(32.0);

                    let AppState::FileSelect(ref mut fs) = self.state else { return };

                    // Drop zone
                    let drop_w = (available.x * DROP_ZONE_RATIO).clamp(DROP_ZONE_MIN_W, DROP_ZONE_MAX_W);
                    let drop_h = if fs.dump_path.is_empty() { DROP_ZONE_H_EMPTY } else { DROP_ZONE_H_LOADED };
                    let (rect, response) = ui.allocate_exact_size(egui::vec2(drop_w, drop_h), egui::Sense::click());
                    let painter = ui.painter_at(rect);

                    // Background + border
                    let bg = if hovering { COLOR_BG_HOVER } else { COLOR_BG_DROP };
                    painter.rect_filled(rect, 12.0, bg);

                    let border_color = if hovering {
                        COLOR_CYAN
                    } else if !fs.dump_path.is_empty() {
                        COLOR_BORDER_LOADED
                    } else {
                        COLOR_BORDER_EMPTY
                    };

                    if fs.dump_path.is_empty() && !hovering {
                        draw_dashed_border(&painter, rect.shrink(1.0), 12.0, 8.0, 6.0, egui::Stroke::new(1.5, border_color));
                    } else {
                        painter.rect_stroke(rect, 12.0, egui::Stroke::new(1.5, border_color));
                    }

                    // Drop zone content
                    if fs.dump_path.is_empty() {
                        draw_download_icon(&painter, rect.center() - egui::vec2(0.0, 18.0), if hovering { COLOR_CYAN } else { COLOR_SUBTLE });
                        let label = if hovering { "Release to load" } else { "Drop .psp2dmp file here" };
                        painter.text(rect.center() + egui::vec2(0.0, 30.0), egui::Align2::CENTER_CENTER, label, egui::FontId::proportional(15.0), if hovering { COLOR_CYAN } else { COLOR_DIM });
                        painter.text(rect.center() + egui::vec2(0.0, 50.0), egui::Align2::CENTER_CENTER, "or click to browse", egui::FontId::proportional(12.0), COLOR_SUBTLE);
                    } else {
                        let filename = std::path::Path::new(&fs.dump_path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| fs.dump_path.clone());
                        draw_checkmark(&painter, rect.center() - egui::vec2(0.0, 12.0), COLOR_GREEN);
                        painter.text(rect.center() + egui::vec2(0.0, 18.0), egui::Align2::CENTER_CENTER, &filename, egui::FontId::monospace(14.0), COLOR_GREEN);
                        painter.text(rect.center() + egui::vec2(0.0, 36.0), egui::Align2::CENTER_CENTER, "click to change", egui::FontId::proportional(11.0), COLOR_SUBTLE);
                    }

                    if response.clicked() {
                        if let Some(path) = rfd::FileDialog::new().add_filter("PSP2 Coredump", &["psp2dmp", "psp2dmp.tmp"]).pick_file() {
                            fs.dump_path = path.to_string_lossy().to_string();
                            if let Some(elf) = find_elf_for_dump(&fs.dump_path) {
                                fs.elf_path = elf;
                                fs.elf_auto = true;
                            }
                        }
                    }

                    ui.add_space(12.0);

                    // ELF status (clickable label)
                    if !fs.elf_path.is_empty() {
                        let elf_filename = std::path::Path::new(&fs.elf_path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| fs.elf_path.clone());
                        let label = if fs.elf_auto { format!("ELF: {} (auto-detected)", elf_filename) } else { format!("ELF: {}", elf_filename) };
                        if ui.label(egui::RichText::new(&label).size(12.0).color(COLOR_GREEN)).on_hover_text("Click to change ELF").clicked() {
                            if let Some(path) = rfd::FileDialog::new().add_filter("ELF Binary", &["elf"]).pick_file() {
                                fs.elf_path = path.to_string_lossy().to_string();
                                fs.elf_auto = false;
                            }
                        }
                    } else if ui.label(egui::RichText::new("No ELF — click to browse").size(12.0).color(COLOR_YELLOW)).on_hover_text("Select ELF for symbol resolution").clicked() {
                        if let Some(path) = rfd::FileDialog::new().add_filter("ELF Binary", &["elf"]).pick_file() {
                            fs.elf_path = path.to_string_lossy().to_string();
                            fs.elf_auto = false;
                        }
                    }

                    ui.add_space(32.0);

                    // Analyze button
                    let can_analyze = !fs.dump_path.is_empty();
                    let error_msg = fs.error.clone();
                    ui.add_enabled_ui(can_analyze, |ui| {
                        let btn = egui::Button::new(egui::RichText::new("    Analyze    ").size(18.0).strong())
                            .fill(COLOR_BTN).rounding(10.0).min_size(BTN_MIN_SIZE);
                        if ui.add(btn).clicked() { do_analyze = true; }
                    });

                    if let Some(ref err) = error_msg {
                        ui.add_space(16.0);
                        ui.label(egui::RichText::new(err).color(COLOR_RED));
                    }
                });
            });

        if do_analyze { self.do_analyze(); }
    }
}

// --- UI: Analysis screen ---

impl App {
    fn draw_analysis(&mut self, ctx: &egui::Context) {
        let mut go_back = false;

        // Top bar
        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Back").clicked() { go_back = true; }
                ui.separator();

                if let AppState::Analysis(ref state) = self.state {
                    ui.label(egui::RichText::new(&state.result.dump_name).strong().monospace());
                    ui.label(egui::RichText::new("+").color(COLOR_DIM));
                    ui.label(egui::RichText::new(&state.result.elf_name).strong().monospace());

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Copy to clipboard").clicked() {
                            let text = state.result.format_thread_text(state.selected_thread);
                            ui.output_mut(|o| o.copied_text = text);
                        }
                        ui.separator();

                        let crashed = state.result.threads.iter().filter(|t| t.crashed).count();
                        let total = state.result.threads.len();
                        if crashed > 0 {
                            ui.label(egui::RichText::new(format!("{} crashed", crashed)).color(COLOR_RED).strong());
                            ui.label(egui::RichText::new(format!("{} threads,", total)).color(COLOR_DIM));
                        } else {
                            ui.label(egui::RichText::new(format!("{} threads, no crash", total)).color(COLOR_GREEN));
                        }
                    });
                }
            });
        });

        if go_back {
            let (elf_path, elf_auto) = find_elf_for_dump("").map(|p| (p, true)).unwrap_or_default();
            self.state = AppState::FileSelect(FileSelectState { dump_path: String::new(), elf_path, elf_auto, error: None });
            return;
        }

        // Thread list sidebar
        egui::SidePanel::left("thread_list")
            .default_width(SIDEBAR_WIDTH)
            .resizable(true)
            .show(ctx, |ui| {
                ui.heading("Threads");
                ui.separator();

                let AppState::Analysis(ref mut state) = self.state else { return };
                let width = ui.available_width();

                egui::ScrollArea::vertical().show(ui, |ui| {
                    for (i, thread) in state.result.threads.iter().enumerate() {
                        let selected = state.selected_thread == i;
                        let name_color = if thread.crashed { COLOR_RED } else if selected { egui::Color32::WHITE } else { COLOR_DIM };
                        let badge_color = if thread.crashed { COLOR_RED } else { egui::Color32::from_rgb(100, 100, 100) };
                        let badge_text = if thread.crashed { format!("CRASHED - {}", thread.stop_reason) } else { thread.status.clone() };

                        let mut job = egui::text::LayoutJob::default();
                        job.wrap = egui::text::TextWrapping { max_width: width - 16.0, ..Default::default() };
                        job.append(&thread.name, 0.0, egui::TextFormat { font_id: egui::FontId::proportional(13.0), color: name_color, ..Default::default() });
                        job.append(&format!("\n{}", badge_text), 0.0, egui::TextFormat { font_id: egui::FontId::proportional(10.0), color: badge_color, ..Default::default() });

                        ui.with_layout(egui::Layout::left_to_right(egui::Align::TOP), |ui| {
                            ui.set_width(width);
                            if ui.add(egui::SelectableLabel::new(selected, job)).clicked() {
                                state.selected_thread = i;
                            }
                        });
                    }
                });
            });

        // Detail panel
        egui::CentralPanel::default()
            .frame(egui::Frame::central_panel(&ctx.style()).fill(COLOR_BG_PANEL))
            .show(ctx, |ui| {
                let AppState::Analysis(ref state) = self.state else { return };
                let Some(thread) = state.result.threads.get(state.selected_thread) else {
                    ui.label("No thread selected");
                    return;
                };
                egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
                    draw_thread_detail(ui, thread);
                });
            });
    }
}

// --- UI: Thread detail ---

fn draw_thread_detail(ui: &mut egui::Ui, thread: &ThreadDisplay) {
    // Header
    ui.heading(egui::RichText::new(&thread.name).size(22.0).strong().color(if thread.crashed { COLOR_RED } else { egui::Color32::WHITE }));
    ui.add_space(4.0);

    // Info grid
    egui::Grid::new("thread_info").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
        let row = |ui: &mut egui::Ui, label: &str, value: egui::RichText| {
            ui.label(egui::RichText::new(label).color(COLOR_DIM));
            ui.label(value);
            ui.end_row();
        };
        row(ui, "Thread ID", egui::RichText::new(format!("0x{:x}", thread.uid)).monospace());
        let sr_color = if thread.crashed { COLOR_RED } else { COLOR_GREEN };
        row(ui, "Stop reason", egui::RichText::new(format!("0x{:x} ({})", thread.stop_reason_code, thread.stop_reason)).monospace().color(sr_color));
        row(ui, "Status", egui::RichText::new(format!("0x{:x} ({})", thread.status_code, thread.status)).monospace());
        row(ui, "PC", egui::RichText::new(&thread.pc_display).monospace().color(COLOR_CYAN));
        if let Some(ref lr) = thread.lr_display {
            row(ui, "LR", egui::RichText::new(lr).monospace().color(COLOR_CYAN));
        }
    });

    let Some(ref crash) = thread.crash else { return };
    ui.add_space(16.0);
    ui.separator();

    // Registers
    ui.add_space(8.0);
    egui::CollapsingHeader::new(egui::RichText::new("Registers").strong().size(16.0))
        .default_open(true)
        .show(ui, |ui| {
            egui::Grid::new("registers").num_columns(6).spacing([8.0, 2.0]).striped(true).show(ui, |ui| {
                for (i, reg) in crash.registers.iter().enumerate() {
                    ui.label(egui::RichText::new(reg.name).monospace().strong().color(COLOR_YELLOW));
                    ui.label(egui::RichText::new(&reg.value).monospace());
                    if let Some(ref resolved) = reg.resolved {
                        ui.label(egui::RichText::new(resolved).monospace().small().color(COLOR_CYAN));
                    } else {
                        ui.label("");
                    }
                    if i % 2 == 1 { ui.end_row(); }
                }
                if crash.registers.len() % 2 == 1 {
                    ui.label(""); ui.label(""); ui.label("");
                    ui.end_row();
                }
            });
        });

    // Disassembly
    for disasm in [&crash.pc_disasm, &crash.lr_disasm].into_iter().flatten() {
        ui.add_space(8.0);
        egui::CollapsingHeader::new(egui::RichText::new(format!("Disassembly - {}", disasm.header)).strong().size(16.0))
            .default_open(true)
            .show(ui, |ui| draw_disasm(ui, &disasm.lines));
    }

    // Stack trace
    if !crash.stack_trace.is_empty() {
        ui.add_space(8.0);
        egui::CollapsingHeader::new(egui::RichText::new("Stack Trace").strong().size(16.0))
            .default_open(true)
            .show(ui, |ui| draw_stack_trace(ui, &crash.stack_trace));
    }

    // Stack memory
    ui.add_space(8.0);
    egui::CollapsingHeader::new(egui::RichText::new("Stack Memory").strong().size(16.0))
        .default_open(false)
        .show(ui, |ui| draw_stack_memory(ui, &crash.stack));
}

// --- UI: Code sections ---

fn draw_disasm(ui: &mut egui::Ui, lines: &[DisasmLine]) {
    code_frame(ui, |ui| {
        for line in lines {
            if line.is_crash {
                ui.label(egui::RichText::new(format!(">>> {}", line.text)).monospace().color(COLOR_RED).strong().background_color(COLOR_BG_CRASH));
            } else {
                ui.label(egui::RichText::new(format!("    {}", line.text)).monospace().color(COLOR_DIM));
            }
        }
    });
}

fn draw_stack_trace(ui: &mut egui::Ui, trace: &[StackTraceLine]) {
    code_frame(ui, |ui| {
        for (i, entry) in trace.iter().enumerate() {
            let color = if entry.is_crash { COLOR_RED } else { egui::Color32::WHITE };
            let dim = if entry.is_crash { COLOR_RED } else { COLOR_DIM };
            let prefix = if entry.is_crash { ">>>" } else { "   " };

            ui.label(egui::RichText::new(format!("{} #{:<2} {}", prefix, i, entry.func_name)).monospace().color(color));

            if !entry.file_loc.is_empty() {
                ui.label(egui::RichText::new(format!("        at {}", entry.file_loc)).monospace().small().color(COLOR_CYAN));
            }
            ui.label(egui::RichText::new(format!("        in {} [{}]", entry.module, entry.addr)).monospace().small().color(dim));

            if i < trace.len() - 1 { ui.add_space(2.0); }
        }
    });
}

fn draw_stack_memory(ui: &mut egui::Ui, stack: &[StackLine]) {
    code_frame(ui, |ui| {
        for entry in stack {
            let mut line = if entry.is_sp { "SP => ".to_string() } else { "      ".to_string() };
            line.push_str(&entry.text);
            if let Some(ref resolved) = entry.resolved {
                line.push_str("  ");
                line.push_str(resolved);
            }
            let color = if entry.is_sp { COLOR_YELLOW } else if entry.resolved.is_some() { COLOR_CYAN } else { COLOR_DIM };
            ui.label(egui::RichText::new(&line).monospace().color(color));
        }
    });
}

/// Wraps content in a dark code block with horizontal scroll
fn code_frame(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::none()
        .fill(COLOR_BG_CODE)
        .inner_margin(8.0)
        .rounding(4.0)
        .show(ui, |ui| {
            egui::ScrollArea::horizontal().show(ui, add_contents);
        });
}

// --- Drawing helpers ---

fn draw_dashed_border(painter: &egui::Painter, rect: egui::Rect, corner: f32, dash: f32, gap: f32, stroke: egui::Stroke) {
    let r = rect;
    let c = corner;
    draw_dashed_line(painter, r.left_top() + egui::vec2(c, 0.0), r.right_top() - egui::vec2(c, 0.0), dash, gap, stroke);
    draw_dashed_line(painter, r.left_bottom() + egui::vec2(c, 0.0), r.right_bottom() - egui::vec2(c, 0.0), dash, gap, stroke);
    draw_dashed_line(painter, r.left_top() + egui::vec2(0.0, c), r.left_bottom() - egui::vec2(0.0, c), dash, gap, stroke);
    draw_dashed_line(painter, r.right_top() + egui::vec2(0.0, c), r.right_bottom() - egui::vec2(0.0, c), dash, gap, stroke);
}

fn draw_dashed_line(painter: &egui::Painter, from: egui::Pos2, to: egui::Pos2, dash: f32, gap: f32, stroke: egui::Stroke) {
    let delta = to - from;
    let len = delta.length();
    if len < 0.1 { return; }
    let dir = delta / len;
    let cycle = dash + gap;
    let mut pos = 0.0;
    while pos < len {
        let start = pos;
        let end = (pos + dash).min(len);
        painter.line_segment([from + dir * start, from + dir * end], stroke);
        pos += cycle;
    }
}

fn draw_download_icon(painter: &egui::Painter, center: egui::Pos2, color: egui::Color32) {
    let stroke = egui::Stroke::new(2.5, color);
    // Arrow shaft
    painter.line_segment([center - egui::vec2(0.0, 12.0), center + egui::vec2(0.0, 12.0)], stroke);
    // Arrow head
    painter.line_segment([center + egui::vec2(0.0, 12.0), center + egui::vec2(-8.0, 4.0)], stroke);
    painter.line_segment([center + egui::vec2(0.0, 12.0), center + egui::vec2(8.0, 4.0)], stroke);
    // Tray
    painter.line_segment([egui::pos2(center.x - 14.0, center.y + 18.0), egui::pos2(center.x + 14.0, center.y + 18.0)], egui::Stroke::new(2.0, color));
}

fn draw_checkmark(painter: &egui::Painter, center: egui::Pos2, color: egui::Color32) {
    let stroke = egui::Stroke::new(2.5, color);
    painter.line_segment([center - egui::vec2(8.0, 0.0), center + egui::vec2(-2.0, 8.0)], stroke);
    painter.line_segment([center + egui::vec2(-2.0, 8.0), center + egui::vec2(10.0, -6.0)], stroke);
}

// --- Entry point ---

fn main() -> eframe::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let initial_dump = args.get(1).cloned();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(WINDOW_SIZE)
            .with_min_inner_size(WINDOW_MIN)
            .with_drag_and_drop(true),
        ..Default::default()
    };

    eframe::run_native(
        "Vita Crashdump Analyzer",
        options,
        Box::new(move |cc| Ok(Box::new(App::new(cc, initial_dump)))),
    )
}
