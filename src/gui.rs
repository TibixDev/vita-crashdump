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

        // Register Phosphor icon font
        let mut fonts = egui::FontDefinitions::default();
        egui_phosphor::add_to_fonts(&mut fonts, egui_phosphor::Variant::Regular);
        cc.egui_ctx.set_fonts(fonts);

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
                    ui.label(egui::RichText::new(format!("{} VITA CRASHDUMP", egui_phosphor::regular::BUG)).size(12.0).color(COLOR_ACCENT).strong());
                    ui.add_space(2.0);
                    ui.heading(egui::RichText::new("Analyzer").size(36.0).strong().color(COLOR_TITLE));
                    ui.add_space(32.0);

                    let AppState::FileSelect(ref mut fs) = self.state else { return };

                    // Two file cards side by side
                    let total_w = (available.x * DROP_ZONE_RATIO).clamp(DROP_ZONE_MIN_W, DROP_ZONE_MAX_W);
                    let card_gap = 12.0;
                    let card_w = (total_w - card_gap) / 2.0;
                    let card_h = 150.0;

                    let mut browse_dump = false;
                    let mut browse_elf = false;

                    ui.allocate_ui(egui::vec2(total_w, card_h), |ui| {
                        ui.horizontal(|ui| {
                            // --- Dump card ---
                            let (rect, response) = ui.allocate_exact_size(egui::vec2(card_w, card_h), egui::Sense::click().union(egui::Sense::hover()));
                            let painter = ui.painter_at(rect);
                            let dump_hovered = response.hovered() || hovering;
                            let has_dump = !fs.dump_path.is_empty();

                            let dump_border = if dump_hovered && !has_dump { COLOR_CYAN } else if has_dump { COLOR_BORDER_LOADED } else { COLOR_BORDER_EMPTY };
                            let bg = if dump_hovered { COLOR_BG_HOVER } else { COLOR_BG_DROP };
                            painter.rect_filled(rect, 10.0, bg);
                            painter.rect_stroke(rect, 10.0, egui::Stroke::new(if dump_hovered { 2.0 } else { 1.0 }, dump_border), egui::StrokeKind::Inside);

                            if !has_dump {
                                let c = if dump_hovered { COLOR_CYAN } else { COLOR_SUBTLE };
                                painter.text(rect.center() - egui::vec2(0.0, 28.0), egui::Align2::CENTER_CENTER, egui_phosphor::regular::DOWNLOAD_SIMPLE, egui::FontId::proportional(28.0), c);
                                painter.text(rect.center() - egui::vec2(0.0, 2.0), egui::Align2::CENTER_CENTER, "Crashdump", egui::FontId::proportional(14.0), if dump_hovered { COLOR_CYAN } else { COLOR_DIM });
                                painter.text(rect.center() + egui::vec2(0.0, 16.0), egui::Align2::CENTER_CENTER, "Drop .psp2dmp or click", egui::FontId::proportional(11.0), if dump_hovered { COLOR_CYAN } else { COLOR_SUBTLE });
                            } else {
                                let filename = std::path::Path::new(&fs.dump_path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| fs.dump_path.clone());
                                painter.text(rect.center() - egui::vec2(0.0, 28.0), egui::Align2::CENTER_CENTER, egui_phosphor::regular::CHECK_CIRCLE, egui::FontId::proportional(24.0), COLOR_GREEN);
                                painter.text(rect.center() - egui::vec2(0.0, 4.0), egui::Align2::CENTER_CENTER, "Crashdump", egui::FontId::proportional(11.0), COLOR_DIM);
                                painter.text(rect.center() + egui::vec2(0.0, 14.0), egui::Align2::CENTER_CENTER, &filename, egui::FontId::monospace(11.0), COLOR_GREEN);
                                painter.text(rect.center() + egui::vec2(0.0, 32.0), egui::Align2::CENTER_CENTER, if dump_hovered { "click to change" } else { "" }, egui::FontId::proportional(10.0), COLOR_SUBTLE);
                            }
                            if response.clicked() { browse_dump = true; }

                            ui.add_space(card_gap);

                            // --- ELF card ---
                            let (rect, response) = ui.allocate_exact_size(egui::vec2(card_w, card_h), egui::Sense::click().union(egui::Sense::hover()));
                            let painter = ui.painter_at(rect);
                            let elf_hovered = response.hovered();
                            let has_elf = !fs.elf_path.is_empty();

                            let elf_border = if elf_hovered { COLOR_CYAN } else if has_elf { COLOR_BORDER_LOADED } else { COLOR_BORDER_EMPTY };
                            let bg = if elf_hovered { COLOR_BG_HOVER } else { COLOR_BG_DROP };
                            painter.rect_filled(rect, 10.0, bg);
                            painter.rect_stroke(rect, 10.0, egui::Stroke::new(if elf_hovered { 2.0 } else { 1.0 }, elf_border), egui::StrokeKind::Inside);

                            if !has_elf {
                                let c = if elf_hovered { COLOR_CYAN } else { COLOR_SUBTLE };
                                painter.text(rect.center() - egui::vec2(0.0, 28.0), egui::Align2::CENTER_CENTER, egui_phosphor::regular::CUBE, egui::FontId::proportional(28.0), c);
                                painter.text(rect.center() - egui::vec2(0.0, 2.0), egui::Align2::CENTER_CENTER, "ELF Binary", egui::FontId::proportional(14.0), if elf_hovered { COLOR_CYAN } else { COLOR_DIM });
                                painter.text(rect.center() + egui::vec2(0.0, 16.0), egui::Align2::CENTER_CENTER, "Optional — click to browse", egui::FontId::proportional(11.0), if elf_hovered { COLOR_CYAN } else { COLOR_SUBTLE });
                            } else {
                                let elf_filename = std::path::Path::new(&fs.elf_path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| fs.elf_path.clone());
                                painter.text(rect.center() - egui::vec2(0.0, 28.0), egui::Align2::CENTER_CENTER, egui_phosphor::regular::CUBE, egui::FontId::proportional(24.0), COLOR_GREEN);
                                painter.text(rect.center() - egui::vec2(0.0, 4.0), egui::Align2::CENTER_CENTER, "ELF Binary", egui::FontId::proportional(11.0), COLOR_DIM);
                                painter.text(rect.center() + egui::vec2(0.0, 14.0), egui::Align2::CENTER_CENTER, &elf_filename, egui::FontId::monospace(11.0), COLOR_GREEN);
                                let tag = if fs.elf_auto { "auto-detected" } else { "" };
                                painter.text(rect.center() + egui::vec2(0.0, 30.0), egui::Align2::CENTER_CENTER, tag, egui::FontId::proportional(10.0), COLOR_SUBTLE);
                                if elf_hovered {
                                    painter.text(rect.center() + egui::vec2(0.0, 44.0), egui::Align2::CENTER_CENTER, "click to change", egui::FontId::proportional(10.0), COLOR_CYAN);
                                }
                            }
                            if response.clicked() { browse_elf = true; }
                        });
                    });

                    if browse_dump {
                        if let Some(path) = rfd::FileDialog::new().add_filter("PSP2 Coredump", &["psp2dmp", "psp2dmp.tmp"]).pick_file() {
                            fs.dump_path = path.to_string_lossy().to_string();
                            if let Some(elf) = find_elf_for_dump(&fs.dump_path) {
                                fs.elf_path = elf;
                                fs.elf_auto = true;
                            }
                        }
                    }
                    if browse_elf {
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
                        let btn = egui::Button::new(egui::RichText::new(format!("  {}  Analyze  ", egui_phosphor::regular::MAGNIFYING_GLASS)).size(18.0).strong())
                            .fill(COLOR_BTN).corner_radius(10.0).min_size(BTN_MIN_SIZE);
                        if ui.add(btn).clicked() { do_analyze = true; }
                    });

                    if let Some(ref err) = error_msg {
                        ui.add_space(32.0);
                        ui.label(egui::RichText::new(format!("{} {}", egui_phosphor::regular::WARNING_CIRCLE, err)).color(COLOR_RED));
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
        egui::TopBottomPanel::top("top_bar")
            .min_height(36.0)
            .show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button(format!("{} Back", egui_phosphor::regular::ARROW_LEFT)).clicked() { go_back = true; }
                ui.separator();

                if let AppState::Analysis(ref state) = self.state {
                    ui.label(egui::RichText::new(format!("{} {}", egui_phosphor::regular::FILE, &state.result.dump_name)).strong().monospace());
                    ui.label(egui::RichText::new("+").color(COLOR_DIM));
                    ui.label(egui::RichText::new(format!("{} {}", egui_phosphor::regular::CUBE, &state.result.elf_name)).strong().monospace());

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button(format!("{} Copy to clipboard", egui_phosphor::regular::CLIPBOARD)).clicked() {
                            let text = state.result.format_thread_text(state.selected_thread);
                            ui.ctx().copy_text(text);
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
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new(egui_phosphor::regular::LIST_BULLETS).size(18.0));
                    ui.heading("Threads");
                });
                ui.add_space(6.0);
                ui.separator();
                ui.add_space(4.0);

                let AppState::Analysis(ref mut state) = self.state else { return };
                let width = ui.available_width();

                egui::ScrollArea::vertical().show(ui, |ui| {
                    for (i, thread) in state.result.threads.iter().enumerate() {
                        let selected = state.selected_thread == i;

                        let icon = if thread.crashed {
                            egui_phosphor::regular::WARNING_CIRCLE
                        } else if thread.status == "Waiting" {
                            egui_phosphor::regular::HOURGLASS
                        } else if thread.status == "Running" {
                            egui_phosphor::regular::PLAY
                        } else if thread.status == "Ready" {
                            egui_phosphor::regular::ARROW_RIGHT
                        } else if thread.status == "Dormant" {
                            egui_phosphor::regular::MOON
                        } else {
                            egui_phosphor::regular::CIRCLE
                        };

                        // [icon | name + subtext] card
                        let card_h = 52.0;
                        let (rect, response) = ui.allocate_exact_size(
                            egui::vec2(width, card_h),
                            egui::Sense::click().union(egui::Sense::hover()),
                        );
                        let hovered = response.hovered();
                        let painter = ui.painter_at(rect);

                        // Background
                        let bg = if selected {
                            COLOR_ACCENT
                        } else if hovered {
                            egui::Color32::from_rgb(35, 35, 50)
                        } else {
                            egui::Color32::TRANSPARENT
                        };
                        painter.rect_filled(rect, 6.0, bg);

                        // Left accent bar for crashed threads
                        if thread.crashed {
                            painter.rect_filled(
                                egui::Rect::from_min_size(rect.left_top(), egui::vec2(3.0, card_h)),
                                3.0, COLOR_RED,
                            );
                        }

                        let icon_color = if thread.crashed { COLOR_RED } else if selected || hovered { egui::Color32::WHITE } else { COLOR_SUBTLE };
                        let name_color = if thread.crashed { COLOR_RED } else if selected || hovered { egui::Color32::WHITE } else { egui::Color32::from_rgb(200, 200, 210) };
                        let sub_color = if thread.crashed { COLOR_RED } else if selected { egui::Color32::from_rgb(190, 190, 200) } else if hovered { egui::Color32::from_rgb(160, 160, 170) } else { egui::Color32::from_rgb(110, 110, 120) };

                        // Big icon, vertically centered
                        let icon_x = rect.left() + 10.0;
                        painter.text(
                            egui::pos2(icon_x, rect.center().y),
                            egui::Align2::LEFT_CENTER,
                            icon,
                            egui::FontId::proportional(22.0),
                            icon_color,
                        );

                        // Name + subtext, stacked vertically
                        let text_x = icon_x + 30.0;
                        painter.text(
                            egui::pos2(text_x, rect.center().y - 8.0),
                            egui::Align2::LEFT_CENTER,
                            &thread.name,
                            egui::FontId::proportional(13.0),
                            name_color,
                        );

                        let badge = if thread.crashed {
                            format!("{} CRASHED — {}", egui_phosphor::regular::SKULL, thread.stop_reason)
                        } else {
                            thread.status.clone()
                        };
                        painter.text(
                            egui::pos2(text_x, rect.center().y + 10.0),
                            egui::Align2::LEFT_CENTER,
                            &badge,
                            egui::FontId::proportional(10.0),
                            sub_color,
                        );

                        if response.clicked() {
                            state.selected_thread = i;
                        }

                        ui.add_space(1.0);
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

                    // TTY output (dump-wide, shown after thread detail)
                    if let Some(ref tty) = state.result.tty_output {
                        ui.add_space(32.0);
                        ui.separator();
                        ui.add_space(32.0);
                        egui::CollapsingHeader::new(egui::RichText::new(format!("{} TTY Output", egui_phosphor::regular::TERMINAL)).strong().size(16.0))
                            .default_open(false)
                            .show(ui, |ui| {
                                code_frame(ui, |ui| {
                                    ui.label(egui::RichText::new(tty).monospace().color(COLOR_DIM));
                                });
                            });
                    }
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
        if let (Some(peak), Some(current)) = (thread.stack_peak, thread.stack_current) {
            row(ui, "Stack usage", egui::RichText::new(format!("{} / {} bytes (peak)", current, peak)).monospace());
        }
    });

    let Some(ref crash) = thread.crash else { return };

    if let Some(ref fault) = crash.fault_addr {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Fault address").color(COLOR_DIM));
            ui.label(egui::RichText::new(fault).monospace().strong().color(COLOR_RED));
        });
    }

    ui.add_space(32.0);
    ui.separator();

    // Registers
    ui.add_space(8.0);
    egui::CollapsingHeader::new(egui::RichText::new(format!("{} Registers", egui_phosphor::regular::CPU)).strong().size(16.0))
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
        ui.add_space(32.0);
        egui::CollapsingHeader::new(egui::RichText::new(format!("{} Disassembly - {}", egui_phosphor::regular::CODE, disasm.header)).strong().size(16.0))
            .default_open(true)
            .show(ui, |ui| draw_disasm(ui, &disasm.lines));
    }

    // Stack trace
    if !crash.stack_trace.is_empty() {
        ui.add_space(32.0);
        egui::CollapsingHeader::new(egui::RichText::new(format!("{} Stack Trace", egui_phosphor::regular::STACK)).strong().size(16.0))
            .default_open(true)
            .show(ui, |ui| draw_stack_trace(ui, &crash.stack_trace));
    }

    // Stack memory
    ui.add_space(32.0);
    egui::CollapsingHeader::new(egui::RichText::new(format!("{} Stack Memory", egui_phosphor::regular::MEMORY)).strong().size(16.0))
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
    egui::Frame::NONE
        .fill(COLOR_BG_CODE)
        .inner_margin(8.0)
        .corner_radius(4.0)
        .show(ui, |ui| {
            egui::ScrollArea::horizontal().show(ui, add_contents);
        });
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
