use std::collections::HashMap;
use std::time::Duration;

use eframe::egui::{self, RichText, TextEdit};

use crate::capture::{read_connections, read_processes, socket_owners};
use crate::model::{NetRow, ProcessRow};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LlmProvider {
    OpenRouter,
    OpenAI,
    Anthropic,
    Ollama,
}

impl LlmProvider {
    pub fn all() -> &'static [Self] {
        &[Self::OpenRouter, Self::OpenAI, Self::Anthropic, Self::Ollama]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::OpenRouter => "OpenRouter",
            Self::OpenAI => "OpenAI",
            Self::Anthropic => "Anthropic",
            Self::Ollama => "Ollama (Local)",
        }
    }

    pub fn default_model(&self) -> &'static str {
        match self {
            Self::OpenRouter => "google/gemini-2.5-flash",
            Self::OpenAI => "gpt-4o-mini",
            Self::Anthropic => "claude-3-5-sonnet-20240620",
            Self::Ollama => "llama3",
        }
    }

    pub fn default_url(&self) -> &'static str {
        match self {
            Self::OpenRouter => "https://openrouter.ai/api/v1/chat/completions",
            Self::OpenAI => "https://api.openai.com/v1/chat/completions",
            Self::Anthropic => "https://api.anthropic.com/v1/messages",
            Self::Ollama => "http://localhost:11434/api/chat",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExplainTab {
    Analysis,
    Evidence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CentralTab {
    Network,
    LlmWorkspace,
}

pub struct ProcSnapshot {
    pub processes: Vec<ProcessRow>,
    pub connections: Vec<NetRow>,
    pub status: String,
}

pub struct VtLensApp {
    processes: Vec<ProcessRow>,
    connections: Vec<NetRow>,
    selected_pid: Option<u32>,
    selected_network_inode: Option<String>,
    process_filter: String,
    network_filter: String,
    explain_prompt: String,
    export_preview: String,
    status: String,
    auto_refresh: bool,
    tx_snapshot: std::sync::mpsc::Sender<ProcSnapshot>,
    rx_snapshot: std::sync::mpsc::Receiver<ProcSnapshot>,
    // LLM Analysis Integration
    api_key: String,
    provider: LlmProvider,
    model_name: String,
    analysis_result: String,
    analysis_loading: bool,
    active_tab: ExplainTab,
    central_tab: CentralTab,
    tx_analysis: std::sync::mpsc::Sender<Result<String, String>>,
    rx_analysis: std::sync::mpsc::Receiver<Result<String, String>>,
}

impl VtLensApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut visuals = egui::Visuals::light();

        // Premium Light Mode styling (Tailwind CSS inspired palette)
        visuals.window_fill = egui::Color32::from_rgb(255, 255, 255);
        visuals.panel_fill = egui::Color32::from_rgb(255, 255, 255);
        visuals.extreme_bg_color = egui::Color32::from_rgb(243, 244, 246); // Tailwind gray-100 (for grids/inputs)
        visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(255, 255, 255);
        visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(249, 250, 251); // Tailwind gray-50
        visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(243, 244, 246);  // Tailwind gray-100
        visuals.widgets.active.bg_fill = egui::Color32::from_rgb(229, 231, 235);   // Tailwind gray-200

        // Borders styling
        visuals.widgets.noninteractive.bg_stroke.color = egui::Color32::from_rgb(229, 231, 235); // faint gray borders
        visuals.widgets.inactive.bg_stroke.color = egui::Color32::from_rgb(229, 231, 235);
        visuals.widgets.noninteractive.bg_stroke.width = 1.0;
        visuals.widgets.inactive.bg_stroke.width = 1.0;

        // Selection highlight color (clean modern sky blue)
        visuals.selection.bg_fill = egui::Color32::from_rgb(14, 165, 233); // Tailwind sky-500
        visuals.selection.stroke.color = egui::Color32::from_rgb(255, 255, 255);

        // Rounded corners
        visuals.widgets.noninteractive.rounding = egui::Rounding::same(6.0);
        visuals.widgets.inactive.rounding = egui::Rounding::same(6.0);
        visuals.widgets.hovered.rounding = egui::Rounding::same(6.0);
        visuals.widgets.active.rounding = egui::Rounding::same(6.0);
        visuals.window_rounding = egui::Rounding::same(8.0);

        cc.egui_ctx.set_visuals(visuals);

        let (tx_analysis, rx_analysis) = std::sync::mpsc::channel();
        let (tx_snapshot, rx_snapshot) = std::sync::mpsc::channel();

        // Spawn background polling thread loop
        let tx_snapshot_clone = tx_snapshot.clone();
        let ctx_clone = cc.egui_ctx.clone();
        std::thread::spawn(move || {
            loop {
                let snapshot = capture_system_snapshot();
                if tx_snapshot_clone.send(snapshot).is_err() {
                    break;
                }
                ctx_clone.request_repaint(); // immediately trigger repaint in the GUI thread
                std::thread::sleep(Duration::from_secs(2));
            }
        });

        Self {
            processes: Vec::new(),
            connections: Vec::new(),
            selected_pid: None,
            selected_network_inode: None,
            process_filter: String::new(),
            network_filter: String::new(),
            explain_prompt: String::new(),
            export_preview: String::new(),
            status: "Starting capture".to_string(),
            auto_refresh: true,
            tx_snapshot,
            rx_snapshot,
            api_key: String::new(),
            provider: LlmProvider::OpenRouter,
            model_name: LlmProvider::OpenRouter.default_model().to_string(),
            analysis_result: String::new(),
            analysis_loading: false,
            active_tab: ExplainTab::Analysis,
            central_tab: CentralTab::Network,
            tx_analysis,
            rx_analysis,
        }
    }



    fn filtered_processes(&self) -> Vec<ProcessRow> {
        let filter = self.process_filter.trim().to_lowercase();
        self.processes
            .iter()
            .filter(|process| {
                filter.is_empty()
                    || process.pid.to_string().contains(&filter)
                    || process.name.to_lowercase().contains(&filter)
                    || process.cmdline.to_lowercase().contains(&filter)
            })
            .cloned()
            .collect()
    }

    fn filtered_connections(&self) -> Vec<NetRow> {
        let filter = self.network_filter.trim().to_lowercase();
        self.connections
            .iter()
            .filter(|connection| {
                if let Some(selected_pid) = self.selected_pid {
                    if connection.owner.as_ref().map(|owner| owner.pid) != Some(selected_pid) {
                        return false;
                    }
                }

                filter.is_empty()
                    || connection.protocol.to_lowercase().contains(&filter)
                    || connection.local_addr.to_lowercase().contains(&filter)
                    || connection.remote_addr.to_lowercase().contains(&filter)
                    || connection.state.to_lowercase().contains(&filter)
                    || connection.owner_label().to_lowercase().contains(&filter)
            })
            .cloned()
            .collect()
    }

    fn selected_process(&self) -> Option<&ProcessRow> {
        self.selected_pid
            .and_then(|pid| self.processes.iter().find(|process| process.pid == pid))
    }

    fn build_prompt(&self) -> String {
        let mut prompt = String::from(
            "Act as VT Security. Explain this local system activity in plain Spanish for Argentina/LatAm. Be direct, practical, and technical. The raw log is the evidence; do not invent facts.\n\n",
        );

        if let Some(process) = self.selected_process() {
            prompt.push_str(&format!(
                "Selected process:\n- pid: {}\n- name: {}\n- state: {}\n- rss_mb: {:.1}\n- threads: {}\n- sockets: {}\n- cmdline: {}\n\n",
                process.pid,
                process.name,
                process.state,
                process.rss_mb(),
                process.threads,
                process.socket_count,
                process.cmdline
            ));
        } else {
            prompt.push_str("No process selected.\n\n");
        }

        if let Some(inode) = &self.selected_network_inode {
            if let Some(connection) = self.connections.iter().find(|c| &c.inode == inode) {
                prompt.push_str(&format!(
                    "Focused Network Connection (Evidence):\n- protocol: {}\n- local: {}\n- remote: {}\n- state: {}\n- owner: {}\n- tx_queue: {}\n- rx_queue: {}\n- inode: {}\n\n",
                    connection.protocol,
                    connection.local_addr,
                    connection.remote_addr,
                    connection.state,
                    connection.owner_label(),
                    connection.tx_queue,
                    connection.rx_queue,
                    connection.inode
                ));
            }
        }

        prompt.push_str("Network sample:\n");
        for connection in self.filtered_connections().into_iter().take(25) {
            prompt.push_str(&format!(
                "- {} {} -> {} [{}] owner={} tx_queue={} rx_queue={} inode={}\n",
                connection.protocol,
                connection.local_addr,
                connection.remote_addr,
                connection.state,
                connection.owner_label(),
                connection.tx_queue,
                connection.rx_queue,
                connection.inode
            ));
        }

        prompt.push_str("\nExplain: what is likely happening, what is normal, what deserves attention, and what command should the learner run next to verify it.\n");
        prompt
    }

    fn build_markdown_export(&self) -> String {
        let mut markdown = String::from("# VT Lens Evidence\n\n");
        markdown.push_str(&format!("Status: {}\n\n", self.status));

        if let Some(process) = self.selected_process() {
            markdown.push_str("## Selected Process\n\n");
            markdown.push_str(&format!("- PID: {}\n", process.pid));
            markdown.push_str(&format!("- Name: {}\n", process.name));
            markdown.push_str(&format!("- State: {}\n", process.state));
            markdown.push_str(&format!("- RSS: {:.1} MB\n", process.rss_mb()));
            markdown.push_str(&format!("- Threads: {}\n", process.threads));
            markdown.push_str(&format!("- Sockets: {}\n", process.socket_count));
            markdown.push_str(&format!("- Cmdline: `{}`\n\n", process.cmdline));
        }

        if let Some(inode) = &self.selected_network_inode {
            if let Some(connection) = self.connections.iter().find(|c| &c.inode == inode) {
                markdown.push_str("## Focused Network Connection\n\n");
                markdown.push_str(&format!("- Protocol: {}\n", connection.protocol));
                markdown.push_str(&format!("- Local: `{}`\n", connection.local_addr));
                markdown.push_str(&format!("- Remote: `{}`\n", connection.remote_addr));
                markdown.push_str(&format!("- State: {}\n", connection.state));
                markdown.push_str(&format!("- Owner: {}\n", connection.owner_label()));
                markdown.push_str(&format!("- Inode: {}\n", connection.inode));
                markdown.push_str(&format!("- Queues: tx={} rx={}\n\n", connection.tx_queue, connection.rx_queue));
            }
        }

        markdown.push_str("## Network Sample\n\n");
        markdown.push_str("| Proto | Local | Remote | State | Owner | Queues |\n");
        markdown.push_str("| --- | --- | --- | --- | --- | --- |\n");

        for connection in self.filtered_connections().into_iter().take(50) {
            markdown.push_str(&format!(
                "| {} | `{}` | `{}` | {} | {} | tx={} rx={} |\n",
                connection.protocol,
                connection.local_addr,
                connection.remote_addr,
                connection.state,
                connection.owner_label(),
                connection.tx_queue,
                connection.rx_queue
            ));
        }

        markdown
    }

    fn show_header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("VT LENS").strong().size(14.0));
            ui.label(RichText::new("see what your machine is doing").weak().size(11.0));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Refresh now").clicked() {
                    let tx = self.tx_snapshot.clone();
                    let ctx = ui.ctx().clone();
                    std::thread::spawn(move || {
                        let snapshot = capture_system_snapshot();
                        let _ = tx.send(snapshot);
                        ctx.request_repaint();
                    });
                }
                ui.checkbox(&mut self.auto_refresh, "auto refresh");
            });
        });
    }

    fn show_processes(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("PROCESOS").strong().size(10.0).color(ui.visuals().weak_text_color()));
        ui.add_space(2.0);
        ui.add(TextEdit::singleline(&mut self.process_filter).hint_text("🔍 filter pid, name, cmdline...").desired_width(f32::INFINITY));
        ui.add_space(6.0);

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("process_grid")
                .striped(true)
                .min_col_width(42.0)
                .show(ui, |ui| {
                    ui.label(RichText::new("PID").weak().size(11.0));
                    ui.label(RichText::new("Nombre").weak().size(11.0));
                    ui.label(RichText::new("Memoria").weak().size(11.0));
                    ui.label(RichText::new("Sockets").weak().size(11.0));
                    ui.end_row();

                    for process in self.filtered_processes().into_iter().take(450) {
                        let selected = self.selected_pid == Some(process.pid);
                        let mut clicked = false;

                        if ui
                            .selectable_label(selected, process.pid.to_string())
                            .on_hover_text(&process.cmdline)
                            .clicked()
                        {
                            clicked = true;
                        }
                        if ui
                            .selectable_label(selected, &process.name)
                            .on_hover_text(&process.cmdline)
                            .clicked()
                        {
                            clicked = true;
                        }
                        if ui
                            .selectable_label(selected, format!("{:.0} MB", process.rss_mb()))
                            .on_hover_text(&process.cmdline)
                            .clicked()
                        {
                            clicked = true;
                        }
                        if ui
                            .selectable_label(selected, process.socket_count.to_string())
                            .on_hover_text(&process.cmdline)
                            .clicked()
                        {
                            clicked = true;
                        }

                        if clicked {
                            if selected {
                                self.selected_pid = None;
                                self.selected_network_inode = None;
                            } else {
                                self.selected_pid = Some(process.pid);
                                self.selected_network_inode = None; // Bugfix: clear socket focus when process changes
                                self.network_filter.clear();
                            }
                        }
                        ui.end_row();
                    }
                });
        });
    }

    fn show_network(&mut self, ui: &mut egui::Ui) {
        let process_label = self.selected_process().map(|p| p.label());
        let socket_inode = self.selected_network_inode.clone();

        ui.horizontal(|ui| {
            ui.label(RichText::new("CONEXIONES DE RED").strong().size(10.0).color(ui.visuals().weak_text_color()));

            if let Some(label) = process_label {
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Proceso:").strong().size(11.0));
                    ui.label(RichText::new(label).color(ui.visuals().selection.bg_fill).size(11.0));
                    if ui.small_button("❌").clicked() {
                        self.selected_pid = None;
                        self.selected_network_inode = None;
                    }
                });
            }

            if let Some(inode) = socket_inode {
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Socket:").strong().size(11.0));
                    ui.label(RichText::new(&inode).color(ui.visuals().selection.bg_fill).size(11.0));
                    if ui.small_button("❌").clicked() {
                        self.selected_network_inode = None;
                    }
                });
            }
        });
        ui.add_space(2.0);
        ui.add(TextEdit::singleline(&mut self.network_filter).hint_text("🔍 filter proto, addr, state, owner...").desired_width(f32::INFINITY));
        ui.add_space(6.0);

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("network_grid")
                .striped(true)
                .min_col_width(76.0)
                .show(ui, |ui| {
                    ui.label(RichText::new("Proto").weak().size(11.0));
                    ui.label(RichText::new("Proceso dueño").weak().size(11.0));
                    ui.label(RichText::new("Local").weak().size(11.0));
                    ui.label(RichText::new("Remoto").weak().size(11.0));
                    ui.label(RichText::new("Estado").weak().size(11.0));
                    ui.end_row();

                    for connection in self.filtered_connections().into_iter().take(500) {
                        let selected = self.selected_network_inode.as_ref() == Some(&connection.inode);
                        let mut clicked = false;

                        if ui
                            .selectable_label(selected, &connection.protocol)
                            .on_hover_text(format!("inode {}", connection.inode))
                            .clicked()
                        {
                            clicked = true;
                        }
                        if ui
                            .selectable_label(selected, connection.owner_label())
                            .on_hover_text(format!("inode {}", connection.inode))
                            .clicked()
                        {
                            clicked = true;
                        }
                        if ui
                            .selectable_label(selected, &connection.local_addr)
                            .on_hover_text(format!("inode {}", connection.inode))
                            .clicked()
                        {
                            clicked = true;
                        }
                        if ui
                            .selectable_label(selected, &connection.remote_addr)
                            .on_hover_text(format!("inode {}", connection.inode))
                            .clicked()
                        {
                            clicked = true;
                        }
                        if ui
                            .selectable_label(selected, &connection.state)
                            .on_hover_text(format!("inode {}", connection.inode))
                            .clicked()
                        {
                            clicked = true;
                        }

                        if clicked {
                            if selected {
                                self.selected_network_inode = None;
                            } else {
                                self.selected_network_inode = Some(connection.inode.clone());
                            }
                        }
                        ui.end_row();
                    }
                });
        });
    }

    fn show_explain(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("ASISTENTE DE INTELIGENCIA ARTIFICIAL").strong().size(10.0).color(ui.visuals().weak_text_color()));
        ui.add_space(6.0);

        // LLM Configuration Row - Clean Flat Minimalism
        ui.horizontal(|ui| {
            ui.label("Proveedor:");
            let prev_provider = self.provider;
            egui::ComboBox::from_id_source("llm_provider_combo")
                .selected_text(self.provider.label())
                .show_ui(ui, |ui| {
                    for p in LlmProvider::all() {
                        ui.selectable_value(&mut self.provider, *p, p.label());
                    }
                });

            if self.provider != prev_provider {
                // Update default model name when provider changes
                self.model_name = self.provider.default_model().to_string();
            }

            ui.separator();
            ui.label("Modelo:");
            ui.add(TextEdit::singleline(&mut self.model_name).desired_width(140.0));

            if self.provider != LlmProvider::Ollama {
                ui.separator();
                ui.label("API Key:");
                ui.add(TextEdit::singleline(&mut self.api_key).password(true).desired_width(140.0));
            }
        });

        ui.add_space(6.0);
        ui.separator();
        ui.add_space(6.0);

        ui.horizontal(|ui| {
            if ui.button("Build LLM prompt").clicked() {
                self.explain_prompt = self.build_prompt();
            }
            if ui.button("Build markdown evidence").clicked() {
                self.export_preview = self.build_markdown_export();
            }
            ui.separator();

            if self.analysis_loading {
                ui.add(egui::Spinner::new());
                ui.label("Analizando con IA...");
            } else {
                let enabled = !self.explain_prompt.is_empty() && (self.provider == LlmProvider::Ollama || !self.api_key.is_empty());
                if ui.add_enabled(enabled, egui::Button::new("✨ Analizar In-App")).clicked() {
                    self.analysis_loading = true;
                    self.analysis_result = "Iniciando análisis...".to_string();
                    self.active_tab = ExplainTab::Analysis; // Switch to analysis tab automatically
                    run_llm_analysis(
                        self.provider,
                        self.model_name.clone(),
                        self.api_key.clone(),
                        self.explain_prompt.clone(),
                        self.tx_analysis.clone(),
                    );
                }
            }
        });

        ui.add_space(8.0);

        // Scrollable workspace grid to prevent overflow bugs on small screen sizes
        egui::ScrollArea::vertical()
            .id_source("explain_workspace_scroll")
            .show(ui, |ui| {
                ui.columns(2, |columns| {
                    columns[0].vertical(|ui| {
                        ui.label(RichText::new("Prompt a enviar al LLM:").strong().size(11.0));
                        ui.add(
                            TextEdit::multiline(&mut self.explain_prompt)
                                .desired_rows(18)
                                .desired_width(f32::INFINITY)
                                .hint_text("Generá un prompt con el botón superior para editarlo o enviarlo"),
                        );
                    });

                    columns[1].vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.selectable_value(&mut self.active_tab, ExplainTab::Analysis, "✨ Análisis IA");
                            ui.selectable_value(&mut self.active_tab, ExplainTab::Evidence, "📝 Exportar Evidencia");
                        });

                        ui.separator();

                        match self.active_tab {
                            ExplainTab::Analysis => {
                                let mut text = self.analysis_result.clone();
                                ui.add(
                                    TextEdit::multiline(&mut text)
                                        .desired_rows(18)
                                        .desired_width(f32::INFINITY)
                                        .hint_text("El resultado de la IA aparecerá acá...")
                                );
                            }
                            ExplainTab::Evidence => {
                                ui.add(
                                    TextEdit::multiline(&mut self.export_preview)
                                        .desired_rows(18)
                                        .desired_width(f32::INFINITY)
                                        .hint_text("Acá se mostrará la evidencia en Markdown exportable"),
                                );
                            }
                        }
                    });
                });
            });
    }
}

impl eframe::App for VtLensApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Poll for snapshots from background thread
        if let Ok(snapshot) = self.rx_snapshot.try_recv() {
            if self.auto_refresh {
                self.processes = snapshot.processes;
                self.connections = snapshot.connections;
                self.status = snapshot.status;
            }
        }

        // Poll for LLM analysis results
        if let Ok(result) = self.rx_analysis.try_recv() {
            self.analysis_loading = false;
            match result {
                Ok(content) => {
                    self.analysis_result = content;
                }
                Err(err) => {
                    self.analysis_result = format!("Error: {err}");
                }
            }
        }

        ctx.request_repaint_after(Duration::from_millis(500));

        egui::TopBottomPanel::top("header")
            .frame(egui::Frame::none().fill(egui::Color32::from_rgb(255, 255, 255)).inner_margin(12.0))
            .show(ctx, |ui| self.show_header(ui));

        egui::TopBottomPanel::bottom("status_bar")
            .frame(egui::Frame::none().fill(egui::Color32::from_rgb(249, 250, 251)).inner_margin(egui::Margin::symmetric(12.0, 6.0)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&self.status).weak().size(11.0));
                });
            });

        egui::SidePanel::left("processes")
            .resizable(true)
            .default_width(320.0)
            .frame(egui::Frame::none().fill(egui::Color32::from_rgb(249, 250, 251)).inner_margin(12.0))
            .show(ctx, |ui| self.show_processes(ui));

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(egui::Color32::from_rgb(255, 255, 255)).inner_margin(16.0))
            .show(ctx, |ui| {
                // Tab Selector Row
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.central_tab, CentralTab::Network, "🌐 Conexiones de Red");
                    ui.selectable_value(&mut self.central_tab, CentralTab::LlmWorkspace, "🤖 Asistente de IA");
                });
                ui.add_space(4.0);
                ui.separator();
                ui.add_space(8.0);

                // Render current active tab
                match self.central_tab {
                    CentralTab::Network => {
                        self.show_network(ui);
                    }
                    CentralTab::LlmWorkspace => {
                        self.show_explain(ui);
                    }
                }
            });
    }
}

fn run_llm_analysis(
    provider: LlmProvider,
    model_name: String,
    api_key: String,
    prompt: String,
    tx: std::sync::mpsc::Sender<Result<String, String>>,
) {
    std::thread::spawn(move || {
        let result = perform_llm_request(provider, model_name, api_key, prompt);
        let _ = tx.send(result);
    });
}

fn perform_llm_request(
    provider: LlmProvider,
    model_name: String,
    api_key: String,
    prompt: String,
) -> Result<String, String> {
    let url = provider.default_url();
    let mut request = ureq::post(url);

    match provider {
        LlmProvider::OpenRouter => {
            if api_key.trim().is_empty() {
                return Err("API Key is required for OpenRouter".to_string());
            }
            request = request
                .set("Authorization", &format!("Bearer {}", api_key.trim()))
                .set("Content-Type", "application/json")
                .set("HTTP-Referer", "https://github.com/ValentinTorassa/vt-lens")
                .set("X-Title", "VT Lens");
        }
        LlmProvider::OpenAI => {
            if api_key.trim().is_empty() {
                return Err("API Key is required for OpenAI".to_string());
            }
            request = request
                .set("Authorization", &format!("Bearer {}", api_key.trim()))
                .set("Content-Type", "application/json");
        }
        LlmProvider::Anthropic => {
            if api_key.trim().is_empty() {
                return Err("API Key is required for Anthropic".to_string());
            }
            request = request
                .set("x-api-key", api_key.trim())
                .set("anthropic-version", "2023-06-01")
                .set("Content-Type", "application/json");
        }
        LlmProvider::Ollama => {
            request = request.set("Content-Type", "application/json");
        }
    }

    let body = match provider {
        LlmProvider::OpenRouter | LlmProvider::OpenAI => {
            serde_json::json!({
                "model": model_name,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            })
        }
        LlmProvider::Anthropic => {
            serde_json::json!({
                "model": model_name,
                "max_tokens": 2048,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            })
        }
        LlmProvider::Ollama => {
            serde_json::json!({
                "model": model_name,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "stream": false
            })
        }
    };

    let response = request
        .send_json(body)
        .map_err(|err| format!("HTTP request failed: {err}"))?;

    let status = response.status();
    if status < 200 || status >= 300 {
        let err_body = response.into_string().unwrap_or_else(|_| "Unknown error".to_string());
        return Err(format!("Server returned status {status}: {err_body}"));
    }

    let json_resp: serde_json::Value = response
        .into_json()
        .map_err(|err| format!("Failed to parse response JSON: {err}"))?;

    match provider {
        LlmProvider::OpenRouter | LlmProvider::OpenAI => {
            let content = json_resp["choices"][0]["message"]["content"]
                .as_str()
                .ok_or_else(|| format!("Invalid response format: {json_resp}"))?;
            Ok(content.to_string())
        }
        LlmProvider::Anthropic => {
            let content = json_resp["content"][0]["text"]
                .as_str()
                .ok_or_else(|| format!("Invalid response format: {json_resp}"))?;
            Ok(content.to_string())
        }
        LlmProvider::Ollama => {
            let content = json_resp["message"]["content"]
                .as_str()
                .ok_or_else(|| format!("Invalid response format: {json_resp}"))?;
            Ok(content.to_string())
        }
    }
}

pub fn capture_system_snapshot() -> ProcSnapshot {
    let owners = socket_owners();
    let mut processes = read_processes();
    let mut socket_counts: HashMap<u32, usize> = HashMap::new();

    for owner in owners.values() {
        *socket_counts.entry(owner.pid).or_default() += 1;
    }

    for process in &mut processes {
        process.socket_count = socket_counts.get(&process.pid).copied().unwrap_or(0);
    }

    let connections = read_connections(&owners);
    let status = format!(
        "{} processes · {} connections · connection-level capture (no root)",
        processes.len(),
        connections.len()
    );

    ProcSnapshot {
        processes,
        connections,
        status,
    }
}
