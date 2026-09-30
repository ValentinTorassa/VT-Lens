use std::collections::HashMap;
use std::time::{Duration, Instant};

use eframe::egui::{self, RichText, TextEdit};

use crate::capture::{read_connections, read_processes, socket_owners};
use crate::evidence::{self, EndpointClass, EvidenceInput};
use crate::keyring::{self, Action as KeyringAction, Outcome as KeyringOutcome};
use crate::model::{NetRow, ProcessRow};
use crate::redaction::redact_with_terms;

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

    fn keyring_name(&self) -> &'static str {
        match self {
            Self::OpenRouter => "openrouter",
            Self::OpenAI => "openai",
            Self::Anthropic => "anthropic",
            Self::Ollama => "ollama",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetFilterType {
    All,
    External,
    Localhost,
    Listening,
    Tcp,
    Udp,
}

pub struct ProcSnapshot {
    pub processes: Vec<ProcessRow>,
    pub connections: Vec<NetRow>,
    pub status: String,
}

struct DnsRequest {
    ip: String,
    ctx: egui::Context,
}

enum LlmMessage {
    Start,
    Chunk(String),
    End(Result<(), String>),
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
    private_terms: String,
    status: String,
    demo_mode: bool,
    auto_refresh: bool,
    tx_snapshot: std::sync::mpsc::Sender<ProcSnapshot>,
    rx_snapshot: std::sync::mpsc::Receiver<ProcSnapshot>,
    // LLM Analysis Integration
    api_key: String,
    keyring_status: String,
    tx_keyring: std::sync::mpsc::Sender<(&'static str, Result<KeyringOutcome, String>)>,
    rx_keyring: std::sync::mpsc::Receiver<(&'static str, Result<KeyringOutcome, String>)>,
    provider: LlmProvider,
    model_name: String,
    analysis_result: String,
    analysis_loading: bool,
    analysis_prepared: bool,
    net_filter_type: NetFilterType,
    tx_analysis: std::sync::mpsc::Sender<LlmMessage>,
    rx_analysis: std::sync::mpsc::Receiver<LlmMessage>,
    only_network_active: bool,
    // Performance Optimization Caches
    filtered_processes_cache: Vec<ProcessRow>,
    filtered_connections_cache: Vec<NetRow>,
    metric_processes_count: usize,
    metric_sockets_count: usize,
    metric_external_count: usize,
    metric_listening_count: usize,
    metric_udp_multicast_count: usize,
    last_snapshot_time: Instant,
    // DNS Resolution
    dns_cache: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>,
    dns_resolving: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    tx_dns: std::sync::mpsc::Sender<DnsRequest>,
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
        let (tx_keyring, rx_keyring) = std::sync::mpsc::channel();
        let (tx_snapshot, rx_snapshot) = std::sync::mpsc::channel();

        // Spawn background polling thread loop
        let tx_snapshot_clone = tx_snapshot.clone();
        let ctx_clone = cc.egui_ctx.clone();
        let demo_mode = std::env::args().any(|arg| arg == "--demo");
        std::thread::spawn(move || {
            loop {
                let snapshot = if demo_mode { demo_snapshot() } else { capture_system_snapshot() };
                if tx_snapshot_clone.send(snapshot).is_err() {
                    break;
                }
                ctx_clone.request_repaint(); // immediately trigger repaint in the GUI thread
                std::thread::sleep(Duration::from_secs(2));
            }
        });

        // Spawn background DNS resolver thread
        let (tx_dns, rx_dns) = std::sync::mpsc::channel::<DnsRequest>();
        let dns_cache = std::sync::Arc::new(std::sync::Mutex::new(HashMap::new()));
        let dns_resolving = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));

        let dns_cache_clone = dns_cache.clone();
        let dns_resolving_clone = dns_resolving.clone();
        std::thread::spawn(move || {
            while let Ok(request) = rx_dns.recv() {
                let ip_str = request.ip.clone();
                let (clean_ip, port_suffix) = if let Some(pos) = ip_str.find(':') {
                    (&ip_str[..pos], &ip_str[pos..])
                } else {
                    (&ip_str[..], "")
                };

                if let Ok(ip_addr) = clean_ip.parse::<std::net::IpAddr>() {
                    match dns_lookup::lookup_addr(&ip_addr) {
                        Ok(hostname) => {
                            let display_name = format!("{}{}", hostname, port_suffix);
                            if let Ok(mut cache) = dns_cache_clone.lock() {
                                cache.insert(ip_str.clone(), display_name);
                            }
                        }
                        Err(_) => {
                            // If resolution fails, store it mapped to itself to avoid repeated retries
                            if let Ok(mut cache) = dns_cache_clone.lock() {
                                cache.insert(ip_str.clone(), ip_str.clone());
                            }
                        }
                    }
                }

                if let Ok(mut resolving) = dns_resolving_clone.lock() {
                    resolving.remove(&ip_str);
                }
                request.ctx.request_repaint();
            }
        });

        let mut app = Self {
            processes: Vec::new(),
            connections: Vec::new(),
            selected_pid: None,
            selected_network_inode: None,
            process_filter: String::new(),
            network_filter: String::new(),
            explain_prompt: String::new(),
            export_preview: String::new(),
            private_terms: String::new(),
            status: "Starting capture".to_string(),
            demo_mode,
            auto_refresh: true,
            tx_snapshot,
            rx_snapshot,
            api_key: String::new(),
            keyring_status: String::new(),
            tx_keyring,
            rx_keyring,
            provider: LlmProvider::OpenRouter,
            model_name: LlmProvider::OpenRouter.default_model().to_string(),
            analysis_result: String::new(),
            analysis_loading: false,
            analysis_prepared: false,
            net_filter_type: NetFilterType::All,
            tx_analysis,
            rx_analysis,
            only_network_active: false,
            filtered_processes_cache: Vec::new(),
            filtered_connections_cache: Vec::new(),
            metric_processes_count: 0,
            metric_sockets_count: 0,
            metric_external_count: 0,
            metric_listening_count: 0,
            metric_udp_multicast_count: 0,
            last_snapshot_time: Instant::now(),
            dns_cache,
            dns_resolving,
            tx_dns,
        };

        app.update_caches();
        if !app.demo_mode {
            app.run_keyring_action(KeyringAction::Load, &cc.egui_ctx);
        }
        app
    }

    fn run_keyring_action(&self, action: KeyringAction, ctx: &egui::Context) {
        let provider = self.provider.keyring_name();
        let tx = self.tx_keyring.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = keyring::perform(provider, action);
            let _ = tx.send((provider, result));
            ctx.request_repaint();
        });
    }

    fn classify_endpoint(addr: &str) -> EndpointClass {
        evidence::classify(addr)
    }

    #[allow(dead_code)]
    fn connection_belongs_to_process(&self, connection: &NetRow, pid: u32) -> bool {
        connection.owner.as_ref().map(|owner| owner.pid) == Some(pid)
    }

    #[allow(dead_code)]
    fn is_external_connection(&self, connection: &NetRow) -> bool {
        Self::classify_endpoint(&connection.remote_addr) == EndpointClass::External
    }

    #[allow(dead_code)]
    fn is_loopback_connection(&self, connection: &NetRow) -> bool {
        Self::classify_endpoint(&connection.remote_addr) == EndpointClass::Localhost
    }

    #[allow(dead_code)]
    fn is_multicast_connection(&self, connection: &NetRow) -> bool {
        Self::classify_endpoint(&connection.remote_addr) == EndpointClass::Multicast
    }

    #[allow(dead_code)]
    fn is_listening_socket(&self, connection: &NetRow) -> bool {
        connection.state == "LISTEN"
    }

    #[allow(dead_code)]
    fn classify_connection(&self, connection: &NetRow) -> EndpointClass {
        Self::classify_endpoint(&connection.remote_addr)
    }

    fn reset_view(&mut self) {
        self.selected_pid = None;
        self.selected_network_inode = None;
        self.process_filter.clear();
        self.network_filter.clear();
        self.net_filter_type = NetFilterType::All;
        self.update_caches();
    }

    fn clear_selected_process(&mut self) {
        self.selected_pid = None;
        self.selected_network_inode = None;
        self.update_caches();
    }

    #[allow(dead_code)]
    fn clear_selected_connection(&mut self) {
        self.selected_network_inode = None;
        self.update_caches();
    }

    fn clear_all_filters(&mut self) {
        self.process_filter.clear();
        self.network_filter.clear();
        self.net_filter_type = NetFilterType::All;
        self.update_caches();
    }



    fn update_caches(&mut self) {
        // 1. Precalculate metrics (Processes, Sockets, External, Listening, UDP/Multicast counts)
        self.metric_processes_count = self.processes.len();
        self.metric_sockets_count = self.connections.len();
        
        let mut ext_count = 0;
        let mut listen_count = 0;
        let mut udp_multi_count = 0;

        for conn in &self.connections {
            let class = Self::classify_endpoint(&conn.remote_addr);
            if class == EndpointClass::External {
                ext_count += 1;
            }
            if conn.state == "LISTEN" {
                listen_count += 1;
            }
            if conn.protocol.starts_with("udp") || class == EndpointClass::Multicast {
                udp_multi_count += 1;
            }
        }

        self.metric_external_count = ext_count;
        self.metric_listening_count = listen_count;
        self.metric_udp_multicast_count = udp_multi_count;

        // 2. Filter processes cache
        let proc_filter = self.process_filter.trim().to_lowercase();
        let only_active = self.only_network_active;
        let mut filtered_procs: Vec<ProcessRow> = self.processes
            .iter()
            .filter(|process| {
                if only_active && process.socket_count == 0 {
                    return false;
                }
                proc_filter.is_empty()
                    || process.pid.to_string().contains(&proc_filter)
                    || process.name.to_lowercase().contains(&proc_filter)
                    || process.cmdline.to_lowercase().contains(&proc_filter)
            })
            .cloned()
            .collect();

        // Sort by socket count descending, then by name
        filtered_procs.sort_by(|a, b| {
            b.socket_count.cmp(&a.socket_count)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });

        self.filtered_processes_cache = filtered_procs;

        // 3. Filter connections cache
        let net_filter = self.network_filter.trim().to_lowercase();
        self.filtered_connections_cache = self.connections
            .iter()
            .filter(|connection| {
                if let Some(selected_pid) = self.selected_pid {
                    if connection.owner.as_ref().map(|owner| owner.pid) != Some(selected_pid) {
                        return false;
                    }
                }

                match self.net_filter_type {
                    NetFilterType::All => {}
                    NetFilterType::External => {
                        if Self::classify_endpoint(&connection.remote_addr) != EndpointClass::External {
                            return false;
                        }
                    }
                    NetFilterType::Localhost => {
                        if Self::classify_endpoint(&connection.remote_addr) != EndpointClass::Localhost {
                            return false;
                        }
                    }
                    NetFilterType::Listening => {
                        if connection.state != "LISTEN" {
                            return false;
                        }
                    }
                    NetFilterType::Tcp => {
                        if !connection.protocol.starts_with("tcp") {
                            return false;
                        }
                    }
                    NetFilterType::Udp => {
                        if !connection.protocol.starts_with("udp") {
                            return false;
                        }
                    }
                }

                net_filter.is_empty()
                    || connection.protocol.to_lowercase().contains(&net_filter)
                    || connection.local_addr.to_lowercase().contains(&net_filter)
                    || connection.remote_addr.to_lowercase().contains(&net_filter)
                    || connection.state.to_lowercase().contains(&net_filter)
                    || connection.owner_label().to_lowercase().contains(&net_filter)
            })
            .cloned()
            .collect();

        // 4. Validate selected connection matches selected process PID
        if let Some(inode) = &self.selected_network_inode {
            if let Some(connection) = self.connections.iter().find(|c| &c.inode == inode) {
                if let Some(selected_pid) = self.selected_pid {
                    if connection.owner.as_ref().map(|owner| owner.pid) != Some(selected_pid) {
                        self.selected_network_inode = None;
                    }
                }
            } else {
                self.selected_network_inode = None;
            }
        }
    }

    fn selected_process(&self) -> Option<&ProcessRow> {
        self.selected_pid
            .and_then(|pid| self.processes.iter().find(|process| process.pid == pid))
    }

    fn evidence_input(&self) -> EvidenceInput<'_> {
        EvidenceInput {
            processes: &self.processes,
            connections: &self.connections,
            selected_pid: self.selected_pid,
            selected_inode: self.selected_network_inode.as_deref(),
            sample: &self.filtered_connections_cache,
        }
    }

    /// Allowlisted evidence only (see evidence.rs): no cmdline, IPs or hostnames.
    fn build_ai_evidence(&self) -> String {
        evidence::build_evidence(&self.evidence_input())
    }

    fn build_ai_prompt(&self) -> String {
        let mut prompt = String::from(
            "You are a Linux security educator and local system observability assistant.\n\n\
             Explain the following local Linux process and socket evidence in plain Spanish for Argentina/LatAm.\n\n\
             Rules:\n\
             * Be direct, practical, and technical.\n\
             * Do not invent facts.\n\
             * Do not claim the remote IP belongs to a company unless the evidence explicitly includes hostname or enrichment data.\n\
             * Treat the raw evidence as the source of truth.\n\
             * Explain what is likely happening, what looks normal, what deserves attention, and what the learner should verify manually.\n\
             * If evidence is incomplete, say what is missing.\n\
             * Always suggest concrete Linux commands to verify the finding manually.\n\
             * Keep the tone educational, not alarmist.\n\n\
             System context:\n\
             * Capture source: /proc\n\
             * No root privileges\n\
             * Connection-level capture only\n\
             * No packet payload inspection\n\
             * No DNS ownership verification unless hostname is present\n\n\
             Answer format:\n\
             1. Resumen corto\n\
             2. Qué está pasando probablemente\n\
             3. Qué parece normal\n\
             4. Qué merece atención\n\
             5. Cómo verificarlo manualmente\n\
             6. Limitaciones de esta evidencia\n\n"
        );

        prompt.push_str("--- REDACTED EVIDENCE ---\n");
        prompt.push_str(&redact_with_terms(&self.build_ai_evidence(), &self.private_terms));
        prompt
    }

    fn build_prompt(&self) -> String {
        self.build_ai_prompt()
    }

    fn build_markdown_export(&self) -> String {
        redact_with_terms(&evidence::build_markdown(&self.evidence_input(), &self.status), &self.private_terms)
    }

    fn show_header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(RichText::new("VT LENS").strong().size(15.0));
                ui.label(RichText::new(if self.demo_mode { "DEMO · datos sintéticos · sin captura del equipo" } else { "Local system visibility · no root · /proc based" }).weak().size(10.0));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("⟳ Refresh").clicked() {
                    let tx = self.tx_snapshot.clone();
                    let ctx = ui.ctx().clone();
                    let demo_mode = self.demo_mode;
                    std::thread::spawn(move || {
                        let snapshot = if demo_mode { demo_snapshot() } else { capture_system_snapshot() };
                        let _ = tx.send(snapshot);
                        ctx.request_repaint();
                    });
                }
                ui.checkbox(&mut self.auto_refresh, "Auto refresh");
            });
        });
    }

    fn show_processes(&mut self, ui: &mut egui::Ui) {
        if ui.button("🌐 Ver todas las conexiones").clicked() {
            self.reset_view();
        }
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            ui.label(RichText::new("PROCESOS").strong().size(10.0).color(ui.visuals().weak_text_color()));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.checkbox(&mut self.only_network_active, "Solo activos 🌐");
            });
        });
        ui.add_space(4.0);
        ui.add(TextEdit::singleline(&mut self.process_filter).hint_text("🔍 filter pid, name...").desired_width(f32::INFINITY));
        ui.add_space(8.0);

        let total_rows = self.filtered_processes_cache.len();
        let row_height = 48.0;

        egui::ScrollArea::vertical().show_rows(ui, row_height, total_rows, |ui, row_range| {
            for idx in row_range {
                let (process_pid, process_name, process_socket_count, process_rss_mb) = {
                    let p = &self.filtered_processes_cache[idx];
                    (p.pid, p.name.clone(), p.socket_count, p.rss_mb())
                };

                let selected = self.selected_pid == Some(process_pid);
                let card_color = if selected {
                    egui::Color32::from_rgb(243, 244, 246)
                } else {
                    egui::Color32::from_rgb(255, 255, 255)
                };

                let ext_count = self.connections.iter().filter(|c| {
                    c.owner.as_ref().map(|o| o.pid) == Some(process_pid) 
                        && Self::classify_endpoint(&c.remote_addr) == EndpointClass::External
                }).count();

                let response = egui::Frame::none()
                    .fill(card_color)
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(229, 231, 235)))
                    .rounding(6.0)
                    .inner_margin(egui::Margin::symmetric(10.0, 8.0))
                    .show(ui, |ui| {
                        ui.vertical(|ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(&process_name).strong().size(12.0));
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if selected {
                                        if ui.small_button("×").clicked() {
                                            self.clear_selected_process();
                                        }
                                    } else if process_socket_count > 0 {
                                        let label_text = if ext_count > 0 {
                                            format!("{} 🌐 ({} ext)", process_socket_count, ext_count)
                                        } else {
                                            format!("{} 🌐", process_socket_count)
                                        };
                                        ui.label(RichText::new(label_text).weak().size(9.0));
                                    }
                                });
                            });
                            ui.add_space(2.0);
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(format!("PID {}", process_pid)).weak().monospace().size(10.0));
                                ui.separator();
                                ui.label(RichText::new(format!("{:.1} MB", process_rss_mb)).weak().size(10.0));
                            });
                        });
                    });

                let response = response.response.interact(egui::Sense::click());
                if response.clicked() {
                    if selected {
                        self.clear_selected_process();
                    } else {
                        self.selected_pid = Some(process_pid);
                        self.selected_network_inode = None;
                        self.network_filter.clear();
                    }
                }
                ui.add_space(4.0);
            }
        });
    }

    fn render_active_context_banner(&mut self, ui: &mut egui::Ui) {
        let selected_info = self.selected_process().map(|p| (p.name.clone(), p.pid, p.socket_count));
        let width = ui.available_width();
        
        egui::Frame::none()
            .fill(egui::Color32::from_rgb(255, 255, 255))
            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(229, 231, 235)))
            .rounding(8.0)
            .inner_margin(egui::Margin::symmetric(14.0, 10.0))
            .show(ui, |ui| {
                if width < 520.0 {
                    ui.vertical(|ui| {
                        ui.vertical(|ui| {
                            if let Some((name, pid, socket_count)) = &selected_info {
                                ui.label(RichText::new(format!("🕵️ Investigando: {}", name)).strong().size(13.0));
                                ui.label(RichText::new(format!("PID {} · {} sockets", pid, socket_count)).weak().size(10.0));
                            } else {
                                ui.label(RichText::new("🌐 Todas las conexiones").strong().size(13.0));
                                ui.label(RichText::new("Mostrando sockets activos desde /proc").weak().size(10.0));
                            }
                        });
                        
                        if selected_info.is_some() {
                            ui.add_space(6.0);
                            ui.horizontal_wrapped(|ui| {
                                if ui.button("Ver todo").clicked() {
                                    self.clear_selected_process();
                                }
                                if ui.button("Limpiar").clicked() {
                                    self.clear_all_filters();
                                }
                                if ui.button("✨ Analizar").clicked() {
                                    self.analysis_loading = true;
                                    self.analysis_result = "Iniciando análisis...".to_string();
                                    run_llm_analysis(
                                        self.provider,
                                        self.model_name.clone(),
                                        self.api_key.clone(),
                                        redact_with_terms(&self.build_prompt(), &self.private_terms),
                                        self.tx_analysis.clone(),
                                        ui.ctx().clone(),
                                    );
                                }
                            });
                        }
                    });
                } else {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            if let Some((name, pid, socket_count)) = &selected_info {
                                ui.label(RichText::new(format!("🕵️ Investigando: {}", name)).strong().size(13.0));
                                ui.label(RichText::new(format!("PID {} · {} sockets detectados", pid, socket_count)).weak().size(10.0));
                            } else {
                                ui.label(RichText::new("🌐 Todas las conexiones").strong().size(13.0));
                                ui.label(RichText::new("Mostrando sockets activos capturados desde /proc").weak().size(10.0));
                            }
                        });
                        
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if selected_info.is_some() {
                                if ui.button("Ver todas las conexiones").clicked() {
                                    self.clear_selected_process();
                                }
                                if ui.button("Limpiar filtros").clicked() {
                                    self.clear_all_filters();
                                }
                                if ui.button("✨ Analizar con IA").clicked() {
                                    self.analysis_loading = true;
                                    self.analysis_result = "Iniciando análisis...".to_string();
                                    run_llm_analysis(
                                        self.provider,
                                        self.model_name.clone(),
                                        self.api_key.clone(),
                                        redact_with_terms(&self.build_prompt(), &self.private_terms),
                                        self.tx_analysis.clone(),
                                        ui.ctx().clone(),
                                    );
                                }
                            }
                        });
                    });
                }
            });
    }

    fn render_filter_chips(&mut self, ui: &mut egui::Ui) -> bool {
        let mut changed = false;
        let has_filters = self.selected_pid.is_some() 
            || self.net_filter_type != NetFilterType::All 
            || !self.network_filter.trim().is_empty();
            
        if has_filters {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Filtros activos:").weak().size(10.0));
                
                if let Some(pid) = self.selected_pid {
                    let proc_name = self.processes.iter().find(|p| p.pid == pid).map(|p| p.name.as_str()).unwrap_or("Proceso");
                    let chip_text = format!("Proceso: {} ({}) ✕", proc_name, pid);
                    if ui.button(RichText::new(chip_text).size(10.0).color(egui::Color32::from_rgb(180, 83, 9))).clicked() {
                        self.selected_pid = None;
                        self.selected_network_inode = None;
                        changed = true;
                    }
                }
                
                if self.net_filter_type != NetFilterType::All {
                    let type_str = match self.net_filter_type {
                        NetFilterType::External => "Externas",
                        NetFilterType::Localhost => "Localhost",
                        NetFilterType::Listening => "Escuchando",
                        NetFilterType::Tcp => "TCP",
                        NetFilterType::Udp => "UDP",
                        NetFilterType::All => "",
                    };
                    let chip_text = format!("Tipo: {} ✕", type_str);
                    if ui.button(RichText::new(chip_text).size(10.0).color(egui::Color32::from_rgb(180, 83, 9))).clicked() {
                        self.net_filter_type = NetFilterType::All;
                        changed = true;
                    }
                }
                
                if !self.network_filter.trim().is_empty() {
                    let chip_text = format!("Búsqueda: \"{}\" ✕", self.network_filter.trim());
                    if ui.button(RichText::new(chip_text).size(10.0).color(egui::Color32::from_rgb(180, 83, 9))).clicked() {
                        self.network_filter.clear();
                        changed = true;
                    }
                }
                
                ui.separator();
                
                if ui.button(RichText::new("Resetear vista").strong().size(10.0).color(egui::Color32::from_rgb(220, 38, 38))).clicked() {
                    self.reset_view();
                    changed = true;
                }
            });
            ui.add_space(4.0);
        }
        changed
    }

    fn render_empty_state(&mut self, ui: &mut egui::Ui) {
        let pid_str = self.selected_pid.map(|p| p.to_string()).unwrap_or_else(|| "Ninguno".to_string());
        let reported_sockets = self.selected_process().map(|p| p.socket_count.to_string()).unwrap_or_else(|| "0".to_string());
        let pid_connections_count = if let Some(pid) = self.selected_pid {
            self.connections.iter().filter(|c| c.owner.as_ref().map(|o| o.pid) == Some(pid)).count()
        } else {
            self.connections.len()
        };
        let visible_count = self.filtered_connections_cache.len();

        ui.vertical_centered(|ui| {
            ui.add_space(40.0);
            ui.label(RichText::new("⚠️ No hay conexiones visibles para este proceso").strong().size(14.0));
            ui.add_space(4.0);
            ui.label(RichText::new("Esto puede deberse a que el proceso cerró sus conexiones, el snapshot cambió o un filtro activo las está ocultando.").weak().size(11.0));
            ui.add_space(12.0);
            
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(243, 244, 246))
                .rounding(6.0)
                .inner_margin(12.0)
                .show(ui, |ui| {
                    ui.set_max_width(400.0);
                    ui.vertical(|ui| {
                        ui.label(RichText::new(format!("• PID seleccionado: {}", pid_str)).monospace().size(10.0));
                        ui.label(RichText::new(format!("• Sockets reportados por proceso: {}", reported_sockets)).monospace().size(10.0));
                        ui.label(RichText::new(format!("• Conexiones capturadas para este PID: {}", pid_connections_count)).monospace().size(10.0));
                        ui.label(RichText::new(format!("• Conexiones visibles después de filtros: {}", visible_count)).monospace().size(10.0));
                    });
                });
                
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                if ui.button("🌐 Ver todas las conexiones").clicked() {
                    self.clear_selected_process();
                }
                if ui.button("🧹 Limpiar filtros").clicked() {
                    self.clear_all_filters();
                }
                if ui.button("⟳ Refrescar ahora").clicked() {
                    let tx = self.tx_snapshot.clone();
                    let ctx = ui.ctx().clone();
                    let demo_mode = self.demo_mode;
                    std::thread::spawn(move || {
                        let snapshot = if demo_mode { demo_snapshot() } else { capture_system_snapshot() };
                        let _ = tx.send(snapshot);
                        ctx.request_repaint();
                    });
                }
            });
        });
    }

    fn show_network(&mut self, ui: &mut egui::Ui) {
        let processes_count = self.metric_processes_count;
        let sockets_count = self.metric_sockets_count;
        let external_count = self.metric_external_count;
        let listening_count = self.metric_listening_count;
        let udp_multicast_count = self.metric_udp_multicast_count;

        // 1. Metric cards row
        let metrics = [
            ("Procesos", processes_count.to_string()),
            ("Sockets", sockets_count.to_string()),
            ("Externas", external_count.to_string()),
            ("Escuchando", listening_count.to_string()),
            ("UDP/Multi", udp_multicast_count.to_string()),
        ];
        
        let available_w = ui.available_width();
        if available_w < 520.0 {
            ui.horizontal_wrapped(|ui| {
                for (label, val) in metrics.iter() {
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgb(255, 255, 255))
                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(229, 231, 235)))
                        .rounding(6.0)
                        .inner_margin(egui::Margin::symmetric(10.0, 6.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(format!("{}:", label)).weak().size(9.0));
                                ui.label(RichText::new(val.as_str()).strong().size(11.0).color(ui.visuals().selection.bg_fill));
                            });
                        });
                }
            });
        } else {
            ui.columns(5, |columns| {
                for (i, (label, val)) in metrics.iter().enumerate() {
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgb(255, 255, 255))
                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(229, 231, 235)))
                        .rounding(6.0)
                        .inner_margin(8.0)
                        .show(&mut columns[i], |ui| {
                            ui.vertical_centered(|ui| {
                                ui.label(RichText::new(*label).weak().size(9.0));
                                ui.label(RichText::new(val.as_str()).strong().size(16.0).color(ui.visuals().selection.bg_fill));
                            });
                        });
                }
            });
        }

        ui.add_space(8.0);

        // 2. Active investigation banner
        self.render_active_context_banner(ui);
        ui.add_space(8.0);

        // 3. Filter chips row & filter choices
        ui.horizontal(|ui| {
            ui.label(RichText::new("FILTROS:").strong().size(9.0).color(ui.visuals().weak_text_color()));
            ui.selectable_value(&mut self.net_filter_type, NetFilterType::All, "Todos");
            ui.selectable_value(&mut self.net_filter_type, NetFilterType::External, "🌐 Externas");
            ui.selectable_value(&mut self.net_filter_type, NetFilterType::Localhost, "🏠 Localhost");
            ui.selectable_value(&mut self.net_filter_type, NetFilterType::Listening, "👂 Escuchando");
            ui.selectable_value(&mut self.net_filter_type, NetFilterType::Tcp, "TCP");
            ui.selectable_value(&mut self.net_filter_type, NetFilterType::Udp, "UDP");
        });

        ui.add_space(6.0);
        
        let chip_changed = self.render_filter_chips(ui);
        if chip_changed {
            self.update_caches();
        }

        ui.add(TextEdit::singleline(&mut self.network_filter).hint_text("🔍 filter proto, addr, state, owner...").desired_width(f32::INFINITY));
        ui.add_space(8.0);

        // 4. Grid Table or Empty State
        if self.filtered_connections_cache.is_empty() {
            self.render_empty_state(ui);
        } else {
            egui::ScrollArea::both()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                egui::Grid::new("network_grid")
                    .striped(true)
                    .min_col_width(70.0)
                    .show(ui, |ui| {
                        ui.label(RichText::new("Proto").weak().size(11.0));
                        ui.label(RichText::new("Proceso dueño").weak().size(11.0));
                        ui.label(RichText::new("Local").weak().size(11.0));
                        ui.label(RichText::new("Remoto").weak().size(11.0));
                        ui.label(RichText::new("Estado").weak().size(11.0));
                        ui.end_row();

                        for connection in self.filtered_connections_cache.iter().take(500) {
                            let selected = self.selected_network_inode.as_ref() == Some(&connection.inode);
                            let mut clicked = false;

                            // Protocol chip cell
                            ui.horizontal(|ui| {
                                let (bg, fg) = if connection.protocol.starts_with("tcp") {
                                    (egui::Color32::from_rgb(224, 242, 254), egui::Color32::from_rgb(3, 105, 161))
                                } else {
                                    (egui::Color32::from_rgb(243, 244, 246), egui::Color32::from_rgb(55, 65, 81))
                                };
                                let resp = egui::Frame::none()
                                    .fill(bg)
                                    .rounding(3.0)
                                    .inner_margin(egui::Margin::symmetric(6.0, 2.0))
                                    .show(ui, |ui| {
                                        ui.label(RichText::new(connection.protocol.to_uppercase()).strong().size(9.0).color(fg));
                                    });
                                let r = resp.response.interact(egui::Sense::click());
                                if r.clicked() || r.double_clicked() { clicked = true; }
                            });

                            // Process cell
                            let owner_label = connection.owner_label();
                            let r_owner = ui.selectable_label(selected, &owner_label);
                            if r_owner.clicked() || r_owner.double_clicked() { clicked = true; }

                            // Local Addr cell
                            let r_local = ui.selectable_label(selected, RichText::new(&connection.local_addr).monospace().size(11.0));
                            if r_local.clicked() || r_local.double_clicked() { clicked = true; }

                            // Remote Addr cell with external/localhost highlighting and DNS resolution
                            let remote_class = Self::classify_endpoint(&connection.remote_addr);
                            let resolved_addr = if let Ok(cache) = self.dns_cache.lock() {
                                cache.get(&connection.remote_addr).cloned().unwrap_or_else(|| {
                                    if remote_class == EndpointClass::External || remote_class == EndpointClass::PrivateLan {
                                        if let Ok(mut resolving) = self.dns_resolving.lock() {
                                            if resolving.insert(connection.remote_addr.clone()) {
                                                let _ = self.tx_dns.send(DnsRequest {
                                                    ip: connection.remote_addr.clone(),
                                                    ctx: ui.ctx().clone(),
                                                });
                                            }
                                        }
                                    }
                                    connection.remote_addr.clone()
                                })
                            } else {
                                connection.remote_addr.clone()
                            };

                            let remote_text = match remote_class {
                                EndpointClass::Localhost => RichText::new(&resolved_addr).weak().monospace().size(11.0),
                                EndpointClass::Multicast => RichText::new(format!("{} 📢", resolved_addr)).weak().monospace().size(11.0),
                                EndpointClass::PrivateLan => RichText::new(format!("{} 🏠", resolved_addr)).weak().monospace().size(11.0),
                                EndpointClass::External => RichText::new(format!("{} 🌐", resolved_addr)).monospace().size(11.0).color(egui::Color32::from_rgb(14, 165, 233)),
                                _ => RichText::new(&resolved_addr).monospace().size(11.0),
                            };
                            let r_remote = ui.selectable_label(selected, remote_text);
                            if r_remote.clicked() || r_remote.double_clicked() { clicked = true; }

                            // State cell
                            ui.horizontal(|ui| {
                                let (bg, fg) = match connection.state.as_str() {
                                    "ESTABLISHED" => (egui::Color32::from_rgb(220, 252, 231), egui::Color32::from_rgb(22, 101, 52)),
                                    "LISTEN" => (egui::Color32::from_rgb(254, 243, 199), egui::Color32::from_rgb(146, 64, 14)),
                                    _ => (egui::Color32::from_rgb(243, 244, 246), egui::Color32::from_rgb(75, 85, 99)),
                                };
                                let resp = egui::Frame::none()
                                    .fill(bg)
                                    .rounding(3.0)
                                    .inner_margin(egui::Margin::symmetric(6.0, 2.0))
                                    .show(ui, |ui| {
                                        ui.label(RichText::new(&connection.state).strong().size(9.0).color(fg));
                                    });
                                let r = resp.response.interact(egui::Sense::click());
                                if r.clicked() || r.double_clicked() { clicked = true; }
                            });

                            if clicked {
                                if selected {
                                    self.selected_network_inode = None;
                                } else {
                                    self.selected_network_inode = Some(connection.inode.clone());
                                    if let Some(ref owner) = connection.owner {
                                        self.selected_pid = Some(owner.pid);
                                    }
                                }
                            }
                            ui.end_row();
                        }
                    });
            });
        }
    }

    fn ui_copyable_command(ui: &mut egui::Ui, command: &str) {
        ui.horizontal_wrapped(|ui| {
            if ui.small_button("📋").on_hover_text("Copiar al portapapeles").clicked() {
                ui.output_mut(|o| o.copied_text = command.to_string());
            }
            ui.add(egui::Label::new(RichText::new(command).monospace().size(10.0)).wrap(true));
        });
    }

    fn render_inspector_panel(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("INSPECTOR DETALLADO").strong().size(10.0).color(ui.visuals().weak_text_color()));
            ui.add_space(4.0);
            if ui.button("✕").on_hover_text("Limpiar selección").clicked() {
                self.selected_pid = None;
                self.selected_network_inode = None;
            }
        });
        ui.add_space(8.0);

        let mut focused_pid = self.selected_pid;
        let mut focused_process = self.selected_process().cloned();

        // Resolve connection owner if a socket is selected but no process selected
        let mut selected_conn = None;
        if let Some(inode) = &self.selected_network_inode {
            if let Some(connection) = self.connections.iter().find(|c| &c.inode == inode) {
                selected_conn = Some(connection.clone());
                if focused_pid.is_none() {
                    if let Some(owner) = &connection.owner {
                        focused_pid = Some(owner.pid);
                        focused_process = self.processes.iter().find(|p| p.pid == owner.pid).cloned();
                    }
                }
            }
        }

        egui::ScrollArea::vertical()
            .id_source("inspector_scroll_area")
            .show(ui, |ui| {
                // STATE B: Connection Selected
                if let Some(conn) = &selected_conn {
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgb(255, 255, 255))
                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(229, 231, 235)))
                        .rounding(6.0)
                        .inner_margin(12.0)
                        .show(ui, |ui| {
                            ui.vertical(|ui| {
                                ui.label(RichText::new("CONEXIÓN SELECCIONADA").strong().size(9.0).color(egui::Color32::from_rgb(14, 165, 233)));
                                ui.add_space(4.0);
                                
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(conn.protocol.to_uppercase()).strong().size(12.0));
                                    ui.separator();
                                    ui.label(RichText::new(&conn.state).strong().size(11.0));
                                });
                                ui.add_space(6.0);
                                
                                ui.label(RichText::new("Local:").weak().size(9.0));
                                ui.label(RichText::new(&conn.local_addr).monospace().size(11.0));
                                ui.add_space(2.0);
                                ui.label(RichText::new("Remoto:").weak().size(9.0));
                                let resolved = if let Ok(cache) = self.dns_cache.lock() {
                                    cache.get(&conn.remote_addr).cloned()
                                } else {
                                    None
                                };
                                
                                if let Some(dns) = resolved {
                                    if dns != conn.remote_addr {
                                        ui.label(RichText::new(format!("{} ({})", dns, conn.remote_addr)).monospace().size(11.0));
                                    } else {
                                        ui.label(RichText::new(&conn.remote_addr).monospace().size(11.0));
                                    }
                                } else {
                                    ui.label(RichText::new(&conn.remote_addr).monospace().size(11.0));
                                }
                                ui.add_space(4.0);
                                
                                let class = Self::classify_endpoint(&conn.remote_addr);
                                let class_label = match class {
                                    EndpointClass::Localhost => "Localhost (Tráfico local interno)",
                                    EndpointClass::PrivateLan => "Private LAN (Red privada local)",
                                    EndpointClass::Listening => "Listening (Escuchando conexiones)",
                                    EndpointClass::Multicast => "Multicast (Transmisión grupal)",
                                    EndpointClass::External => "External (Servidor/IP externa)",
                                    EndpointClass::Unknown => "Desconocido",
                                };
                                ui.label(RichText::new(format!("Clasificación: {}", class_label)).size(10.0));
                                ui.label(RichText::new(format!("Inode: {}", conn.inode)).weak().monospace().size(10.0));
                                
                                if let Some(owner) = &conn.owner {
                                    ui.add_space(4.0);
                                    ui.label(RichText::new(format!("Proceso dueño: {} (PID {})", owner.process, owner.pid)).size(10.0));
                                }
                            });
                        });
                    ui.add_space(10.0);

                    // Verification commands for connection
                    if let Some(pid) = focused_pid {
                        ui.label(RichText::new("VERIFICACIÓN MANUAL").strong().size(10.0).color(ui.visuals().weak_text_color()));
                        ui.add_space(2.0);
                        egui::Frame::none()
                            .fill(egui::Color32::from_rgb(249, 250, 251))
                            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(229, 231, 235)))
                            .rounding(6.0)
                            .inner_margin(8.0)
                            .show(ui, |ui| {
                                ui.vertical(|ui| {
                                    Self::ui_copyable_command(ui, &format!("ss -tunap | grep {}", pid));
                                    ui.add_space(4.0);
                                    Self::ui_copyable_command(ui, &format!("lsof -p {} -i", pid));
                                    ui.add_space(4.0);
                                    Self::ui_copyable_command(ui, &format!("ps -fp {}", pid));
                                    ui.add_space(4.0);
                                    Self::ui_copyable_command(ui, &format!("readlink /proc/{}/fd/* 2>/dev/null | grep 'socket:\\[{}\\]'", pid, conn.inode));
                                });
                            });
                        ui.add_space(10.0);
                    }
                }
                // STATE A: Process Selected, No Connection Selected
                else if let Some(p) = focused_process {
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgb(255, 255, 255))
                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(229, 231, 235)))
                        .rounding(6.0)
                        .inner_margin(12.0)
                        .show(ui, |ui| {
                            ui.vertical(|ui| {
                                ui.label(RichText::new("PROCESO SELECCIONADO").strong().size(9.0).color(ui.visuals().selection.bg_fill));
                                ui.label(RichText::new(&p.name).strong().size(14.0));
                                ui.add_space(4.0);
                                ui.label(RichText::new(format!("PID: {}", p.pid)).monospace().size(11.0));
                                ui.label(RichText::new(format!("Estado: {}", p.state)).size(11.0));
                                ui.label(RichText::new(format!("Memoria: {:.1} MB", p.rss_mb())).size(11.0));
                                ui.label(RichText::new(format!("Threads: {}", p.threads)).size(11.0));
                                ui.label(RichText::new(format!("Sockets reportados: {}", p.socket_count)).size(11.0));
                                ui.add_space(4.0);
                                ui.label(RichText::new("Comando:").weak().size(9.0));
                                egui::ScrollArea::vertical()
                                    .id_source("cmdline_scroll")
                                    .max_height(60.0)
                                    .show(ui, |ui| {
                                        ui.add(egui::Label::new(RichText::new(&p.cmdline).monospace().size(9.0)).wrap(true));
                                    });
                            });
                        });
                    ui.add_space(10.0);

                    // Connection Summary Card for Process
                    let pid_conns: Vec<&NetRow> = self.connections.iter().filter(|c| c.owner.as_ref().map(|o| o.pid) == Some(p.pid)).collect();
                    let total = pid_conns.len();
                    let ext = pid_conns.iter().filter(|c| Self::classify_endpoint(&c.remote_addr) == EndpointClass::External).count();
                    let local = pid_conns.iter().filter(|c| Self::classify_endpoint(&c.remote_addr) == EndpointClass::Localhost).count();
                    let listen = pid_conns.iter().filter(|c| c.state == "LISTEN").count();
                    let udp_multi = pid_conns.iter().filter(|c| c.protocol.starts_with("udp") || Self::classify_endpoint(&c.remote_addr) == EndpointClass::Multicast).count();

                    egui::Frame::none()
                        .fill(egui::Color32::from_rgb(255, 255, 255))
                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(229, 231, 235)))
                        .rounding(6.0)
                        .inner_margin(12.0)
                        .show(ui, |ui| {
                            ui.vertical(|ui| {
                                ui.label(RichText::new("CONEXIONES DE ESTE PROCESO").strong().size(9.0).color(egui::Color32::from_rgb(22, 163, 74)));
                                ui.add_space(4.0);
                                ui.label(RichText::new(format!("• Total conexiones: {}", total)).size(11.0));
                                ui.label(RichText::new(format!("• Externas: {}", ext)).size(11.0));
                                ui.label(RichText::new(format!("• Localhost: {}", local)).size(11.0));
                                ui.label(RichText::new(format!("• Escuchando: {}", listen)).size(11.0));
                                ui.label(RichText::new(format!("• UDP/Multicast: {}", udp_multi)).size(11.0));
                            });
                        });
                    ui.add_space(10.0);

                    // Verification commands for process
                    ui.label(RichText::new("VERIFICACIÓN MANUAL").strong().size(10.0).color(ui.visuals().weak_text_color()));
                    ui.add_space(2.0);
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgb(249, 250, 251))
                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(229, 231, 235)))
                        .rounding(6.0)
                        .inner_margin(8.0)
                        .show(ui, |ui| {
                            ui.vertical(|ui| {
                                Self::ui_copyable_command(ui, &format!("ps -fp {}", p.pid));
                                ui.add_space(4.0);
                                Self::ui_copyable_command(ui, &format!("ls -l /proc/{}/fd | grep socket", p.pid));
                                ui.add_space(4.0);
                                Self::ui_copyable_command(ui, &format!("ss -tunap | grep {}", p.pid));
                                ui.add_space(4.0);
                                Self::ui_copyable_command(ui, &format!("lsof -p {} -i", p.pid));
                            });
                        });
                    ui.add_space(10.0);
                }

                // AI Assistant integrated
                ui.separator();
                ui.add_space(4.0);
                ui.label(RichText::new("ASISTENTE DE SEGURIDAD IA").strong().size(10.0).color(ui.visuals().weak_text_color()));
                ui.add_space(4.0);

                ui.horizontal(|ui| {
                    let prev_provider = self.provider;
                    egui::ComboBox::from_id_source("inspector_provider_combo")
                        .selected_text(self.provider.label())
                        .show_ui(ui, |ui| {
                            for p in LlmProvider::all() {
                                ui.selectable_value(&mut self.provider, *p, p.label());
                            }
                        });
                    if self.provider != prev_provider {
                        self.model_name = self.provider.default_model().to_string();
                        self.api_key.clear();
                        self.keyring_status.clear();
                        if !self.demo_mode && self.provider != LlmProvider::Ollama {
                            self.run_keyring_action(KeyringAction::Load, ui.ctx());
                        }
                    }

                    ui.add(TextEdit::singleline(&mut self.model_name).hint_text("Modelo").desired_width(100.0));
                });

                if self.provider != LlmProvider::Ollama {
                    ui.add_space(4.0);
                    ui.add(TextEdit::singleline(&mut self.api_key).password(true).hint_text("API Key").desired_width(f32::INFINITY));
                    ui.horizontal(|ui| {
                        if ui.add_enabled(!self.api_key.trim().is_empty(), egui::Button::new("Guardar en llavero")).clicked() {
                            self.run_keyring_action(KeyringAction::Save(self.api_key.clone()), ui.ctx());
                        }
                        if ui.button("Cargar").clicked() {
                            self.run_keyring_action(KeyringAction::Load, ui.ctx());
                        }
                        if ui.button("Borrar del llavero").clicked() {
                            self.run_keyring_action(KeyringAction::Clear, ui.ctx());
                        }
                    });
                    if !self.keyring_status.is_empty() {
                        ui.label(RichText::new(&self.keyring_status).small().weak());
                    }
                }

                ui.add_space(6.0);

                ui.horizontal(|ui| {
                    if self.analysis_loading {
                        ui.add(egui::Spinner::new());
                        ui.label("Analizando...");
                    } else {
                        if ui.button("1. Preparar vista previa").clicked() {
                            self.explain_prompt = self.build_prompt();
                            self.export_preview = self.build_markdown_export();
                            self.analysis_prepared = true;
                        }
                        if self.analysis_prepared && ui.button("2. Enviar a IA").clicked() {
                            self.analysis_loading = true;
                            self.analysis_result = "Iniciando análisis...".to_string();
                            run_llm_analysis(
                                self.provider,
                                self.model_name.clone(),
                                self.api_key.clone(),
                                redact_with_terms(&self.explain_prompt, &self.private_terms),
                                self.tx_analysis.clone(),
                                ui.ctx().clone(),
                            );
                        }
                    }
                });

                if !self.analysis_result.is_empty() {
                    ui.add_space(6.0);
                    egui::ScrollArea::vertical()
                        .id_source("inspector_analysis_scroll")
                        .max_height(200.0)
                        .show(ui, |ui| {
                            let mut text = self.analysis_result.clone();
                            ui.add(
                                TextEdit::multiline(&mut text)
                                    .desired_rows(8)
                                    .desired_width(f32::INFINITY)
                            );
                        });
                }
                
                ui.add_space(8.0);

                // Collapsible Learning Mode panel
                ui.collapsing("💡 Notas Educativas (Learning Mode)", |ui| {
                    ui.vertical(|ui| {
                        if selected_conn.is_some() {
                            ui.label(RichText::new("• 127.0.0.1 (localhost) indica tráfico local interno que no sale de tu máquina.").size(10.0));
                            ui.add_space(2.0);
                            ui.label(RichText::new("• 0.0.0.0 (wildcard) indica que un servicio escucha peticiones en todas las interfaces de red.").size(10.0));
                            ui.add_space(2.0);
                            ui.label(RichText::new("• Puerto 443 suele ser TLS/HTTPS (tráfico web seguro), pero VT Lens no inspecciona payloads.").size(10.0));
                            ui.add_space(2.0);
                            ui.label(RichText::new("• 224.0.0.251:5353 suele ser Multicast DNS (mDNS) para descubrimiento local.").size(10.0));
                        } else {
                            ui.label(RichText::new("• Un proceso puede tener muchos file descriptors (FDs). Algunos FDs representan sockets de red.").size(10.0));
                            ui.add_space(2.0);
                            ui.label(RichText::new("• VT Lens mapea inodes de sockets desde /proc/<pid>/fd/ hacia /proc/net/tcp y /proc/net/udp.").size(10.0));
                        }
                    });
                });

                ui.add_space(8.0);

                // Collapsible raw evidence/prompt section
                egui::CollapsingHeader::new("📝 Vista previa redactada · revisá antes de enviar o compartir")
                    .default_open(true)
                    .show(ui, |ui| {
                    ui.label("Términos privados adicionales (separados por coma; solo esta sesión):");
                    ui.add(TextEdit::singleline(&mut self.private_terms).desired_width(f32::INFINITY));
                    ui.horizontal(|ui| {
                        if ui.small_button("Build Prompt").clicked() {
                            self.explain_prompt = self.build_prompt();
                            self.analysis_prepared = true;
                        }
                        if ui.small_button("Build Evidence").clicked() {
                            self.export_preview = self.build_markdown_export();
                        }
                    });
                    ui.add_space(4.0);
                    ui.label(RichText::new("Prompt:").weak().size(9.0));
                    ui.add(TextEdit::multiline(&mut self.explain_prompt).desired_rows(6).desired_width(f32::INFINITY));
                    ui.add_space(4.0);
                    ui.label(RichText::new("Evidencia Markdown:").weak().size(9.0));
                    ui.add(TextEdit::multiline(&mut self.export_preview).desired_rows(6).desired_width(f32::INFINITY));
                    });
            });
    }
}

/// Public screenshots use this explicit synthetic dataset; no host telemetry is captured.
pub fn demo_snapshot() -> ProcSnapshot {
    let processes = [
        (1420, "browser", "browser --profile demo", 420_000, 12, 2),
        (1842, "web-server", "web-server --listen 127.0.0.1:8080", 86_000, 6, 1),
        (2301, "ssh-agent", "ssh-agent", 4_600, 1, 0),
        (2714, "database", "database --config demo", 152_000, 8, 1),
        (3380, "vt-lens", "vt-lens --demo", 74_000, 5, 0),
    ].into_iter().map(|(pid, name, cmdline, rss_kb, threads, socket_count)| ProcessRow {
        pid, name: name.into(), cmdline: cmdline.into(), state: "S".into(),
        rss_kb, threads, socket_count, uid: Some(1000),
    }).collect();
    let connections = [
        ("tcp", "127.0.0.1:8080", "0.0.0.0:0", "LISTEN", 1842, "web-server"),
        ("tcp", "192.0.2.10:53918", "198.51.100.42:443", "ESTABLISHED", 1420, "browser"),
        ("tcp", "127.0.0.1:5432", "0.0.0.0:0", "LISTEN", 2714, "database"),
    ].into_iter().enumerate().map(|(index, (protocol, local_addr, remote_addr, state, pid, process))| NetRow {
        protocol: protocol.into(), local_addr: local_addr.into(), remote_addr: remote_addr.into(),
        state: state.into(), tx_queue: 0, rx_queue: 0, inode: format!("demo-{index}"),
        owner: Some(crate::model::SocketOwner { pid, process: process.into() }),
    }).collect();
    ProcSnapshot { processes, connections, status: "DEMO · datos sintéticos · sin captura del equipo".into() }
}

impl eframe::App for VtLensApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 1. Capture filter/selection state before rendering
        let prev_proc_filter = self.process_filter.clone();
        let prev_net_filter = self.network_filter.clone();
        let prev_net_filter_type = self.net_filter_type;
        let prev_selected_pid = self.selected_pid;
        let prev_selected_inode = self.selected_network_inode.clone();
        let prev_only_active = self.only_network_active;

        // Poll for snapshots from background thread
        if let Ok(snapshot) = self.rx_snapshot.try_recv() {
            if self.auto_refresh {
                self.processes = snapshot.processes;
                self.connections = snapshot.connections;
                self.status = snapshot.status;
                self.last_snapshot_time = Instant::now();
                self.update_caches();
            }
        }

        // Poll for LLM analysis results
        while let Ok(msg) = self.rx_analysis.try_recv() {
            match msg {
                LlmMessage::Start => {
                    self.analysis_loading = true;
                    self.analysis_result.clear();
                }
                LlmMessage::Chunk(chunk) => {
                    self.analysis_result.push_str(&chunk);
                }
                LlmMessage::End(Ok(())) => {
                    self.analysis_loading = false;
                }
                LlmMessage::End(Err(err)) => {
                    self.analysis_loading = false;
                    self.analysis_result = format!("Error: {err}");
                }
            }
            ctx.request_repaint();
        }

        while let Ok((provider, result)) = self.rx_keyring.try_recv() {
            if provider != self.provider.keyring_name() {
                continue;
            }
            match result {
                Ok(KeyringOutcome::Loaded(key)) => {
                    if self.api_key.is_empty() {
                        self.api_key = key;
                    }
                    self.keyring_status = "Clave cargada del llavero".to_string();
                }
                Ok(KeyringOutcome::Saved) => self.keyring_status = "Clave guardada en el llavero".to_string(),
                Ok(KeyringOutcome::Cleared) => {
                    self.api_key.clear();
                    self.keyring_status = "Clave borrada del llavero".to_string();
                }
                Err(message) => self.keyring_status = message,
            }
        }

        ctx.request_repaint_after(Duration::from_millis(500));

        // Header Panel
        egui::TopBottomPanel::top("header")
            .frame(egui::Frame::none().fill(egui::Color32::from_rgb(255, 255, 255)).inner_margin(egui::Margin::symmetric(16.0, 12.0)))
            .show(ctx, |ui| self.show_header(ui));

        // Bottom Status Bar
        egui::TopBottomPanel::bottom("status_bar")
            .frame(egui::Frame::none().fill(egui::Color32::from_rgb(249, 250, 251)).inner_margin(egui::Margin::symmetric(16.0, 8.0)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let total_proc = self.processes.len();
                    let total_sock = self.connections.len();
                    let visible_sock = self.filtered_connections_cache.len();
                    let age = self.last_snapshot_time.elapsed().as_secs();
                    
                    let selection_info = if let Some(pid) = self.selected_pid {
                        let proc_name = self.processes.iter().find(|p| p.pid == pid).map(|p| p.name.as_str()).unwrap_or("unknown");
                        format!(" · seleccionado {} PID {}", proc_name, pid)
                    } else {
                        String::new()
                    };

                    let status_text = format!(
                        "{} procesos · {} sockets · {} visibles{} · último escaneo hace {}s · /proc no root",
                        total_proc, total_sock, visible_sock, selection_info, age
                    );
                    ui.label(RichText::new(status_text).weak().size(11.0));
                });
            });

        // Left Process Sidebar
        egui::SidePanel::left("processes")
            .resizable(true)
            .default_width(280.0)
            .min_width(180.0)
            .frame(egui::Frame::none().fill(egui::Color32::from_rgb(249, 250, 251)).inner_margin(12.0))
            .show(ctx, |ui| self.show_processes(ui));

        // Right Inspector Panel (collapsible slide-out)
        let show_inspector = self.selected_pid.is_some() || self.selected_network_inode.is_some();
        if show_inspector {
            egui::SidePanel::right("inspector")
                .resizable(true)
                .default_width(320.0)
                .min_width(180.0)
                .frame(egui::Frame::none().fill(egui::Color32::from_rgb(255, 255, 255)).inner_margin(12.0))
                .show(ctx, |ui| {
                    self.render_inspector_panel(ui);
                });
        }

        // Central Panel (Network Connections Table)
        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(egui::Color32::from_rgb(246, 248, 250)).inner_margin(16.0))
            .show(ctx, |ui| {
                self.show_network(ui);
            });

        // 2. If filtering or selection changed, update caches for the next frame
        if self.process_filter != prev_proc_filter
            || self.network_filter != prev_net_filter
            || self.net_filter_type != prev_net_filter_type
            || self.selected_pid != prev_selected_pid
            || self.selected_network_inode != prev_selected_inode
            || self.only_network_active != prev_only_active
        {
            self.update_caches();
            self.analysis_prepared = false;
        }
    }
}

fn run_llm_analysis(
    provider: LlmProvider,
    model_name: String,
    api_key: String,
    prompt: String,
    tx: std::sync::mpsc::Sender<LlmMessage>,
    ctx: egui::Context,
) {
    std::thread::spawn(move || {
        let _ = tx.send(LlmMessage::Start);
        ctx.request_repaint();

        match perform_llm_stream_request(provider, model_name, api_key, prompt, &tx, &ctx) {
            Ok(()) => {
                let _ = tx.send(LlmMessage::End(Ok(())));
            }
            Err(err) => {
                let _ = tx.send(LlmMessage::End(Err(err)));
            }
        }
        ctx.request_repaint();
    });
}

fn perform_llm_stream_request(
    provider: LlmProvider,
    model_name: String,
    api_key: String,
    prompt: String,
    tx: &std::sync::mpsc::Sender<LlmMessage>,
    ctx: &egui::Context,
) -> Result<(), String> {
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
                ],
                "stream": true
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
                ],
                "stream": true
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
                "stream": true
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

    let reader = std::io::BufReader::new(response.into_reader());

    use std::io::BufRead;
    for line_result in reader.lines() {
        let line = line_result.map_err(|err| format!("Failed to read stream line: {err}"))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Standard SSE event line: "data: {JSON}"
        if trimmed.starts_with("data: ") {
            let data_str = &trimmed["data: ".len()..];
            if data_str.trim() == "[DONE]" {
                break;
            }

            if let Ok(json_chunk) = serde_json::from_str::<serde_json::Value>(data_str) {
                let chunk_text = match provider {
                    LlmProvider::OpenRouter | LlmProvider::OpenAI => {
                        json_chunk["choices"][0]["delta"]["content"].as_str().map(|s| s.to_string())
                    }
                    LlmProvider::Anthropic => {
                        json_chunk["delta"]["text"].as_str().map(|s| s.to_string())
                    }
                    LlmProvider::Ollama => {
                        json_chunk["message"]["content"].as_str().map(|s| s.to_string())
                    }
                };

                if let Some(text) = chunk_text {
                    let _ = tx.send(LlmMessage::Chunk(text));
                    ctx.request_repaint();
                }
            }
        } else if provider == LlmProvider::Ollama {
            // Ollama might output raw JSON line directly
            if let Ok(json_chunk) = serde_json::from_str::<serde_json::Value>(trimmed) {
                if let Some(text) = json_chunk["message"]["content"].as_str() {
                    let _ = tx.send(LlmMessage::Chunk(text.to_string()));
                    ctx.request_repaint();
                }
            }
        }
    }

    Ok(())
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
