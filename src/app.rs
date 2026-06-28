use std::collections::HashMap;
use std::time::{Duration, Instant};

use eframe::egui::{self, RichText, TextEdit};

use crate::capture::{read_connections, read_processes, socket_owners};
use crate::model::{NetRow, ProcessRow};

pub struct VtLensApp {
    processes: Vec<ProcessRow>,
    connections: Vec<NetRow>,
    selected_pid: Option<u32>,
    process_filter: String,
    network_filter: String,
    explain_prompt: String,
    export_preview: String,
    status: String,
    auto_refresh: bool,
    last_refresh: Instant,
    refresh_interval: Duration,
}

impl VtLensApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());

        let mut app = Self {
            processes: Vec::new(),
            connections: Vec::new(),
            selected_pid: None,
            process_filter: String::new(),
            network_filter: String::new(),
            explain_prompt: String::new(),
            export_preview: String::new(),
            status: "Starting capture".to_string(),
            auto_refresh: true,
            last_refresh: Instant::now() - Duration::from_secs(5),
            refresh_interval: Duration::from_secs(2),
        };

        app.refresh_snapshot();
        app
    }

    fn refresh_snapshot(&mut self) {
        let owners = socket_owners();
        let mut processes = read_processes();
        let mut socket_counts: HashMap<u32, usize> = HashMap::new();

        for owner in owners.values() {
            *socket_counts.entry(owner.pid).or_default() += 1;
        }

        for process in &mut processes {
            process.socket_count = socket_counts.get(&process.pid).copied().unwrap_or(0);
        }

        self.connections = read_connections(&owners);
        self.processes = processes;
        self.status = format!(
            "{} processes · {} connections · connection-level capture (no root)",
            self.processes.len(),
            self.connections.len()
        );
        self.last_refresh = Instant::now();
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
            prompt.push_str("No process selected. Explain the visible network sample.\n\n");
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
        ui.horizontal_wrapped(|ui| {
            ui.heading("VT Lens");
            ui.label(RichText::new("see what your machine is doing").weak());
            ui.separator();
            ui.checkbox(&mut self.auto_refresh, "auto refresh");
            if ui.button("Refresh now").clicked() {
                self.refresh_snapshot();
            }
            ui.label(RichText::new(&self.status).weak());
        });
    }

    fn show_processes(&mut self, ui: &mut egui::Ui) {
        ui.heading("Processes");
        ui.label(RichText::new("Click a process to focus its network activity.").weak());
        ui.add(TextEdit::singleline(&mut self.process_filter).hint_text("filter pid, name, cmdline"));

        ui.separator();
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("process_grid")
                .striped(true)
                .min_col_width(42.0)
                .show(ui, |ui| {
                    ui.strong("PID");
                    ui.strong("Name");
                    ui.strong("RSS");
                    ui.strong("Sock");
                    ui.end_row();

                    for process in self.filtered_processes().into_iter().take(450) {
                        let selected = self.selected_pid == Some(process.pid);
                        if ui
                            .selectable_label(selected, process.pid.to_string())
                            .on_hover_text(&process.cmdline)
                            .clicked()
                        {
                            self.selected_pid = Some(process.pid);
                            self.network_filter.clear();
                        }
                        ui.label(&process.name).on_hover_text(&process.cmdline);
                        ui.label(format!("{:.0} MB", process.rss_mb()));
                        ui.label(process.socket_count.to_string());
                        ui.end_row();
                    }
                });
        });
    }

    fn show_network(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Network");
            if let Some(process) = self.selected_process() {
                ui.label(RichText::new(format!("focused on {}", process.label())).weak());
                if ui.button("Clear focus").clicked() {
                    self.selected_pid = None;
                }
            } else {
                ui.label(RichText::new("all visible connections").weak());
            }
        });
        ui.add(TextEdit::singleline(&mut self.network_filter).hint_text("filter proto, addr, state, owner"));
        ui.label(RichText::new("MVP uses /proc connection tables: no packet payload, no root.").weak());

        ui.separator();
        egui::ScrollArea::vertical()
            .max_height(300.0)
            .show(ui, |ui| {
                egui::Grid::new("network_grid")
                    .striped(true)
                    .min_col_width(76.0)
                    .show(ui, |ui| {
                        ui.strong("Proto");
                        ui.strong("Owner");
                        ui.strong("Local");
                        ui.strong("Remote");
                        ui.strong("State");
                        ui.end_row();

                        for connection in self.filtered_connections().into_iter().take(500) {
                            ui.label(&connection.protocol);
                            ui.label(connection.owner_label());
                            ui.label(&connection.local_addr);
                            ui.label(&connection.remote_addr);
                            ui.label(&connection.state)
                                .on_hover_text(format!("inode {}", connection.inode));
                            ui.end_row();
                        }
                    });
            });
    }

    fn show_explain(&mut self, ui: &mut egui::Ui) {
        ui.heading("LLM analysis workspace");
        ui.label(RichText::new("M1 builds the prompt and evidence export. Provider streaming lands in M2.").weak());

        ui.horizontal(|ui| {
            if ui.button("Build LLM prompt from current slice").clicked() {
                self.explain_prompt = self.build_prompt();
            }
            if ui.button("Build markdown evidence").clicked() {
                self.export_preview = self.build_markdown_export();
            }
        });

        ui.columns(2, |columns| {
            columns[0].label("Prompt to send to an LLM");
            columns[0].add(
                TextEdit::multiline(&mut self.explain_prompt)
                    .desired_rows(12)
                    .hint_text("Build a prompt from the selected process/network slice"),
            );

            columns[1].label("Evidence export");
            columns[1].add(
                TextEdit::multiline(&mut self.export_preview)
                    .desired_rows(12)
                    .hint_text("Build markdown evidence for a lab/writeup"),
            );
        });
    }
}

impl eframe::App for VtLensApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.auto_refresh && self.last_refresh.elapsed() >= self.refresh_interval {
            self.refresh_snapshot();
        }

        ctx.request_repaint_after(Duration::from_millis(500));

        egui::TopBottomPanel::top("header").show(ctx, |ui| self.show_header(ui));
        egui::SidePanel::left("processes")
            .resizable(true)
            .default_width(410.0)
            .show(ctx, |ui| self.show_processes(ui));
        egui::CentralPanel::default().show(ctx, |ui| {
            self.show_network(ui);
            ui.separator();
            self.show_explain(ui);
        });
    }
}
