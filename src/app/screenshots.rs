//! README screenshots, rendered offscreen (wgpu, no window) from the demo
//! dataset, so they never show anything from the machine that renders them.
//!
//! ```sh
//! cargo test --features screenshots screenshots
//! ```
//!
//! writes `docs/screenshots/*.png`. The scenes use the Linux wording; the
//! layout is the same on macOS.

use std::path::PathBuf;

use eframe::egui;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

use super::VtLensApp;
use crate::capture::{self, Platform};

const SIZE: [f32; 2] = [1280.0, 820.0];
const PIXELS_PER_POINT: f32 = 2.0;

type DemoHarness = Harness<'static, VtLensApp>;

fn render(name: &str, scene: impl FnOnce(&mut DemoHarness)) {
    let mut harness = Harness::builder()
        .with_size(SIZE)
        .with_pixels_per_point(PIXELS_PER_POINT)
        .with_theme(egui::Theme::Light)
        .wgpu()
        .build_eframe(|cc| VtLensApp::new(cc, capture::demo_source(Platform::Linux)));
    harness.run();
    scene(&mut harness);
    // A few more frames settle layouts sized from the previous frame.
    harness.run();
    harness.run_steps(2);

    let image = harness.render().expect("wgpu render");
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/screenshots");
    std::fs::create_dir_all(&dir).expect("create docs/screenshots");
    let path = dir.join(format!("{name}.png"));
    image.save(&path).expect("write png");
    eprintln!("wrote {}", path.display());
}

fn select(harness: &mut DemoHarness, pid: u32, remote: Option<&str>) {
    let app = harness.state_mut();
    app.selected_pid = Some(pid);
    app.selected_socket = remote.map(|remote| {
        app.connections
            .iter()
            .find(|row| row.remote_addr == remote)
            .map(|row| row.socket_id)
            .expect("demo connection")
    });
    app.update_caches();
    harness.run();
}

#[test]
fn screenshots() {
    // 1. Every process and every visible socket.
    render("overview", |_| {});

    // 2. One process selected: its sockets, details and manual checks.
    render("process", |harness| select(harness, 1420, None));

    // 3. One connection selected and the redacted evidence prepared,
    //    with the inspector scrolled down to the prompt's evidence block
    //    and the Markdown export.
    render("evidence", |harness| {
        select(harness, 1420, Some("198.51.100.42:443"));
        harness.state_mut().prepare_analysis_preview();
        harness.run();
        harness.get_by_label("Evidencia Markdown:").scroll_to_me();
        harness.run();
        for _ in 0..SCROLL_STEPS {
            harness.get_by_label("Evidencia Markdown:").scroll_down();
            harness.run();
        }
    });
}

/// 100 points each, past the label so the Markdown text shows too.
const SCROLL_STEPS: usize = 3;
