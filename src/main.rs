mod app;
mod capture;
mod comparison;
mod evidence;
mod keyring;
mod model;
mod redaction;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([960.0, 640.0]),
        ..Default::default()
    };

    // --demo: synthetic data for screenshots and videos; nothing is captured.
    let source = if std::env::args().any(|arg| arg == "--demo") {
        capture::demo_source(capture::Platform::host())
    } else {
        capture::system_source()
    };

    eframe::run_native(
        "VT Lens",
        options,
        Box::new(|cc| Ok(Box::new(app::VtLensApp::new(cc, source)))),
    )
}
