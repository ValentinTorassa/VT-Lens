mod app;
mod capture;
mod model;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([960.0, 640.0]),
        ..Default::default()
    };

    eframe::run_native(
        "VT Lens",
        options,
        Box::new(|cc| Box::new(app::VtLensApp::new(cc))),
    )
}
