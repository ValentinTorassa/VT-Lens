# Changelog

## 0.2.0

- macOS support. Processes come from libproc (through `sysinfo`) and sockets
  from `lsof`, without root. Without `sudo`, `lsof` only sees your own
  processes' sockets, and other users' processes show no memory, threads or
  arguments; the app says so in its notes and in the LLM prompt. The keyring
  buttons are Linux-only for now.
- Prebuilt binaries for macOS 11+ on Apple Silicon (`aarch64-apple-darwin`)
  and Intel (`x86_64-apple-darwin`) next to Linux x86_64, all in
  `SHA256SUMS`. `install.sh` picks the right one and still verifies it.
- eframe/egui 0.27 → 0.36.2 (wgpu renderer: Metal on macOS, Vulkan or GL on
  Linux). This also clears RUSTSEC-2026-0257 (webbrowser), so `cargo audit`
  no longer needs an exception.
- README screenshots, rendered offscreen from the demo dataset
  (`cargo test --features screenshots screenshots`). The demo grew to 12
  processes and 15 sockets, still documentation addresses only.
- Fixes: ⟳ Refresh works while auto refresh is paused; a selected external
  peer no longer disappears into the selection highlight; close marks render
  as × instead of an empty box; the UI stays light under a dark OS theme.
- CI runs `cargo fmt --check` and `cargo clippy -D warnings`, and a macOS job.

Earlier releases: see the [GitHub releases](https://github.com/ValentinTorassa/VT-Lens/releases).
