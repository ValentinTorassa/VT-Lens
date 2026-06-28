# VT Lens

> No podes defender sistemas que no entendes como funcionan.

VT Lens is a native Rust GUI that helps you understand what your computer is
doing: running processes, visible network connections, and an evidence workspace
that turns a selected slice into an LLM-ready prompt or Markdown export.

This is an educational instrument, not a packet sniffer or an EDR. The MVP uses
Linux `/proc` connection tables, so it shows process and connection metadata
without requiring root access.

## MVP Features

- Native minimal GUI with `egui` / `eframe`.
- Live process table: PID, name, command line, memory, threads, socket count.
- Live network table: protocol, owner process, local address, remote address,
  connection state, queue sizes, socket inode.
- Process focus: click a process to filter its network activity.
- LLM analysis workspace: build a prompt from the selected process/network
  slice.
- Markdown evidence export for labs, writeups, and videos.

## Run

```bash
cargo run
```

## Verify

```bash
cargo test
cargo build
```

`cargo fmt` is expected, but this local Rust toolchain currently does not ship
with `rustfmt`.

## Privacy And Safety

- The raw log is the evidence. An LLM explanation is only interpretation.
- Do not publish exports that contain real private hosts, internal services,
  tokens, customer data, employer data, or personal network details.
- The MVP does not capture packet payloads.
- Future LLM integration must redact API keys and must never log provider keys.

## Roadmap

1. Wire OpenRouter/OpenAI/Anthropic streaming into the analysis panel.
2. Store provider keys locally via the OS keyring.
3. Add redaction before export and before LLM submission.
4. Add optional packet capture mode behind an explicit root/capability warning.
5. Add DNS/SNI/cert-chain enrichment for the network pane.

## License

GPL-3.0-only.
