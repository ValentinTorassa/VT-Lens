# AGENTS.md

VT Lens is a public educational Rust project for VT Security.

## Objective

Build a modern, minimal native GUI that helps learners understand local system
activity through processes, visible network connections, exported evidence, and
LLM-assisted explanations.

## Voice

- Spanish/LatAm by default for published content.
- Direct, practical, technical, low hype.
- Explain systems from the problem upward: processes, sockets, files,
  protocols, logs, permissions, and failure modes.
- Avoid fearmongering, tool worship, and marketing language.

## Safety Rules

- Never include real tokens, API keys, private keys, passwords, shell history,
  browser profiles, employer data, client data, private hostnames, or internal
  infrastructure details.
- Treat logs and exports as potentially sensitive.
- Use synthetic examples in docs, tests, videos, and labs.
- Future LLM integration must redact secrets before sending context to a model.
- The raw log is evidence; the LLM response is an explanation that can be wrong.

## Technical Rules

- Keep the MVP small and understandable.
- Prefer no-root collection first: `/proc` process and connection metadata.
- Packet capture, SNI parsing, and deeper inspection are phase-2 features and
  must be explicit about permissions and privacy.
- Before shipping changes, run `cargo test` and `cargo build`.
- Run `cargo fmt` when `rustfmt` is available.
