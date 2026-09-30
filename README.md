# VT Lens

> No podes defender sistemas que no entendes como funcionan.

VT Lens is a native Rust GUI that helps you understand what your computer is
doing: running processes, visible network connections, and an evidence workspace
that turns a selected slice into an LLM-ready prompt or Markdown export.

This is an educational instrument, not a packet sniffer or an EDR. The MVP uses
Linux `/proc` connection tables, so it shows process and connection metadata
without requiring root access.

## Instalación (Installation)

### 1. Dependencias del Sistema (solo para compilar)
Si instalas el binario precompilado (ver punto 2) no necesitas Rust ni estas dependencias. Para compilar la interfaz gráfica nativa con `egui/eframe` desde el código fuente, necesitas las dependencias de desarrollo correspondientes a tu distribución de Linux:

**Debian / Ubuntu / Mint / Pop!_OS:**
```bash
sudo apt-get install -y build-essential libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libxkbcommon-dev libssl-dev libgtk-3-dev
```

**Fedora / RHEL:**
```bash
sudo dnf install -y gcc-c++ libxcb-devel libxkbcommon-devel openssl-devel gtk3-devel
```

**Arch Linux / Manjaro:**
```bash
sudo pacman -S --needed base-devel libxcb xkbcommon openssl gtk3
```

---

### 2. Instalación Directa de una Línea (vía Curl)
Para instalar VT Lens y registrar su lanzador de escritorio de manera automatizada, ejecuta:
```bash
curl -sSL https://raw.githubusercontent.com/ValentinTorassa/vt-lens/main/install.sh | bash
```
El script descarga el binario precompilado de la última [release](https://github.com/ValentinTorassa/VT-Lens/releases) para Linux x86_64 (glibc 2.35 o superior: Ubuntu 22.04+, Debian 12+), verifica su SHA256 contra `SHA256SUMS` y aborta si no coincide. Solo hay binario para Linux: la app lee `/proc`, que macOS no tiene. Si no hay binario para tu sistema, clona y compila desde el código fuente (requiere Rust y las dependencias del punto 1).

Opciones (pásalas con `| bash -s -- <opciones>`):
- `--from-source`: compila desde el código fuente aunque exista un binario precompilado.
- `--prefix DIR`: instala en `DIR/bin` en lugar de `~/.local/bin`.
- `--dry-run`: muestra lo que haría sin instalar nada.

Cada release también publica los archivos `vt-lens-<versión>-<target>.tar.gz` para descargarlos a mano.

---

### 3. Instalación de Escritorio Manual (Lanzador y Menú)
Si ya tienes el repositorio clonado localmente, ejecuta el script de instalación:
1. Dale permisos de ejecución al script:
   ```bash
   chmod +x install.sh
   ```
2. Ejecuta el script:
   ```bash
   ./install.sh
   ```

Una vez completado, podrás buscar **"VT Lens"** en tu lanzador de aplicaciones de escritorio o ejecutarlo con:
```bash
vt-lens
```

Para una captura pública sin exponer procesos, sockets o nombres del equipo,
ejecutá `vt-lens --demo`. La ventana muestra datos sintéticos y una etiqueta
visible de demo; el botón de refrescar conserva ese modo durante toda la sesión.

---

### 4. Instalación vía NPM (Global)
Si tienes Node.js configurado, puedes instalarlo de manera global ejecutando:
```bash
npm install -g ValentinTorassa/vt-lens
```
NPM compilará automáticamente el binario nativo en modo release y lo registrará en tu ruta de binarios globales.

---

### 5. Paquete Debian (`.deb`), opcional
Las releases publican solo el tarball Linux x86_64 y `SHA256SUMS`; no hay `.deb` precompilado. Si querés un paquete, generalo vos con [`cargo-deb`](https://github.com/kornelski/cargo-deb):
```bash
cargo install cargo-deb
cargo deb
sudo apt install ./target/debian/vt-lens_*.deb
```

---

### 6. Instalación Rápida con Cargo (Para Desarrolladores Rust)
Si tienes el entorno de desarrollo de Rust configurado y quieres compilar e instalar la app directamente en tu directorio binario de cargo:
```bash
cargo install --path .
```

---

## MVP Features

- Native minimal GUI with `egui` / `eframe`.
- Live process table: PID, name, command line, memory, threads, socket count.
- Live network table: protocol, owner process, local address, remote address,
  connection state, queue sizes, socket inode.
- Process focus: click a process to filter its network activity.
- LLM analysis workspace: every analysis goes through a preview of the
  prompt built from the selected process/network slice; nothing is sent until
  you press **2. Enviar a IA**.
- Markdown evidence preview for labs, writeups, and videos, built from the
  same allowlist as the prompt.

---

## Ejecución en Desarrollo (Run)

Para probar la aplicación localmente en modo desarrollo:
```bash
cargo run
```

## Verificación de Código (Verify)

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
- The prompt evidence and the Markdown export are built from an allowlist of
  structured fields (`src/evidence.rs`): process basename, PID, memory and
  thread counts, UID class (root / sistema / usuario), protocol, socket state,
  inode, and each endpoint reduced to its class and port (`externa/v4:443`,
  `loopback/v6:631`). Command lines, IP addresses, hostnames and account names
  are never included, so they cannot leak through a pattern that failed to match.
- Control characters in `comm` and argv are replaced at capture time.
- Everything that leaves the app (including text you type into the editable
  preview) then goes through free-text redaction: credential names with `:` or
  `=` (`OPENAI_API_KEY=`, `GITHUB_TOKEN:`), secret flags (`--password X`),
  `user:pass@` in URLs, common key formats (`sk-`, `ghp_`, `github_pat_`,
  `AKIA`, `xox*-`, `AIza`, `glpat-`), long high-entropy tokens, email
  addresses, home paths and IPv4/IPv6 literals. The preview also accepts
  comma-separated private terms for this session; they are applied again
  immediately before a provider request. Review the preview before sending or
  sharing: pattern matching cannot recognize every kind of private data.
- Reverse DNS lookups (display only, never exported) tell your resolver which
  peers are on screen; demo mode does not perform them.
- Provider keys are used for the request and are not written to logs. On Linux,
  `secret-tool` stores them in the desktop OS keyring when you click **Guardar en
  llavero**. VT Lens loads the selected provider's key at startup and when you
  switch providers. **Borrar del llavero** removes it. A locked or unavailable
  keyring leaves the field empty; you can still paste a key for this session.
  Demo mode never reads or writes the keyring (its buttons are disabled).
- The Anthropic provider defaults to `claude-opus-5-5` with the server-side
  fallback beta enabled; the model field stays editable.

## Roadmap

1. Persist private-term preferences locally without copying them to exports.
2. Add optional packet capture mode behind an explicit root/capability warning.
3. Add DNS/SNI/cert-chain enrichment for the network pane.

## License

GPL-3.0-only.

## Verificación de regresiones - 2026-09-14

```bash
cargo test --locked
cargo build --locked
```

GitHub Actions verifica en Linux con las dependencias gráficas documentadas. Hasta cerrar el resultado de software activo en VT-Tasks, mantener el alcance del MVP: visualización local de procesos y conexiones.
