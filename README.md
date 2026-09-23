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

---

### 4. Instalación vía NPM (Global)
Si tienes Node.js configurado, puedes instalarlo de manera global ejecutando:
```bash
npm install -g ValentinTorassa/vt-lens
```
NPM compilará automáticamente el binario nativo en modo release y lo registrará en tu ruta de binarios globales.

---

### 5. Instalación vía APT (Debian/Ubuntu)
Si deseas utilizar un paquete Debian (`.deb`), puedes descargar el archivo `.deb` compilado desde la pestaña de Releases en GitHub e instalarlo usando:
```bash
sudo apt install ./vt-lens_*.deb
```
*(También puedes empaquetarlo tú mismo instalando `cargo-deb` y ejecutando `cargo deb` en la raíz del proyecto).*

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
- LLM analysis workspace: build a prompt from the selected process/network
  slice.
- Markdown evidence export for labs, writeups, and videos.

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
- Future LLM integration must redact API keys and must never log provider keys.

## Roadmap

1. Wire OpenRouter/OpenAI/Anthropic streaming into the analysis panel.
2. Store provider keys locally via the OS keyring.
3. Add redaction before export and before LLM submission.
4. Add optional packet capture mode behind an explicit root/capability warning.
5. Add DNS/SNI/cert-chain enrichment for the network pane.

## License

GPL-3.0-only.

## Verificación de regresiones - 2026-09-14

```bash
cargo test --locked
cargo build --locked
```

GitHub Actions verifica en Linux con las dependencias gráficas documentadas. Hasta cerrar el resultado de software activo en VT-Tasks, mantener el alcance del MVP: visualización local de procesos y conexiones.
