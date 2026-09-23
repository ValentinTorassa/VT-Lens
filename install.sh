#!/usr/bin/env bash

set -eo pipefail

# Text formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

REPO="ValentinTorassa/VT-Lens"
FROM_SOURCE=0
DRY_RUN=0
PREFIX="$HOME/.local"

usage() {
    cat <<EOF
Uso: install.sh [opciones]

Instala VT Lens. Primero intenta descargar el binario precompilado de la última
release de GitHub (verificando su SHA256); si no hay uno para tu sistema, compila
desde el código fuente con Cargo.

Opciones:
  --from-source    Compila desde el código fuente aunque exista un binario precompilado.
  --prefix DIR     Instala en DIR/bin y DIR/share/applications (por defecto: \$HOME/.local).
  --dry-run        Muestra lo que haría sin instalar ni compilar nada. Las descargas
                   van a un directorio temporal que se borra al terminar.
  -h, --help       Muestra esta ayuda.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --from-source) FROM_SOURCE=1 ;;
        --dry-run) DRY_RUN=1 ;;
        --prefix)
            if [ -z "${2:-}" ]; then
                echo -e "${RED}Error: --prefix requiere un directorio.${NC}"
                exit 1
            fi
            PREFIX="$2"
            shift
            ;;
        --prefix=*) PREFIX="${1#--prefix=}" ;;
        -h|--help) usage; exit 0 ;;
        *)
            echo -e "${RED}Error: opción desconocida: $1${NC}"
            usage
            exit 1
            ;;
    esac
    shift
done

BIN_DIR="$PREFIX/bin"
APP_DIR="$PREFIX/share/applications"

# Temporary directories are removed on exit.
TEMP_DIRS=()
cleanup() {
    if [ ${#TEMP_DIRS[@]} -gt 0 ]; then
        rm -rf "${TEMP_DIRS[@]}"
    fi
}
trap cleanup EXIT

# Sets TEMP_DIR (no command substitution, so the cleanup list survives).
make_temp_dir() {
    TEMP_DIR=$(mktemp -d)
    TEMP_DIRS+=("$TEMP_DIR")
}

# Runs a command, or only prints it in --dry-run mode.
run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        echo -e "${YELLOW}[dry-run]${NC} $*"
    else
        "$@"
    fi
}

echo -e "${BLUE}=== VT Lens Installer ===${NC}"
if [ "$DRY_RUN" -eq 1 ]; then
    echo -e "${YELLOW}Modo --dry-run: no se instalará ni compilará nada.${NC}"
fi

# Copies the binary (and the desktop shortcut, when present) into the prefix.
install_files() {
    local bin_src="$1"
    local desktop_src="$2"

    run mkdir -p "$BIN_DIR"
    run mkdir -p "$APP_DIR"

    echo -e "${BLUE}Instalando binario ejecutable...${NC}"
    run cp "$bin_src" "$BIN_DIR/vt-lens"
    run chmod +x "$BIN_DIR/vt-lens"
    echo -e "${GREEN}✓ Ejecutable instalado en: $BIN_DIR/vt-lens${NC}"

    if [ -f "$desktop_src" ]; then
        echo -e "${BLUE}Instalando acceso directo de escritorio...${NC}"
        run cp "$desktop_src" "$APP_DIR/vt-lens.desktop"
        run chmod +x "$APP_DIR/vt-lens.desktop"
        echo -e "${GREEN}✓ Acceso directo instalado en: $APP_DIR/vt-lens.desktop${NC}"
    fi
}

# Maps this machine to the target triple used in release asset names.
detect_target() {
    case "$(uname -s)-$(uname -m)" in
        Linux-x86_64|Linux-amd64) echo "x86_64-unknown-linux-gnu" ;;
        *) return 1 ;;
    esac
}

sha256_of() {
    if command -v sha256sum &> /dev/null; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# Downloads and verifies the prebuilt binary from the latest GitHub release.
# Returns 0 and sets PREBUILT_DIR when a verified binary is ready, 1 when no
# usable prebuilt exists (fall back to a source build), and exits the script
# when the checksum does not match. It is called as an `if` condition, where
# `set -e` does not apply, so every step checks its own result.
fetch_prebuilt() {
    local target latest_url tag asset base tmp expected actual dir

    if ! target=$(detect_target); then
        echo -e "${YELLOW}No hay binario precompilado para $(uname -s) $(uname -m).${NC}"
        return 1
    fi
    if ! command -v curl &> /dev/null; then
        echo -e "${YELLOW}curl no está instalado; no se puede descargar el binario precompilado.${NC}"
        return 1
    fi
    if ! command -v sha256sum &> /dev/null && ! command -v shasum &> /dev/null; then
        echo -e "${YELLOW}No hay sha256sum ni shasum para verificar la descarga.${NC}"
        return 1
    fi

    echo -e "${BLUE}Buscando la última release de VT Lens para $target...${NC}"
    # /releases/latest redirects to /releases/tag/<tag> when a release exists.
    if ! latest_url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest"); then
        echo -e "${YELLOW}No se pudo consultar la última release.${NC}"
        return 1
    fi
    tag="${latest_url##*/releases/tag/}"
    if [ -z "$tag" ] || [ "$tag" = "$latest_url" ]; then
        echo -e "${YELLOW}Todavía no hay releases publicadas.${NC}"
        return 1
    fi

    asset="vt-lens-$tag-$target.tar.gz"
    base="https://github.com/$REPO/releases/download/$tag"
    make_temp_dir
    tmp="$TEMP_DIR"

    if ! curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS" \
        || ! curl -fsSL -o "$tmp/$asset" "$base/$asset"; then
        echo -e "${YELLOW}La release $tag no tiene $asset o SHA256SUMS.${NC}"
        return 1
    fi

    # From here on, any problem with the downloaded files is fatal: never fall
    # back silently after a failed integrity check.
    expected=$(awk -v f="$asset" '$2 == f || $2 == "*" f {print $1; exit}' "$tmp/SHA256SUMS")
    if [ -z "$expected" ]; then
        echo -e "${RED}Error: SHA256SUMS de $tag no incluye $asset. Instalación abortada.${NC}"
        exit 1
    fi
    actual=$(sha256_of "$tmp/$asset")
    if [ "$expected" != "$actual" ]; then
        echo -e "${RED}Error: el SHA256 de $asset no coincide. Instalación abortada.${NC}"
        echo -e "  esperado: $expected"
        echo -e "  obtenido: $actual"
        exit 1
    fi
    echo -e "${GREEN}✓ SHA256 verificado ($asset).${NC}"

    dir="$tmp/vt-lens-$tag-$target"
    if ! tar -xzf "$tmp/$asset" -C "$tmp" || [ ! -f "$dir/vt-lens" ]; then
        echo -e "${RED}Error: $asset no contiene el binario vt-lens. Instalación abortada.${NC}"
        exit 1
    fi

    PREBUILT_DIR="$dir"
    return 0
}

install_from_source() {
    # Detect if running from inside the source directory or if we need to clone it
    if [ ! -f "Cargo.toml" ] || ! grep -q "vt-lens" Cargo.toml 2>/dev/null; then
        echo -e "${BLUE}No se detectó el código fuente local de VT Lens.${NC}"

        if ! command -v git &> /dev/null; then
            echo -e "${RED}Error: Git no está instalado y es requerido para clonar el proyecto.${NC}"
            exit 1
        fi

        if [ "$DRY_RUN" -eq 1 ]; then
            echo -e "${YELLOW}[dry-run]${NC} git clone https://github.com/$REPO.git <directorio temporal>"
            echo -e "${YELLOW}[dry-run]${NC} cargo build --release --locked"
            install_files "target/release/vt-lens" "vt-lens.desktop"
            return
        fi

        echo -e "${BLUE}Clonando repositorio temporal desde GitHub...${NC}"
        make_temp_dir
        git clone "https://github.com/$REPO.git" "$TEMP_DIR"
        cd "$TEMP_DIR"
    fi

    # 1. Check for cargo/rust
    if ! command -v cargo &> /dev/null; then
        echo -e "${RED}Error: Rust/Cargo no está instalado.${NC}"
        echo -e "Por favor, instala Rust ejecutando:"
        echo -e "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        echo -e "Y reinicia tu terminal antes de volver a intentar la instalación."
        exit 1
    fi

    # 2. Build in release mode
    if [ "$DRY_RUN" -eq 1 ]; then
        echo -e "${YELLOW}[dry-run]${NC} cargo build --release --locked"
    else
        echo -e "${BLUE}Compilando VT Lens en modo release...${NC}"
        if cargo build --release --locked; then
            echo -e "${GREEN}✓ Compilación completada con éxito.${NC}"
        else
            echo -e "${RED}Error: La compilación falló.${NC}"
            echo -e "Asegúrate de tener instaladas las dependencias gráficas necesarias de egui/eframe."
            exit 1
        fi
    fi

    # 3. Install binary and desktop shortcut
    install_files "target/release/vt-lens" "vt-lens.desktop"
}

if [ "$FROM_SOURCE" -eq 1 ]; then
    echo -e "${BLUE}--from-source: se compilará desde el código fuente.${NC}"
    install_from_source
elif fetch_prebuilt; then
    install_files "$PREBUILT_DIR/vt-lens" "$PREBUILT_DIR/vt-lens.desktop"
else
    echo -e "${BLUE}Se compilará desde el código fuente.${NC}"
    install_from_source
fi

# Inform user about PATH if needed
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo -e "${YELLOW}Advertencia: $BIN_DIR no está en tu variable \$PATH.${NC}"
    echo -e "Para ejecutar 'vt-lens' directamente desde la terminal, añade esto a tu ~/.bashrc o ~/.zshrc:"
    echo -e "  export PATH=\"$BIN_DIR:\$PATH\""
fi

if [ "$DRY_RUN" -eq 1 ]; then
    echo -e "\n${GREEN}=== Dry run terminado: no se instaló nada. ===${NC}"
else
    echo -e "\n${GREEN}=== ¡Instalación Completada! ===${NC}"
    echo -e "Ahora puedes buscar 'VT Lens' en el menú de aplicaciones de tu escritorio o ejecutarlo desde la terminal con: vt-lens"
fi
