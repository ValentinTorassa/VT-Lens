#!/usr/bin/env bash

set -eo pipefail

# Text formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== VT Lens Installer ===${NC}"

# Detect if running from inside the source directory or if we need to clone it
if [ ! -f "Cargo.toml" ] || ! grep -q "vt-lens" Cargo.toml 2>/dev/null; then
    echo -e "${BLUE}No se detectó el código fuente local de VT Lens.${NC}"
    echo -e "${BLUE}Clonando repositorio temporal desde GitHub...${NC}"
    
    if ! command -v git &> /dev/null; then
        echo -e "${RED}Error: Git no está instalado y es requerido para clonar el proyecto.${NC}"
        exit 1
    fi
    
    TEMP_DIR=$(mktemp -d)
    git clone https://github.com/ValentinTorassa/vt-lens.git "$TEMP_DIR"
    cd "$TEMP_DIR"
    
    # Clean up the temp directory on exit
    trap 'rm -rf "$TEMP_DIR"' EXIT
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
echo -e "${BLUE}Compilando VT Lens en modo release...${NC}"
if cargo build --release; then
    echo -e "${GREEN}✓ Compilación completada con éxito.${NC}"
else
    echo -e "${RED}Error: La compilación falló.${NC}"
    echo -e "Asegúrate de tener instaladas las dependencias gráficas necesarias de egui/eframe."
    exit 1
fi

# 3. Create destination folders if they don't exist
BIN_DIR="$HOME/.local/bin"
APP_DIR="$HOME/.local/share/applications"

mkdir -p "$BIN_DIR"
mkdir -p "$APP_DIR"

# 4. Copy binary
echo -e "${BLUE}Instalando binario ejecutable...${NC}"
cp target/release/vt-lens "$BIN_DIR/vt-lens"
chmod +x "$BIN_DIR/vt-lens"
echo -e "${GREEN}✓ Ejecutable instalado en: $BIN_DIR/vt-lens${NC}"

# 5. Copy desktop shortcut
echo -e "${BLUE}Instalando acceso directo de escritorio...${NC}"
cp vt-lens.desktop "$APP_DIR/vt-lens.desktop"
chmod +x "$APP_DIR/vt-lens.desktop"
echo -e "${GREEN}✓ Acceso directo instalado en: $APP_DIR/vt-lens.desktop${NC}"

# 6. Inform user about PATH if needed
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo -e "${YELLOW}Advertencia: $BIN_DIR no está en tu variable \$PATH.${NC}"
    echo -e "Para ejecutar 'vt-lens' directamente desde la terminal, añade esto a tu ~/.bashrc o ~/.zshrc:"
    echo -e "  export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

echo -e "\n${GREEN}=== ¡Instalación Completada! ===${NC}"
echo -e "Ahora puedes buscar 'VT Lens' en el menú de aplicaciones de tu escritorio o ejecutarlo desde la terminal con: vt-lens"
