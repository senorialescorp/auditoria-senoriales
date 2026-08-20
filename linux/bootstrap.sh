#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# bootstrap.sh
# Instalador de Claude Code para Linux (equivalente de bootstrap.ps1).
#
# NOTA DE ALCANCE: este archivo NO forma parte de la suite de auditoria. Es la
# traduccion del bootstrap.ps1 que acompanaba a la carpeta windows/, y se
# conserva por fidelidad con el original. Para verificar los requisitos de la
# suite de auditoria use ./preflight.sh.
#
# Descarga el binario de la plataforma, verifica su suma de comprobacion contra
# el manifiesto publicado y delega la instalacion al propio binario.
#
# USO
#   ./bootstrap.sh              Instala la version 'latest'
#   ./bootstrap.sh stable       Instala el canal estable
#   ./bootstrap.sh 1.2.3        Instala una version concreta
# ---------------------------------------------------------------------------

set -euo pipefail

TARGET=${1:-latest}

# Validacion del argumento, equivalente al ValidatePattern del original
case $TARGET in
    stable|latest) ;;
    [0-9]*.[0-9]*.[0-9]*) ;;
    *)
        echo "ERROR: destino no valido '$TARGET'. Use 'stable', 'latest' o una version X.Y.Z." >&2
        exit 1 ;;
esac

DOWNLOAD_BASE_URL='https://downloads.claude.ai/claude-code-releases'
DOWNLOAD_DIR="$HOME/.claude/downloads"

# ---------------------------------------------------------------------------
# Deteccion de plataforma
# ---------------------------------------------------------------------------
case "$(uname -s)" in
    Linux) ;;
    Darwin) ;;
    *) echo "ERROR: sistema operativo no soportado: $(uname -s)" >&2; exit 1 ;;
esac

case "$(uname -m)" in
    x86_64|amd64)  ARCH='x64' ;;
    aarch64|arm64) ARCH='arm64' ;;
    *) echo "ERROR: arquitectura no soportada: $(uname -m)" >&2; exit 1 ;;
esac

if [ "$(uname -s)" = 'Darwin' ]; then
    PLATFORM="darwin-$ARCH"
else
    PLATFORM="linux-$ARCH"
    # Las distribuciones con musl (Alpine) requieren la variante estatica
    if ! ldd /bin/sh 2>/dev/null | grep -q 'GNU C Library\|libc.so.6'; then
        PLATFORM="linux-$ARCH-musl"
    fi
fi

# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------
if command -v curl >/dev/null 2>&1; then
    obtener() { curl -fsSL --max-time 120 "$1"; }
    descargar() { curl -fsSL --max-time 600 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
    obtener() { wget -qO- --timeout=120 "$1"; }
    descargar() { wget -q --timeout=600 -O "$2" "$1"; }
else
    echo "ERROR: se requiere 'curl' o 'wget' para descargar el instalador." >&2
    exit 1
fi

sha256_de() {
    if   command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum    >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
    elif command -v openssl   >/dev/null 2>&1; then openssl dgst -sha256 "$1" | awk '{print $NF}'
    else echo "ERROR: no hay herramienta para calcular SHA-256." >&2; exit 1
    fi
}

mkdir -p "$DOWNLOAD_DIR"

# ---------------------------------------------------------------------------
# Version: siempre se consulta 'latest', que trae el instalador mas reciente
# ---------------------------------------------------------------------------
if ! VERSION=$(obtener "$DOWNLOAD_BASE_URL/latest"); then
    echo "ERROR: no se pudo obtener la ultima version." >&2
    exit 1
fi
VERSION=$(printf '%s' "$VERSION" | tr -d '[:space:]')

# Rechazar contenido que no sea una version (por ejemplo, una pagina de error)
case $VERSION in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *)
        echo "ERROR: no se obtuvo una version valida de downloads.claude.ai (contenido inesperado)." >&2
        echo "Puede ocurrir si el servicio de descarga no es alcanzable o no esta disponible en su region:" >&2
        echo "  https://www.anthropic.com/supported-countries" >&2
        exit 1 ;;
esac

# ---------------------------------------------------------------------------
# Manifiesto y suma de comprobacion
# ---------------------------------------------------------------------------
if ! MANIFEST=$(obtener "$DOWNLOAD_BASE_URL/$VERSION/manifest.json"); then
    echo "ERROR: no se pudo obtener el manifiesto." >&2
    exit 1
fi

if command -v jq >/dev/null 2>&1; then
    CHECKSUM=$(printf '%s' "$MANIFEST" | jq -r --arg p "$PLATFORM" '.platforms[$p].checksum // empty')
else
    # Extraccion sin jq, para no imponer la dependencia en el instalador
    CHECKSUM=$(printf '%s' "$MANIFEST" |
        tr -d ' \n' |
        sed -n "s/.*\"$PLATFORM\":{[^}]*\"checksum\":\"\([a-f0-9]*\)\".*/\1/p")
fi

if [ -z "$CHECKSUM" ]; then
    echo "ERROR: la plataforma $PLATFORM no figura en el manifiesto." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Descarga y verificacion
# ---------------------------------------------------------------------------
BINARIO="$DOWNLOAD_DIR/claude-$VERSION-$PLATFORM"

limpiar() { rm -f "$BINARIO" 2>/dev/null || true; }

if ! descargar "$DOWNLOAD_BASE_URL/$VERSION/$PLATFORM/claude" "$BINARIO"; then
    echo "ERROR: fallo la descarga del binario." >&2
    limpiar
    exit 1
fi

ACTUAL=$(sha256_de "$BINARIO" | tr 'A-F' 'a-f')
if [ "$ACTUAL" != "$(printf '%s' "$CHECKSUM" | tr 'A-F' 'a-f')" ]; then
    echo "ERROR: la verificacion de la suma de comprobacion fallo." >&2
    echo "  esperada: $CHECKSUM" >&2
    echo "  obtenida: $ACTUAL" >&2
    limpiar
    exit 1
fi

chmod +x "$BINARIO"

# ---------------------------------------------------------------------------
# Instalacion
# ---------------------------------------------------------------------------
echo 'Configurando Claude Code...'
set +e
"$BINARIO" install "$TARGET"
RC=$?
set -e

limpiar

if [ "$RC" -ne 0 ]; then
    echo "ERROR: la instalacion fallo (codigo de salida $RC)" >&2
    exit "$RC"
fi

echo
printf '\xe2\x9c\x85 Instalacion completada.\n'
echo
