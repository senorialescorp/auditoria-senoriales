#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# preflight.sh
# Verificacion de requisitos previos de la suite de auditoria.
#
# No tiene equivalente en la version Windows: alli el entorno de ejecucion
# (PowerShell, WMI, .NET) es homogeneo y viene con el sistema. En Linux la
# disponibilidad de herramientas varia entre distribuciones e incluso entre
# instalaciones minimas de la misma, asi que conviene saber ANTES de auditar
# que parte de la cobertura sera efectiva y cual quedara como brecha.
#
# Es de solo lectura: no instala nada.
#
# USO
#   ./preflight.sh
#
# Codigos de salida:
#   0  listo para una corrida con cobertura completa
#   1  ejecutable, pero con cobertura reducida (faltan herramientas opcionales)
#   2  no ejecutable (falta una dependencia dura)
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

VERDE=''; AMARILLO=''; ROJO=''; GRIS=''; RESET=''
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    VERDE=$'\033[0;32m'; AMARILLO=$'\033[0;33m'; ROJO=$'\033[0;31m'
    GRIS=$'\033[2m'; RESET=$'\033[0m'
fi

duras_faltantes=0
opcionales_faltantes=0

ok()   { printf '  %s[ OK ]%s %-22s %s\n' "$VERDE" "$RESET" "$1" "${2:-}"; }
warn() { printf '  %s[ !! ]%s %-22s %s\n' "$AMARILLO" "$RESET" "$1" "${2:-}"; opcionales_faltantes=$((opcionales_faltantes+1)); }
err()  { printf '  %s[FALTA]%s %-21s %s\n' "$ROJO" "$RESET" "$1" "${2:-}"; duras_faltantes=$((duras_faltantes+1)); }
info() { printf '  %s%s%s\n' "$GRIS" "$1" "$RESET"; }

titulo() { printf '\n%s\n' "$1"; }

printf '===============================================================\n'
printf '  VERIFICACION DE REQUISITOS - SUITE DE AUDITORIA\n'
printf '===============================================================\n'

# ---------------------------------------------------------------------------
titulo 'Plataforma'
# ---------------------------------------------------------------------------
if [ -r /etc/os-release ]; then
    distro=$(. /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-$ID}")
    ok 'Distribucion' "$distro"
else
    warn 'Distribucion' 'no se pudo leer /etc/os-release'
fi
ok 'Kernel' "$(uname -r 2>/dev/null)"
ok 'Arquitectura' "$(uname -m 2>/dev/null)"

bash_major=${BASH_VERSINFO[0]:-0}
if [ "$bash_major" -ge 4 ]; then
    ok 'bash' "version ${BASH_VERSION%%(*} (se requiere 4.0 o superior)"
else
    err 'bash' "version ${BASH_VERSION:-desconocida}; la suite requiere bash 4.0 o superior"
fi

# ---------------------------------------------------------------------------
titulo 'Dependencias obligatorias'
# ---------------------------------------------------------------------------
if command -v jq >/dev/null 2>&1; then
    ok 'jq' "$(jq --version 2>/dev/null)"
else
    err 'jq' 'toda la suite intercambia JSON; sin jq no puede ejecutarse'
    info '      Debian/Ubuntu: apt-get install jq | RHEL: dnf install jq'
    info '      SUSE: zypper install jq          | Alpine: apk add jq'
fi

for h in awk sed grep sort find stat date; do
    if command -v "$h" >/dev/null 2>&1; then ok "$h" ''; else err "$h" 'utilidad POSIX ausente'; fi
done

if command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || command -v openssl >/dev/null 2>&1; then
    ok 'SHA-256' 'disponible (cadena de custodia de la evidencia)'
else
    err 'SHA-256' 'sin sha256sum, shasum ni openssl no hay hashes de integridad'
fi

# ---------------------------------------------------------------------------
titulo 'Entregables ofimaticos (.xlsx / .docx)'
# ---------------------------------------------------------------------------
if command -v zip >/dev/null 2>&1; then
    ok 'zip' 'contenedor OOXML'
elif command -v python3 >/dev/null 2>&1; then
    ok 'python3' 'contenedor OOXML (respaldo de zip)'
else
    warn 'zip / python3' 'sin uno de los dos NO se generaran .xlsx ni .docx (si HTML/CSV/JSON)'
fi

# ---------------------------------------------------------------------------
titulo 'Gestor de paquetes (capa L4, prioritaria)'
# ---------------------------------------------------------------------------
if   command -v dpkg-query >/dev/null 2>&1; then ok 'dpkg' 'familia Debian/Ubuntu'
elif command -v rpm        >/dev/null 2>&1; then ok 'rpm'  'familia RHEL/SUSE'
elif command -v apk        >/dev/null 2>&1; then ok 'apk'  'Alpine'
else
    err 'gestor de paquetes' 'sin dpkg, rpm ni apk la capa L4 queda sin evidencia'
fi

for extra in snap flatpak; do
    command -v "$extra" >/dev/null 2>&1 && ok "$extra" 'formato adicional inventariado'
done

# ---------------------------------------------------------------------------
titulo 'Cobertura por colector'
# ---------------------------------------------------------------------------
comprobar() {  # comprobar <colector> <descripcion> <cmd1> [cmd2 ...]
    local col=$1 desc=$2; shift 2
    local c
    for c in "$@"; do
        if command -v "$c" >/dev/null 2>&1; then ok "$col" "$desc (via $c)"; return; fi
    done
    warn "$col" "$desc: cobertura reducida (falta: $*)"
}

comprobar 'L1-01' 'inventario de discos'      lsblk
comprobar 'L1-01' 'detalle de CPU'            lscpu
comprobar 'L1-01' 'modulos de memoria'        dmidecode
comprobar 'L2-01' 'zona horaria y NTP'        timedatectl
comprobar 'L2-03' 'control de acceso obligatorio' getenforce aa-status
comprobar 'L2-03' 'firewall de host'          firewall-cmd ufw nft iptables
comprobar 'L2-03' 'auditoria del kernel'      auditctl
comprobar 'L5-01' 'servicios'                 systemctl rc-status
comprobar 'L6-01' 'ultimo inicio de sesion'   lastlog
comprobar 'L7-01' 'puertos en escucha'        ss netstat
comprobar 'L8-01' 'registro del sistema'      journalctl
comprobar 'L8-01' 'instantaneas de volumen'   lvs btrfs zfs

# ---------------------------------------------------------------------------
titulo 'Privilegios'
# ---------------------------------------------------------------------------
if [ "$(id -u)" -eq 0 ]; then
    ok 'root' 'cobertura completa'
else
    warn 'root' "ejecutando como $(id -un); varias verificaciones quedaran como brecha de evidencia"
    info '      No es un error: la suite degrada y documenta lo que no pudo verificar.'
    info '      Para un expediente formal, ejecutar con sudo.'
fi

# ---------------------------------------------------------------------------
titulo 'Archivos de la suite'
# ---------------------------------------------------------------------------
for f in lib/audit_core.sh lib/classify.awk lib/xlsx_writer.sh lib/docx_writer.sh \
         config/audit.config.json config/criterios.auditoria.json config/arquitectura.json \
         audit.sh; do
    if [ -r "$SCRIPT_DIR/$f" ]; then ok "$f" ''; else err "$f" 'archivo ausente'; fi
done

n_col=$(find "$SCRIPT_DIR/collectors" -maxdepth 1 -name '*.sh' 2>/dev/null | grep -c .)
if [ "${n_col:-0}" -gt 0 ]; then ok 'collectors/' "$n_col colectores"; else err 'collectors/' 'sin colectores'; fi

if command -v jq >/dev/null 2>&1; then
    for f in config/audit.config.json config/criterios.auditoria.json config/arquitectura.json; do
        [ -r "$SCRIPT_DIR/$f" ] || continue
        if jq -e . "$SCRIPT_DIR/$f" >/dev/null 2>&1; then ok "$f" 'JSON valido'; else err "$f" 'JSON MAL FORMADO'; fi
    done
fi

# ---------------------------------------------------------------------------
printf '\n===============================================================\n'
if [ "$duras_faltantes" -gt 0 ]; then
    printf '  %sNO EJECUTABLE%s: faltan %s dependencias obligatorias.\n' "$ROJO" "$RESET" "$duras_faltantes"
    printf '===============================================================\n\n'
    exit 2
elif [ "$opcionales_faltantes" -gt 0 ]; then
    printf '  %sEJECUTABLE CON COBERTURA REDUCIDA%s: %s comprobaciones limitadas.\n' \
        "$AMARILLO" "$RESET" "$opcionales_faltantes"
    printf '  Las limitaciones se documentaran como brechas de evidencia en el reporte.\n'
    printf '===============================================================\n\n'
    exit 1
else
    printf '  %sLISTO%s para una corrida con cobertura completa.\n' "$VERDE" "$RESET"
    printf '===============================================================\n\n'
    exit 0
fi
