#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# audit_core.sh
# Nucleo comun de la suite de auditoria de sistemas (equivalente Linux de
# Modules/AuditCore/AuditCore.psm1).
#
# Provee: contexto de ejecucion, logging, contrato de colectores, generacion
# de hallazgos, inventario base de software, verificacion de integridad de
# paquetes y exportacion de evidencia con hashes.
#
# NOTA DE CODIFICACION: este archivo se mantiene deliberadamente en ASCII (sin
# tildes ni caracteres especiales) para que sea legible en consolas con locale
# POSIX y en servidores sin soporte UTF-8 configurado. Los textos de salida
# (HTML/CSV/JSON) se escriben siempre como UTF-8.
#
# EQUIVALENCIAS WINDOWS -> LINUX aplicadas en este nucleo:
#   Registro Uninstall        -> dpkg-query / rpm -qa / apk info / flatpak / snap
#   Firma Authenticode        -> pertenencia a paquete gestionado + verificacion
#                                de integridad del gestor (dpkg -V / rpm -V) +
#                                firma GPG del repositorio de origen
#   Get-FileHash SHA256       -> sha256sum
#   Test-IsAdministrator      -> EUID == 0
#   Win32_* (CIM)             -> /proc, /sys, dmidecode, lsblk, lscpu, ip
# ---------------------------------------------------------------------------

# Modo estricto sin -e: los colectores degradan con elegancia ante datos ausentes.
set -o pipefail
umask 077

# ---------------------------------------------------------------------------
# Dependencias
# ---------------------------------------------------------------------------

AUDIT_CORE_VERSION='1.0.0'

# Directorio de este propio archivo: los colectores lo necesitan para localizar
# los auxiliares (classify.awk) sin depender del directorio de trabajo actual.
AUDIT_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export AUDIT_LIB_DIR

has_cmd() { command -v "$1" >/dev/null 2>&1; }

# jq es la unica dependencia dura: la suite entera intercambia JSON.
if ! has_cmd jq; then
    echo "ERROR: la suite requiere 'jq'. Instalelo con el gestor de la distribucion:" >&2
    echo "  Debian/Ubuntu : apt-get install jq" >&2
    echo "  RHEL/Rocky    : dnf install jq" >&2
    echo "  SUSE          : zypper install jq" >&2
    echo "  Alpine        : apk add jq" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Deteccion de plataforma
# ---------------------------------------------------------------------------

# Familia de gestor de paquetes: deb | rpm | apk | unknown
detect_pkg_family() {
    if [ -n "${AUDIT_PKG_FAMILY:-}" ]; then printf '%s' "$AUDIT_PKG_FAMILY"; return; fi
    local f='unknown'
    if has_cmd dpkg-query && [ -f /var/lib/dpkg/status ]; then f='deb'
    elif has_cmd rpm && [ -d /var/lib/rpm ] || has_cmd rpm && [ -d /usr/lib/sysimage/rpm ]; then f='rpm'
    elif has_cmd apk && [ -f /lib/apk/db/installed ]; then f='apk'
    elif has_cmd rpm; then f='rpm'
    fi
    AUDIT_PKG_FAMILY=$f
    printf '%s' "$f"
}

# Herramienta de actualizacion de alto nivel: apt | dnf | yum | zypper | apk
detect_pkg_tool() {
    if [ -n "${AUDIT_PKG_TOOL:-}" ]; then printf '%s' "$AUDIT_PKG_TOOL"; return; fi
    local t=''
    if   has_cmd apt-get; then t='apt'
    elif has_cmd dnf;     then t='dnf'
    elif has_cmd yum;     then t='yum'
    elif has_cmd zypper;  then t='zypper'
    elif has_cmd apk;     then t='apk'
    fi
    AUDIT_PKG_TOOL=$t
    printf '%s' "$t"
}

# Sistema de init: systemd | openrc | sysvinit | unknown
detect_init_system() {
    if [ -n "${AUDIT_INIT_SYSTEM:-}" ]; then printf '%s' "$AUDIT_INIT_SYSTEM"; return; fi
    local i='unknown'
    if [ -d /run/systemd/system ] && has_cmd systemctl; then i='systemd'
    elif has_cmd rc-status || [ -d /etc/runlevels ]; then i='openrc'
    elif [ -d /etc/init.d ]; then i='sysvinit'
    fi
    AUDIT_INIT_SYSTEM=$i
    printf '%s' "$i"
}

# Identificador de distribucion segun /etc/os-release
os_release_field() {
    local campo=$1 v=''
    if [ -r /etc/os-release ]; then
        v=$(. /etc/os-release 2>/dev/null; eval "printf '%s' \"\${$campo:-}\"")
    fi
    printf '%s' "$v"
}

# ---------------------------------------------------------------------------
# Serializacion JSON
# ---------------------------------------------------------------------------

# Escapa una cadena para incrustarla como valor JSON (sin comillas envolventes).
# Implementado en bash puro para evitar un subproceso por campo: el inventario
# de software puede generar decenas de miles de campos.
json_escape() {
    local s=${1-}
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/ }
    s=${s//$'\r'/ }
    s=${s//$'\t'/ }
    # Caracteres de control restantes: se eliminan (solo si los hay)
    case $s in
        *[$'\001'-$'\037']*|*$'\177'*)
            s=$(printf '%s' "$s" | LC_ALL=C tr -d '\001-\037\177') ;;
    esac
    printf '%s' "$s"
}

# Normaliza a numero JSON valido; devuelve 0 si el valor no es numerico.
json_num() {
    local v=${1-}
    v=${v//,/.}
    v=${v// /}
    case $v in
        ''|*[!0-9.eE+-]*) printf '0' ;;
        *) printf '%s' "$v" ;;
    esac
}

# Normaliza a booleano JSON.
json_bool() {
    case "${1-}" in
        true|TRUE|True|1|yes|Yes|si|Si|SI|on|On) printf 'true' ;;
        *) printf 'false' ;;
    esac
}

# Construye un objeto JSON a partir de pares clave/valor.
#
#   json_obj Nombre "nginx" Puerto:n 443 Activo:b si Extra:j '{"a":1}'
#
# Sufijos de tipo en la clave:
#   :n  -> numero      :b -> booleano
#   :j  -> JSON crudo  :r -> arreglo de cadenas separadas por '|'
# Sin sufijo el valor se emite como cadena.
json_obj() {
    local out='{' first=1 k v tipo item
    while [ "$#" -gt 0 ]; do
        k=$1; v=${2-}; shift 2 2>/dev/null || shift
        tipo='s'
        case $k in
            *:n) k=${k%:n}; tipo='n' ;;
            *:b) k=${k%:b}; tipo='b' ;;
            *:j) k=${k%:j}; tipo='j' ;;
            *:r) k=${k%:r}; tipo='r' ;;
        esac
        [ $first -eq 1 ] || out+=','
        first=0
        out+="\"$(json_escape "$k")\":"
        case $tipo in
            n) out+="$(json_num "$v")" ;;
            b) out+="$(json_bool "$v")" ;;
            j) out+="${v:-null}" ;;
            r) out+='['
               local sep='' IFS='|'
               for item in $v; do
                   [ -z "$item" ] && continue
                   out+="$sep\"$(json_escape "$item")\""
                   sep=','
               done
               unset IFS
               out+=']' ;;
            *) out+="\"$(json_escape "$v")\"" ;;
        esac
    done
    out+='}'
    printf '%s' "$out"
}

# Recorta y normaliza una cadena para que sea apta como campo de evidencia.
# Equivalente de ConvertTo-SafeString.
safe_str() {
    local s=${1-} max=${2:-4000}
    s=${s//$'\n'/ }
    s=${s//$'\r'/ }
    s=${s//$'\t'/ }
    # Colapsa espacios repetidos en cualquier posicion, no solo al inicio
    while [ "$s" != "${s//  / }" ]; do s=${s//  / }; done
    s=${s#"${s%%[![:space:]]*}"}
    s=${s%"${s##*[![:space:]]}"}
    if [ ${#s} -gt "$max" ]; then s="${s:0:$max}..."; fi
    printf '%s' "$s"
}

# ---------------------------------------------------------------------------
# Contexto de ejecucion
# ---------------------------------------------------------------------------

# init_audit_context <root_path> [output_root] [run_id] [log_root]
init_audit_context() {
    AUDIT_ROOT=${1:?ruta raiz requerida}
    AUDIT_OUTPUT_ROOT=${2:-}
    AUDIT_RUN_ID=${3:-}
    AUDIT_LOG_ROOT=${4:-}

    [ -n "$AUDIT_RUN_ID" ]      || AUDIT_RUN_ID=$(date +%Y%m%d-%H%M%S)
    [ -n "$AUDIT_OUTPUT_ROOT" ] || AUDIT_OUTPUT_ROOT="$AUDIT_ROOT/Output"
    [ -n "$AUDIT_LOG_ROOT" ]    || AUDIT_LOG_ROOT="$AUDIT_ROOT/Logs"

    AUDIT_RUN_PATH="$AUDIT_OUTPUT_ROOT/$AUDIT_RUN_ID"
    AUDIT_RAW_PATH="$AUDIT_RUN_PATH/raw"
    AUDIT_CSV_PATH="$AUDIT_RUN_PATH/csv"
    AUDIT_EVIDENCE_PATH="$AUDIT_RUN_PATH/evidence"
    AUDIT_LOG_FILE="$AUDIT_LOG_ROOT/audit-$AUDIT_RUN_ID.log"

    mkdir -p "$AUDIT_RUN_PATH" "$AUDIT_RAW_PATH" "$AUDIT_CSV_PATH" \
             "$AUDIT_EVIDENCE_PATH" "$AUDIT_LOG_ROOT" 2>/dev/null

    AUDIT_START_EPOCH=$(date +%s)
    AUDIT_START_TIME=$(date +%Y-%m-%dT%H:%M:%S)
    AUDIT_HOSTNAME=$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || printf 'desconocido')
    AUDIT_DOMAIN=$(hostname -d 2>/dev/null || printf '')
    AUDIT_RUNAS=$(id -un 2>/dev/null || printf "${USER:-desconocido}")
    if [ "$(id -u 2>/dev/null || printf 1)" -eq 0 ]; then AUDIT_IS_ROOT=1; else AUDIT_IS_ROOT=0; fi

    # Manifiesto de artefactos escritos (cadena de custodia)
    AUDIT_ARTIFACTS_FILE=$(mktemp) || AUDIT_ARTIFACTS_FILE="/tmp/audit-artifacts.$$"
    : > "$AUDIT_ARTIFACTS_FILE"

    export AUDIT_ROOT AUDIT_RUN_ID AUDIT_RUN_PATH AUDIT_RAW_PATH AUDIT_CSV_PATH \
           AUDIT_EVIDENCE_PATH AUDIT_LOG_FILE AUDIT_HOSTNAME AUDIT_DOMAIN \
           AUDIT_RUNAS AUDIT_IS_ROOT AUDIT_ARTIFACTS_FILE AUDIT_START_TIME

    audit_log INFO CORE "Contexto inicializado. RunId=$AUDIT_RUN_ID Host=$AUDIT_HOSTNAME Root=$AUDIT_IS_ROOT Distro=$(os_release_field PRETTY_NAME) Pkg=$(detect_pkg_family) Init=$(detect_init_system)"
}

is_root() { [ "${AUDIT_IS_ROOT:-0}" -eq 1 ]; }

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

C_RESET=''; C_GRAY=''; C_YELLOW=''; C_RED=''; C_GREEN=''; C_CYAN=''; C_WHITE=''; C_DIM=''
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != 'dumb' ]; then
    C_RESET=$'\033[0m'; C_GRAY=$'\033[0;37m'; C_YELLOW=$'\033[0;33m'
    C_RED=$'\033[0;31m'; C_GREEN=$'\033[0;32m'; C_CYAN=$'\033[0;36m'
    C_WHITE=$'\033[1;37m'; C_DIM=$'\033[2m'
fi

# audit_log <NIVEL> <FUENTE> <MENSAJE> [quiet]
audit_log() {
    local nivel=${1:-INFO} fuente=${2:-CORE} msg=${3:-} quiet=${4:-}
    local stamp linea color
    stamp=$(date '+%Y-%m-%d %H:%M:%S')
    linea=$(printf '%s [%-5s] [%s] %s' "$stamp" "$nivel" "$fuente" "$msg")

    if [ -n "${AUDIT_LOG_FILE:-}" ]; then
        printf '%s\n' "$linea" >> "$AUDIT_LOG_FILE" 2>/dev/null
    fi
    [ -n "$quiet" ] && return 0

    case $nivel in
        DEBUG) color=$C_DIM ;; INFO) color=$C_GRAY ;; WARN) color=$C_YELLOW ;;
        ERROR) color=$C_RED ;; OK) color=$C_GREEN ;; *) color='' ;;
    esac
    printf '%s%s%s\n' "$color" "$linea" "$C_RESET" >&2
}

# ---------------------------------------------------------------------------
# Acceso a configuracion
# ---------------------------------------------------------------------------

# cfg <filtro jq> [default]   -> lee AUDIT_CONFIG (audit.config.json)
cfg() {
    local filtro=$1 def=${2:-}
    local v
    v=$(jq -r "$filtro // empty" "${AUDIT_CONFIG:?AUDIT_CONFIG no definido}" 2>/dev/null)
    [ -n "$v" ] && [ "$v" != 'null' ] && { printf '%s' "$v"; return 0; }
    printf '%s' "$def"
}

# cfg_json <filtro jq>  -> devuelve JSON crudo (arreglos/objetos)
cfg_json() {
    jq -c "${1} // []" "${AUDIT_CONFIG:?}" 2>/dev/null || printf '[]'
}

# arq <filtro jq> [default]  -> lee AUDIT_ARQUITECTURA (arquitectura.json)
arq() {
    local filtro=$1 def=${2:-} v
    [ -n "${AUDIT_ARQUITECTURA:-}" ] && [ -r "$AUDIT_ARQUITECTURA" ] || { printf '%s' "$def"; return 0; }
    v=$(jq -r "$filtro // empty" "$AUDIT_ARQUITECTURA" 2>/dev/null)
    [ -n "$v" ] && [ "$v" != 'null' ] && { printf '%s' "$v"; return 0; }
    printf '%s' "$def"
}

arq_json() {
    [ -n "${AUDIT_ARQUITECTURA:-}" ] && [ -r "$AUDIT_ARQUITECTURA" ] || { printf '[]'; return 0; }
    jq -c "${1} // []" "$AUDIT_ARQUITECTURA" 2>/dev/null || printf '[]'
}

# ---------------------------------------------------------------------------
# Ejecucion de binarios nativos con timeout duro
# ---------------------------------------------------------------------------
#
# Equivalente de Invoke-NativeCapture. Captura stdout y stderr por separado y
# aplica un limite de tiempo para que un comando colgado no bloquee la corrida
# completa (requisito del criterio AUD-01: la auditoria no debe degradar el
# servicio del activo auditado).
#
# Resultado en variables globales: NC_OUT, NC_ERR, NC_RC, NC_TIMEDOUT
native_capture() {
    local timeout_seg=$1; shift
    local tmp_out tmp_err
    tmp_out=$(mktemp) ; tmp_err=$(mktemp)
    NC_OUT=''; NC_ERR=''; NC_RC=0; NC_TIMEDOUT=0

    if has_cmd timeout; then
        timeout -k 2 "$timeout_seg" "$@" >"$tmp_out" 2>"$tmp_err"
        NC_RC=$?
        [ $NC_RC -eq 124 ] && NC_TIMEDOUT=1
    else
        "$@" >"$tmp_out" 2>"$tmp_err"
        NC_RC=$?
    fi

    NC_OUT=$(cat "$tmp_out" 2>/dev/null)
    NC_ERR=$(cat "$tmp_err" 2>/dev/null)
    rm -f "$tmp_out" "$tmp_err"
    return 0
}

# Atajo: ejecuta y devuelve solo stdout, silenciando errores.
run_q() { native_capture "${NC_TIMEOUT:-30}" "$@" ; printf '%s' "$NC_OUT"; }

# ---------------------------------------------------------------------------
# Contrato de colectores
# ---------------------------------------------------------------------------
#
# Cada colector:
#   1. Declara su manifiesto con collector_meta y responde a --manifest
#   2. Acumula registros con  rec  <k> <v> ...
#   3. Acumula hallazgos con  finding  ...
#   4. Acumula brechas con    gap  <texto>
#   5. Acumula metricas con   metric <clave> <valor> [tipo]
#   6. Cierra con             emit_result
#
# La salida es un unico objeto JSON en stdout. Todo lo informativo va a stderr.

collector_init() {
    COL_ID=${1:?}; COL_NOMBRE=${2:?}; COL_LAYER=${3:?}
    COL_CRITERIOS=${4:-}      # separados por '|'
    COL_REQUIERE_ROOT=${5:-false}
    COL_DESCRIPCION=${6:-}

    COL_RECORDS=$(mktemp);  : > "$COL_RECORDS"
    COL_FINDINGS=$(mktemp); : > "$COL_FINDINGS"
    COL_GAPS=$(mktemp);     : > "$COL_GAPS"
    COL_METRICS=$(mktemp);  : > "$COL_METRICS"
    COL_STATUS='Completed'
    COL_REC_COUNT=0
    COL_FIND_COUNT=0

    trap 'rm -f "$COL_RECORDS" "$COL_FINDINGS" "$COL_GAPS" "$COL_METRICS" 2>/dev/null' EXIT
}

# Responde a --manifest y termina. Se invoca al inicio de cada colector: el
# orquestador consulta primero el manifiesto de todos para armar el plan de
# ejecucion sin ejecutar ninguna recoleccion.
maybe_emit_manifest() {
    case "${1:-}" in
        --manifest|-m) collector_manifest_json; exit 0 ;;
    esac
}

collector_manifest_json() {
    json_obj \
        Id "$COL_ID" \
        Nombre "$COL_NOMBRE" \
        Layer "$COL_LAYER" \
        Criterios:r "$COL_CRITERIOS" \
        RequiereRoot:b "$COL_REQUIERE_ROOT" \
        Descripcion "$COL_DESCRIPCION"
}

# rec <clave> <valor> [<clave> <valor> ...]
rec() {
    json_obj "$@" >> "$COL_RECORDS"
    printf '\n' >> "$COL_RECORDS"
    COL_REC_COUNT=$((COL_REC_COUNT + 1))
}

# Numero de registros acumulados. Se lee del archivo y no de la variable
# COL_REC_COUNT porque los bucles "cmd | while read" corren en un subshell:
# el archivo persiste, el contador en memoria no.
rec_count() { grep -c . "$COL_RECORDS" 2>/dev/null || printf 0; }

find_count() { grep -c . "$COL_FINDINGS" 2>/dev/null || printf 0; }

# Anade un registro ya construido como JSON crudo.
rec_raw() {
    printf '%s\n' "$1" >> "$COL_RECORDS"
    COL_REC_COUNT=$((COL_REC_COUNT + 1))
}

# gap <texto>  -> brecha de evidencia (verificacion que no pudo completarse)
gap() {
    printf '%s\n' "$(safe_str "$1" 900)" >> "$COL_GAPS"
}

# metric <clave> <valor> [n|b|s]
metric() {
    local k=$1 v=$2 t=${3:-s}
    case $t in
        n) json_obj k "$k" "v:n" "$v" >> "$COL_METRICS" ;;
        b) json_obj k "$k" "v:b" "$v" >> "$COL_METRICS" ;;
        *) json_obj k "$k" v  "$v"    >> "$COL_METRICS" ;;
    esac
    printf '\n' >> "$COL_METRICS"
}

severity_rank() {
    case $1 in
        Critical) printf 5 ;; High) printf 4 ;; Medium) printf 3 ;;
        Low) printf 2 ;; *) printf 1 ;;
    esac
}

short_hash() {
    local t=$1 h=''
    if has_cmd sha1sum; then h=$(printf '%s' "$t" | sha1sum | cut -c1-8)
    elif has_cmd shasum; then h=$(printf '%s' "$t" | shasum | cut -c1-8)
    elif has_cmd md5sum; then h=$(printf '%s' "$t" | md5sum | cut -c1-8)
    else h=$(printf '%s' "$t" | cksum | tr -d ' ' | cut -c1-8)
    fi
    printf '%s' "$(printf '%s' "$h" | tr 'a-f' 'A-F')"
}

file_sha256() {
    local f=$1
    if   has_cmd sha256sum; then sha256sum "$f" 2>/dev/null | cut -d' ' -f1
    elif has_cmd shasum;    then shasum -a 256 "$f" 2>/dev/null | cut -d' ' -f1
    elif has_cmd openssl;   then openssl dgst -sha256 "$f" 2>/dev/null | awk '{print $NF}'
    fi
}

# finding <severidad> <titulo> [opciones]
#   -a <activo>          -c <categoria>
#   -d <detalle>         -e <evidencia>
#   -k <criterios|sep>   -r <recomendacion>
finding() {
    local sev=$1 titulo=$2; shift 2
    local activo='' categoria='Configuracion' detalle='' evidencia='' criterios='' reco=''
    while [ "$#" -gt 0 ]; do
        case $1 in
            -a) activo=$2; shift 2 ;;
            -c) categoria=$2; shift 2 ;;
            -d) detalle=$2; shift 2 ;;
            -e) evidencia=$2; shift 2 ;;
            -k) criterios=$2; shift 2 ;;
            -r) reco=$2; shift 2 ;;
            *) shift ;;
        esac
    done

    local fid crit_txt
    fid="$COL_ID-$(short_hash "$COL_ID|$titulo|$activo")"
    crit_txt=${criterios//|/; }

    json_obj \
        FindingId "$fid" \
        CollectorId "$COL_ID" \
        Layer "$COL_LAYER" \
        Severity "$sev" \
        SeverityRank:n "$(severity_rank "$sev")" \
        Category "$categoria" \
        Title "$(safe_str "$titulo" 300)" \
        Asset "$(safe_str "$activo" 400)" \
        Detail "$(safe_str "$detalle" 3000)" \
        Evidence "$(safe_str "$evidencia" 3000)" \
        Criterios:r "$criterios" \
        CriteriosTexto "$crit_txt" \
        Recommendation "$(safe_str "$reco" 2000)" \
        Host "${AUDIT_HOSTNAME:-$(hostname 2>/dev/null)}" \
        DetectedAt "$(date +%Y-%m-%dT%H:%M:%S)" >> "$COL_FINDINGS"
    printf '\n' >> "$COL_FINDINGS"
    COL_FIND_COUNT=$((COL_FIND_COUNT + 1))
}

collector_status() { COL_STATUS=$1; }

# Emite el resultado completo del colector como un unico objeto JSON.
emit_result() {
    local meta records findings gaps metrics
    meta=$(collector_manifest_json)
    records=$(jq -sc '.' < "$COL_RECORDS" 2>/dev/null || printf '[]')
    findings=$(jq -sc '.' < "$COL_FINDINGS" 2>/dev/null || printf '[]')
    metrics=$(jq -sc 'map({(.k): .v}) | add // {}' < "$COL_METRICS" 2>/dev/null || printf '{}')
    if [ -s "$COL_GAPS" ]; then
        gaps=$(jq -Rsc 'split("\n") | map(select(length > 0))' < "$COL_GAPS" 2>/dev/null || printf '[]')
    else
        gaps='[]'
    fi
    [ -n "$records" ]  || records='[]'
    [ -n "$findings" ] || findings='[]'
    [ -n "$metrics" ]  || metrics='{}'

    jq -nc \
        --argjson meta "$meta" \
        --arg status "$COL_STATUS" \
        --argjson records "$records" \
        --argjson findings "$findings" \
        --argjson metrics "$metrics" \
        --argjson gaps "$gaps" \
        --arg collected "$(date +%Y-%m-%dT%H:%M:%S)" \
        '{Meta:$meta, Status:$status, Records:$records,
          RecordCount:($records|length), Findings:$findings,
          Metrics:$metrics, Gaps:$gaps, CollectedAt:$collected}'
}

# ---------------------------------------------------------------------------
# Inventario base de software (fuente compartida por varios colectores)
# ---------------------------------------------------------------------------
#
# Equivalente de Get-InstalledSoftwareRaw. En Windows la fuente autoritativa es
# el registro Uninstall; en Linux lo es la base de datos del gestor de paquetes.
#
# Se evita deliberadamente cualquier operacion que modifique estado: nada de
# 'apt update', 'dnf makecache' ni reconstruccion de indices. Solo consultas de
# lectura sobre la base local, igual que la version Windows evita Win32_Product
# por disparar reconfiguraciones MSI.
#
# Emite una linea JSON por paquete con el esquema normalizado:
#   DisplayName DisplayVersion Publisher InstallDate InstallLocation
#   EstimatedSizeMB Scope Architecture PackageType Section Source Comments
#
# Cache: el resultado se memoiza en $AUDIT_SW_CACHE para que L4-01, L4-05 y
# L4-06 no repitan la consulta (es la operacion mas cara del inventario).

installed_software_raw() {
    if [ -n "${AUDIT_SW_CACHE:-}" ] && [ -s "$AUDIT_SW_CACHE" ]; then
        cat "$AUDIT_SW_CACHE"; return 0
    fi
    AUDIT_SW_CACHE=$(mktemp); export AUDIT_SW_CACHE

    local familia; familia=$(detect_pkg_family)

    case $familia in
        deb) _sw_raw_deb ;;
        rpm) _sw_raw_rpm ;;
        apk) _sw_raw_apk ;;
    esac >> "$AUDIT_SW_CACHE"

    # Formatos de empaquetado transversales, presentes en cualquier familia.
    _sw_raw_snap    >> "$AUDIT_SW_CACHE"
    _sw_raw_flatpak >> "$AUDIT_SW_CACHE"

    cat "$AUDIT_SW_CACHE"
}

_sw_raw_deb() {
    # La fecha de instalacion no existe en la base dpkg: se reconstruye desde
    # /var/log/dpkg.log*, que es la unica fuente con trazabilidad temporal.
    local fechas; fechas=$(_deb_install_dates)
    local arch_host; arch_host=$(dpkg --print-architecture 2>/dev/null)

    dpkg-query -W -f='${Package}\t${Version}\t${Maintainer}\t${Installed-Size}\t${Architecture}\t${Section}\t${Status}\t${binary:Summary}\n' 2>/dev/null |
    while IFS=$'\t' read -r nombre version mant tam arch seccion estado resumen; do
        case $estado in *' installed'*) : ;; *) continue ;; esac
        [ -n "$nombre" ] || continue

        local sizemb='0' fecha='' ambito='Sistema'
        [ -n "$tam" ] && sizemb=$(awk -v k="$tam" 'BEGIN{printf "%.1f", k/1024}')
        fecha=$(printf '%s' "$fechas" | awk -F'\t' -v p="$nombre" '$1==p{print $2; exit}')
        [ "$arch" = "$arch_host" ] || [ -z "$arch_host" ] || ambito="Sistema-$arch"

        json_obj \
            DisplayName "$nombre" \
            DisplayVersion "$version" \
            Publisher "$(safe_str "$mant" 128)" \
            InstallDate "$fecha" \
            InstallLocation "" \
            EstimatedSizeMB:n "$sizemb" \
            Scope "$ambito" \
            Architecture "$arch" \
            PackageType 'deb' \
            Section "$seccion" \
            Comments "$(safe_str "$resumen" 400)" \
            Source 'dpkg'
        printf '\n'
    done
}

# Reconstruye "paquete -> fecha de ultima instalacion/actualizacion" desde el
# log de dpkg. Devuelve lineas "paquete<TAB>YYYY-MM-DD".
_deb_install_dates() {
    local logs='' f
    for f in /var/log/dpkg.log /var/log/dpkg.log.1; do
        [ -r "$f" ] && logs="$logs $f"
    done
    if [ -z "$logs" ]; then return 0; fi
    # shellcheck disable=SC2086
    awk '$3=="install"||$3=="upgrade"{split($4,a,":"); print a[1]"\t"$1}' $logs 2>/dev/null |
        sort -u -k1,1 -k2,2r | awk -F'\t' '!seen[$1]++'
    # Los .gz se leen solo si zcat esta disponible y son pocos
    if has_cmd zcat; then
        zcat /var/log/dpkg.log.*.gz 2>/dev/null |
            awk '$3=="install"||$3=="upgrade"{split($4,a,":"); print a[1]"\t"$1}' |
            sort -u -k1,1 | awk -F'\t' '!seen[$1]++'
    fi
}

_sw_raw_rpm() {
    # rpm expone fecha de instalacion, vendor y tamano de forma nativa.
    rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{INSTALLTIME:date}\t%{SIZE}\t%{ARCH}\t%{GROUP}\t%{SUMMARY}\t%{INSTALLTIME}\n' 2>/dev/null |
    while IFS=$'\t' read -r nombre version vendor fechatxt tam arch grupo resumen epoch; do
        [ -n "$nombre" ] || continue
        local sizemb='0' fecha=''
        [ -n "$tam" ] && sizemb=$(awk -v b="$tam" 'BEGIN{printf "%.1f", b/1048576}')
        if [ -n "$epoch" ] && [ "$epoch" -gt 0 ] 2>/dev/null; then
            fecha=$(date -d "@$epoch" +%Y-%m-%d 2>/dev/null)
        fi
        json_obj \
            DisplayName "$nombre" \
            DisplayVersion "$version" \
            Publisher "$(safe_str "$vendor" 128)" \
            InstallDate "$fecha" \
            InstallLocation "" \
            EstimatedSizeMB:n "$sizemb" \
            Scope 'Sistema' \
            Architecture "$arch" \
            PackageType 'rpm' \
            Section "$grupo" \
            Comments "$(safe_str "$resumen" 400)" \
            Source 'rpm'
        printf '\n'
    done
}

_sw_raw_apk() {
    apk info -v 2>/dev/null | while read -r linea; do
        [ -n "$linea" ] || continue
        # formato: nombre-version-rREV
        local nombre version
        nombre=$(printf '%s' "$linea" | sed -E 's/-[0-9][^-]*-r[0-9]+$//')
        version=$(printf '%s' "$linea" | sed -E "s/^${nombre}-//")
        json_obj \
            DisplayName "$nombre" \
            DisplayVersion "$version" \
            Publisher '' \
            InstallDate '' \
            InstallLocation '' \
            EstimatedSizeMB:n 0 \
            Scope 'Sistema' \
            Architecture "$(apk --print-arch 2>/dev/null)" \
            PackageType 'apk' \
            Section '' \
            Comments '' \
            Source 'apk'
        printf '\n'
    done
}

# Snap: instala fuera del gestor nativo y monta squashfs de solo lectura.
_sw_raw_snap() {
    has_cmd snap || return 0
    snap list 2>/dev/null | tail -n +2 | while read -r nombre version rev tracking publisher resto; do
        [ -n "$nombre" ] || continue
        json_obj \
            DisplayName "$nombre" \
            DisplayVersion "$version" \
            Publisher "$publisher" \
            InstallDate '' \
            InstallLocation "/snap/$nombre/current" \
            EstimatedSizeMB:n 0 \
            Scope 'Snap' \
            Architecture '' \
            PackageType 'snap' \
            Section "$tracking" \
            Comments "Revision $rev" \
            Source 'snap'
        printf '\n'
    done
}

# Flatpak: instalable por usuario sin privilegios; punto ciego clasico.
_sw_raw_flatpak() {
    has_cmd flatpak || return 0
    flatpak list --columns=application,version,origin,installation 2>/dev/null |
    while IFS=$'\t' read -r app version origen instalacion; do
        [ -n "$app" ] || continue
        local ambito='Flatpak-Sistema'
        [ "$instalacion" = 'user' ] && ambito='Flatpak-Usuario'
        json_obj \
            DisplayName "$app" \
            DisplayVersion "$version" \
            Publisher "$origen" \
            InstallDate '' \
            InstallLocation '' \
            EstimatedSizeMB:n 0 \
            Scope "$ambito" \
            Architecture '' \
            PackageType 'flatpak' \
            Section '' \
            Comments '' \
            Source 'flatpak'
        printf '\n'
    done
}

# ---------------------------------------------------------------------------
# Procedencia e integridad de archivos
# ---------------------------------------------------------------------------
#
# Equivalente funcional de Get-SignatureInfo. En Windows la pregunta es "quien
# firmo este binario y sigue intacto"; en Linux la pregunta equivalente es
# "que paquete lo instalo y coincide con el manifiesto del gestor". Un archivo
# que no pertenece a ningun paquete es el analogo directo de un binario sin
# firma Authenticode: no tiene procedencia verificable.
#
# Estados devueltos en PKG_SIG_STATUS:
#   Managed      -> pertenece a un paquete y su hash coincide (equiv. 'Valid')
#   HashMismatch -> pertenece a un paquete pero fue modificado tras instalarse
#   Unmanaged    -> no pertenece a ningun paquete (equiv. 'NotSigned')
#   NotChecked   -> el gestor no pudo verificarlo
#
# Cache por ruta: es la operacion mas cara del inventario, igual que en Windows.

_PKG_OWNER_CACHE_FILE=''

_pkg_cache_init() {
    [ -n "$_PKG_OWNER_CACHE_FILE" ] && return 0
    _PKG_OWNER_CACHE_FILE=$(mktemp)
}

# file_package_info <ruta> [--hash]
# Rellena: PKG_SIG_STATUS PKG_OWNER PKG_VENDOR PKG_SHA256 PKG_SIZE_KB
#          PKG_MTIME PKG_EXISTS PKG_TRUSTED
file_package_info() {
    local ruta=$1 con_hash=${2:-}
    PKG_SIG_STATUS='NotChecked'; PKG_OWNER=''; PKG_VENDOR=''
    PKG_SHA256=''; PKG_SIZE_KB=0; PKG_MTIME=''; PKG_EXISTS=0; PKG_TRUSTED=0

    [ -f "$ruta" ] || return 0
    PKG_EXISTS=1

    local bytes
    bytes=$(stat -c %s "$ruta" 2>/dev/null || stat -f %z "$ruta" 2>/dev/null)
    [ -n "$bytes" ] && PKG_SIZE_KB=$(awk -v b="$bytes" 'BEGIN{printf "%.1f", b/1024}')
    PKG_MTIME=$(stat -c %y "$ruta" 2>/dev/null | cut -d. -f1)

    _pkg_cache_init
    local cacheado
    cacheado=$(grep -F -m1 "$ruta"$'\t' "$_PKG_OWNER_CACHE_FILE" 2>/dev/null)
    if [ -n "$cacheado" ]; then
        IFS=$'\t' read -r _ PKG_SIG_STATUS PKG_OWNER PKG_VENDOR <<< "$cacheado"
    else
        _resolve_pkg_owner "$ruta"
        printf '%s\t%s\t%s\t%s\n' "$ruta" "$PKG_SIG_STATUS" "$PKG_OWNER" "$PKG_VENDOR" \
            >> "$_PKG_OWNER_CACHE_FILE"
    fi

    if [ -n "$con_hash" ]; then
        PKG_SHA256=$(file_sha256 "$ruta")
    fi

    # Confianza: el vendor/mantenedor figura en PublicadoresConfiables
    if [ -n "$PKG_VENDOR" ] && [ -n "${AUDIT_TRUSTED_PUBLISHERS:-}" ]; then
        local p
        while IFS= read -r p; do
            [ -z "$p" ] && continue
            case ${PKG_VENDOR,,} in *"${p,,}"*) PKG_TRUSTED=1; break ;; esac
        done <<< "$AUDIT_TRUSTED_PUBLISHERS"
    fi
    return 0
}

_resolve_pkg_owner() {
    local ruta=$1 familia
    familia=$(detect_pkg_family)

    case $familia in
        deb)
            local salida
            salida=$(dpkg -S "$ruta" 2>/dev/null | head -1)
            if [ -n "$salida" ]; then
                PKG_OWNER=${salida%%:*}
                PKG_OWNER=${PKG_OWNER%% *}
                PKG_VENDOR=$(dpkg-query -W -f='${Maintainer}' "$PKG_OWNER" 2>/dev/null)
                # dpkg -V compara el md5 registrado contra el archivo actual
                if dpkg -V "$PKG_OWNER" 2>/dev/null | grep -qF "$ruta"; then
                    PKG_SIG_STATUS='HashMismatch'
                else
                    PKG_SIG_STATUS='Managed'
                fi
            else
                PKG_SIG_STATUS='Unmanaged'
            fi
            ;;
        rpm)
            local salida
            salida=$(rpm -qf --qf '%{NAME}\t%{VENDOR}\n' "$ruta" 2>/dev/null | head -1)
            if [ -n "$salida" ] && ! printf '%s' "$salida" | grep -q 'not owned'; then
                PKG_OWNER=$(printf '%s' "$salida" | cut -f1)
                PKG_VENDOR=$(printf '%s' "$salida" | cut -f2)
                local verif
                verif=$(rpm -Vf "$ruta" 2>/dev/null | head -3)
                # Columna 3 = '5' significa digest (hash) distinto al del paquete
                if printf '%s' "$verif" | awk '{print substr($1,3,1)}' | grep -q '5'; then
                    PKG_SIG_STATUS='HashMismatch'
                else
                    PKG_SIG_STATUS='Managed'
                fi
            else
                PKG_SIG_STATUS='Unmanaged'
            fi
            ;;
        apk)
            local salida
            salida=$(apk info -W "$ruta" 2>/dev/null | head -1)
            if printf '%s' "$salida" | grep -q 'owned by'; then
                PKG_OWNER=$(printf '%s' "$salida" | sed -E 's/.*owned by //; s/-[0-9].*$//')
                PKG_SIG_STATUS='Managed'
            else
                PKG_SIG_STATUS='Unmanaged'
            fi
            ;;
        *)
            PKG_SIG_STATUS='NotChecked'
            ;;
    esac
}

# Carga la lista de publicadores confiables desde la configuracion, una vez.
load_trusted_publishers() {
    [ -n "${AUDIT_TRUSTED_PUBLISHERS:-}" ] && return 0
    AUDIT_TRUSTED_PUBLISHERS=$(jq -r '.PublicadoresConfiables[]? // empty' "${AUDIT_CONFIG:-/dev/null}" 2>/dev/null)
    export AUDIT_TRUSTED_PUBLISHERS
}

# ---------------------------------------------------------------------------
# Arquitectura empresarial: resolucion de rutas, descripcion y rol
# ---------------------------------------------------------------------------
#
# Determina la ruta real de instalacion de un artefacto aplicando una cascada
# de fuentes, porque la base de paquetes no declara un "InstallLocation" unico
# como el registro de Windows:
#   1. Ruta declarada explicitamente (snap/flatpak)
#   2. Prefijo comun de los archivos que el paquete instalo
#   3. Directorio del ejecutable principal si se conoce
#
# Rellena: RIP_RUTA RIP_ORIGEN RIP_VERIFICADA

resolve_install_path() {
    local declarada=$1 paquete=$2 ejecutable=$3
    RIP_RUTA=''; RIP_ORIGEN='No determinada'; RIP_VERIFICADA=0

    # 1. Ruta declarada
    if [ -n "$declarada" ]; then
        RIP_RUTA=${declarada%/}
        RIP_ORIGEN='Gestor: ruta declarada'
        [ -d "$RIP_RUTA" ] && { RIP_VERIFICADA=1; return 0; }
        RIP_ORIGEN='Gestor: ruta declarada (no verificada)'
    fi

    # 2. Prefijo comun de los archivos del paquete
    if [ -n "$paquete" ]; then
        local prefijo
        prefijo=$(_pkg_install_prefix "$paquete")
        if [ -n "$prefijo" ] && [ -d "$prefijo" ]; then
            RIP_RUTA=$prefijo
            RIP_ORIGEN='Manifiesto del paquete'
            RIP_VERIFICADA=1
            return 0
        fi
    fi

    # 3. Directorio del binario principal
    if [ -n "$ejecutable" ] && [ -e "$ejecutable" ]; then
        RIP_RUTA=$(dirname "$ejecutable")
        RIP_ORIGEN='Binario en ejecucion'
        RIP_VERIFICADA=1
        return 0
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Indice "paquete -> prefijo de instalacion"
# ---------------------------------------------------------------------------
#
# Se construye de UNA sola pasada sobre los manifiestos del gestor de paquetes
# y se carga en un mapa en memoria. La alternativa literal (consultar el gestor
# una vez por paquete) supone del orden de 10000 subprocesos en un servidor con
# 2000 paquetes: minutos de ejecucion y una carga que el criterio AUD-01 exige
# evitar sobre un activo en produccion.
#
# Criterio de seleccion del prefijo, de mayor a menor especificidad:
#   1. /opt/<x>            directorio propio del producto
#   2. /usr/lib(exec)/<x>  directorio de biblioteca propio
#   3. /usr/share/<x>      datos propios (se descartan doc/man/locale/licenses)
#   4. /var/lib/<x>        estado propio
#   5. /usr/bin | /usr/sbin  el paquete solo aporta ejecutables al sistema

declare -A PKG_PREFIX 2>/dev/null || true
_PKG_PREFIX_LOADED=0

_prefix_awk_program() {
    cat <<'AWKEOF'
function considerar(pkg, prio, ruta) {
    # Gana la prioridad mas alta; a igual prioridad gana la ruta mas corta, que
    # es la raiz del producto (/opt/sap antes que /opt/sap/hostctrl). El desempate
    # por longitud hace el resultado independiente del orden del manifiesto.
    if (!(pkg in mejor) || prio < prio_de[pkg] ||
        (prio == prio_de[pkg] && length(ruta) < length(mejor[pkg]))) {
        mejor[pkg] = ruta; prio_de[pkg] = prio
    }
}
{
    pkg = paquete_de_linea()
    ruta = $0
    if (pkg == "" || ruta == "") next
    if (ruta ~ /^\/opt\/[^\/]+(\/[^\/]+)?$/)           considerar(pkg, 1, ruta)
    else if (ruta ~ /^\/usr\/lib(exec)?\/[^\/]+$/)     considerar(pkg, 2, ruta)
    else if (ruta ~ /^\/usr\/share\/[^\/]+$/) {
        if (ruta !~ /\/(doc|man|locale|licenses|info)$/) considerar(pkg, 3, ruta)
    }
    else if (ruta ~ /^\/var\/lib\/[^\/]+$/)            considerar(pkg, 4, ruta)
    else if (ruta ~ /^\/usr\/sbin\/[^\/]+$/)           considerar(pkg, 5, "/usr/sbin")
    else if (ruta ~ /^\/usr\/bin\/[^\/]+$/)            considerar(pkg, 5, "/usr/bin")
}
END { for (p in mejor) printf "%s\t%s\n", p, mejor[p] }
AWKEOF
}

build_pkg_prefix_index() {
    [ -n "${AUDIT_PKG_PREFIX_INDEX:-}" ] && [ -s "$AUDIT_PKG_PREFIX_INDEX" ] && return 0
    AUDIT_PKG_PREFIX_INDEX=$(mktemp); export AUDIT_PKG_PREFIX_INDEX

    local familia; familia=$(detect_pkg_family)
    case $familia in
        deb)
            # El nombre del paquete es el nombre del archivo .list; se recorren
            # todos de una vez y awk deduce el paquete de FILENAME.
            awk 'function paquete_de_linea(  n, a, base) {
                     base = FILENAME
                     sub(/.*\//, "", base); sub(/\.list$/, "", base); sub(/:.*$/, "", base)
                     return base
                 }
                 '"$(_prefix_awk_program)"'' \
                /var/lib/dpkg/info/*.list > "$AUDIT_PKG_PREFIX_INDEX" 2>/dev/null
            ;;
        rpm)
            # Una sola consulta que emite "paquete<TAB>archivo" para todo el sistema.
            rpm -qa --qf '[%{NAME}\t%{FILENAMES}\n]' 2>/dev/null |
            awk -F'\t' 'function paquete_de_linea() { return pkg }
                        { pkg = $1; $0 = $2 }
                        '"$(_prefix_awk_program)"'' \
                > "$AUDIT_PKG_PREFIX_INDEX" 2>/dev/null
            ;;
        apk)
            # apk info -L emite un encabezado "pkg-ver contains:" y luego rutas
            # relativas; se normalizan a absolutas.
            apk info -L 2>/dev/null |
            awk 'function paquete_de_linea() { return pkg }
                 /contains:$/ { pkg = $1; sub(/-[0-9][^ ]*$/, "", pkg); next }
                 NF { $0 = "/" $0 }
                 '"$(_prefix_awk_program)"'' \
                > "$AUDIT_PKG_PREFIX_INDEX" 2>/dev/null
            ;;
    esac
    return 0
}

load_pkg_prefix_map() {
    [ "$_PKG_PREFIX_LOADED" -eq 1 ] && return 0
    build_pkg_prefix_index
    local p pre
    if [ -s "${AUDIT_PKG_PREFIX_INDEX:-}" ]; then
        while IFS=$'\t' read -r p pre; do
            [ -n "$p" ] && PKG_PREFIX["$p"]=$pre
        done < "$AUDIT_PKG_PREFIX_INDEX"
    fi
    _PKG_PREFIX_LOADED=1
    return 0
}

# Prefijo de instalacion de un paquete. Usa el mapa en memoria; solo consulta
# el gestor directamente si el mapa no pudo construirse.
_pkg_install_prefix() {
    local paquete=$1
    [ -n "$paquete" ] || return 0

    if [ "$_PKG_PREFIX_LOADED" -eq 1 ]; then
        printf '%s' "${PKG_PREFIX[$paquete]:-}"
        return 0
    fi

    local archivos
    case $(detect_pkg_family) in
        deb) archivos=$(dpkg -L "$paquete" 2>/dev/null) ;;
        rpm) archivos=$(rpm -ql "$paquete" 2>/dev/null) ;;
        apk) archivos=$(apk info -L "$paquete" 2>/dev/null | sed 's|^|/|') ;;
        *) return 0 ;;
    esac
    [ -n "$archivos" ] || return 0

    printf '%s\n' "$archivos" | awk '
        /^\/opt\/[^\/]+$/          { print 1"\t"$0; next }
        /^\/usr\/lib(exec)?\/[^\/]+$/ { print 2"\t"$0; next }
        /^\/usr\/share\/[^\/]+$/   { if ($0 !~ /\/(doc|man|locale|licenses|info)$/) print 3"\t"$0; next }
        /^\/var\/lib\/[^\/]+$/     { print 4"\t"$0; next }
        /^\/usr\/s?bin\/[^\/]+$/   { print 5"\t/usr/bin"; next }
    ' | sort -n | head -1 | cut -f2
}

# ---------------------------------------------------------------------------
# Descripcion funcional del artefacto (cascada de fuentes)
#   1. Descripcion del gestor de paquetes (equivale a Comments del registro)
#   2. Descripcion declarada en el catalogo de arquitectura
#   3. Descripcion generica del rol arquitectonico asignado
# Rellena: GSD_TEXTO GSD_ORIGEN
# ---------------------------------------------------------------------------
get_software_description() {
    local comentarios=$1 desc_rol=$2 desc_catalogo=$3
    GSD_TEXTO=''; GSD_ORIGEN='Sin descripcion'

    if [ -n "$comentarios" ]; then
        GSD_TEXTO=$(safe_str "$comentarios" 400); GSD_ORIGEN='Gestor de paquetes'; return 0
    fi
    if [ -n "$desc_catalogo" ]; then
        GSD_TEXTO=$desc_catalogo; GSD_ORIGEN='Catalogo de arquitectura'; return 0
    fi
    if [ -n "$desc_rol" ]; then
        GSD_TEXTO=$desc_rol; GSD_ORIGEN='Rol arquitectonico (generico)'; return 0
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Clasificacion en la taxonomia de roles arquitectonicos
#
# Evalua el catalogo de aplicaciones primero (autoridad maxima) y luego los
# patrones de la taxonomia en el orden declarado. Los patrones se precargan en
# memoria una sola vez: evaluar jq por artefacto seria inviable con miles de
# paquetes.
#
# Rellena: AR_ROLID AR_ROLNOMBRE AR_CAPAEA AR_ROLDESC AR_ENCATALOGO
#          AR_APPID AR_APPNOMBRE AR_PROPIETARIO AR_CRITICIDAD AR_ORIGEN
# ---------------------------------------------------------------------------

_CR=$(awk 'BEGIN{printf "%c", 13}')   # CR, construido sin incrustar el byte en el fuente
_ARQ_APPS_FILE=''
_ARQ_ROLES_FILE=''
_ARQ_DEFAULT_LOADED=0

load_architecture_taxonomy() {
    [ -n "$_ARQ_ROLES_FILE" ] && return 0
    [ -n "${AUDIT_ARQUITECTURA:-}" ] && [ -r "$AUDIT_ARQUITECTURA" ] || return 1

    _ARQ_APPS_FILE=$(mktemp)
    _ARQ_ROLES_FILE=$(mktemp)

    jq -r '.Aplicaciones[]? |
        [ .Id, .Patron, (.Rol // "AplicacionNegocio"), (.CapaEA // "Aplicacion"),
          (.Descripcion // ""), .Nombre, (.Propietario // ""), (.Criticidad // ""),
          ((.Autorizado // false)|tostring) ] | @tsv' \
        "$AUDIT_ARQUITECTURA" 2>/dev/null > "$_ARQ_APPS_FILE"

    jq -r '.Roles[]? |
        [ .Id, .Patron, .Nombre, (.CapaEA // ""), (.Descripcion // "") ] | @tsv' \
        "$AUDIT_ARQUITECTURA" 2>/dev/null > "$_ARQ_ROLES_FILE"

    AR_DEF_ID=$(arq '.RolPorDefecto.Id' 'SinClasificar')
    AR_DEF_NOMBRE=$(arq '.RolPorDefecto.Nombre' 'Sin clasificar')
    AR_DEF_CAPA=$(arq '.RolPorDefecto.CapaEA' 'No determinada')
    AR_DEF_DESC=$(arq '.RolPorDefecto.Descripcion' '')
    _ARQ_DEFAULT_LOADED=1
    return 0
}

# Clasificacion EN LOTE. Lee de stdin un TSV "clave|nombre|publicador|ruta" y
# emite por stdout un TSV de 11 campos con el rol resuelto (ver lib/classify.awk).
# Es la via a usar cuando hay que clasificar un inventario completo: resuelve
# miles de artefactos en un solo proceso en lugar de un grep por patron.
classify_batch() {
    load_architecture_taxonomy || return 1
    awk -v apps="$_ARQ_APPS_FILE" -v roles="$_ARQ_ROLES_FILE"         -v defid="$AR_DEF_ID" -v defnom="$AR_DEF_NOMBRE"         -v defcapa="$AR_DEF_CAPA" -v defdesc="$AR_DEF_DESC"         -f "${AUDIT_LIB_DIR:-$AUDIT_ROOT/lib}/classify.awk"
}

# get_architecture_role <nombre> <publicador> <ruta>
#
# Version de un solo artefacto. Para inventarios completos usar classify_batch,
# que resuelve todo en un unico proceso.
#
# Un patron coincide si lo hace contra el nombre solo o contra el sujeto
# completo: probar el nombre por separado es lo que permite que funcionen los
# patrones anclados al final, como '^git$' o '.*-dev$'.
get_architecture_role() {
    local nombre=$1 publicador=${2:-} ruta=${3:-}
    local sujeto="$nombre $publicador $ruta"

    AR_ROLID=''; AR_ROLNOMBRE=''; AR_CAPAEA=''; AR_ROLDESC=''
    AR_ENCATALOGO=false; AR_APPID=''; AR_APPNOMBRE=''
    AR_PROPIETARIO=''; AR_CRITICIDAD=''; AR_ORIGEN='Sin coincidencia'

    load_architecture_taxonomy || {
        AR_ROLID='SinClasificar'; AR_ROLNOMBRE='Sin clasificar'
        AR_CAPAEA='No determinada'; return 0
    }

    local id patron rol capa desc nom prop crit autorizado

    # 1. Catalogo de aplicaciones de negocio (autoridad maxima)
    while IFS=$'\t' read -r id patron rol capa desc nom prop crit autorizado; do
        patron=${patron%"$_CR"}
        [ -n "$patron" ] || continue
        if printf '%s' "$nombre" | grep -qiE "$patron" 2>/dev/null ||
           printf '%s' "$sujeto" | grep -qiE "$patron" 2>/dev/null; then
            AR_ROLID=$rol; AR_ROLNOMBRE='Aplicacion de negocio'
            AR_CAPAEA=$capa; AR_ROLDESC=$desc
            AR_ENCATALOGO=true; AR_APPID=$id; AR_APPNOMBRE=$nom
            AR_PROPIETARIO=$prop; AR_CRITICIDAD=$crit
            AR_ORIGEN='Catalogo de aplicaciones'
            return 0
        fi
    done < "$_ARQ_APPS_FILE"

    # 2. Taxonomia de roles
    while IFS=$'\t' read -r id patron nom capa desc; do
        patron=${patron%"$_CR"}
        [ -n "$patron" ] || continue
        if printf '%s' "$nombre" | grep -qiE "$patron" 2>/dev/null ||
           printf '%s' "$sujeto" | grep -qiE "$patron" 2>/dev/null; then
            AR_ROLID=$id; AR_ROLNOMBRE=$nom; AR_CAPAEA=$capa; AR_ROLDESC=$desc
            AR_ORIGEN='Taxonomia de roles'
            return 0
        fi
    done < "$_ARQ_ROLES_FILE"

    # 3. Sin clasificar
    AR_ROLID=$AR_DEF_ID; AR_ROLNOMBRE=$AR_DEF_NOMBRE
    AR_CAPAEA=$AR_DEF_CAPA; AR_ROLDESC=$AR_DEF_DESC
    return 0
}

# ---------------------------------------------------------------------------
# Exportacion de evidencia
# ---------------------------------------------------------------------------

write_utf8() {
    local ruta=$1 contenido=$2
    printf '%s' "$contenido" > "$ruta"
}

# Convierte un arreglo JSON de objetos a CSV con encabezado (union de claves).
# Los valores de tipo arreglo se aplanan con '; ' para que el CSV sea legible.
json_to_csv() {
    jq -r '
        if (type == "array" and length > 0) then
            ( [ .[] | keys_unsorted[] ] | unique_by(.) ) as $ignore
            | ( reduce .[] as $o ([]; . + ($o | keys_unsorted) ) | unique_by(.) ) as $u
            | ( [ .[0] | keys_unsorted[] ] ) as $primeras
            | ( $primeras + ($u - $primeras) ) as $cols
            | ( $cols, ( .[] | [ .[$cols[]] |
                  if . == null then ""
                  elif type == "array" then (map(tostring) | join("; "))
                  elif type == "object" then (tojson)
                  else tostring end ] ) )
            | @csv
        else empty end'
}

# export_artifact <nombre> <json-array> [Json|Csv|Both]
export_artifact() {
    local nombre=$1 datos=$2 formato=${3:-Both}
    local escritos=()

    [ -n "$datos" ] || datos='[]'

    if [ "$formato" = 'Json' ] || [ "$formato" = 'Both' ]; then
        local jp="$AUDIT_RAW_PATH/$nombre.json"
        if printf '%s' "$datos" | jq '.' > "$jp" 2>/dev/null; then
            escritos+=("$jp")
        else
            audit_log WARN EXPORT "No se pudo escribir JSON '$nombre'."
        fi
    fi

    if [ "$formato" = 'Csv' ] || [ "$formato" = 'Both' ]; then
        local cp="$AUDIT_CSV_PATH/$nombre.csv"
        if printf '%s' "$datos" | json_to_csv > "$cp" 2>/dev/null; then
            escritos+=("$cp")
        else
            : > "$cp"
            escritos+=("$cp")
        fi
    fi

    local f sha bytes
    for f in "${escritos[@]}"; do
        sha=$(file_sha256 "$f")
        bytes=$(stat -c %s "$f" 2>/dev/null || printf 0)
        json_obj File "$(basename "$f")" Path "$f" SHA256 "$sha" Bytes:n "$bytes" \
            >> "$AUDIT_ARTIFACTS_FILE"
        printf '\n' >> "$AUDIT_ARTIFACTS_FILE"
    done
    printf '%s\n' "${escritos[@]}"
}

register_artifact() {
    local f=$1 sha bytes
    [ -f "$f" ] || return 0
    sha=$(file_sha256 "$f")
    bytes=$(stat -c %s "$f" 2>/dev/null || printf 0)
    json_obj File "$(basename "$f")" Path "$f" SHA256 "$sha" Bytes:n "$bytes" \
        >> "$AUDIT_ARTIFACTS_FILE"
    printf '\n' >> "$AUDIT_ARTIFACTS_FILE"
}

# ---------------------------------------------------------------------------
# Empaquetado ZIP (necesario para .xlsx y .docx, que son contenedores OOXML)
# ---------------------------------------------------------------------------
#
# Se intenta 'zip' y, si no existe, el modulo zipfile de python3. Es una
# concesion consciente: sin uno de los dos no es posible emitir OOXML, y la
# suite lo reporta como brecha en lugar de instalar dependencias en el activo
# auditado.
zip_available() {
    has_cmd zip || has_cmd python3
}

# zip_dir <directorio_origen> <archivo_destino>
zip_dir() {
    local origen=$1 destino=$2
    rm -f "$destino" 2>/dev/null

    if has_cmd zip; then
        ( cd "$origen" && zip -q -r -X "$destino" . ) && return 0
    fi
    if has_cmd python3; then
        python3 - "$origen" "$destino" <<'PY' && return 0
import os, sys, zipfile
origen, destino = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(destino, 'w', zipfile.ZIP_DEFLATED) as z:
    # [Content_Types].xml debe ir primero para maxima compatibilidad
    ct = os.path.join(origen, '[Content_Types].xml')
    if os.path.isfile(ct):
        z.write(ct, '[Content_Types].xml')
    for raiz, _, archivos in os.walk(origen):
        for a in sorted(archivos):
            ruta = os.path.join(raiz, a)
            arc = os.path.relpath(ruta, origen).replace(os.sep, '/')
            if arc == '[Content_Types].xml':
                continue
            z.write(ruta, arc)
PY
    fi
    return 1
}

# Escape XML/HTML para los generadores OOXML y la ficha imprimible.
#
# Los reemplazos van ENTRECOMILLADOS de forma deliberada: desde bash 5.2 un '&'
# sin comillas dentro del reemplazo de ${var//pat/rep} significa "el texto que
# coincidio" (como en sed), y '&lt;' produciria '<lt;'. Entrecomillar lo vuelve
# literal y funciona igual en bash 4.x, donde '&' nunca fue especial.
xml_escape() {
    local s=${1-} q="'"
    # Ruta rapida: la inmensa mayoria de los valores no necesita escape alguno
    case $s in
        *'&'*|*'<'*|*'>'*|*'"'*|*"'"*) ;;
        *[$'\001'-$'\010'$'\013'$'\014'$'\016'-$'\037']*) ;;
        *) printf '%s' "$s"; return 0 ;;
    esac
    case $s in
        *[$'\001'-$'\010'$'\013'$'\014'$'\016'-$'\037']*)
            s=$(printf '%s' "$s" | LC_ALL=C tr -d '\001-\010\013\014\016-\037') ;;
    esac
    s=${s//&/"&amp;"}
    s=${s//</"&lt;"}
    s=${s//>/"&gt;"}
    s=${s//\"/"&quot;"}
    s=${s//"$q"/"&apos;"}
    printf '%s' "$s"
}

html_escape() {
    local s=${1-}
    case $s in
        *'&'*|*'<'*|*'>'*|*'"'*) ;;
        *) printf '%s' "$s"; return 0 ;;
    esac
    s=${s//&/"&amp;"}
    s=${s//</"&lt;"}
    s=${s//>/"&gt;"}
    s=${s//\"/"&quot;"}
    printf '%s' "$s"
}

# ---------------------------------------------------------------------------
# Utilidades de fecha y numero
# ---------------------------------------------------------------------------

# Dias transcurridos desde una fecha YYYY-MM-DD hasta hoy (negativo si futura).
days_since() {
    local fecha=$1 e_then e_now
    [ -n "$fecha" ] || { printf ''; return 1; }
    e_then=$(date -d "$fecha" +%s 2>/dev/null) || { printf ''; return 1; }
    e_now=$(date +%s)
    printf '%d' $(( (e_now - e_then) / 86400 ))
}

# Redondea a N decimales.
round() { awk -v v="$1" -v d="${2:-1}" 'BEGIN{printf "%.*f", d, v}'; }

# Porcentaje a/b con 1 decimal, tolerante a b=0.
pct() { awk -v a="$1" -v b="$2" 'BEGIN{ if (b+0==0) print 0; else printf "%.1f", (a/b)*100 }'; }

# Comparacion numerica tolerante a decimales: gt <a> <b>
num_gt() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a+0 > b+0)}'; }
num_lt() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a+0 < b+0)}'; }
