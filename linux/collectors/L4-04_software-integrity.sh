#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# L4-04_software-integrity.sh
# Capa L4 - ARTEFACTOS DE SOFTWARE.
#
# Verificacion de integridad y procedencia de los binarios que efectivamente se
# ejecutan en el servidor: imagenes de las unidades de servicio y de los
# procesos activos. Produce ademas la linea base de hashes para comparacion
# entre ejecuciones.
#
# Criterios de auditoria -> SW-01, SW-03, ARQ-01, VUL-02, CAM-01
#
# EQUIVALENCIAS respecto de L4-04_Software-Integrity.ps1:
#   Win32_Service.PathName -> ExecStart de las unidades systemd / OpenRC
#   Get-Process .Path      -> /proc/<pid>/exe
#   Get-AuthenticodeSignature -> pertenencia a paquete + verificacion de
#                                integridad del gestor (ver lib/audit_core.sh)
#   TimeStamperCertificate -> no aplica; se sustituye por la deteccion de
#                             binarios eliminados del disco pero aun en memoria,
#                             que es el indicador de compromiso equivalente
#                             (y no tiene analogo en la version Windows).
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/audit_core.sh"

collector_init 'L4-04' 'Integridad y procedencia de binarios en ejecucion' 'L4' \
    'SW-01|SW-03|ARQ-01|VUL-02|CAM-01' false \
    'Procedencia, integridad y hash SHA256 de las imagenes de servicios y procesos; genera linea base comparable.'
maybe_emit_manifest "${1:-}"

load_trusted_publishers

TMP_BIN=$(mktemp)     # ruta<TAB>contexto<TAB>detalle
trap 'rm -f "$TMP_BIN" 2>/dev/null' EXIT

# ---------------------------------------------------------------------------
# 1. Imagenes de las unidades de servicio
# ---------------------------------------------------------------------------
init=$(detect_init_system)

if [ "$init" = 'systemd' ]; then
    systemctl list-units --type=service --all --no-legend --no-pager 2>/dev/null |
    awk '{print $1}' | grep '\.service$' |
    while read -r unidad; do
        [ -n "$unidad" ] || continue
        # ExecStart trae la linea completa con argumentos; el binario es el
        # primer token, tras descartar los prefijos de systemd (- @ : + ! !!)
        linea=$(systemctl show "$unidad" -p ExecStart --value 2>/dev/null)
        exe=$(printf '%s' "$linea" | sed -nE 's/.*path=([^ ;]+).*/\1/p' | head -1)
        if [ -z "$exe" ]; then
            exe=$(printf '%s' "$linea" | awk '{print $1}' | sed 's/^[-@:+!]*//')
        fi
        [ -n "$exe" ] || continue
        case $exe in /*) ;; *) continue ;; esac

        estado=$(systemctl is-active "$unidad" 2>/dev/null)
        arranque=$(systemctl is-enabled "$unidad" 2>/dev/null)
        usuario=$(systemctl show "$unidad" -p User --value 2>/dev/null)
        printf '%s\t%s\t%s\n' "$exe" "Servicio: $unidad" \
            "Estado=$estado Inicio=$arranque Cuenta=${usuario:-root}" >> "$TMP_BIN"
    done
elif [ "$init" = 'openrc' ]; then
    for script in /etc/init.d/*; do
        [ -f "$script" ] && [ -x "$script" ] || continue
        nombre=$(basename "$script")
        exe=$(awk -F'=' '/^command=/{gsub(/"/,"",$2); print $2; exit}' "$script" 2>/dev/null)
        [ -n "$exe" ] || continue
        estado='desconocido'
        rc-service "$nombre" status >/dev/null 2>&1 && estado='activo'
        printf '%s\t%s\t%s\n' "$exe" "Servicio: $nombre" "Estado=$estado (OpenRC)" >> "$TMP_BIN"
    done
else
    gap "Sistema de init no reconocido ($init); no se pudieron enumerar las imagenes de los servicios."
fi

# ---------------------------------------------------------------------------
# 2. Imagenes de los procesos en ejecucion
# ---------------------------------------------------------------------------
sin_acceso=0
eliminados=0
lista_eliminados=''

for pid_dir in /proc/[0-9]*; do
    pid=$(basename "$pid_dir")
    # /proc/<pid>/exe es un enlace simbolico al binario real en disco
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
    if [ -z "$exe" ]; then
        sin_acceso=$((sin_acceso + 1))
        continue
    fi

    nombre=$(tr -d '\000' < "/proc/$pid/comm" 2>/dev/null)
    rss_kb=$(awk '/^VmRSS:/{print $2}' "/proc/$pid/status" 2>/dev/null)
    usuario=$(awk '/^Uid:/{print $2}' "/proc/$pid/status" 2>/dev/null)
    usuario_nom=$(getent passwd "${usuario:-0}" 2>/dev/null | cut -d: -f1)

    # Binario borrado del disco pero aun en ejecucion. En Linux es un indicador
    # de compromiso de primer orden: el atacante ejecuta y borra el artefacto
    # para no dejar rastro en el sistema de archivos. No tiene equivalente en la
    # version Windows, donde el sistema mantiene bloqueada la imagen.
    case $exe in
        *' (deleted)')
            eliminados=$((eliminados + 1))
            ruta_real=${exe% (deleted)}
            [ "$eliminados" -le 10 ] && lista_eliminados="$lista_eliminados | PID $pid ($nombre) => $ruta_real"
            printf '%s\t%s\t%s\n' "$ruta_real" "Proceso: $nombre" \
                "PID=$pid BINARIO ELIMINADO DEL DISCO Usuario=${usuario_nom:-$usuario}" >> "$TMP_BIN"
            continue ;;
    esac

    printf '%s\t%s\t%s\n' "$exe" "Proceso: $nombre" \
        "PID=$pid Memoria=$(awk -v k="${rss_kb:-0}" 'BEGIN{printf "%.1f", k/1024}')MB Usuario=${usuario_nom:-$usuario}" >> "$TMP_BIN"
done

if [ "$sin_acceso" -gt 0 ]; then
    if is_root; then
        gap "No se pudo resolver la ruta de $sin_acceso procesos (habitualmente hilos del kernel, que no tienen imagen en disco)."
    else
        gap "No se pudo resolver la ruta de $sin_acceso procesos: sin privilegios de root solo son legibles los procesos propios. La cobertura de este colector es PARCIAL."
    fi
fi

# ---------------------------------------------------------------------------
# 3. Analisis de procedencia e integridad, deduplicando por ruta
# ---------------------------------------------------------------------------
no_gestionados=0;  lista_no_gest=''
alterados=0;       lista_alterados=''
no_confiables=0;   proveedores=''
gestionados=0

# Se agrupan los contextos por ruta: un mismo binario puede respaldar varios
# servicios y procesos.
sort -t$'\t' -k1,1 "$TMP_BIN" | awk -F'\t' '
{
    if ($1 != prev && prev != "") { print prev "\t" ctx "\t" det; ctx=""; det="" }
    prev=$1
    ctx = (ctx == "") ? $2 : ctx "; " $2
    det = (det == "") ? $3 : det
}
END { if (prev != "") print prev "\t" ctx "\t" det }
' > "$TMP_BIN.agg"

while IFS=$'\t' read -r ruta contextos detalle; do
    [ -n "$ruta" ] || continue

    file_package_info "$ruta" '--hash'
    [ "$PKG_EXISTS" -eq 1 ] || continue

    case $PKG_SIG_STATUS in
        Managed)
            gestionados=$((gestionados + 1))
            if [ "$PKG_TRUSTED" -eq 0 ]; then
                no_confiables=$((no_confiables + 1))
                case " $proveedores " in
                    *" ${PKG_VENDOR} "*) ;;
                    *) [ -n "$PKG_VENDOR" ] && proveedores="$proveedores ${PKG_VENDOR}" ;;
                esac
            fi ;;
        HashMismatch)
            alterados=$((alterados + 1))
            [ "$alterados" -le 10 ] && lista_alterados="$lista_alterados | $ruta SHA256=$PKG_SHA256 <= $contextos" ;;
        Unmanaged)
            no_gestionados=$((no_gestionados + 1))
            [ "$no_gestionados" -le 15 ] && lista_no_gest="$lista_no_gest | $ruta <= $contextos" ;;
    esac

    rec Ruta "$ruta" \
        Nombre "$(basename "$ruta")" \
        Contextos "$(safe_str "$contextos" 400)" \
        Detalle "$(safe_str "$detalle" 300)" \
        EstadoProcedencia "$PKG_SIG_STATUS" \
        PaqueteOrigen "$PKG_OWNER" \
        Proveedor "$(safe_str "$PKG_VENDOR" 200)" \
        ProveedorConfiable:b "$PKG_TRUSTED" \
        SHA256 "$PKG_SHA256" \
        TamanoKB:n "$PKG_SIZE_KB" \
        UltimaEscritura "$PKG_MTIME"

done < "$TMP_BIN.agg"

rm -f "$TMP_BIN.agg" 2>/dev/null

# ---------------------------------------------------------------------------
# Hallazgos
# ---------------------------------------------------------------------------
if [ "$eliminados" -gt 0 ]; then
    finding Critical 'Procesos ejecutando binarios eliminados del disco' \
        -c 'IndicadorDeCompromiso' -a "$eliminados procesos" \
        -d "Se detectaron $eliminados procesos cuya imagen fue borrada del sistema de archivos pero sigue en memoria. Borrar el binario tras lanzarlo es una tecnica habitual para evadir el analisis forense y los escaneos de integridad. Tambien ocurre de forma legitima cuando un paquete se actualiza y el servicio no se reinicia, por lo que cada caso debe verificarse." \
        -e "$(safe_str "${lista_eliminados# | }" 1200)" \
        -k 'SW-01|VUL-02|REG-02' \
        -r 'Para cada proceso: confirmar si corresponde a un servicio cuyo paquete se actualizo recientemente (caso benigno, se resuelve reiniciando el servicio) o si no hay actualizacion que lo explique. En el segundo caso, preservar la imagen desde /proc/<pid>/exe antes de terminar el proceso y activar el procedimiento de gestion de incidentes.'
fi

if [ "$no_gestionados" -gt 0 ]; then
    finding High 'Servicios o procesos ejecutando binarios sin procedencia verificable' \
        -c 'IntegridadDeSoftware' -a "$no_gestionados binarios" \
        -d "$no_gestionados imagenes en ejecucion no pertenecen a ningun paquete instalado. Estos binarios operan con los privilegios de su contexto sin que sea posible verificar su origen, comprobar su integridad ni aplicarles parches por el canal del gestor de paquetes." \
        -e "$(safe_str "${lista_no_gest# | }" 1500)" \
        -k 'SW-01|SW-03|ARQ-01' \
        -r 'Identificar el proveedor de cada binario y exigir entregables distribuidos como paquete firmado. Registrar el hash SHA256 como linea base y monitorear su cambio entre ejecuciones de auditoria.'
fi

if [ "$alterados" -gt 0 ]; then
    finding Critical 'Binario en ejecucion alterado respecto del paquete que lo instalo' \
        -c 'IndicadorDeCompromiso' -a "$alterados binarios" \
        -d 'El contenido de estos archivos no corresponde al manifiesto de integridad del paquete que los instalo: fueron modificados despues de la instalacion. Es el equivalente directo de un HashMismatch de firma Authenticode y debe tratarse como posible indicador de compromiso.' \
        -e "$(safe_str "${lista_alterados# | }" 1500)" \
        -k 'SW-01|SW-03|VUL-02|REG-02' \
        -r 'Activar el procedimiento de gestion de incidentes: aislar el binario, preservar la evidencia con su hash y contrastarlo contra el paquete original del repositorio (apt-get download / dnf reinstall --downloadonly) antes de reemplazarlo.'
fi

if [ "$no_confiables" -gt 0 ]; then
    finding Low 'Binarios provistos por proveedores no incluidos en la lista de confianza' \
        -c 'Procedencia' -a "$no_confiables binarios" \
        -d 'Estos artefactos provienen de paquetes correctamente instalados y con integridad valida, pero su proveedor no figura en la lista de origenes aprobados de la configuracion. No es necesariamente una desviacion, pero requiere validacion contra el inventario autorizado.' \
        -e "$(safe_str "${proveedores# }" 1200)" \
        -k 'INV-01|SW-03|SW-04' \
        -r 'Revisar cada proveedor con el responsable del activo y actualizar la lista PublicadoresConfiables en config/audit.config.json para reducir el ruido en ejecuciones posteriores.'
fi

metric BinariosAnalizados "$(rec_count)" n
metric NoGestionados "$no_gestionados" n
metric Alterados "$alterados" n
metric ProveedorNoConfiable "$no_confiables" n
metric Gestionados "$gestionados" n
metric BinariosEliminados "$eliminados" n

emit_result
