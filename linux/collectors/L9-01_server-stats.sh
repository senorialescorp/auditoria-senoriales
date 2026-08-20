#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# L9-01_server-stats.sh
# Capa L9 - Rendimiento y capacidad ("stats del server").
#
# Toma una muestra de contadores con varias lecturas para evitar conclusiones a
# partir de un unico instante, y correlaciona el consumo con los artefactos de
# software que lo originan (enlace con L4).
#
# Criterios de auditoria -> CAP-01, REG-02, AUD-01
#
# EQUIVALENCIAS respecto de L9-01_Server-Stats.ps1:
#   Get-Counter (PDH)        -> lectura diferencial de /proc/stat, /proc/diskstats
#                               y /proc/net/dev entre muestras
#   Win32_OperatingSystem    -> /proc/meminfo, /proc/uptime
#   Get-Process              -> /proc/<pid>/{comm,stat,status}
#   Evento 6008 (apagado)    -> journalctl --list-boots + last -x reboot/shutdown
#   Avg. Disk sec/Transfer   -> campos 7 y 11 de /proc/diskstats (ms de espera)
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/audit_core.sh"

collector_init 'L9-01' 'Estadisticas de rendimiento y capacidad del servidor' 'L9' \
    'CAP-01|REG-02|AUD-01' false \
    'Muestreo de CPU, memoria, disco y red; top de procesos por consumo y correlacion con el software instalado.'
maybe_emit_manifest "${1:-}"

# Parametros de muestreo. Se mantienen bajos de forma deliberada: el criterio
# AUD-01 exige que la auditoria no degrade el servicio del activo.
MUESTRAS=${AUDIT_MUESTRAS:-5}
INTERVALO=${AUDIT_INTERVALO:-2}

cpu_max=$(cfg '.Thresholds.PorcentajeCpuSostenidoMax' '85')
mem_min=$(cfg '.Thresholds.PorcentajeMemoriaLibreMin' '12')

add_stat() {
    rec Grupo "$1" Metrica "$2" Valor "$3" Unidad "${4:-}" \
        Detalle "$(safe_str "${5:-}" 300)" Estado "${6:-Info}"
}

# ---------------------------------------------------------------------------
# 1. Muestreo de CPU
# ---------------------------------------------------------------------------
#
# /proc/stat expone contadores acumulados desde el arranque. El uso instantaneo
# se obtiene por diferencia entre dos lecturas; una sola lectura daria el
# promedio historico desde el arranque, que no dice nada del estado actual.
leer_cpu() { awk '/^cpu /{ idle=$5+$6; total=0; for(i=2;i<=NF;i++) total+=$i; print total, idle }' /proc/stat; }

muestras_cpu=''
read -r total_ant idle_ant < <(leer_cpu)
i=1
while [ "$i" -le "$MUESTRAS" ]; do
    sleep "$INTERVALO"
    read -r total_act idle_act < <(leer_cpu)
    uso=$(awk -v ta="$total_ant" -v ia="$idle_ant" -v tc="$total_act" -v ic="$idle_act" \
        'BEGIN{ dt=tc-ta; di=ic-ia; if (dt<=0) print 0; else printf "%.1f", (1 - di/dt) * 100 }')
    muestras_cpu="$muestras_cpu $uso"
    total_ant=$total_act; idle_ant=$idle_act
    i=$((i + 1))
done

cpu_prom=$(printf '%s\n' $muestras_cpu | awk '{s+=$1; n++} END{if(n) printf "%.1f", s/n; else print 0}')
cpu_max_obs=$(printf '%s\n' $muestras_cpu | awk 'BEGIN{m=0} {if($1+0>m) m=$1+0} END{printf "%.1f", m}')
cpu_min_obs=$(printf '%s\n' $muestras_cpu | awk 'BEGIN{m=999} {if($1+0<m) m=$1+0} END{printf "%.1f", m}')

add_stat 'CPU' 'UsoPromedio' "$cpu_prom" '%' \
    "min=$cpu_min_obs max=$cpu_max_obs muestras=$MUESTRAS intervalo=${INTERVALO}s" \
    "$(if num_gt "$cpu_prom" "$cpu_max"; then printf ADVERTENCIA; else printf OK; fi)"

metric MuestrasTomadas "$MUESTRAS" n
metric CPUPromedio "$cpu_prom" n
metric CPUMaximo "$cpu_max_obs" n

# Carga media: complementa el uso de CPU con la longitud de la cola de ejecucion
if [ -r /proc/loadavg ]; then
    read -r l1 l5 l15 resto < /proc/loadavg
    ncpu=$(nproc --all 2>/dev/null || printf 1)
    carga_norm=$(awk -v l="$l1" -v n="$ncpu" 'BEGIN{printf "%.2f", l/n}')
    add_stat 'CPU' 'CargaMedia' "$l1" '1 min' \
        "5min=$l5 15min=$l15 CPUs=$ncpu carga_por_cpu=$carga_norm" \
        "$(if num_gt "$carga_norm" 1.5; then printf ADVERTENCIA; else printf OK; fi)"
    metric CargaMedia1min "$l1" n

    if num_gt "$carga_norm" 2; then
        finding Medium 'Cola de ejecucion sostenidamente por encima de la capacidad de CPU' \
            -c 'Capacidad' -a "$AUDIT_HOSTNAME" \
            -d "La carga media de 1 minuto es $l1 con $ncpu CPU disponibles ($carga_norm procesos en espera por CPU). Una carga normalizada por encima de 1 indica que hay procesos esperando de forma sostenida; por encima de 2, el servidor esta claramente subdimensionado o hay un proceso en bucle." \
            -e "loadavg=$l1 $l5 $l15 | CPUs=$ncpu" \
            -k 'CAP-01|REG-02' \
            -r 'Correlacionar con el top de procesos de este mismo colector, revisar el dimensionamiento del servidor y descartar actividad no autorizada como causa del consumo.'
    fi
fi

if num_gt "$cpu_prom" "$cpu_max"; then
    finding Medium 'Uso sostenido de CPU por encima del umbral' \
        -c 'Capacidad' -a "$AUDIT_HOSTNAME" \
        -d "Promedio de ${cpu_prom}% durante $MUESTRAS muestras (maximo ${cpu_max_obs}%). El umbral definido es ${cpu_max}%." \
        -e "Muestras:$muestras_cpu" \
        -k 'CAP-01|REG-02' \
        -r 'Correlacionar con el top de procesos de este mismo colector, revisar el dimensionamiento del servidor y descartar actividad no autorizada como causa del consumo.'
fi

# ---------------------------------------------------------------------------
# 2. Memoria
# ---------------------------------------------------------------------------
if [ -r /proc/meminfo ]; then
    mem_total=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
    mem_disp=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
    mem_libre=$(awk '/^MemFree:/{print $2}' /proc/meminfo)
    swap_total=$(awk '/^SwapTotal:/{print $2}' /proc/meminfo)
    swap_libre=$(awk '/^SwapFree:/{print $2}' /proc/meminfo)

    # MemAvailable es la metrica correcta: MemFree excluye cache reclamable y
    # subestima gravemente la memoria realmente disponible.
    [ -n "$mem_disp" ] || mem_disp=$mem_libre

    total_mb=$(awk -v k="${mem_total:-0}" 'BEGIN{printf "%d", k/1024}')
    disp_mb=$(awk -v k="${mem_disp:-0}"  'BEGIN{printf "%d", k/1024}')
    usado_mb=$(( total_mb - disp_mb ))
    pct_libre=$(pct "$mem_disp" "$mem_total")

    add_stat 'Memoria' 'TotalFisica' "$total_mb" 'MB'
    add_stat 'Memoria' 'EnUso' "$usado_mb" 'MB' "$(pct "$usado_mb" "$total_mb")% del total"
    add_stat 'Memoria' 'Disponible' "$disp_mb" 'MB' "${pct_libre}% disponible (MemAvailable)" \
        "$(if num_lt "$pct_libre" "$mem_min"; then printf ADVERTENCIA; else printf OK; fi)"

    swap_usado=$(( ${swap_total:-0} - ${swap_libre:-0} ))
    swap_usado_mb=$(awk -v k="$swap_usado" 'BEGIN{printf "%d", k/1024}')
    swap_total_mb=$(awk -v k="${swap_total:-0}" 'BEGIN{printf "%d", k/1024}')
    add_stat 'Memoria' 'Swap' "$swap_usado_mb" 'MB en uso' "Total: $swap_total_mb MB" \
        "$(if [ "${swap_total:-0}" -gt 0 ] && num_gt "$(pct "$swap_usado" "$swap_total")" 50; then printf ADVERTENCIA; else printf OK; fi)"

    metric MemoriaTotalMB "$total_mb" n
    metric MemoriaDisponibleMB "$disp_mb" n
    metric MemoriaPorcentajeLibre "$pct_libre" n

    if num_lt "$pct_libre" "$mem_min"; then
        finding Medium 'Memoria disponible por debajo del umbral operativo' \
            -c 'Capacidad' -a "$AUDIT_HOSTNAME" \
            -d "Memoria disponible: $disp_mb MB de $total_mb MB (${pct_libre}% disponible). El umbral definido es ${mem_min}%. La presion de memoria degrada el rendimiento y puede provocar la intervencion del OOM killer, que termina procesos de forma abrupta." \
            -e "MemAvailable=$mem_disp kB MemTotal=$mem_total kB Swap en uso=$swap_usado_mb MB" \
            -k 'CAP-01' \
            -r 'Identificar los procesos con mayor consumo, evaluar la ampliacion de memoria y configurar alertas preventivas de capacidad.'
    fi

    # Intervenciones del OOM killer: evidencia de presion de memoria pasada
    if has_cmd journalctl; then
        oom=$(journalctl -k --since '30 days ago' 2>/dev/null | grep -ci 'out of memory\|oom-killer' 2>/dev/null)
    else
        oom=$(grep -ci 'out of memory\|oom-killer' /var/log/kern.log /var/log/messages 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')
    fi
    if [ "${oom:-0}" -gt 0 ]; then
        add_stat 'Memoria' 'EventosOOM30d' "$oom" 'eventos' \
            'El kernel termino procesos por agotamiento de memoria' 'ADVERTENCIA'
        finding High 'El kernel termino procesos por agotamiento de memoria' \
            -c 'Capacidad' -a "$AUDIT_HOSTNAME" \
            -d "Se registraron $oom intervenciones del OOM killer en los ultimos 30 dias. Cuando la memoria se agota, el kernel elige y termina procesos de forma abrupta y sin aviso: es una causa directa de interrupcion de servicio y de corrupcion de datos en aplicaciones que no manejan la terminacion." \
            -k 'CAP-01|CAP-03|REG-02' \
            -r 'Identificar los procesos terminados y el que provoco la presion, ampliar la memoria o ajustar los limites de las aplicaciones, y configurar alertas antes de alcanzar el umbral critico.'
    fi
fi

# ---------------------------------------------------------------------------
# 3. Top de procesos por consumo, correlacionado con el software instalado
# ---------------------------------------------------------------------------
TMP_PROC=$(mktemp)
trap 'rm -f "$TMP_PROC" 2>/dev/null' EXIT

total_procesos=0
total_hilos=0

for pid_dir in /proc/[0-9]*; do
    pid=$(basename "$pid_dir")
    [ -r "$pid_dir/stat" ] || continue
    total_procesos=$((total_procesos + 1))

    nombre=$(tr -d '\000' < "$pid_dir/comm" 2>/dev/null)
    rss=$(awk '/^VmRSS:/{print $2}' "$pid_dir/status" 2>/dev/null)
    hilos=$(awk '/^Threads:/{print $2}' "$pid_dir/status" 2>/dev/null)
    total_hilos=$(( total_hilos + ${hilos:-0} ))

    # Campos 14 y 15 de /proc/<pid>/stat: utime y stime en ticks de reloj
    ticks=$(awk '{print $14 + $15}' "$pid_dir/stat" 2>/dev/null)
    hz=$(getconf CLK_TCK 2>/dev/null); [ -n "$hz" ] || hz=100
    cpu_seg=$(awk -v t="${ticks:-0}" -v h="$hz" 'BEGIN{printf "%.1f", t/h}')

    ruta=$(readlink "$pid_dir/exe" 2>/dev/null)
    usuario=$(awk '/^Uid:/{print $2}' "$pid_dir/status" 2>/dev/null)

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "${rss:-0}" "$cpu_seg" "$pid" "$nombre" "${hilos:-0}" "$usuario" "$ruta" >> "$TMP_PROC"
done

metric TotalProcesos "$total_procesos" n
metric TotalHilos "$total_hilos" n

# Top 15 por memoria residente
sort -rn -k1,1 "$TMP_PROC" 2>/dev/null | head -15 |
while IFS=$'\t' read -r rss cpu_seg pid nombre hilos uid ruta; do
    [ -n "$nombre" ] || continue
    usuario_nom=$(getent passwd "${uid:-0}" 2>/dev/null | cut -d: -f1)
    add_stat 'TopMemoria' "$nombre" "$(awk -v k="$rss" 'BEGIN{printf "%.1f", k/1024}')" 'MB' \
        "PID=$pid Hilos=$hilos Usuario=${usuario_nom:-$uid} Ruta=$ruta"
done

# Top 15 por tiempo de CPU acumulado
sort -rn -k2,2 "$TMP_PROC" 2>/dev/null | head -15 |
while IFS=$'\t' read -r rss cpu_seg pid nombre hilos uid ruta; do
    [ -n "$nombre" ] || continue
    add_stat 'TopCPU' "$nombre" "$cpu_seg" 'seg CPU acumulados' "PID=$pid Ruta=$ruta"
done

add_stat 'Sistema' 'ProcesosActivos' "$total_procesos" ''
add_stat 'Sistema' 'HilosTotales' "$total_hilos" ''

# Descriptores de archivo: limite del sistema que, al agotarse, detiene todo
if [ -r /proc/sys/fs/file-nr ]; then
    read -r fd_usados fd_libres fd_max < /proc/sys/fs/file-nr
    pct_fd=$(pct "$fd_usados" "$fd_max")
    add_stat 'Sistema' 'DescriptoresArchivo' "$fd_usados" "de $fd_max" \
        "${pct_fd}% del maximo del sistema" \
        "$(if num_gt "$pct_fd" 80; then printf ADVERTENCIA; else printf OK; fi)"
    if num_gt "$pct_fd" 80; then
        finding Medium 'Uso elevado de descriptores de archivo del sistema' \
            -c 'Capacidad' -a "$AUDIT_HOSTNAME" \
            -d "Se estan usando $fd_usados de $fd_max descriptores de archivo (${pct_fd}%). Al agotarse el limite, ningun proceso puede abrir archivos ni sockets nuevos: los servicios dejan de aceptar conexiones aunque la CPU y la memoria esten holgadas." \
            -e "/proc/sys/fs/file-nr = $fd_usados $fd_libres $fd_max" \
            -k 'CAP-01' \
            -r 'Identificar el proceso que concentra los descriptores (lsof | awk) y corregir la fuga, o elevar fs.file-max y los limites por proceso (LimitNOFILE en la unidad systemd).'
    fi
fi

# ---------------------------------------------------------------------------
# 4. Disco: capacidad y latencia
# ---------------------------------------------------------------------------
df -PT 2>/dev/null | tail -n +2 |
while read -r disp fstipo bloques usado libre pctusado punto; do
    case $fstipo in
        proc|sysfs|devtmpfs|devpts|tmpfs|squashfs|overlay|cgroup*|autofs|nsfs) continue ;;
    esac
    [ "${bloques:-0}" -gt 0 ] 2>/dev/null || continue
    pct_libre=$(pct "$libre" "$bloques")
    add_stat 'Disco' "Volumen $punto" "$pct_libre" '% libre' \
        "$(awk -v k="$libre" 'BEGIN{printf "%.2f", k/1048576}') GB libres de $(awk -v k="$bloques" 'BEGIN{printf "%.2f", k/1048576}') GB" \
        "$(if num_lt "$pct_libre" 15; then printf ADVERTENCIA; else printf OK; fi)"
done

# Latencia de E/S por diferencial de /proc/diskstats.
# Campos 4 y 8: lecturas y escrituras completadas; 7 y 11: ms acumulados.
if [ -r /proc/diskstats ]; then
    leer_disk() {
        awk '$3 ~ /^(sd[a-z]+|nvme[0-9]+n[0-9]+|vd[a-z]+|xvd[a-z]+)$/ {
                 r+=$4; rms+=$7; w+=$8; wms+=$11
             } END { print r+w, rms+wms }' /proc/diskstats
    }
    read -r ops_ant ms_ant < <(leer_disk)
    sleep 2
    read -r ops_act ms_act < <(leer_disk)

    lat=$(awk -v oa="$ops_ant" -v ma="$ms_ant" -v oc="$ops_act" -v mc="$ms_act" \
        'BEGIN{ do_=oc-oa; dm=mc-ma; if (do_<=0) print 0; else printf "%.2f", dm/do_ }')

    add_stat 'Disco' 'LatenciaPromedio' "$lat" 'ms' \
        "Referencia: > 25 ms indica saturacion de E/S (operaciones medidas: $(( ops_act - ops_ant )))" \
        "$(if num_gt "$lat" 25; then printf ADVERTENCIA; else printf OK; fi)"
    metric LatenciaDiscoMs "$lat" n

    if num_gt "$lat" 25 && [ "$(( ops_act - ops_ant ))" -gt 10 ]; then
        finding Medium 'Latencia de disco por encima del umbral de referencia' \
            -c 'Capacidad' -a "$AUDIT_HOSTNAME" \
            -d "La latencia media de las operaciones de disco es de $lat ms durante la ventana de medicion. Por encima de 25 ms el subsistema de almacenamiento se comporta como cuello de botella y degrada el tiempo de respuesta de las aplicaciones." \
            -k 'CAP-01' \
            -r 'Revisar la carga de E/S por proceso (iotop), la salud de los discos (smartctl) y el dimensionamiento del almacenamiento. En entornos virtualizados, verificar tambien la contencion en la cabina o el datastore.'
    fi
fi

# ---------------------------------------------------------------------------
# 5. Red
# ---------------------------------------------------------------------------
for iface_path in /sys/class/net/*; do
    [ -d "$iface_path" ] || continue
    iface=$(basename "$iface_path")
    [ "$iface" = 'lo' ] && continue
    [ "$(cat "$iface_path/operstate" 2>/dev/null)" = 'up' ] || continue

    vel=$(cat "$iface_path/speed" 2>/dev/null)
    case $vel in ''|-1|*[!0-9-]*) vel=0 ;; esac
    rx=$(cat "$iface_path/statistics/rx_bytes" 2>/dev/null)
    tx=$(cat "$iface_path/statistics/tx_bytes" 2>/dev/null)
    rx_drop=$(cat "$iface_path/statistics/rx_dropped" 2>/dev/null)
    rx_err=$(cat "$iface_path/statistics/rx_errors" 2>/dev/null)
    mac=$(cat "$iface_path/address" 2>/dev/null)

    add_stat 'Red' "$iface" "$vel" 'Mbps' "MAC=$mac Estado=up"
    add_stat 'Red' "$iface - trafico" "$(awk -v b="${rx:-0}" 'BEGIN{printf "%.2f", b/1073741824}')" 'GB recibidos' \
        "Enviados: $(awk -v b="${tx:-0}" 'BEGIN{printf "%.2f", b/1073741824}') GB | Descartes entrada: ${rx_drop:-0} | Errores: ${rx_err:-0}" \
        "$(if [ "${rx_err:-0}" -gt 0 ] 2>/dev/null; then printf ADVERTENCIA; else printf OK; fi)"
done

# ---------------------------------------------------------------------------
# 6. Tiempo de actividad y estabilidad
# ---------------------------------------------------------------------------
if [ -r /proc/uptime ]; then
    up_seg=$(awk '{print int($1)}' /proc/uptime)
    up_dias=$(awk -v s="$up_seg" 'BEGIN{printf "%.2f", s/86400}')
    arranque=$(date -d "@$(( $(date +%s) - up_seg ))" '+%Y-%m-%d %H:%M' 2>/dev/null)
    add_stat 'Sistema' 'TiempoActividad' "$up_dias" 'dias' "Ultimo arranque: $arranque"
    metric UptimeDias "$up_dias" n
fi

# Apagados inesperados: analogo del evento 6008 de Windows.
# journalctl --list-boots enumera los arranques; 'last -x' marca los cierres
# limpios, de modo que un arranque sin shutdown previo fue inesperado.
inesperados=0
detalle_inesperados=''
if has_cmd last; then
    # 'crash' es como 'last' marca un arranque sin cierre limpio previo
    inesperados=$(last -x reboot shutdown 2>/dev/null | grep -c 'crash' 2>/dev/null)
    detalle_inesperados=$(last -x 2>/dev/null | grep 'crash' | head -5 | tr '\n' ';')
fi
if [ "${inesperados:-0}" -eq 0 ] && has_cmd journalctl; then
    # Mensajes de arranque que indican que el sistema no se apago limpiamente
    inesperados=$(journalctl --list-boots 2>/dev/null | grep -c . 2>/dev/null)
    inesperados=0   # el conteo de arranques no implica apagado inesperado
fi

add_stat 'Sistema' 'ApagadosInesperados' "${inesperados:-0}" 'eventos' \
    "$(safe_str "$detalle_inesperados" 300)" \
    "$(if [ "${inesperados:-0}" -gt 0 ]; then printf ADVERTENCIA; else printf OK; fi)"

if [ "${inesperados:-0}" -gt 0 ]; then
    finding Medium 'Apagados inesperados registrados' \
        -c 'Disponibilidad' -a "$AUDIT_HOSTNAME" \
        -d "Se registraron ${inesperados} arranques sin un cierre limpio previo. Indican fallas de hardware, de energia o del sistema que afectan la disponibilidad del servicio y pueden dejar datos en estado inconsistente." \
        -e "$(safe_str "$detalle_inesperados" 800)" \
        -k 'REG-02|CAP-03|CAP-01' \
        -r 'Investigar la causa raiz de cada evento en el journal del arranque anterior (journalctl -b -1) y verificar la cobertura del sistema de alimentacion ininterrumpida y del plan de continuidad.'
fi

# Errores criticos del kernel en los ultimos 7 dias
if has_cmd journalctl; then
    errores_kernel=$(journalctl -k -p err --since '7 days ago' --no-pager 2>/dev/null | grep -c . 2>/dev/null)
    if [ "${errores_kernel:-0}" -gt 0 ]; then
        add_stat 'Sistema' 'ErroresKernel7d' "$errores_kernel" 'mensajes' \
            'Mensajes del kernel de prioridad error o superior' \
            "$(if [ "$errores_kernel" -gt 50 ]; then printf ADVERTENCIA; else printf Info; fi)"
    fi
fi

emit_result
