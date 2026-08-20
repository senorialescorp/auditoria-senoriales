#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# L2-01_os-baseline.sh
# Capa L2 - Sistema operativo: linea base e identidad del SO.
# Criterios de auditoria -> INV-01, ARQ-01, ARQ-04
#
# EQUIVALENCIAS respecto de L2-01_OS-Baseline.ps1:
#   Win32_OperatingSystem      -> /etc/os-release, uname, /proc/uptime
#   SoftwareLicensingProduct   -> estado de suscripcion de soporte
#                                 (subscription-manager / ua status / SUSEConnect)
#   Win32_TimeZone + W32Time   -> timedatectl, chrony, systemd-timesyncd, ntpd
#   ExecutionPolicy            -> permisos de los directorios del PATH y umask
#                                 (control equivalente sobre ejecucion de codigo)
#   RebootPending (registro)   -> /var/run/reboot-required, needs-restarting,
#                                 zypper ps, comparacion kernel activo vs instalado
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/audit_core.sh"

collector_init 'L2-01' 'Linea base del sistema operativo' 'L2' \
    'INV-01|ARQ-01|ARQ-04' false \
    'Version del SO, soporte, tiempo de actividad, zona horaria y sincronizacion de reloj.'
maybe_emit_manifest "${1:-}"

umbral_reinicio=$(cfg '.Thresholds.DiasMaxSinReinicio' '60')

# --- Identidad del SO -------------------------------------------------------
so_nombre=$(os_release_field PRETTY_NAME)
so_id=$(os_release_field ID)
so_version=$(os_release_field VERSION_ID)
[ -n "$so_nombre" ] || so_nombre="$(uname -s) $(uname -r)"

kernel=$(uname -r 2>/dev/null)
arquitectura=$(uname -m 2>/dev/null)

rec Categoria 'SistemaOperativo' Elemento 'Version' \
    Valor "$so_nombre" Detalle "ID=$so_id VersionId=$so_version"
rec Categoria 'SistemaOperativo' Elemento 'Kernel' \
    Valor "$kernel" Detalle "Arquitectura $arquitectura"
rec Categoria 'SistemaOperativo' Elemento 'Arquitectura' \
    Valor "$arquitectura" Detalle "Init: $(detect_init_system) | Paquetes: $(detect_pkg_family)"

metric SO "$so_nombre"
metric Kernel "$kernel"
metric Build "$so_version"

# Fecha de instalacion: no hay campo nativo. La aproximacion mas fiable es la
# fecha de creacion del sistema de archivos raiz o del directorio de la base
# de paquetes, en ese orden.
fecha_inst=''
if has_cmd tune2fs; then
    raiz_dev=$(findmnt -no SOURCE / 2>/dev/null)
    if [ -n "$raiz_dev" ]; then
        fecha_inst=$(tune2fs -l "$raiz_dev" 2>/dev/null | awk -F': *' '/Filesystem created:/{print $2}')
        [ -n "$fecha_inst" ] && fecha_inst=$(date -d "$fecha_inst" +%Y-%m-%d 2>/dev/null)
    fi
fi
if [ -z "$fecha_inst" ]; then
    for cand in /var/log/installer /etc/machine-id /var/lib/dpkg /var/lib/rpm; do
        [ -e "$cand" ] || continue
        fecha_inst=$(stat -c %y "$cand" 2>/dev/null | cut -d' ' -f1)
        [ -n "$fecha_inst" ] && break
    done
fi
if [ -n "$fecha_inst" ]; then
    dias_inst=$(days_since "$fecha_inst")
    rec Categoria 'SistemaOperativo' Elemento 'FechaInstalacion' \
        Valor "$fecha_inst" Detalle "${dias_inst:-?} dias de antiguedad (estimado)"
else
    gap 'No fue posible estimar la fecha de instalacion del sistema operativo.'
fi

# --- Tiempo de actividad ----------------------------------------------------
uptime_seg=$(awk '{print int($1)}' /proc/uptime 2>/dev/null)
if [ -n "$uptime_seg" ]; then
    uptime_dias=$(awk -v s="$uptime_seg" 'BEGIN{printf "%.1f", s/86400}')
    arranque=$(date -d "@$(( $(date +%s) - uptime_seg ))" '+%Y-%m-%d %H:%M' 2>/dev/null)

    rec Categoria 'SistemaOperativo' Elemento 'UltimoArranque' \
        Valor "$arranque" Detalle "$uptime_dias dias de actividad continua"
    metric UptimeDias "$uptime_dias" n

    if num_gt "$uptime_dias" "$umbral_reinicio"; then
        finding Medium 'Tiempo de actividad excesivo sin reinicio' \
            -c 'Parcheo' -a "$AUDIT_HOSTNAME" \
            -d "El servidor lleva $uptime_dias dias sin reiniciarse (umbral: $umbral_reinicio). Las actualizaciones de kernel y de bibliotecas compartidas en uso no se aplican de forma efectiva hasta el reinicio o hasta que los procesos que las cargan se reinicien." \
            -e "Ultimo arranque=$arranque" \
            -k 'VUL-01|ARQ-01' \
            -r 'Programar una ventana de mantenimiento para reinicio y verificar que la aplicacion efectiva de parches (incluido el reinicio de servicios con bibliotecas obsoletas en memoria) forme parte del procedimiento de cambios.'
    fi
else
    gap 'No fue posible leer /proc/uptime.'
fi

rec Categoria 'SistemaOperativo' Elemento 'DirectorioSistema' \
    Valor '/usr' Detalle "Locale $(printf '%s' "${LANG:-no definido}")"

# Instalacion con entorno grafico: analogo de "Server con Experiencia de
# Escritorio" frente a Server Core. Amplia la superficie de ataque.
if [ -d /usr/share/xsessions ] || command -v Xorg >/dev/null 2>&1 || \
   systemctl get-default 2>/dev/null | grep -q 'graphical'; then
    rec Categoria 'SistemaOperativo' Elemento 'Instalacion' \
        Valor 'Servidor con entorno grafico' \
        Detalle 'Mayor superficie de ataque que una instalacion minima sin escritorio.'
fi

# --- Soporte / suscripcion (INV-04) ----------------------------------------
#
# Analogo del estado de activacion de Windows: determina si el activo tiene
# derecho a recibir actualizaciones de seguridad del proveedor.
estado_soporte='No aplica / distribucion comunitaria'
soporte_ok=1

if has_cmd subscription-manager; then
    native_capture 25 subscription-manager status
    if printf '%s' "$NC_OUT" | grep -qi 'Overall Status: *Current'; then
        estado_soporte='Suscripcion vigente'
    elif [ -n "$NC_OUT" ]; then
        estado_soporte=$(printf '%s' "$NC_OUT" | awk -F: '/Overall Status/{sub(/^ /,"",$2); print $2; exit}')
        [ -n "$estado_soporte" ] || estado_soporte='Sin suscripcion valida'
        soporte_ok=0
    fi
elif has_cmd pro; then
    native_capture 25 pro status --format json
    if printf '%s' "$NC_OUT" | grep -q '"attached": *true'; then
        estado_soporte='Ubuntu Pro adjunto'
    else
        estado_soporte='Ubuntu Pro no adjunto (solo soporte estandar)'
    fi
elif has_cmd SUSEConnect; then
    native_capture 25 SUSEConnect --status-text
    if printf '%s' "$NC_OUT" | grep -qi 'Registered'; then
        estado_soporte='Registrado en SCC'
    else
        estado_soporte='No registrado en SCC'
        soporte_ok=0
    fi
fi

rec Categoria 'Soporte' Elemento 'EstadoSuscripcion' \
    Valor "$estado_soporte" Detalle "$so_nombre"
metric Soporte "$estado_soporte"

if [ "$soporte_ok" -eq 0 ]; then
    finding Medium 'Sistema operativo sin suscripcion de soporte valida' \
        -c 'Cumplimiento' -a "$AUDIT_HOSTNAME" \
        -d "Estado de suscripcion: $estado_soporte. Un sistema sin suscripcion activa pierde acceso a las actualizaciones de seguridad del proveedor y expone a la organizacion a incumplimiento contractual." \
        -e "Distribucion=$so_nombre" \
        -k 'INV-04|VUL-01' \
        -r 'Regularizar la suscripcion con el area de activos de TI antes del cierre de la auditoria, o migrar a una distribucion con soporte comunitario vigente documentado.'
fi

# --- Zona horaria y sincronizacion de reloj (ARQ-04) -----------------------
zona=''; sincronizado=''; servicio_tiempo='Ausente'; ntp_servidor=''

if has_cmd timedatectl; then
    native_capture 15 timedatectl show
    zona=$(printf '%s' "$NC_OUT" | awk -F= '/^Timezone=/{print $2}')
    sincronizado=$(printf '%s' "$NC_OUT" | awk -F= '/^NTPSynchronized=/{print $2}')
fi
[ -n "$zona" ] || zona=$(cat /etc/timezone 2>/dev/null)
[ -n "$zona" ] || zona=$(readlink -f /etc/localtime 2>/dev/null | sed 's|.*/zoneinfo/||')

rec Categoria 'Tiempo' Elemento 'ZonaHoraria' \
    Valor "${zona:-no determinada}" Detalle "Desfase actual $(date +%z 2>/dev/null)"

# Identificar el demonio de tiempo activo y su fuente configurada.
if systemctl is-active chronyd >/dev/null 2>&1 || systemctl is-active chrony >/dev/null 2>&1; then
    servicio_tiempo='chrony (activo)'
    ntp_servidor=$(awk '/^(server|pool)[ \t]/{printf "%s ", $2}' /etc/chrony/chrony.conf /etc/chrony.conf 2>/dev/null)
elif systemctl is-active systemd-timesyncd >/dev/null 2>&1; then
    servicio_tiempo='systemd-timesyncd (activo)'
    ntp_servidor=$(awk -F= '/^ *NTP=/{printf "%s ", $2}' /etc/systemd/timesyncd.conf 2>/dev/null)
    [ -n "$ntp_servidor" ] || ntp_servidor=$(awk -F= '/^ *NTP=/{printf "%s ", $2}' /etc/systemd/timesyncd.conf.d/*.conf 2>/dev/null)
elif systemctl is-active ntpd >/dev/null 2>&1 || systemctl is-active ntp >/dev/null 2>&1; then
    servicio_tiempo='ntpd (activo)'
    ntp_servidor=$(awk '/^(server|pool)[ \t]/{printf "%s ", $2}' /etc/ntp.conf 2>/dev/null)
elif has_cmd rc-service && rc-service chronyd status >/dev/null 2>&1; then
    servicio_tiempo='chrony (OpenRC, activo)'
    ntp_servidor=$(awk '/^(server|pool)[ \t]/{printf "%s ", $2}' /etc/chrony/chrony.conf 2>/dev/null)
fi

rec Categoria 'Tiempo' Elemento 'ServicioSincronizacion' \
    Valor "$servicio_tiempo" \
    Detalle "Sincronizado=${sincronizado:-desconocido} Servidores=$(safe_str "$ntp_servidor" 200)"
metric SincronizacionTiempo "$servicio_tiempo"

if [ "$servicio_tiempo" = 'Ausente' ]; then
    finding High 'Servicio de sincronizacion de tiempo detenido o ausente' \
        -c 'Registro' -a 'chrony / systemd-timesyncd / ntpd' \
        -d 'No se detecto ningun demonio de sincronizacion de reloj activo. Sin sincronizacion, los registros de eventos pierden valor probatorio y la correlacion forense entre sistemas deja de ser fiable.' \
        -e "Sincronizado segun timedatectl=${sincronizado:-desconocido}" \
        -k 'ARQ-04|REG-01' \
        -r 'Habilitar e iniciar chrony (o systemd-timesyncd) con arranque automatico y apuntarlo a una fuente NTP autorizada de la organizacion.'
elif [ -z "$(safe_str "$ntp_servidor")" ]; then
    finding Low 'Fuente NTP no declarada explicitamente' \
        -c 'Registro' -a "$servicio_tiempo" \
        -d 'El servicio de tiempo esta activo pero no se encontro un servidor NTP configurado de forma explicita; estaria usando los valores por omision de la distribucion, que apuntan a servidores publicos.' \
        -k 'ARQ-04' \
        -r 'Configurar la jerarquia de tiempo hacia una fuente autorizada de la organizacion y documentarla en la linea base.'
elif [ "$sincronizado" = 'no' ]; then
    finding Medium 'Reloj del sistema no sincronizado' \
        -c 'Registro' -a "$servicio_tiempo" \
        -d 'El demonio de tiempo esta activo pero el sistema reporta que el reloj no esta sincronizado con su fuente. Los sellos de tiempo de los registros pueden estar desviados.' \
        -e "NTPSynchronized=$sincronizado Servidores=$(safe_str "$ntp_servidor" 200)" \
        -k 'ARQ-04|REG-01' \
        -r 'Verificar conectividad con la fuente NTP (puerto 123/UDP) y revisar el estado con "chronyc tracking" o "timedatectl status".'
fi

# --- Control sobre la ejecucion de codigo -----------------------------------
#
# Analogo funcional de ExecutionPolicy de PowerShell: en Linux el control
# equivalente es que los directorios del PATH del sistema no sean escribibles
# por usuarios sin privilegios, y que no haya rutas relativas en el PATH.
rec Categoria 'Plataforma' Elemento 'Shell' \
    Valor "$(bash --version 2>/dev/null | head -1)" Detalle "SHELL=${SHELL:-no definido}"

path_inseguro=''
IFS=':' read -ra _dirs <<< "${PATH:-}"
for d in "${_dirs[@]}"; do
    if [ -z "$d" ] || [ "$d" = '.' ]; then
        path_inseguro="$path_inseguro (ruta relativa o vacia)"
        continue
    fi
    [ -d "$d" ] || continue
    # Directorio del PATH escribible por otros: permite sustituir binarios
    if [ -w "$d" ] && [ ! -O "$d" ] 2>/dev/null; then
        path_inseguro="$path_inseguro $d"
    fi
    perms=$(stat -c %a "$d" 2>/dev/null)
    case $perms in
        *[2367]) path_inseguro="$path_inseguro $d(modo $perms)" ;;
    esac
done
unset IFS

rec Categoria 'Plataforma' Elemento 'IntegridadPATH' \
    Valor "$(if [ -n "$path_inseguro" ]; then printf 'Rutas debiles detectadas'; else printf 'OK'; fi)" \
    Detalle "$(safe_str "${path_inseguro:-Ningun directorio del PATH es escribible por terceros}" 400)"

if [ -n "$path_inseguro" ]; then
    finding Medium 'Directorios del PATH escribibles por usuarios sin privilegios' \
        -c 'Hardening' -a 'PATH del sistema' \
        -d "Se detectaron directorios en el PATH escribibles por cuentas sin privilegios o entradas relativas:$path_inseguro. Cualquier usuario con acceso a esas rutas puede sustituir un binario y lograr ejecucion de codigo en el contexto de quien lo invoque." \
        -e "PATH=$(safe_str "$PATH" 400)" \
        -k 'SW-05|SW-03' \
        -r 'Restringir los permisos de los directorios afectados a root:root modo 755 y eliminar del PATH toda entrada relativa o vacia.'
fi

# --- Reinicio pendiente -----------------------------------------------------
#
# Analogo de las claves CBS/WindowsUpdate/PendingFileRenameOperations.
pendiente=''

[ -f /var/run/reboot-required ] && pendiente="$pendiente Debian:reboot-required"
[ -f /run/reboot-required ]     && pendiente="$pendiente Debian:reboot-required"

if has_cmd needs-restarting; then
    # -r devuelve 1 cuando se requiere reinicio (RHEL/Fedora)
    needs-restarting -r >/dev/null 2>&1 || pendiente="$pendiente RHEL:needs-restarting"
fi
if has_cmd zypper; then
    zypper ps -s 2>/dev/null | grep -qi 'reboot' && pendiente="$pendiente SUSE:zypper-ps"
fi

# Kernel en ejecucion distinto del kernel mas reciente instalado: el indicador
# mas fiable y transversal de "parche aplicado pero no efectivo".
kernel_instalado=''
case $(detect_pkg_family) in
    deb) kernel_instalado=$(dpkg-query -W -f='${Package}\n' 'linux-image-[0-9]*' 2>/dev/null |
                            sed 's/^linux-image-//' | sort -V | tail -1) ;;
    rpm) kernel_instalado=$(rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' kernel 2>/dev/null |
                            sort -V | tail -1) ;;
esac
if [ -n "$kernel_instalado" ] && [ "$kernel_instalado" != "$kernel" ]; then
    case $kernel in
        "$kernel_instalado"*) : ;;
        *) pendiente="$pendiente Kernel:activo=$kernel/instalado=$kernel_instalado" ;;
    esac
fi

rec Categoria 'Estado' Elemento 'ReinicioPendiente' \
    Valor "$(if [ -n "$pendiente" ]; then printf 'Si'; else printf 'No'; fi)" \
    Detalle "$(safe_str "$pendiente" 400)"
metric ReinicioPendiente "$(if [ -n "$pendiente" ]; then printf true; else printf false; fi)" b

if [ -n "$pendiente" ]; then
    finding Medium 'Reinicio pendiente: parches aplicados pero no efectivos' \
        -c 'Parcheo' -a "$AUDIT_HOSTNAME" \
        -d "Indicadores detectados:$pendiente. Hasta que se reinicie el sistema (o al menos los servicios afectados), las correcciones instaladas no protegen al servidor." \
        -e "Kernel activo=$kernel | Kernel instalado=${kernel_instalado:-n/d}" \
        -k 'VUL-01|CAM-01' \
        -r 'Coordinar el reinicio dentro de la proxima ventana de mantenimiento aprobada. Si el reinicio no es viable, evaluar parcheo en caliente del kernel (kpatch/ksplice/livepatch) y reiniciar los servicios con bibliotecas obsoletas cargadas.'
fi

emit_result
