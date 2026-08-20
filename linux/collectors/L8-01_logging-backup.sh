#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# L8-01_logging-backup.sh
# Capa L8 - Datos, registro y resiliencia.
# Criterios de auditoria -> REG-01, REG-02, REG-03, CAP-01, CAP-02, CAP-03,
#                           DAT-01, DAT-03
#
# EQUIVALENCIAS respecto de L8-01_Logging-Backup.ps1:
#   Get-WinEvent -ListLog        -> journald (persistencia, tamano) + rsyslog
#   Registros criticos (Security)-> auth.log/secure, audit.log, journal
#   Evento 1102 (borrado de log) -> huecos en el journal, rotacion forzada y
#                                   comprobacion de integridad (journalctl --verify)
#   WEF (reenvio centralizado)   -> rsyslog/syslog-ng con destino remoto,
#                                   journal-upload, agentes de SIEM
#   Win32_ShadowCopy             -> instantaneas LVM, Btrfs y ZFS
#   wbengine / Windows Backup    -> unidades y temporizadores de las herramientas
#                                   de respaldo instaladas
#   Win32_LogicalDisk (capacidad)-> df, incluyendo inodos (sin equivalente en
#                                   Windows y causa habitual de caidas en Linux)
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/audit_core.sh"

collector_init 'L8-01' 'Registro de eventos, respaldo y resiliencia' 'L8' \
    'REG-01|REG-02|REG-03|CAP-01|CAP-02|CAP-03|DAT-01|DAT-03' false \
    'Configuracion y salud del registro de eventos, reenvio centralizado, instantaneas, respaldos y capacidad de almacenamiento.'
maybe_emit_manifest "${1:-}"

pct_min=$(cfg '.Thresholds.PorcentajeDiscoLibreMin' '15')
pct_crit=$(cfg '.Thresholds.PorcentajeDiscoLibreCrit' '8')

# ---------------------------------------------------------------------------
# 1. Registro de eventos (REG-01)
# ---------------------------------------------------------------------------
#
# En Linux los "canales" equivalentes a Security/System/Application son los
# archivos de log y las unidades del journal. Se evalua su existencia, su
# persistencia tras reinicio y su tamano de retencion.

journal_persistente='no'
journal_tam=''
if [ -d /var/log/journal ]; then
    journal_persistente='si'
    journal_tam=$(du -sh /var/log/journal 2>/dev/null | awk '{print $1}')
elif [ -d /run/log/journal ]; then
    journal_persistente='no (volatil, se pierde al reiniciar)'
fi

storage_conf=$(awk -F= '/^ *Storage=/{gsub(/ /,"",$2); print $2; exit}' /etc/systemd/journald.conf 2>/dev/null)
max_use=$(awk -F= '/^ *SystemMaxUse=/{gsub(/ /,"",$2); print $2; exit}' /etc/systemd/journald.conf 2>/dev/null)
max_retention=$(awk -F= '/^ *MaxRetentionSec=/{gsub(/ /,"",$2); print $2; exit}' /etc/systemd/journald.conf 2>/dev/null)

rec Categoria 'RegistroEventos' Elemento 'journald' \
    Valor "Persistente=$journal_persistente" \
    Detalle "Storage=${storage_conf:-por omision} SystemMaxUse=${max_use:-sin limite explicito} MaxRetentionSec=${max_retention:-sin limite} Tamano=${journal_tam:-n/d}" \
    Estado "$(if [ "$journal_persistente" = 'si' ]; then printf OK; else printf FALLA; fi)"

metric JournalPersistente "$journal_persistente"

if [ "$journal_persistente" != 'si' ]; then
    finding High 'Registro del sistema no persistente entre reinicios' \
        -c 'Registro' -a 'systemd-journald' \
        -d 'El journal esta configurado como volatil: se almacena en /run y se pierde por completo al reiniciar el servidor. Cualquier evidencia de un incidente desaparece con el primer reinicio, y un atacante solo necesita provocar uno para borrar el rastro.' \
        -e "Storage=${storage_conf:-por omision} | /var/log/journal ausente" \
        -k 'REG-01|REG-03|REG-02' \
        -r 'Establecer Storage=persistent en /etc/systemd/journald.conf, crear /var/log/journal y definir SystemMaxUse y MaxRetentionSec conforme a la politica de retencion. Complementar con reenvio a una plataforma central.'
fi

# Archivos de registro clasicos
for log in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages \
           /var/log/audit/audit.log /var/log/cron /var/log/faillog; do
    if [ -e "$log" ]; then
        tam=$(stat -c %s "$log" 2>/dev/null)
        tam_mb=$(awk -v b="${tam:-0}" 'BEGIN{printf "%.1f", b/1048576}')
        mtime=$(stat -c %y "$log" 2>/dev/null | cut -d. -f1)
        perm=$(stat -c %a "$log" 2>/dev/null)
        rec Categoria 'RegistroEventos' Elemento "$log" \
            Valor "Presente (${tam_mb} MB)" \
            Detalle "Ultima escritura: $mtime | Permisos: $perm" Estado 'OK'
    fi
done

# Solo se exige la existencia del registro de autenticacion: es el equivalente
# funcional del registro de seguridad de Windows.
if [ ! -e /var/log/auth.log ] && [ ! -e /var/log/secure ] && [ "$journal_persistente" != 'si' ]; then
    finding High 'Sin registro persistente de eventos de autenticacion' \
        -c 'Registro' -a 'auth.log / secure / journal' \
        -d 'No existe ni /var/log/auth.log ni /var/log/secure, y el journal no es persistente. No queda registro de los inicios de sesion, las elevaciones con sudo ni los intentos fallidos: es la perdida de la fuente de evidencia mas importante para investigar un acceso no autorizado.' \
        -k 'REG-01|REG-02|REG-03|ACC-01' \
        -r 'Habilitar el journal persistente o instalar y configurar rsyslog para que escriba los eventos de la facility auth en un archivo dedicado, con permisos restrictivos y rotacion conforme a la politica.'
fi

# ---------------------------------------------------------------------------
# 2. Integridad del registro (analogo del evento 1102)
# ---------------------------------------------------------------------------
if has_cmd journalctl && [ "$journal_persistente" = 'si' ]; then
    if is_root; then
        native_capture 60 journalctl --verify
        if printf '%s' "$NC_ERR$NC_OUT" | grep -qiE 'fail|corrupt|invalid'; then
            finding High 'El registro del sistema presenta inconsistencias de integridad' \
                -c 'IndicadorDeCompromiso' -a 'systemd-journald' \
                -d 'La verificacion del journal reporto archivos corruptos o inconsistentes. Puede deberse a un cierre abrupto del sistema o a una manipulacion deliberada del registro para eliminar evidencia.' \
                -e "$(safe_str "${NC_ERR:-$NC_OUT}" 800)" \
                -k 'REG-01|REG-03|REG-02' \
                -r 'Correlacionar la fecha de los archivos afectados con apagados inesperados registrados. Si no hay un apagado que lo explique, tratar como posible manipulacion de evidencia y escalar a gestion de incidentes. Habilitar el sellado criptografico del journal (journalctl --setup-keys) para detectar alteraciones a futuro.'
        fi

        # Sellado criptografico (FSS): permite probar que el log no fue alterado
        if [ ! -f /var/log/journal/*/fss ] 2>/dev/null; then
            rec Categoria 'RegistroEventos' Elemento 'SelladoJournal (FSS)' \
                Valor 'No configurado' \
                Detalle 'Sin sellado no es posible demostrar criptograficamente que el registro no fue alterado' \
                Estado 'ADVERTENCIA'
        fi
    else
        gap 'La verificacion de integridad del journal requiere privilegios de root; no se evaluo el criterio REG-03 en ese aspecto.'
    fi
fi

# ---------------------------------------------------------------------------
# 3. Reenvio centralizado de registros (REG-03)
# ---------------------------------------------------------------------------
reenvio=''
for f in /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog-ng/syslog-ng.conf; do
    [ -r "$f" ] || continue
    # @host = UDP, @@host = TCP; en syslog-ng, destination con tcp()/udp()
    d=$(grep -hE '^\s*[^#]*@@?[a-zA-Z0-9.]|destination.*(tcp|udp)\s*\(' "$f" 2>/dev/null | head -3)
    [ -n "$d" ] && reenvio="$reenvio $f: $(safe_str "$d" 150)"
done
if [ -r /etc/systemd/journal-upload.conf ]; then
    u=$(awk -F= '/^ *URL=/{print $2; exit}' /etc/systemd/journal-upload.conf 2>/dev/null)
    [ -n "$u" ] && reenvio="$reenvio journal-upload: $u"
fi
# Agentes de SIEM que hacen el reenvio por su cuenta
for agente in filebeat winlogbeat auditbeat fluentd fluent-bit td-agent \
              splunkd splunk-forwarder nxlog wazuh-agent ossec-agent rsyslog; do
    systemctl is-active "$agente" >/dev/null 2>&1 && reenvio="$reenvio agente:$agente(activo)"
done

tiene_reenvio=0
[ -n "$(safe_str "$reenvio")" ] && tiene_reenvio=1

rec Categoria 'RegistroEventos' Elemento 'ReenvioCentralizado' \
    Valor "$(if [ "$tiene_reenvio" -eq 1 ]; then printf Configurado; else printf 'No configurado'; fi)" \
    Detalle "$(safe_str "$reenvio" 400)" \
    Estado "$(if [ "$tiene_reenvio" -eq 1 ]; then printf OK; else printf ADVERTENCIA; fi)"
metric ReenvioEventos "$tiene_reenvio" b

if [ "$tiene_reenvio" -eq 0 ]; then
    finding Medium 'Sin reenvio de registros a una plataforma centralizada' \
        -c 'Registro' -a "$AUDIT_HOSTNAME" \
        -d 'Los registros permanecen unicamente en el propio servidor. Un atacante con privilegios de root puede borrarlos o alterarlos, y la correlacion de eventos entre sistemas no es posible.' \
        -k 'REG-01|REG-02|REG-03' \
        -r 'Configurar rsyslog/syslog-ng hacia el colector central por TCP con TLS, o desplegar el agente de SIEM corporativo, remitiendo como minimo los canales de autenticacion, auditd y kernel con retencion e integridad protegidas en destino.'
fi

# Rotacion de logs: sin ella el disco se llena y el registro se detiene
if [ -d /etc/logrotate.d ] || [ -f /etc/logrotate.conf ]; then
    n_reglas=$(ls /etc/logrotate.d 2>/dev/null | wc -l)
    rec Categoria 'RegistroEventos' Elemento 'Rotacion (logrotate)' \
        Valor "Configurado ($n_reglas reglas)" Detalle '/etc/logrotate.d' Estado 'OK'
else
    finding Medium 'Sin rotacion de registros configurada' \
        -c 'Registro' -a 'logrotate' \
        -d 'No se detecto configuracion de logrotate. Sin rotacion los archivos de registro crecen sin limite hasta agotar el sistema de archivos, lo que detiene el registro y puede provocar la caida de los servicios que escriben en el.' \
        -k 'REG-01|CAP-01|DAT-01' \
        -r 'Instalar y configurar logrotate con politicas de rotacion, compresion y retencion alineadas con la politica de conservacion de evidencia.'
fi

# ---------------------------------------------------------------------------
# 4. Instantaneas y respaldo (CAP-02 / CAP-03)
# ---------------------------------------------------------------------------
instantaneas=0

# LVM
if has_cmd lvs && is_root; then
    while read -r lv vg attr resto; do
        [ -n "$lv" ] || continue
        case $attr in s*) ;; *) continue ;; esac
        instantaneas=$((instantaneas + 1))
        rec Categoria 'Instantanea' Elemento "$vg/$lv" Valor 'LVM' \
            Detalle "Atributos: $attr" Estado 'Info'
    done < <(lvs --noheadings 2>/dev/null)
fi

# Btrfs
if has_cmd btrfs; then
    for punto in $(findmnt -nt btrfs -o TARGET 2>/dev/null | head -5); do
        n=$(btrfs subvolume list -s "$punto" 2>/dev/null | grep -c . 2>/dev/null)
        [ "${n:-0}" -gt 0 ] || continue
        instantaneas=$((instantaneas + n))
        rec Categoria 'Instantanea' Elemento "$punto" Valor "Btrfs ($n)" \
            Detalle 'Subvolumenes de instantanea' Estado 'Info'
    done
fi

# ZFS
if has_cmd zfs; then
    n=$(zfs list -t snapshot -H 2>/dev/null | grep -c . 2>/dev/null)
    if [ "${n:-0}" -gt 0 ]; then
        instantaneas=$((instantaneas + n))
        reciente=$(zfs list -t snapshot -H -o name,creation -s creation 2>/dev/null | tail -1)
        rec Categoria 'Instantanea' Elemento 'ZFS' Valor "$n instantaneas" \
            Detalle "$(safe_str "$reciente" 200)" Estado 'Info'
    fi
fi

metric InstantaneasVolumen "$instantaneas" n

# Herramientas de respaldo instaladas y su ultima ejecucion
respaldo=''
for h in bacula-fd bareos-fd amanda-client borgmatic restic duplicity rsnapshot \
         veeamservice commvault netbackup dsmcad urbackupclientbackend; do
    if systemctl is-active "$h" >/dev/null 2>&1 || systemctl is-enabled "$h" >/dev/null 2>&1; then
        estado=$(systemctl is-active "$h" 2>/dev/null)
        respaldo="$respaldo $h($estado)"
        rec Categoria 'Respaldo' Elemento "$h" Valor "$estado" \
            Detalle 'Agente de respaldo detectado' Estado 'Info'
    fi
done
# Temporizadores de respaldo
if [ "$(detect_init_system)" = 'systemd' ]; then
    while read -r unidad; do
        case $unidad in *backup*|*borg*|*restic*|*duplicity*|*rsnapshot*|*snapshot*) ;; *) continue ;; esac
        ultimo=$(systemctl show "$unidad" -p LastTriggerUSec --value 2>/dev/null)
        respaldo="$respaldo $unidad"
        rec Categoria 'Respaldo' Elemento "$unidad" Valor 'Temporizador' \
            Detalle "Ultima ejecucion: ${ultimo:-nunca}" Estado 'Info'
    done < <(systemctl list-units --type=timer --all --no-legend --no-pager 2>/dev/null | awk '{print $1}')
fi

metric Respaldo "$(safe_str "${respaldo:-ninguno detectado}" 200)"

if [ -z "$(safe_str "$respaldo")" ] && [ "$instantaneas" -eq 0 ]; then
    finding Medium 'Sin mecanismo de respaldo ni instantaneas detectado en el servidor' \
        -c 'Resiliencia' -a "$AUDIT_HOSTNAME" \
        -d 'No se detecto ningun agente de respaldo, temporizador de copia ni instantanea de volumen. No constituye por si mismo una deficiencia si el respaldo se realiza desde fuera del activo (a nivel de hipervisor o de almacenamiento), pero en ese caso debe evidenciarse: desde el propio servidor no hay constancia de que sus datos sean recuperables.' \
        -k 'CAP-02|CAP-03' \
        -r 'Confirmar que existe una estrategia de respaldo documentada y probada que cubra este servidor, y evidenciar la ultima restauracion verificada. Si el respaldo se realiza a nivel de hipervisor, documentarlo como control compensatorio con evidencia del proveedor.'
fi

# ---------------------------------------------------------------------------
# 5. Capacidad de almacenamiento (CAP-01)
# ---------------------------------------------------------------------------
df -PT 2>/dev/null | tail -n +2 |
while read -r disp fstipo bloques usado libre pctusado punto; do
    case $fstipo in
        proc|sysfs|devtmpfs|devpts|tmpfs|squashfs|overlay|cgroup*|securityfs|pstore|debugfs|tracefs|configfs|fusectl|bpf|autofs|mqueue|hugetlbfs|binfmt_misc|nsfs|ramfs)
            continue ;;
    esac
    [ "${bloques:-0}" -gt 0 ] 2>/dev/null || continue

    pct_libre=$(pct "$libre" "$bloques")
    libre_gb=$(awk -v k="$libre" 'BEGIN{printf "%.2f", k/1048576}')
    total_gb=$(awk -v k="$bloques" 'BEGIN{printf "%.2f", k/1048576}')

    if num_lt "$pct_libre" "$pct_crit"; then estado='CRITICO'
    elif num_lt "$pct_libre" "$pct_min"; then estado='ADVERTENCIA'
    else estado='OK'; fi

    rec Categoria 'Capacidad' Elemento "Volumen $punto" \
        Valor "${pct_libre}% libre" \
        Detalle "$libre_gb GB libres de $total_gb GB ($disp, $fstipo)" Estado "$estado"

    if [ "$estado" != 'OK' ]; then
        sev='Medium'; [ "$estado" = 'CRITICO' ] && sev='High'
        finding "$sev" "Espacio libre insuficiente en el volumen $punto" \
            -c 'Capacidad' -a "$punto" \
            -d "Espacio libre: ${pct_libre}% ($libre_gb GB de $total_gb GB). Umbral de advertencia: ${pct_min}%, umbral critico: ${pct_crit}%. La falta de espacio compromete el registro de eventos, la aplicacion de parches y la disponibilidad del servicio." \
            -e "Dispositivo=$disp Tipo=$fstipo Punto=$punto" \
            -k 'CAP-01|REG-01' \
            -r 'Liberar espacio, ampliar el volumen (con LVM en caliente si es posible) y establecer alertas de capacidad con umbral preventivo en la plataforma de monitoreo.'
    fi
done

# Agotamiento de inodos: causa habitual de "disco lleno" con espacio disponible.
# No tiene equivalente en el original porque NTFS no expone esta limitacion.
df -PTi 2>/dev/null | tail -n +2 |
while read -r disp fstipo inodos usados libres pctusado punto; do
    case $fstipo in
        proc|sysfs|devtmpfs|devpts|tmpfs|squashfs|overlay|cgroup*|autofs|nsfs) continue ;;
    esac
    [ "${inodos:-0}" -gt 0 ] 2>/dev/null || continue
    pct_libre_i=$(pct "$libres" "$inodos")

    if num_lt "$pct_libre_i" 10; then
        rec Categoria 'Capacidad' Elemento "Inodos $punto" \
            Valor "${pct_libre_i}% libres" \
            Detalle "$libres inodos libres de $inodos" Estado 'ADVERTENCIA'

        finding High "Agotamiento de inodos en el volumen $punto" \
            -c 'Capacidad' -a "$punto" \
            -d "Solo queda el ${pct_libre_i}% de los inodos disponibles ($libres de $inodos). Al agotarse, el sistema de archivos no admite archivos nuevos aunque quede espacio libre en bloques: los servicios fallan con 'No space left on device' sin que el uso de disco lo explique. Suele deberse a la acumulacion de archivos pequenos (sesiones, colas de correo, cache)." \
            -e "Dispositivo=$disp Punto=$punto Inodos=$inodos Libres=$libres" \
            -k 'CAP-01' \
            -r 'Identificar el directorio que concentra los archivos (find <punto> -xdev -type f | cut -d/ -f2 | sort | uniq -c | sort -rn) y aplicar limpieza o rotacion. Incluir la ocupacion de inodos en el monitoreo de capacidad.'
    fi
done

# ---------------------------------------------------------------------------
# 6. Higiene de archivos temporales (DAT-01)
# ---------------------------------------------------------------------------
for tmp in /tmp /var/tmp; do
    [ -d "$tmp" ] || continue
    total_arch=$(find "$tmp" -xdev -maxdepth 3 -type f 2>/dev/null | grep -c . 2>/dev/null)
    antiguos=$(find "$tmp" -xdev -maxdepth 3 -type f -mtime +90 2>/dev/null | grep -c . 2>/dev/null)
    tam=$(du -sm "$tmp" 2>/dev/null | awk '{print $1}')

    rec Categoria 'Temporales' Elemento "$tmp" \
        Valor "${total_arch:-0} archivos, ${tam:-0} MB" \
        Detalle "${antiguos:-0} con mas de 90 dias" \
        Estado "$(if [ "${antiguos:-0}" -gt 500 ]; then printf ADVERTENCIA; else printf OK; fi)"

    if [ "${antiguos:-0}" -gt 500 ]; then
        finding Low 'Acumulacion de archivos temporales antiguos' \
            -c 'HigieneDeDatos' -a "$tmp" \
            -d "$antiguos archivos con mas de 90 dias ocupan ${tam:-0} MB. Los temporales pueden contener fragmentos de informacion sensible y consumen capacidad e inodos sin proposito." \
            -e "Ruta=$tmp Total=$total_arch Antiguos=$antiguos" \
            -k 'DAT-01|CAP-01' \
            -r 'Configurar systemd-tmpfiles con una politica de limpieza automatica alineada con la politica de retencion y eliminacion de informacion.'
    fi
done

# ---------------------------------------------------------------------------
# 7. Medios extraibles montados (DAT-03)
# ---------------------------------------------------------------------------
if has_cmd lsblk; then
    extraibles=$(lsblk -ln -o NAME,RM,MOUNTPOINT 2>/dev/null | awk '$2==1 && $3!="" {print $1" -> "$3}')
    if [ -n "$extraibles" ]; then
        rec Categoria 'Medios' Elemento 'Extraibles montados' \
            Valor "$(safe_str "$extraibles" 300)" Detalle '' Estado 'ADVERTENCIA'
        finding Medium 'Medios extraibles montados en el servidor' \
            -c 'Medios' -a "$(safe_str "$extraibles" 200)" \
            -d 'Se detectaron dispositivos extraibles montados y accesibles. En un servidor de produccion representan un canal de fuga de informacion o de introduccion de codigo no autorizado.' \
            -e "$(safe_str "$extraibles" 500)" \
            -k 'DAT-03|DAT-02' \
            -r 'Desmontar y retirar el medio si no responde a una necesidad operativa aprobada, y evaluar el bloqueo de dispositivos de almacenamiento USB mediante reglas udev o USBGuard.'
    fi
fi

emit_result
