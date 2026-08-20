#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# L2-02_patch-level.sh
# Capa L2 - Nivel de parcheo y gestion de actualizaciones.
# Criterios de auditoria -> VUL-01, CAM-01
#
# EQUIVALENCIAS respecto de L2-02_Patch-Level.ps1:
#   Get-HotFix               -> /var/log/dpkg.log  |  rpm -qa --last  |  apk
#   Configuracion WU (AU)    -> unattended-upgrades | dnf-automatic | zypper
#   Servicio wuauserv        -> unidad/temporizador de actualizaciones automaticas
#   Microsoft.Update.Session -> apt list --upgradable | dnf check-update |
#                               zypper list-updates | apk version -l '<'
#   Severidad MSRC           -> origen del repositorio de seguridad
#                               (-security en Debian/Ubuntu, updateinfo en RHEL)
#
# NOTA IMPORTANTE: este colector NO ejecuta 'apt update' ni 'dnf makecache'.
# Refrescar los indices modificaria el estado del activo auditado y violaria el
# criterio AUD-01. Se consulta unicamente la cache local, y si esta obsoleta se
# reporta como brecha de evidencia.
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/audit_core.sh"

collector_init 'L2-02' 'Nivel de parcheo y actualizaciones' 'L2' \
    'VUL-01|CAM-01' false \
    'Historial de actualizaciones instaladas, configuracion de actualizacion automatica y latencia de parcheo.'
maybe_emit_manifest "${1:-}"

dias_max=$(cfg '.Thresholds.DiasMaxSinParche' '45')
familia=$(detect_pkg_family)
herramienta=$(detect_pkg_tool)

# ---------------------------------------------------------------------------
# 1. Historial de actualizaciones instaladas
# ---------------------------------------------------------------------------
ultimo_parche=''
total_upd=0

case $familia in
    deb)
        # /var/log/dpkg.log es la unica fuente con trazabilidad temporal en dpkg.
        logs=''
        for f in /var/log/dpkg.log /var/log/dpkg.log.1; do
            [ -r "$f" ] && logs="$logs $f"
        done
        if [ -n "$logs" ]; then
            # shellcheck disable=SC2086
            historial=$(awk '$3=="upgrade"||$3=="install"{print $1"\t"$4"\t"$3"\t"$5}' $logs 2>/dev/null | sort -r)
            n=0
            while IFS=$'\t' read -r fecha paquete accion version; do
                [ -n "$paquete" ] || continue
                n=$((n+1))
                [ "$n" -gt 400 ] && break     # tope: el historial completo va al CSV del gestor
                pkg=${paquete%%:*}
                dias=$(days_since "$fecha")
                rec Categoria 'Actualizacion' Identificador "$pkg" \
                    Tipo "$accion" InstaladoEl "$fecha" \
                    Version "$version" DiasDesde:n "${dias:-0}" \
                    Origen 'dpkg.log'
            done <<< "$historial"
            total_upd=$(printf '%s\n' "$historial" | grep -c . 2>/dev/null)
            ultimo_parche=$(printf '%s\n' "$historial" | head -1 | cut -f1)
        else
            gap 'No se pudo leer /var/log/dpkg.log; sin el no es posible calcular la latencia de parcheo en sistemas basados en dpkg.'
        fi
        ;;
    rpm)
        historial=$(rpm -qa --last 2>/dev/null | head -400)
        n=0
        while read -r nvr resto; do
            [ -n "$nvr" ] || continue
            n=$((n+1))
            fecha=$(date -d "$resto" +%Y-%m-%d 2>/dev/null)
            dias=$(days_since "$fecha")
            rec Categoria 'Actualizacion' Identificador "$nvr" \
                Tipo 'install/upgrade' InstaladoEl "${fecha:-$resto}" \
                Version '' DiasDesde:n "${dias:-0}" Origen 'rpm -qa --last'
            [ "$n" -eq 1 ] && ultimo_parche=$fecha
        done <<< "$historial"
        total_upd=$(rpm -qa 2>/dev/null | wc -l)
        ;;
    apk)
        if [ -r /var/log/apk.log ]; then
            historial=$(tac /var/log/apk.log 2>/dev/null | head -400)
            while read -r linea; do
                [ -n "$linea" ] || continue
                fecha=$(printf '%s' "$linea" | awk '{print $1}' | cut -dT -f1)
                rec Categoria 'Actualizacion' Identificador "$(safe_str "$linea" 200)" \
                    Tipo 'apk' InstaladoEl "$fecha" Version '' \
                    DiasDesde:n "$(days_since "$fecha")" Origen 'apk.log'
                [ -z "$ultimo_parche" ] && ultimo_parche=$fecha
            done <<< "$historial"
        else
            gap 'Alpine no conserva un historial de instalacion legible (/var/log/apk.log ausente); no es posible calcular la latencia de parcheo.'
        fi
        ;;
    *)
        gap "Gestor de paquetes no reconocido; no se pudo levantar el historial de actualizaciones."
        ;;
esac

metric TotalActualizaciones "${total_upd:-0}" n

if [ -n "$ultimo_parche" ]; then
    dias=$(days_since "$ultimo_parche")
    metric DiasDesdeUltimoParche "${dias:-0}" n
    metric UltimoParche "$ultimo_parche"

    sev=''
    if [ -n "$dias" ] && [ "$dias" -gt $(( dias_max * 2 )) ] 2>/dev/null; then
        sev='Critical'
    elif [ -n "$dias" ] && [ "$dias" -gt "$dias_max" ] 2>/dev/null; then
        sev='High'
    fi

    if [ -n "$sev" ]; then
        finding "$sev" 'Latencia de parcheo fuera del umbral definido' \
            -c 'Parcheo' -a "$AUDIT_HOSTNAME" \
            -d "La ultima actualizacion registrada es del $ultimo_parche ($dias dias). El umbral establecido para este servidor es de $dias_max dias." \
            -e "Fuente=$familia | Ultimo evento=$ultimo_parche" \
            -k 'VUL-01' \
            -r 'Ejecutar el ciclo de actualizacion pendiente y verificar la conectividad del servidor con el repositorio corporativo o el servidor de replica interno (Spacewalk/Katello/Landscape/SUSE Manager).'
    fi
else
    gap 'Ninguna actualizacion reporta fecha de instalacion; no es posible calcular la latencia de parcheo.'
fi

if [ "${total_upd:-0}" -eq 0 ]; then
    finding High 'Sin historial de actualizaciones instaladas' \
        -c 'Parcheo' -a "$AUDIT_HOSTNAME" \
        -d 'El gestor de paquetes no devolvio ninguna actualizacion registrada. El sistema podria no haber recibido parches desde su instalacion, o el historial fue purgado o rotado sin conservacion.' \
        -k 'VUL-01' \
        -r 'Verificar manualmente el estado del gestor de paquetes y la conectividad con la fuente de actualizaciones. Revisar la politica de rotacion de /var/log para conservar la trazabilidad de cambios.'
fi

# ---------------------------------------------------------------------------
# 2. Configuracion de actualizaciones automaticas
#    Analogo de la directiva AUOptions / NoAutoUpdate de Windows Update.
# ---------------------------------------------------------------------------
modo_auto='No configurado'
auto_activo=0

case $herramienta in
    apt)
        cfg_auto='/etc/apt/apt.conf.d/20auto-upgrades'
        if [ -r "$cfg_auto" ]; then
            per=$(awk -F'"' '/Update-Package-Lists/{print $2}' "$cfg_auto" 2>/dev/null)
            upg=$(awk -F'"' '/Unattended-Upgrade/{print $2}' "$cfg_auto" 2>/dev/null)
            if [ "$upg" = '1' ]; then
                modo_auto='unattended-upgrades habilitado'
                auto_activo=1
            else
                modo_auto="unattended-upgrades presente pero deshabilitado (Update-Lists=$per Upgrade=$upg)"
            fi
        elif has_cmd unattended-upgrade; then
            modo_auto='unattended-upgrades instalado, sin configuracion de activacion'
        fi
        systemctl is-enabled unattended-upgrades >/dev/null 2>&1 && auto_activo=1
        ;;
    dnf|yum)
        if systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1 || \
           systemctl is-enabled dnf-automatic-install.timer >/dev/null 2>&1; then
            modo_auto='dnf-automatic habilitado'
            auto_activo=1
        elif systemctl is-enabled yum-cron >/dev/null 2>&1; then
            modo_auto='yum-cron habilitado'
            auto_activo=1
        elif has_cmd dnf-automatic || [ -f /etc/dnf/automatic.conf ]; then
            modo_auto='dnf-automatic instalado pero no habilitado'
        fi
        ;;
    zypper)
        if systemctl is-enabled zypper-automatic.timer >/dev/null 2>&1 || \
           systemctl is-enabled zypp-refresh.timer >/dev/null 2>&1; then
            modo_auto='Actualizacion automatica de zypper habilitada'
            auto_activo=1
        fi
        ;;
    apk)
        crontab -l 2>/dev/null | grep -q 'apk upgrade' && {
            modo_auto='apk upgrade programado por cron'; auto_activo=1; }
        ;;
esac

# Repositorio de replica interno vs repositorios publicos (equivalente a WSUS)
repos_internos=''
case $familia in
    deb)
        repos_internos=$(cat /etc/apt/sources.list /etc/apt/sources.list.d/*.list \
                             /etc/apt/sources.list.d/*.sources 2>/dev/null |
                         grep -oE 'https?://[^ ]+' | sed -E 's|https?://||; s|/.*||' |
                         sort -u | tr '\n' ' ') ;;
    rpm)
        repos_internos=$(grep -rhoE '^(baseurl|mirrorlist|metalink)=.*' /etc/yum.repos.d/ /etc/zypp/repos.d/ 2>/dev/null |
                         grep -oE 'https?://[^ /]+' | sed -E 's|https?://||' |
                         sort -u | tr '\n' ' ') ;;
    apk)
        repos_internos=$(grep -oE 'https?://[^/]+' /etc/apk/repositories 2>/dev/null | sed -E 's|https?://||' | sort -u | tr '\n' ' ') ;;
esac

rec Categoria 'ConfiguracionActualizacion' Identificador 'ActualizacionAutomatica' \
    Tipo "$modo_auto" InstaladoEl '' Version '' DiasDesde:n 0 \
    Origen "$(safe_str "Repositorios: $repos_internos" 500)"

metric ModoActualizacion "$modo_auto"
metric Repositorios "$(safe_str "$repos_internos" 300)"

if [ "$auto_activo" -eq 0 ]; then
    finding High 'Actualizaciones automaticas de seguridad no habilitadas' \
        -c 'Parcheo' -a "$herramienta" \
        -d "No se detecto un mecanismo de actualizacion automatica activo ($modo_auto). Sin el, la aplicacion de parches depende enteramente de una intervencion manual, lo que en la practica alarga la ventana de exposicion." \
        -e "Gestor=$herramienta Familia=$familia" \
        -k 'VUL-01' \
        -r 'Si el parcheo se gestiona por una herramienta externa (Ansible, Landscape, Satellite, SUSE Manager), documentarlo como control compensatorio y evidenciar su cobertura sobre este servidor. En caso contrario, habilitar unattended-upgrades o dnf-automatic limitado a actualizaciones de seguridad.'
fi

# ---------------------------------------------------------------------------
# 3. Actualizaciones pendientes
#    Se consulta SOLO la cache local. No se refrescan indices (AUD-01).
# ---------------------------------------------------------------------------
pendientes=0
pend_seguridad=0
cache_obsoleta=0

case $herramienta in
    apt)
        # Antiguedad de la cache: si supera 7 dias el conteo no es representativo.
        if [ -d /var/lib/apt/lists ]; then
            edad_cache=$(( ( $(date +%s) - $(stat -c %Y /var/lib/apt/lists 2>/dev/null || date +%s) ) / 86400 ))
            [ "$edad_cache" -gt 7 ] 2>/dev/null && cache_obsoleta=1
        fi
        native_capture 120 apt-get --just-print upgrade
        if [ -n "$NC_OUT" ]; then
            lista=$(printf '%s\n' "$NC_OUT" | awk '/^Inst /{print $2" "$3" "$4}')
            pendientes=$(printf '%s\n' "$lista" | grep -c . 2>/dev/null)
            while read -r paquete ver origen; do
                [ -n "$paquete" ] || continue
                es_sec=''
                case $origen in *[Ss]ecurity*) es_sec='Seguridad'; pend_seguridad=$((pend_seguridad+1)) ;; esac
                rec Categoria 'Pendiente' Identificador "$paquete" \
                    Tipo "$(safe_str "$ver $origen" 200)" InstaladoEl '' Version "$ver" \
                    DiasDesde:n 0 Origen "${es_sec:-Actualizacion regular}"
            done <<< "$lista"
        fi
        ;;
    dnf|yum)
        native_capture 180 "$herramienta" -q --cacheonly check-update
        # check-update devuelve 100 cuando hay actualizaciones disponibles
        if [ -n "$NC_OUT" ]; then
            lista=$(printf '%s\n' "$NC_OUT" | awk 'NF==3 && $1 !~ /^(Last|Obsoleting|Security:)/ {print $1"\t"$2"\t"$3}')
            pendientes=$(printf '%s\n' "$lista" | grep -c . 2>/dev/null)
            while IFS=$'\t' read -r paquete ver repo; do
                [ -n "$paquete" ] || continue
                rec Categoria 'Pendiente' Identificador "$paquete" \
                    Tipo "$ver" InstaladoEl '' Version "$ver" DiasDesde:n 0 Origen "$repo"
            done <<< "$lista"
        fi
        # updateinfo clasifica por severidad, el analogo mas cercano a MSRC
        if [ "$herramienta" = 'dnf' ]; then
            native_capture 120 dnf -q --cacheonly updateinfo list --security
            pend_seguridad=$(printf '%s\n' "$NC_OUT" | grep -c . 2>/dev/null)
        fi
        ;;
    zypper)
        native_capture 180 zypper --non-interactive --no-refresh list-updates
        if [ -n "$NC_OUT" ]; then
            lista=$(printf '%s\n' "$NC_OUT" | awk -F'|' '/^v /{gsub(/ /,"",$3); gsub(/ /,"",$5); print $3"\t"$5}')
            pendientes=$(printf '%s\n' "$lista" | grep -c . 2>/dev/null)
            while IFS=$'\t' read -r paquete ver; do
                [ -n "$paquete" ] || continue
                rec Categoria 'Pendiente' Identificador "$paquete" Tipo "$ver" \
                    InstaladoEl '' Version "$ver" DiasDesde:n 0 Origen 'zypper'
            done <<< "$lista"
        fi
        native_capture 120 zypper --non-interactive --no-refresh list-patches --category security
        pend_seguridad=$(printf '%s\n' "$NC_OUT" | awk -F'|' '/security/{n++} END{print n+0}')
        ;;
    apk)
        native_capture 120 apk version -l '<'
        if [ -n "$NC_OUT" ]; then
            lista=$(printf '%s\n' "$NC_OUT" | tail -n +2)
            pendientes=$(printf '%s\n' "$lista" | grep -c . 2>/dev/null)
            while read -r paquete resto; do
                [ -n "$paquete" ] || continue
                rec Categoria 'Pendiente' Identificador "$paquete" Tipo "$resto" \
                    InstaladoEl '' Version '' DiasDesde:n 0 Origen 'apk'
            done <<< "$lista"
        fi
        ;;
    *)
        gap 'No se pudo determinar la herramienta de actualizacion; no se evaluaron actualizaciones pendientes.'
        ;;
esac

metric ActualizacionesPendientes "${pendientes:-0}" n
metric ActualizacionesSeguridadPendientes "${pend_seguridad:-0}" n

if [ "$cache_obsoleta" -eq 1 ]; then
    gap "La cache de indices del gestor de paquetes tiene mas de 7 dias de antiguedad. El conteo de actualizaciones pendientes es una COTA INFERIOR: puede haber mas parches disponibles. La suite no refresca los indices de forma deliberada para no alterar el activo auditado."
fi

if [ "${pend_seguridad:-0}" -gt 0 ]; then
    finding Critical 'Actualizaciones de seguridad pendientes de instalacion' \
        -c 'Parcheo' -a "$AUDIT_HOSTNAME" \
        -d "Hay $pendientes actualizaciones pendientes, de las cuales $pend_seguridad provienen del canal de seguridad de la distribucion." \
        -e "Gestor=$herramienta | Cache obsoleta=$cache_obsoleta" \
        -k 'VUL-01' \
        -r 'Priorizar la instalacion de las actualizaciones de seguridad en la proxima ventana y registrar el cambio en el proceso formal de gestion de cambios.'
elif [ "${pendientes:-0}" -gt 0 ]; then
    finding Low 'Actualizaciones no clasificadas como de seguridad pendientes' \
        -c 'Parcheo' -a "$AUDIT_HOSTNAME" \
        -d "$pendientes actualizaciones estan disponibles en la cache local y no instaladas." \
        -e "Gestor=$herramienta" \
        -k 'VUL-01' \
        -r 'Incorporar al ciclo regular de mantenimiento.'
fi

emit_result
