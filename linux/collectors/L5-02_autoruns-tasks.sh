#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# L5-02_autoruns-tasks.sh
# Capa L5 - Persistencia y automatizacion.
# Criterios de auditoria -> SW-03, REG-02, CAM-02, ARQ-01
#
# EQUIVALENCIAS respecto de L5-02_Autoruns-Tasks.ps1:
#   Get-ScheduledTask        -> temporizadores systemd + cron (sistema y usuario)
#                               + anacron + at
#   Claves Run / RunOnce     -> /etc/profile.d, rc.local, ~/.bashrc, ~/.profile,
#                               unidades systemd de usuario
#   Carpetas de inicio       -> /etc/xdg/autostart, ~/.config/autostart
#   Winlogon\Userinit        -> /etc/ld.so.preload y LD_PRELOAD en el entorno de
#                               los servicios (mecanismo de secuestro equivalente,
#                               y el indicador de rootkit de usuario mas directo)
#   Suscripciones WMI        -> reglas udev y unidades .path de systemd, que son
#                               los mecanismos de "ejecutar codigo ante un evento"
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/audit_core.sh"

collector_init 'L5-02' 'Tareas programadas y puntos de autoarranque' 'L5' \
    'SW-03|REG-02|CAM-02|ARQ-01' false \
    'Temporizadores systemd, cron, perfiles de shell, autostart, ld.so.preload y reglas udev.'
maybe_emit_manifest "${1:-}"

add_autorun() {
    rec Tipo "$1" Nombre "$(safe_str "$2" 200)" Comando "$(safe_str "$3" 600)" \
        Contexto "$(safe_str "${4:-}" 120)" Estado "${5:-}" Origen "${6:-}" \
        Notas "$(safe_str "${7:-}" 300)"
}

tareas_terceros=0;  lista_terceros=''
alto_privilegio=0;  lista_alto=''
autoarranques=0;    lista_auto=''
preload=0;          lista_preload=''
udev_exec=0;        lista_udev=''
total_tareas=0

# ---------------------------------------------------------------------------
# 1. Temporizadores de systemd (analogo directo de las tareas programadas)
# ---------------------------------------------------------------------------
if [ "$(detect_init_system)" = 'systemd' ]; then
    while read -r unidad; do
        [ -n "$unidad" ] || continue
        total_tareas=$((total_tareas + 1))

        servicio=$(systemctl show "$unidad" -p Unit --value 2>/dev/null)
        [ -n "$servicio" ] || servicio="${unidad%.timer}.service"
        estado=$(systemctl is-active "$unidad" 2>/dev/null)
        fragmento=$(systemctl show "$unidad" -p FragmentPath --value 2>/dev/null)
        calendario=$(systemctl show "$unidad" -p TimersCalendar --value 2>/dev/null)

        comando=$(systemctl show "$servicio" -p ExecStart --value 2>/dev/null)
        exe=$(printf '%s' "$comando" | sed -nE 's/.*path=([^ ;]+).*/\1/p' | head -1)
        usuario=$(systemctl show "$servicio" -p User --value 2>/dev/null)
        [ -n "$usuario" ] || usuario='root'

        # Los temporizadores provistos por la distribucion viven bajo /usr/lib o
        # /lib; los de terceros, bajo /etc/systemd/system.
        es_sistema=1
        case $fragmento in
            /etc/systemd/system/*) es_sistema=0 ;;
        esac

        add_autorun 'TemporizadorSystemd' "$unidad" "${exe:-$comando}" \
            "$usuario" "$estado" "${fragmento:-systemd}" \
            "Servicio=$servicio Calendario=$(safe_str "$calendario" 120)"

        if [ "$es_sistema" -eq 0 ] && [ "$estado" != 'inactive' ]; then
            tareas_terceros=$((tareas_terceros + 1))
            [ "$tareas_terceros" -le 15 ] && lista_terceros="$lista_terceros | $unidad => ${exe:-$comando}"
            if [ "$usuario" = 'root' ]; then
                alto_privilegio=$((alto_privilegio + 1))
                [ "$alto_privilegio" -le 12 ] && lista_alto="$lista_alto | $unidad [root]"
            fi
        fi
    done < <(systemctl list-units --type=timer --all --no-legend --no-pager 2>/dev/null | awk '{print $1}' | grep '\.timer$')
fi

# ---------------------------------------------------------------------------
# 2. cron: sistema, directorios periodicos y crontabs de usuario
# ---------------------------------------------------------------------------
leer_crontab() {
    local archivo=$1 contexto=$2
    [ -r "$archivo" ] || return 0
    while IFS= read -r linea; do
        case $linea in ''|\#*) continue ;; esac
        # /etc/crontab y /etc/cron.d incluyen un campo de usuario tras el horario
        total_tareas=$((total_tareas + 1))
        tareas_terceros=$((tareas_terceros + 1))
        [ "$tareas_terceros" -le 15 ] && lista_terceros="$lista_terceros | $archivo: $(safe_str "$linea" 120)"

        usuario_cron=$contexto
        case $archivo in
            /etc/crontab|/etc/cron.d/*)
                usuario_cron=$(printf '%s' "$linea" | awk '{print $6}') ;;
        esac
        case $linea in
            @reboot*|*root*) : ;;
        esac
        if [ "$usuario_cron" = 'root' ]; then
            alto_privilegio=$((alto_privilegio + 1))
            [ "$alto_privilegio" -le 12 ] && lista_alto="$lista_alto | $archivo [root]: $(safe_str "$linea" 90)"
        fi
        add_autorun 'Cron' "$(basename "$archivo")" "$linea" \
            "${usuario_cron:-$contexto}" 'Activo' "$archivo"
    done < "$archivo"
}

leer_crontab /etc/crontab 'root'
for f in /etc/cron.d/*; do [ -f "$f" ] && leer_crontab "$f" 'root'; done

# Scripts en los directorios periodicos
for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    [ -d "$dir" ] || continue
    for s in "$dir"/*; do
        [ -f "$s" ] || continue
        case $(basename "$s") in .placeholder|README|*.dpkg-*) continue ;; esac
        total_tareas=$((total_tareas + 1))
        file_package_info "$s"
        add_autorun 'CronPeriodico' "$(basename "$s")" "$s" 'root' 'Activo' "$dir" \
            "Procedencia: $PKG_SIG_STATUS ${PKG_OWNER:+(paquete $PKG_OWNER)}"
        if [ "$PKG_SIG_STATUS" = 'Unmanaged' ]; then
            tareas_terceros=$((tareas_terceros + 1))
            alto_privilegio=$((alto_privilegio + 1))
            [ "$alto_privilegio" -le 12 ] && lista_alto="$lista_alto | $s [root, sin paquete]"
        fi
    done
done

# Crontabs de usuario
for spool in /var/spool/cron/crontabs /var/spool/cron; do
    [ -d "$spool" ] || continue
    for u in "$spool"/*; do
        [ -f "$u" ] || continue
        usuario=$(basename "$u")
        if [ -r "$u" ]; then
            leer_crontab "$u" "$usuario"
        else
            gap "El crontab del usuario '$usuario' no es legible sin privilegios de root; su contenido no fue auditado."
        fi
    done
done

metric TotalTareas "$total_tareas" n
metric TareasDeTerceros "$tareas_terceros" n

if [ "$tareas_terceros" -gt 0 ]; then
    finding Medium 'Tareas programadas de terceros activas en el servidor' \
        -c 'Automatizacion' -a "$tareas_terceros tareas" \
        -d 'Cada tarea programada de terceros ejecuta codigo de forma automatica y desatendida. Constituyen tanto un mecanismo operativo legitimo como el vector de persistencia mas utilizado; deben estar inventariadas y aprobadas.' \
        -e "$(safe_str "${lista_terceros# | }" 1500)" \
        -k 'SW-03|CAM-02|REG-02' \
        -r 'Documentar cada tarea en el procedimiento operativo del servidor: proposito, responsable, cuenta de ejecucion y frecuencia. Deshabilitar las que no tengan dueno identificable.'
fi

if [ "$alto_privilegio" -gt 0 ]; then
    finding High 'Tareas programadas de terceros ejecutandose como root' \
        -c 'Privilegios' -a "$alto_privilegio tareas" \
        -d 'Estas tareas se ejecutan con la cuenta root. Si el script o binario invocado reside en una ubicacion escribible por usuarios sin privilegios, cualquiera con acceso a esa ruta logra ejecucion privilegiada de forma automatica y periodica.' \
        -e "$(safe_str "${lista_alto# | }" 1500)" \
        -k 'ACC-02|SW-03|SW-05' \
        -r 'Reducir la cuenta de ejecucion al minimo privilegio necesario y proteger con permisos restrictivos (root:root, 700) todos los archivos que estas tareas invocan.'
fi

# ---------------------------------------------------------------------------
# 3. Puntos de autoarranque de shell y sesion
#    Analogo de las claves Run / RunOnce y de las carpetas de inicio.
# ---------------------------------------------------------------------------
for f in /etc/profile /etc/bash.bashrc /etc/rc.local /etc/rc.d/rc.local; do
    [ -f "$f" ] || continue
    contenido=$(grep -vE '^\s*(#|$)' "$f" 2>/dev/null | head -20)
    [ -n "$contenido" ] || continue
    autoarranques=$((autoarranques + 1))
    lista_auto="$lista_auto | $f"
    add_autorun 'PerfilShell' "$(basename "$f")" "$(safe_str "$contenido" 500)" \
        'Todos los usuarios' 'Activo' "$f"
done

for d in /etc/profile.d; do
    [ -d "$d" ] || continue
    for s in "$d"/*.sh; do
        [ -f "$s" ] || continue
        file_package_info "$s"
        add_autorun 'PerfilShell' "$(basename "$s")" "$s" 'Todos los usuarios' 'Activo' "$d" \
            "Procedencia: $PKG_SIG_STATUS"
        if [ "$PKG_SIG_STATUS" = 'Unmanaged' ]; then
            autoarranques=$((autoarranques + 1))
            [ "$autoarranques" -le 15 ] && lista_auto="$lista_auto | $s (sin paquete)"
        fi
    done
done

for d in /etc/xdg/autostart /root/.config/autostart; do
    [ -d "$d" ] || continue
    for f in "$d"/*.desktop; do
        [ -f "$f" ] || continue
        cmd=$(awk -F= '/^Exec=/{print $2; exit}' "$f" 2>/dev/null)
        autoarranques=$((autoarranques + 1))
        [ "$autoarranques" -le 15 ] && lista_auto="$lista_auto | $f => $cmd"
        add_autorun 'Autostart' "$(basename "$f")" "$cmd" \
            "$(if [ "${d#/root}" != "$d" ]; then printf root; else printf 'Todos los usuarios'; fi)" \
            'Activo' "$d"
    done
done

# Perfiles de shell de las cuentas con shell interactivo
while IFS=: read -r usuario _ uid _ _ home shell; do
    case $shell in */nologin|*/false|'') continue ;; esac
    [ -d "$home" ] || continue
    for rc in .bashrc .bash_profile .profile .zshrc; do
        f="$home/$rc"
        [ -f "$f" ] || continue
        if [ ! -r "$f" ]; then
            gap "El perfil $f no es legible sin privilegios de root; no fue auditado."
            continue
        fi
        # Solo interesan las lineas que ejecutan algo ajeno al perfil por omision
        sospechosas=$(grep -nE '^\s*(curl|wget|nc |ncat|bash -c|sh -c|python|perl|eval|base64|/tmp/|/dev/shm/)' "$f" 2>/dev/null | head -5)
        if [ -n "$sospechosas" ]; then
            autoarranques=$((autoarranques + 1))
            [ "$autoarranques" -le 15 ] && lista_auto="$lista_auto | $f: $(safe_str "$sospechosas" 120)"
            add_autorun 'PerfilUsuario' "$f" "$(safe_str "$sospechosas" 400)" \
                "$usuario" 'Activo' "$home" 'Contiene invocaciones de red o de ejecucion dinamica'
        fi
    done
done < /etc/passwd

metric EntradasAutorun "$autoarranques" n

if [ "$autoarranques" -gt 0 ]; then
    finding Low 'Puntos de autoarranque configurados en el sistema' \
        -c 'Automatizacion' -a "$autoarranques entradas" \
        -d 'Los perfiles de shell, los scripts de /etc/profile.d y las entradas de autostart ejecutan codigo automaticamente al iniciar sesion o al arrancar. En un servidor deben ser minimos y estar justificados.' \
        -e "$(safe_str "${lista_auto# | }" 1500)" \
        -k 'SW-03|ARQ-01' \
        -r 'Validar cada entrada contra el inventario de software autorizado y eliminar las que no correspondan a un producto aprobado.'
fi

# ---------------------------------------------------------------------------
# 4. ld.so.preload: el vector de secuestro mas directo del sistema
# ---------------------------------------------------------------------------
#
# Es el equivalente funcional de la clave Winlogon\Userinit: una biblioteca
# listada aqui se carga en TODOS los procesos dinamicamente enlazados del
# sistema, incluidos los privilegiados. Su presencia es el indicador clasico de
# un rootkit de espacio de usuario, y en un servidor limpio el archivo no existe.
if [ -f /etc/ld.so.preload ]; then
    contenido=$(grep -vE '^\s*(#|$)' /etc/ld.so.preload 2>/dev/null)
    if [ -n "$contenido" ]; then
        preload=1
        lista_preload=$contenido
        add_autorun 'LdPreload' '/etc/ld.so.preload' "$(safe_str "$contenido" 400)" \
            'Todos los procesos' 'Activo' '/etc/ld.so.preload' \
            'Biblioteca precargada en todo proceso enlazado dinamicamente'

        finding Critical 'Bibliotecas precargadas globalmente via /etc/ld.so.preload' \
            -c 'IndicadorDeCompromiso' -a '/etc/ld.so.preload' \
            -d "El archivo /etc/ld.so.preload declara bibliotecas que se cargan en TODOS los procesos enlazados dinamicamente del sistema, incluidos los que corren como root. Es el mecanismo de secuestro mas amplio disponible en Linux y el indicador clasico de un rootkit de espacio de usuario. En un servidor limpio este archivo normalmente no existe. Contenido: $(safe_str "$contenido" 300)" \
            -e "$(safe_str "$contenido" 800)" \
            -k 'ARQ-01|VUL-02|REG-02' \
            -r 'Verificar el origen de cada biblioteca listada y si corresponde a un producto autorizado (algunos agentes de seguridad y de auditoria lo usan legitimamente). Si no se puede justificar, tratar como incidente de seguridad: aislar el servidor y preservar la evidencia antes de modificar el archivo.'
    fi
fi

# LD_PRELOAD inyectado en el entorno de los servicios
if [ "$(detect_init_system)" = 'systemd' ]; then
    inyectados=$(systemctl show '*.service' -p Environment 2>/dev/null | grep -i 'LD_PRELOAD' | head -5)
    if [ -n "$inyectados" ]; then
        add_autorun 'LdPreload' 'Environment=LD_PRELOAD' "$(safe_str "$inyectados" 400)" \
            'Unidades systemd' 'Activo' 'systemd'
        finding High 'LD_PRELOAD inyectado en el entorno de unidades de servicio' \
            -c 'Persistencia' -a 'systemd Environment' \
            -d 'Una o mas unidades de servicio definen LD_PRELOAD en su entorno, forzando la carga de una biblioteca arbitraria en el proceso del servicio. Es un mecanismo legitimo para algunos productos, pero tambien una tecnica de persistencia y de intercepcion de credenciales.' \
            -e "$(safe_str "$inyectados" 800)" \
            -k 'ARQ-01|VUL-02' \
            -r 'Identificar el producto que exige la precarga y verificar la procedencia de la biblioteca. Si no corresponde a software autorizado, tratar como incidente.'
    fi
fi
metric LdPreload "$preload" b

# ---------------------------------------------------------------------------
# 5. Reglas udev y unidades .path: ejecucion de codigo ante eventos
#    Analogo de las suscripciones permanentes de eventos WMI.
# ---------------------------------------------------------------------------
for d in /etc/udev/rules.d; do
    [ -d "$d" ] || continue
    for f in "$d"/*.rules; do
        [ -f "$f" ] || continue
        reglas=$(grep -E 'RUN[+]?=' "$f" 2>/dev/null | head -5)
        [ -n "$reglas" ] || continue
        udev_exec=$((udev_exec + 1))
        lista_udev="$lista_udev | $f"
        add_autorun 'ReglaUdev' "$(basename "$f")" "$(safe_str "$reglas" 400)" \
            'root (evento de dispositivo)' 'Activo' "$f" \
            'Ejecuta un programa al conectarse o cambiar un dispositivo'
    done
done

if [ "$(detect_init_system)" = 'systemd' ]; then
    while read -r unidad; do
        [ -n "$unidad" ] || continue
        ruta_vig=$(systemctl show "$unidad" -p Paths --value 2>/dev/null)
        udev_exec=$((udev_exec + 1))
        lista_udev="$lista_udev | $unidad"
        add_autorun 'UnidadPath' "$unidad" "$(safe_str "$ruta_vig" 300)" \
            'systemd' "$(systemctl is-active "$unidad" 2>/dev/null)" 'systemd' \
            'Lanza un servicio cuando cambia una ruta vigilada'
    done < <(systemctl list-units --type=path --all --no-legend --no-pager 2>/dev/null | awk '{print $1}' | grep '\.path$')
fi

if [ "$udev_exec" -gt 0 ]; then
    finding Medium 'Mecanismos de ejecucion de codigo ante eventos del sistema' \
        -c 'Persistencia' -a "$udev_exec mecanismos" \
        -d 'Se detectaron reglas udev con directiva RUN o unidades .path de systemd. Ambos ejecutan codigo de forma automatica ante un evento (conexion de un dispositivo, cambio en un archivo) y sobreviven a los reinicios. Son poco frecuentes en configuraciones estandar y constituyen una tecnica de persistencia sigilosa, equivalente a las suscripciones permanentes de eventos WMI en Windows.' \
        -e "$(safe_str "${lista_udev# | }" 1200)" \
        -k 'REG-02|VUL-02|SW-03' \
        -r 'Identificar el producto que registro cada mecanismo. Si no se corresponde con software autorizado (agentes de monitoreo, gestion de hardware o respaldo), tratar como incidente.'
fi

# ---------------------------------------------------------------------------
# 6. Modulos del kernel cargados fuera del arbol de la distribucion
# ---------------------------------------------------------------------------
if has_cmd lsmod && has_cmd modinfo; then
    fuera_arbol=''
    while read -r modulo resto; do
        [ -n "$modulo" ] || continue
        case $modulo in Module) continue ;; esac
        firma=$(modinfo -F sig_id "$modulo" 2>/dev/null)
        ruta_mod=$(modinfo -n "$modulo" 2>/dev/null)
        case $ruta_mod in
            */updates/*|/opt/*|/usr/local/*)
                fuera_arbol="$fuera_arbol $modulo" ;;
        esac
        if [ -z "$firma" ] && [ -n "$ruta_mod" ]; then
            case $ruta_mod in
                */kernel/*) : ;;
                *) fuera_arbol="$fuera_arbol $modulo(sin firma)" ;;
            esac
        fi
    done < <(lsmod 2>/dev/null | tail -n +2)

    if [ -n "$fuera_arbol" ]; then
        add_autorun 'ModuloKernel' 'Modulos fuera del arbol' "$(safe_str "$fuera_arbol" 400)" \
            'kernel' 'Cargado' 'lsmod'
        finding High 'Modulos del kernel cargados fuera del arbol de la distribucion' \
            -c 'Persistencia' -a "$(safe_str "$fuera_arbol" 200)" \
            -d "Se detectaron modulos cargados en el kernel que no provienen del arbol firmado de la distribucion, o que carecen de firma:$fuera_arbol. Un modulo del kernel se ejecuta con el maximo privilegio posible y puede ocultar procesos, archivos y conexiones al resto del sistema. Es tambien el mecanismo de los rootkits de kernel." \
            -e "Modulos:$fuera_arbol" \
            -k 'VUL-02|SW-03|REG-02' \
            -r 'Verificar el origen de cada modulo: los controladores de hardware y de hipervisor compilados por DKMS son legitimos y deben documentarse. Todo modulo sin origen justificable debe tratarse como incidente. Evaluar la activacion de la exigencia de firma de modulos en el arranque.'
    fi
fi

metric TotalPuntosPersistencia "$(rec_count)" n

emit_result
