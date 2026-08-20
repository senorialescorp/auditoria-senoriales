#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# L5-01_services.sh
# Capa L5 - Servicios y procesos.
# Criterios de auditoria -> ARQ-01, ACC-02, SW-03, SW-05
#
# EQUIVALENCIAS respecto de L5-01_Services.ps1:
#   Win32_Service            -> systemctl show / OpenRC
#   StartName (cuenta)       -> directiva User= de la unidad (root si se omite)
#   Ruta sin comillas        -> no aplica en systemd (ExecStart usa argv, no una
#                               cadena que el sistema deba dividir). Se sustituye
#                               por el control equivalente en Linux: permisos
#                               debiles sobre el binario, la unidad o su
#                               directorio, que permiten el mismo secuestro.
#   Rutas estandar           -> /usr/bin, /usr/sbin, /bin, /sbin, /usr/lib
#   Auto pero detenido       -> enabled pero inactive
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/audit_core.sh"

collector_init 'L5-01' 'Servicios del sistema y configuracion de ejecucion' 'L5' \
    'ARQ-01|ACC-02|SW-03|SW-05' false \
    'Inventario de unidades de servicio con analisis de privilegios, aislamiento, rutas no estandar y permisos susceptibles de secuestro.'
maybe_emit_manifest "${1:-}"

init=$(detect_init_system)
if [ "$init" = 'unknown' ]; then
    gap 'No se pudo determinar el sistema de init; no fue posible enumerar los servicios.'
    collector_status 'Failed'
    emit_result
    exit 0
fi

es_ruta_estandar() {
    case $1 in
        /usr/bin/*|/usr/sbin/*|/bin/*|/sbin/*|/usr/lib/*|/usr/libexec/*|/lib/*) return 0 ;;
        *) return 1 ;;
    esac
}

total=0; en_ejecucion=0; como_root=0
fuera_estandar=0;  lista_fuera=''
secuestrables=0;   lista_secuestro=''
auto_detenidos=0;  lista_auto_det=''
sin_aislamiento=0; lista_sin_aisl=''
no_gestionados=0;  lista_no_gest=''

TMP_SVC=$(mktemp)
trap 'rm -f "$TMP_SVC" 2>/dev/null' EXIT

if [ "$init" = 'systemd' ]; then
    systemctl list-units --type=service --all --no-legend --no-pager 2>/dev/null |
        awk '{print $1}' | grep '\.service$' | sort -u > "$TMP_SVC"
else
    for s in /etc/init.d/*; do
        [ -f "$s" ] && [ -x "$s" ] && basename "$s" >> "$TMP_SVC"
    done
fi

while read -r unidad; do
    [ -n "$unidad" ] || continue
    total=$((total + 1))

    if [ "$init" = 'systemd' ]; then
        # Una sola invocacion de systemctl show por unidad, pidiendo todas las
        # propiedades a la vez: consultar una por una multiplicaria por seis el
        # numero de subprocesos.
        props=$(systemctl show "$unidad" \
            -p ExecStart -p User -p Group -p ActiveState -p UnitFileState \
            -p Description -p MainPID -p FragmentPath \
            -p ProtectSystem -p PrivateTmp -p NoNewPrivileges -p ProtectHome \
            2>/dev/null)

        valor() { printf '%s\n' "$props" | awk -F= -v k="$1" '$1==k{sub("^" k "=",""); print; exit}'; }

        exec_start=$(valor ExecStart)
        usuario=$(valor User);        [ -n "$usuario" ] || usuario='root'
        grupo=$(valor Group)
        estado=$(valor ActiveState)
        arranque=$(valor UnitFileState)
        descripcion=$(valor Description)
        pid=$(valor MainPID)
        unidad_path=$(valor FragmentPath)
        protect_system=$(valor ProtectSystem)
        private_tmp=$(valor PrivateTmp)
        no_new_priv=$(valor NoNewPrivileges)
        protect_home=$(valor ProtectHome)

        exe=$(printf '%s' "$exec_start" | sed -nE 's/.*path=([^ ;]+).*/\1/p' | head -1)
        [ -n "$exe" ] || exe=$(printf '%s' "$exec_start" | awk '{print $1}' | sed 's/^[-@:+!]*//')
        ruta_imagen=$(safe_str "$exec_start" 500)
    else
        exe=$(awk -F'=' '/^command=/{gsub(/"/,"",$2); print $2; exit}' "/etc/init.d/$unidad" 2>/dev/null)
        usuario='root'; grupo=''; descripcion=''; pid=''; unidad_path="/etc/init.d/$unidad"
        protect_system=''; private_tmp=''; no_new_priv=''; protect_home=''
        estado='unknown'
        rc-service "$unidad" status >/dev/null 2>&1 && estado='active'
        arranque='unknown'
        rc-update show 2>/dev/null | grep -q "^\s*$unidad" && arranque='enabled'
        ruta_imagen=$exe
    fi

    [ "$estado" = 'active' ] && en_ejecucion=$((en_ejecucion + 1))
    [ "$usuario" = 'root' ] && como_root=$((como_root + 1))

    en_estandar=false
    if [ -n "$exe" ] && es_ruta_estandar "$exe"; then en_estandar=true; fi

    # --- Permisos susceptibles de secuestro ---
    #
    # Sustituye al control de "ruta de servicio sin comillas" de Windows. El
    # riesgo equivalente en Linux es que el binario del servicio, su directorio
    # o el archivo de unidad sean escribibles por alguien distinto de root:
    # cualquiera con ese acceso logra ejecucion con los privilegios del servicio.
    secuestrable=''
    for objetivo in "$exe" "$unidad_path"; do
        [ -n "$objetivo" ] && [ -e "$objetivo" ] || continue
        perm=$(stat -c %a "$objetivo" 2>/dev/null)
        duenio=$(stat -c %U "$objetivo" 2>/dev/null)
        # Ultimo digito con bit de escritura para "otros"
        case $perm in
            *[2367]) secuestrable="$secuestrable $objetivo(escritura general, modo $perm)" ;;
        esac
        [ -n "$duenio" ] && [ "$duenio" != 'root' ] && \
            secuestrable="$secuestrable $objetivo(propietario $duenio)"
    done
    if [ -n "$exe" ]; then
        dir_exe=$(dirname "$exe")
        perm_dir=$(stat -c %a "$dir_exe" 2>/dev/null)
        case $perm_dir in
            *[2367]) secuestrable="$secuestrable $dir_exe/(directorio escribible, modo $perm_dir)" ;;
        esac
    fi

    # --- Procedencia del binario ---
    gestionado='n/d'
    if [ -n "$exe" ] && [ -f "$exe" ]; then
        file_package_info "$exe"
        gestionado=$PKG_SIG_STATUS
    fi

    # --- Aislamiento (endurecimiento de la unidad systemd) ---
    aislado=true
    if [ "$init" = 'systemd' ] && [ "$usuario" = 'root' ] && [ "$estado" = 'active' ]; then
        case "$protect_system" in ''|no) aislado=false ;; esac
        [ "$no_new_priv" = 'no' ] && aislado=false
    fi

    rec Nombre "$unidad" \
        Descripcion "$(safe_str "$descripcion" 300)" \
        Estado "$estado" \
        TipoInicio "$arranque" \
        Cuenta "$usuario" \
        Grupo "$grupo" \
        RutaImagen "$ruta_imagen" \
        Ejecutable "$exe" \
        EnRutaEstandar:b "$en_estandar" \
        Procedencia "$gestionado" \
        PermisosDebiles "$(safe_str "$secuestrable" 400)" \
        ProtectSystem "$protect_system" \
        PrivateTmp "$private_tmp" \
        NoNewPrivileges "$no_new_priv" \
        ProtectHome "$protect_home" \
        PID "$pid"

    # --- Acumuladores ---
    if [ -n "$secuestrable" ]; then
        secuestrables=$((secuestrables + 1))
        [ "$secuestrables" -le 12 ] && lista_secuestro="$lista_secuestro | $unidad =>$secuestrable"
    fi
    if [ "$en_estandar" = 'false' ] && [ -n "$exe" ] && [ "$arranque" != 'masked' ] && [ "$arranque" != 'disabled' ]; then
        fuera_estandar=$((fuera_estandar + 1))
        [ "$fuera_estandar" -le 12 ] && lista_fuera="$lista_fuera | $unidad => $exe"
    fi
    if [ "$arranque" = 'enabled' ] && [ "$estado" != 'active' ]; then
        auto_detenidos=$((auto_detenidos + 1))
        [ "$auto_detenidos" -le 12 ] && lista_auto_det="$lista_auto_det, $unidad"
    fi
    if [ "$aislado" = 'false' ]; then
        sin_aislamiento=$((sin_aislamiento + 1))
        [ "$sin_aislamiento" -le 12 ] && lista_sin_aisl="$lista_sin_aisl | $unidad"
    fi
    if [ "$gestionado" = 'Unmanaged' ] && [ "$estado" = 'active' ]; then
        no_gestionados=$((no_gestionados + 1))
        [ "$no_gestionados" -le 12 ] && lista_no_gest="$lista_no_gest | $unidad => $exe"
    fi

done < "$TMP_SVC"

# ---------------------------------------------------------------------------
# Hallazgos
# ---------------------------------------------------------------------------
if [ "$secuestrables" -gt 0 ]; then
    finding High 'Servicios con binarios o unidades susceptibles de secuestro' \
        -c 'EscaladaDePrivilegios' -a "$secuestrables servicios" \
        -d 'El binario de estos servicios, su directorio o su archivo de unidad son escribibles por cuentas sin privilegios, o no pertenecen a root. Cualquier usuario con ese acceso puede sustituir el contenido y lograr ejecucion de codigo con los privilegios del servicio, habitualmente root. Es el equivalente en Linux del secuestro de rutas de servicio sin comillas de Windows.' \
        -e "$(safe_str "${lista_secuestro# | }" 1500)" \
        -k 'ARQ-01|ACC-02|SW-05' \
        -r 'Restablecer la propiedad a root:root y los permisos a 755 (binarios) y 644 (archivos de unidad) en todos los objetos afectados, y verificar que ningun directorio intermedio de la ruta sea escribible por terceros.'
fi

if [ "$fuera_estandar" -gt 0 ]; then
    finding Medium 'Servicios ejecutando binarios fuera de las rutas estandar del sistema' \
        -c 'SoftwareNoGestionado' -a "$fuera_estandar servicios" \
        -d 'Estos servicios ejecutan binarios que no residen en las rutas del sistema (/usr/bin, /usr/sbin, /usr/lib y equivalentes), lo que sugiere software desplegado sin el gestor de paquetes o fuera del proceso de gestion de cambios.' \
        -e "$(safe_str "${lista_fuera# | }" 1500)" \
        -k 'SW-03|ARQ-01' \
        -r 'Correlacionar cada servicio con el inventario de software autorizado (colector L4-01) y confirmar la procedencia de su binario (colector L4-04).'
fi

if [ "$no_gestionados" -gt 0 ]; then
    finding High 'Servicios activos ejecutando binarios sin procedencia verificable' \
        -c 'IntegridadDeSoftware' -a "$no_gestionados servicios" \
        -d "$no_gestionados servicios en ejecucion arrancan un binario que no pertenece a ningun paquete instalado. No es posible verificar su origen ni recibiran parches por el canal del gestor de paquetes." \
        -e "$(safe_str "${lista_no_gest# | }" 1500)" \
        -k 'SW-01|SW-03|ARQ-01' \
        -r 'Empaquetar el software o incorporarlo al inventario formal con version, hash y responsable, y sumarlo al seguimiento de vulnerabilidades.'
fi

if [ "$sin_aislamiento" -gt 0 ]; then
    finding Medium 'Servicios ejecutandose como root sin directivas de aislamiento' \
        -c 'Privilegios' -a "$sin_aislamiento servicios" \
        -d "$sin_aislamiento unidades activas corren como root sin ProtectSystem ni NoNewPrivileges. systemd ofrece contencion de bajo costo (sistema de archivos de solo lectura, /tmp privado, prohibicion de escalar privilegios) que limita el alcance de una vulnerabilidad en el servicio; no aplicarla deja el compromiso del servicio equivalente al compromiso del servidor." \
        -e "$(safe_str "${lista_sin_aisl# | }" 1200)" \
        -k 'ACC-02|ARQ-01' \
        -r 'Anadir a cada unidad, como minimo, ProtectSystem=strict, ProtectHome=yes, PrivateTmp=yes y NoNewPrivileges=yes, y ejecutar el servicio bajo una cuenta dedicada cuando el producto lo permita.'
fi

if [ "$auto_detenidos" -gt 0 ]; then
    finding Low 'Servicios habilitados para arranque automatico que se encuentran detenidos' \
        -c 'Operacion' -a "$auto_detenidos servicios" \
        -d 'Un servicio habilitado pero inactivo puede indicar una falla no atendida o la desactivacion manual de un control de seguridad sin registrar.' \
        -e "$(safe_str "${lista_auto_det#, }" 1200)" \
        -k 'REG-02|ARQ-01' \
        -r 'Revisar el journal de cada servicio (journalctl -u <unidad>) y determinar si la interrupcion es intencional y esta documentada.'
fi

metric TotalServicios "$total" n
metric ServiciosEnEjecucion "$en_ejecucion" n
metric ComoRoot "$como_root" n
metric FueraDeRutaEstandar "$fuera_estandar" n
metric PermisosSecuestrables "$secuestrables" n
metric SinAislamiento "$sin_aislamiento" n
metric SistemaInit "$init"

emit_result
