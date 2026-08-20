#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# L4-03_unmanaged-binaries.sh
# Capa L4 - ARTEFACTOS DE SOFTWARE.
#
# Descubrimiento de binarios y scripts que residen en el servidor sin haber
# pasado por el gestor de paquetes (software copiado a mano, artefactos
# desplegados por tarball, scripts operativos). Es la evidencia central del
# control SW-03 y del fenomeno de shadow IT.
#
# Criterios de auditoria -> SW-03, INV-03, SW-05
#
# EQUIVALENCIA CENTRAL respecto de L4-03_Unmanaged-Binaries.ps1:
#   En Windows la pregunta es "este binario tiene firma Authenticode valida".
#   En Linux la pregunta equivalente es "este archivo pertenece a algun paquete
#   y coincide con el manifiesto del gestor". Un archivo que no pertenece a
#   ningun paquete carece de procedencia verificable: es el analogo exacto de un
#   ejecutable sin firma digital.
#
# Se anade un control que no tiene equivalente directo en Windows y que en Linux
# es de primer orden: los binarios SUID/SGID no gestionados, que otorgan
# privilegios elevados a cualquier usuario que los ejecute.
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/audit_core.sh"

collector_init 'L4-03' 'Binarios y scripts no gestionados (shadow IT)' 'L4' \
    'SW-03|INV-03|SW-05' false \
    'Escaneo de rutas configuradas en busca de ejecutables y scripts fuera del gestor de paquetes, con verificacion de procedencia e integridad.'
maybe_emit_manifest "${1:-}"

habilitado=$(cfg '.UnmanagedScan.Habilitado' 'false')
if [ "$habilitado" != 'true' ]; then
    gap 'El escaneo de binarios no gestionados esta deshabilitado en config/audit.config.json (UnmanagedScan.Habilitado).'
    collector_status 'Skipped'
    emit_result
    exit 0
fi

load_trusted_publishers

profundidad=$(cfg '.UnmanagedScan.ProfundidadMax' '4')
max_archivos=$(cfg '.UnmanagedScan.MaxArchivos' '3000')
calc_hash=$(cfg '.UnmanagedScan.CalcularHash' 'true')
tam_min_kb=$(cfg '.Thresholds.TamMinBinarioPortableKB' '64')
incluir_sin_ext=$(cfg '.UnmanagedScan.IncluirSinExtension' 'true')

mapfile -t rutas      < <(cfg_json '.UnmanagedScan.Rutas'          | jq -r '.[]?' 2>/dev/null)
mapfile -t excluidas  < <(cfg_json '.UnmanagedScan.RutasExcluidas' | jq -r '.[]?' 2>/dev/null)
mapfile -t extensiones< <(cfg_json '.UnmanagedScan.Extensiones'    | jq -r '.[]?' 2>/dev/null)

# ---------------------------------------------------------------------------
# Construccion de la expresion find
# ---------------------------------------------------------------------------
#
# Se acota con -maxdepth y se podan las rutas excluidas con -prune, para que el
# escaneo no recorra arboles enormes (contenedores, cache de paquetes) que
# ademas no aportan evidencia de auditoria.
prune_args=()
for ex in "${excluidas[@]}"; do
    [ -n "$ex" ] || continue
    prune_args+=( -path "$ex" -prune -o )
done

archivos_evaluados=0
limite_alcanzado=0
rutas_omitidas=''

sin_gestor=0;    lista_sin_gestor=''
alterados=0;     lista_alterados=''
scripts=0;       lista_scripts=''
en_riesgo=0;     lista_riesgo=''
suid_no_gest=0;  lista_suid=''
gestionados=0

TMP_LISTA=$(mktemp)
trap 'rm -f "$TMP_LISTA" 2>/dev/null' EXIT

for raiz in "${rutas[@]}"; do
    [ -n "$raiz" ] || continue
    [ -d "$raiz" ] || continue
    [ "$limite_alcanzado" -eq 1 ] && break

    # -xdev evita cruzar a otros sistemas de archivos (montajes de red, /proc)
    find "$raiz" -xdev -maxdepth "$profundidad" \
        "${prune_args[@]}" \
        -type f \( -perm -u+x -o -perm -g+x -o -perm -o+x \) -print 2>/dev/null \
        >> "$TMP_LISTA"

    # Archivos por extension, aunque no sean ejecutables (scripts sin +x, .jar)
    for ext in "${extensiones[@]}"; do
        [ -n "$ext" ] || continue
        find "$raiz" -xdev -maxdepth "$profundidad" \
            "${prune_args[@]}" \
            -type f -name "*$ext" -print 2>/dev/null >> "$TMP_LISTA"
    done
done

if [ ! -s "$TMP_LISTA" ]; then
    gap "El escaneo no encontro archivos candidatos en las rutas configuradas: ${rutas[*]}"
fi

# Deduplicar y aplicar el tope de seguridad
total_candidatos=$(sort -u "$TMP_LISTA" | grep -c . 2>/dev/null)
if [ "${total_candidatos:-0}" -gt "$max_archivos" ]; then
    limite_alcanzado=1
fi

sort -u "$TMP_LISTA" | head -n "$max_archivos" > "$TMP_LISTA.uniq"

while IFS= read -r archivo; do
    [ -n "$archivo" ] || continue
    [ -f "$archivo" ] || continue

    # La extension se deduce del NOMBRE, no de la ruta completa: un directorio
    # con punto (/opt/mi.app/binario) daria una extension falsa si se calculara
    # sobre la ruta entera.
    nombre_base=$(basename "$archivo")
    case $nombre_base in
        ?*.*) extension=".${nombre_base##*.}" ;;
        *)    extension='' ;;
    esac

    tam_bytes=$(stat -c %s "$archivo" 2>/dev/null || printf 0)
    tam_kb=$(awk -v b="${tam_bytes:-0}" 'BEGIN{printf "%.1f", b/1024}')

    # Se ignoran binarios triviales, igual que la version Windows con .exe/.dll
    es_binario=0
    case $extension in
        .so|.bin|.run|'') es_binario=1 ;;
    esac
    if [ "$es_binario" -eq 1 ] && num_lt "$tam_kb" "$tam_min_kb"; then
        continue
    fi

    archivos_evaluados=$((archivos_evaluados + 1))

    # --- Procedencia e integridad ---
    if [ "$calc_hash" = 'true' ]; then
        file_package_info "$archivo" '--hash'
    else
        file_package_info "$archivo"
    fi

    es_script=0
    case $extension in .sh|.bash|.py|.pl|.rb|.php) es_script=1 ;; esac

    # Permisos SUID/SGID: privilegio delegado al ejecutable.
    # Se usan los operadores -u/-g de test, que consultan el modo directamente:
    # interpretar la cadena de 'stat -c %a' es fragil porque unas implementaciones
    # emiten "4755" y otras "04755".
    permisos=$(stat -c %a "$archivo" 2>/dev/null)
    propietario=$(stat -c '%U:%G' "$archivo" 2>/dev/null)
    suid=0
    if [ -u "$archivo" ] || [ -g "$archivo" ]; then suid=1; fi

    # --- Clasificacion ---
    case $PKG_SIG_STATUS in
        Managed)
            if [ "$PKG_TRUSTED" -eq 1 ]; then
                clasificacion='Gestionado - proveedor confiable'
            else
                clasificacion='Gestionado - proveedor no catalogado'
            fi
            gestionados=$((gestionados + 1)) ;;
        HashMismatch) clasificacion='ALTERADO tras la instalacion' ;;
        Unmanaged)    clasificacion='No gestionado (sin procedencia verificable)' ;;
        *)            clasificacion="No verificable ($PKG_SIG_STATUS)" ;;
    esac

    rec Ruta "$archivo" \
        Nombre "$(basename "$archivo")" \
        Extension "$extension" \
        TamanoKB:n "$tam_kb" \
        UltimaEscritura "$PKG_MTIME" \
        Permisos "$permisos" \
        Propietario "$propietario" \
        SUID:b "$suid" \
        EstadoProcedencia "$PKG_SIG_STATUS" \
        PaqueteOrigen "$PKG_OWNER" \
        Proveedor "$(safe_str "$PKG_VENDOR" 200)" \
        ProveedorConfiable:b "$PKG_TRUSTED" \
        SHA256 "$PKG_SHA256" \
        Clasificacion "$clasificacion"

    # --- Acumuladores ---
    case $PKG_SIG_STATUS in
        Unmanaged)
            if [ "$es_script" -eq 1 ]; then
                scripts=$((scripts + 1))
                [ "$scripts" -le 15 ] && lista_scripts="$lista_scripts | $archivo"
            else
                sin_gestor=$((sin_gestor + 1))
                [ "$sin_gestor" -le 15 ] && lista_sin_gestor="$lista_sin_gestor | $archivo [${tam_kb} KB]"
            fi
            if [ "$suid" -eq 1 ]; then
                suid_no_gest=$((suid_no_gest + 1))
                [ "$suid_no_gest" -le 15 ] && lista_suid="$lista_suid | $archivo ($permisos, $propietario)"
            fi ;;
        HashMismatch)
            alterados=$((alterados + 1))
            [ "$alterados" -le 15 ] && lista_alterados="$lista_alterados | $archivo <= paquete $PKG_OWNER" ;;
    esac

    # Ejecutables en rutas de escritura general: vector de persistencia
    case $archivo in
        /tmp/*|/var/tmp/*|/dev/shm/*)
            if [ "$es_script" -eq 0 ] || [ "$es_script" -eq 1 ]; then
                en_riesgo=$((en_riesgo + 1))
                [ "$en_riesgo" -le 15 ] && lista_riesgo="$lista_riesgo | $archivo"
            fi ;;
    esac

done < "$TMP_LISTA.uniq"

rm -f "$TMP_LISTA.uniq" 2>/dev/null

metric ArchivosEvaluados "$archivos_evaluados" n
metric LimiteAlcanzado "$limite_alcanzado" b
metric NoGestionados "$sin_gestor" n
metric Alterados "$alterados" n
metric Scripts "$scripts" n
metric EnRutasRiesgosas "$en_riesgo" n
metric SUIDNoGestionados "$suid_no_gest" n
metric GestionadosConfiables "$gestionados" n

if [ "$limite_alcanzado" -eq 1 ]; then
    gap "Se alcanzo el tope de $max_archivos archivos definido en UnmanagedScan.MaxArchivos (candidatos totales: $total_candidatos). La cobertura del escaneo es PARCIAL; ajuste el limite o acote las rutas para obtener cobertura completa."
    audit_log WARN "$COL_ID" "Cobertura parcial: se alcanzo el tope de $max_archivos archivos." quiet
fi
[ -n "$rutas_omitidas" ] && gap "Rutas no accesibles durante el escaneo: $rutas_omitidas"

if ! is_root; then
    gap 'El escaneo se ejecuto sin privilegios de root: los archivos en directorios sin permiso de lectura (por ejemplo /root o perfiles de otros usuarios) no fueron evaluados. La cobertura es parcial.'
fi

# ---------------------------------------------------------------------------
# Hallazgos
# ---------------------------------------------------------------------------
if [ "$sin_gestor" -gt 0 ]; then
    finding High 'Ejecutables sin procedencia verificable fuera del gestor de paquetes' \
        -c 'IntegridadDeSoftware' -a "$sin_gestor archivos" \
        -d "Se identificaron $sin_gestor ejecutables o bibliotecas que no pertenecen a ningun paquete instalado. Sin un paquete de origen no es posible verificar su procedencia, comprobar su integridad frente a la fuente oficial, ni recibir parches de seguridad para ellos: quedan fuera de todo el ciclo de gestion de vulnerabilidades del servidor." \
        -e "$(safe_str "${lista_sin_gestor# | }" 1500)" \
        -k 'SW-03|SW-01|ARQ-01' \
        -r 'Verificar el origen de cada binario y, cuando exista, reinstalarlo desde el repositorio oficial de la distribucion o del proveedor. Para el software que necesariamente se despliega fuera del gestor, mantener un inventario formal con version, hash y responsable, e incluirlo en el seguimiento de vulnerabilidades.'
fi

if [ "$alterados" -gt 0 ]; then
    finding Critical 'Archivos de paquetes alterados tras su instalacion' \
        -c 'IntegridadDeSoftware' -a "$alterados archivos" \
        -d 'Estos archivos pertenecen a un paquete instalado pero su contenido ya no coincide con el manifiesto de integridad del gestor: fueron modificados despues de instalarse. Es el analogo exacto de una firma digital con HashMismatch y debe tratarse como posible indicador de compromiso, salvo que corresponda a una personalizacion documentada.' \
        -e "$(safe_str "${lista_alterados# | }" 1500)" \
        -k 'SW-01|SW-03|VUL-02|REG-02' \
        -r 'Contrastar cada archivo con la version oficial del paquete (debsums / rpm -V) y determinar si la modificacion responde a un cambio autorizado. Si no hay justificacion, aislar el sistema y activar el procedimiento de gestion de incidentes.'
fi

if [ "$scripts" -gt 0 ]; then
    finding Medium 'Scripts operativos sin control de versiones ni procedencia' \
        -c 'CodigoOperativo' -a "$scripts scripts" \
        -d "Se identificaron $scripts scripts (.sh/.py/.pl/.rb) que no pertenecen a ningun paquete. El codigo operativo sin trazabilidad puede ser modificado sin deteccion y suele ejecutarse con privilegios elevados desde cron o systemd." \
        -e "$(safe_str "${lista_scripts# | }" 1500)" \
        -k 'SW-05|SW-03|CAM-01' \
        -r 'Trasladar el codigo operativo a un repositorio con control de versiones, desplegarlo mediante el gestor de configuracion (Ansible/Puppet) y registrar su hash en la linea base para detectar modificaciones no autorizadas.'
fi

if [ "$suid_no_gest" -gt 0 ]; then
    finding Critical 'Binarios SUID/SGID que no pertenecen a ningun paquete' \
        -c 'EscaladaDePrivilegios' -a "$suid_no_gest archivos" \
        -d "Se detectaron $suid_no_gest binarios con bit SUID o SGID activo y sin paquete de origen. Un ejecutable SUID corre con los privilegios de su propietario (habitualmente root) sin importar quien lo invoque; si ademas no tiene procedencia verificable, constituye una via de escalada de privilegios directa y es un mecanismo de persistencia habitual tras un compromiso." \
        -e "$(safe_str "${lista_suid# | }" 1500)" \
        -k 'SW-05|SW-03|ACC-02' \
        -r 'Justificar cada binario con el responsable del activo. Retirar el bit SUID/SGID de los que no lo requieran (chmod u-s) y eliminar los que no correspondan a una necesidad operativa aprobada. Incorporar la lista de binarios SUID a la linea base y monitorear sus cambios.'
fi

if [ "$en_riesgo" -gt 0 ]; then
    finding High 'Ejecutables alojados en directorios temporales o de escritura general' \
        -c 'ControlDeAplicaciones' -a "$en_riesgo archivos" \
        -d 'Los ejecutables situados en /tmp, /var/tmp o /dev/shm son el vector habitual de persistencia y de ejecucion de codigo tras un compromiso: son escribibles por cualquier usuario y su contenido no forma parte de ninguna linea base. Ninguna aplicacion de produccion deberia ejecutarse desde estas ubicaciones.' \
        -e "$(safe_str "${lista_riesgo# | }" 1500)" \
        -k 'SW-03|SW-05' \
        -r 'Eliminar los binarios que no correspondan a una necesidad operativa y montar /tmp, /var/tmp y /dev/shm con las opciones noexec,nosuid,nodev para impedir la ejecucion desde esas rutas.'
fi

emit_result
