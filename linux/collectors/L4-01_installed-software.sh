#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# L4-01_installed-software.sh
# Capa L4 - ARTEFACTOS DE SOFTWARE (capa prioritaria de esta auditoria).
#
# Inventario consolidado, normalizado y ENRIQUECIDO de todo el software
# instalado mediante mecanismos gestionados. Cada artefacto se acompana de:
#   - Descripcion funcional (cascada catalogo -> gestor -> rol)
#   - Ruta de instalacion resuelta y verificada
#   - Rol arquitectonico y capa de arquitectura empresarial
#   - Propietario y criticidad cuando el catalogo los declara
#
# Criterios de auditoria -> INV-01, SW-03, INV-03, DAT-02, CAM-01
#
# EQUIVALENCIAS respecto de L4-01_Installed-Software.ps1:
#   Registro Uninstall (3 vistas) -> dpkg / rpm / apk (base del gestor)
#   Get-AppxPackage               -> snap y flatpak (formatos transversales que
#                                    escapan al inventario del gestor nativo)
#   InstallDate del registro      -> /var/log/dpkg.log | rpm INSTALLTIME
#   Publisher                     -> Maintainer (deb) | Vendor (rpm)
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/audit_core.sh"

collector_init 'L4-01' 'Inventario consolidado de software instalado' 'L4' \
    'INV-01|SW-03|INV-03|DAT-02|CAM-01' false \
    'Inventario normalizado con descripcion funcional, ruta de instalacion, rol arquitectonico y deteccion de software no permitido.'
maybe_emit_manifest "${1:-}"

dias_abandono=$(cfg '.Thresholds.DiasSoftwareSinActualizar' '730')

TMP_RAW=$(mktemp)          # inventario crudo, una linea JSON por paquete
TMP_TSV=$(mktemp)          # proyeccion TSV para el clasificador en lote
TMP_CLASS=$(mktemp)        # salida del clasificador
TMP_INV=$(mktemp)          # inventario enriquecido, JSON por linea
trap 'rm -f "$TMP_RAW" "$TMP_TSV" "$TMP_CLASS" "$TMP_INV" 2>/dev/null' EXIT

# ---------------------------------------------------------------------------
# 1. Inventario base desde el gestor de paquetes
# ---------------------------------------------------------------------------
installed_software_raw > "$TMP_RAW" 2>/dev/null

if [ ! -s "$TMP_RAW" ]; then
    gap "No fue posible levantar el inventario del gestor de paquetes (familia detectada: $(detect_pkg_family)). El inventario de software queda sin evidencia."
    collector_status 'NoData'
    emit_result
    exit 0
fi

total_crudo=$(grep -c . "$TMP_RAW")

# Indice "paquete -> prefijo de instalacion", construido de una sola pasada.
# Sin el, resolver la ruta de cada artefacto consultando al gestor uno por uno
# supondria miles de subprocesos sobre un servidor en produccion.
load_pkg_prefix_map

# Proyeccion a TSV: clave, nombre, publicador, ruta declarada.
# Una sola invocacion de jq para todo el inventario.
jq -r '[(.DisplayName + "|" + (.DisplayVersion // "")),
        .DisplayName, (.Publisher // ""), (.InstallLocation // "")] | @tsv' \
    < "$TMP_RAW" > "$TMP_TSV" 2>/dev/null

# ---------------------------------------------------------------------------
# 2. Clasificacion arquitectonica en lote
# ---------------------------------------------------------------------------
if classify_batch < "$TMP_TSV" > "$TMP_CLASS" 2>/dev/null && [ -s "$TMP_CLASS" ]; then
    :
else
    gap 'No se pudo cargar la taxonomia de arquitectura (config/arquitectura.json); los artefactos quedaran sin clasificar.'
    : > "$TMP_CLASS"
fi

# ---------------------------------------------------------------------------
# 3. Reglas de software no permitido (SW-03 / INV-03)
# ---------------------------------------------------------------------------
TMP_REGLAS=$(mktemp)
cfg_json '.SoftwareNoPermitido' | jq -r '.[] | [.Patron, .Severidad, .Categoria] | @tsv' \
    > "$TMP_REGLAS" 2>/dev/null

# ---------------------------------------------------------------------------
# 4. Fusion: inventario crudo + clasificacion + evaluacion de politica
# ---------------------------------------------------------------------------
#
# Se hace en un unico paso awk/jq para no invocar un proceso por paquete.
# El resultado es una linea JSON por artefacto con el esquema del inventario.

hoy=$(date +%Y-%m-%d)

# Volcado del crudo a TSV con todos los campos que necesita la fusion
jq -r '[(.DisplayName + "|" + (.DisplayVersion // "")),
        .DisplayName, (.DisplayVersion // ""), (.Publisher // ""),
        (.InstallDate // ""), (.InstallLocation // ""),
        ((.EstimatedSizeMB // 0)|tostring), (.Scope // ""), (.Architecture // ""),
        (.PackageType // ""), (.Comments // ""), (.Source // "")] | @tsv' \
    < "$TMP_RAW" > "$TMP_TSV.full" 2>/dev/null

# Indice de clasificacion: clave -> resto de campos
awk -F'\t' 'NR==FNR { c[$1]=$0; next }
{
    clave=$1
    split((clave in c) ? c[clave] : (clave "\tSinClasificar\tSin clasificar\tNo determinada\t\tfalse\t\t\t\t\tSin coincidencia"), r, "\t")
    # Salida fusionada: campos del crudo (1..12) + clasificacion (2..11 de r)
    printf "%s", $0
    for (i=2; i<=11; i++) printf "\t%s", r[i]
    printf "\n"
}' "$TMP_CLASS" "$TMP_TSV.full" > "$TMP_TSV.merged"

# ---------------------------------------------------------------------------
# 5. Construccion del inventario enriquecido y deteccion de hallazgos
# ---------------------------------------------------------------------------
sin_publicador=0
sin_ruta=0
recientes=0
antiguos=0
en_riesgo=0
sin_clasificar=0
apps_negocio=0
con_ruta_verificada=0
con_descripcion=0
paquetes_usuario=0

lista_sin_publicador=''
lista_sin_ruta=''
lista_recientes=''
lista_antiguos=''

while IFS=$'\t' read -r clave nombre version publicador fecha_inst ruta_decl \
                       tam ambito arqui tipo_pkg comentarios origen \
                       rolid rolnombre capaea roldesc encatalogo appid appnombre \
                       propietario criticidad origen_rol; do
    [ -n "$nombre" ] || continue

    # --- Resolucion de la ruta de instalacion ---
    resolve_install_path "$ruta_decl" "$nombre" ''
    ruta=$RIP_RUTA
    ruta_origen=$RIP_ORIGEN
    ruta_verif=$RIP_VERIFICADA
    [ "$ruta_verif" -eq 1 ] && con_ruta_verificada=$((con_ruta_verificada + 1))

    # --- Descripcion funcional (cascada) ---
    desc_catalogo=''
    [ "$encatalogo" = 'true' ] && desc_catalogo=$roldesc
    get_software_description "$comentarios" "$roldesc" "$desc_catalogo"
    descripcion=$GSD_TEXTO
    desc_origen=$GSD_ORIGEN
    [ -n "$descripcion" ] && con_descripcion=$((con_descripcion + 1))

    # --- Antiguedad ---
    dias_inst=''
    [ -n "$fecha_inst" ] && dias_inst=$(days_since "$fecha_inst")

    # --- Evaluacion contra software no permitido ---
    riesgo=''
    cat_riesgo=''
    if [ -s "$TMP_REGLAS" ]; then
        while IFS=$'\t' read -r patron sev categoria; do
            [ -n "$patron" ] || continue
            if printf '%s' "$nombre" | grep -qiE "$patron" 2>/dev/null ||
               printf '%s' "$publicador" | grep -qiE "$patron" 2>/dev/null; then
                riesgo=$sev
                cat_riesgo=$categoria
                break
            fi
        done < "$TMP_REGLAS"
    fi

    if [ -n "$riesgo" ]; then
        en_riesgo=$((en_riesgo + 1))
        # Los criterios citados dependen de la categoria de riesgo, igual que en
        # la version Windows.
        criterios='SW-03|INV-03'
        case ${cat_riesgo,,} in
            *nube*)          criterios='DAT-02|SW-03' ;;
            *p2p*)           criterios='SW-03|DAT-02|INV-03' ;;
            *remoto*)        criterios='SW-03|ACC-04|RED-01' ;;
            *ofensiva*)      criterios='SW-05|SW-03' ;;
            *tunelizacion*)  criterios='RED-02|SW-03|DAT-02' ;;
        esac
        finding "$riesgo" "Software fuera de politica instalado: $nombre" \
            -c 'SoftwareNoPermitido' -a "$nombre $version" \
            -d "Categoria de riesgo: $cat_riesgo. Publicador declarado: $publicador. Rol arquitectonico: $rolnombre. Este tipo de software no corresponde al perfil de un servidor de produccion y amplia la superficie de ataque o habilita canales de datos no controlados." \
            -e "Ruta: ${ruta:-no determinada} | Paquete: $nombre ($tipo_pkg)" \
            -k "$criterios" \
            -r 'Validar la justificacion de negocio con el responsable del activo. De no existir autorizacion formal, desinstalar y registrar la desviacion como no conformidad frente a SW-03.'
    fi

    # --- Acumuladores para hallazgos agregados ---
    if [ -z "$publicador" ]; then
        sin_publicador=$((sin_publicador + 1))
        [ "$sin_publicador" -le 12 ] && lista_sin_publicador="$lista_sin_publicador; $nombre [${ruta:-sin ruta}]"
    fi
    if [ -z "$ruta" ]; then
        sin_ruta=$((sin_ruta + 1))
        [ "$sin_ruta" -le 15 ] && lista_sin_ruta="$lista_sin_ruta; $nombre"
    fi
    if [ -n "$dias_inst" ] && [ "$dias_inst" -le 30 ] 2>/dev/null; then
        recientes=$((recientes + 1))
        [ "$recientes" -le 15 ] && lista_recientes="$lista_recientes; $nombre $version [$fecha_inst]"
    fi
    if [ -n "$dias_inst" ] && [ "$dias_inst" -gt "$dias_abandono" ] 2>/dev/null; then
        antiguos=$((antiguos + 1))
        [ "$antiguos" -le 15 ] && lista_antiguos="$lista_antiguos; $nombre $version [$fecha_inst]"
    fi
    [ "$rolid" = 'SinClasificar' ] && sin_clasificar=$((sin_clasificar + 1))
    [ "$rolid" = 'AplicacionNegocio' ] && apps_negocio=$((apps_negocio + 1))
    case $ambito in *Usuario*|*User*) paquetes_usuario=$((paquetes_usuario + 1)) ;; esac

    json_obj \
        Nombre "$nombre" \
        Version "$version" \
        Descripcion "$descripcion" \
        OrigenDescripcion "$desc_origen" \
        RutaInstalacion "$ruta" \
        RutaVerificada:b "$ruta_verif" \
        OrigenRuta "$ruta_origen" \
        RolArquitectonico "$rolnombre" \
        RolId "$rolid" \
        CapaEA "$capaea" \
        AplicacionNegocio "$appnombre" \
        Propietario "$propietario" \
        Criticidad "$criticidad" \
        EnCatalogoEA:b "$encatalogo" \
        Publicador "$publicador" \
        FechaInstalacion "$fecha_inst" \
        DiasDesdeInstalacion:n "${dias_inst:-0}" \
        Arquitectura "$arqui" \
        TipoPaquete "$tipo_pkg" \
        TamanoMB:n "$tam" \
        Ambitos "$ambito" \
        Origen "$origen" \
        Riesgo "$riesgo" \
        CategoriaRiesgo "$cat_riesgo" >> "$TMP_INV"
    printf '\n' >> "$TMP_INV"

done < "$TMP_TSV.merged"

rm -f "$TMP_REGLAS" "$TMP_TSV.full" "$TMP_TSV.merged" 2>/dev/null

# El inventario se ordena por capa de arquitectura, rol y nombre, igual que la
# version Windows, para que el entregable sea legible por un arquitecto.
jq -s 'sort_by(.CapaEA, .RolArquitectonico, .Nombre)[]' -c < "$TMP_INV" 2>/dev/null |
while IFS= read -r linea; do
    [ -n "$linea" ] && rec_raw "$linea"
done

total=$(rec_count)

# ---------------------------------------------------------------------------
# 6. Hallazgos agregados
# ---------------------------------------------------------------------------
if [ "$sin_publicador" -gt 0 ]; then
    finding Medium 'Software instalado sin publicador declarado' \
        -c 'Procedencia' -a "$sin_publicador paquetes" \
        -d "Se identificaron $sin_publicador entradas sin mantenedor ni proveedor declarado. La ausencia de publicador impide verificar la procedencia del artefacto y su inclusion en el inventario autorizado." \
        -e "$(safe_str "${lista_sin_publicador#; }" 1200)" \
        -k 'INV-01|SW-03' \
        -r 'Documentar el origen de cada paquete y contrastarlo con la lista de software autorizado. Los artefactos sin origen verificable deben ser retirados o reinstalados desde un repositorio firmado y confiable.'
fi

if [ "$sin_ruta" -gt 0 ]; then
    finding Low 'Artefactos sin ruta de instalacion determinable' \
        -c 'LineaBaseEA' -a "$sin_ruta paquetes" \
        -d "No fue posible resolver la ubicacion fisica de $sin_ruta artefactos a partir del manifiesto del gestor de paquetes. Sin ruta conocida no se puede verificar integridad, aplicar control de aplicaciones ni delimitar el respaldo." \
        -e "$(safe_str "${lista_sin_ruta#; }" 1200)" \
        -k 'INV-01|SW-03' \
        -r 'Completar la ruta manualmente en el inventario de arquitectura para estos artefactos, o retirarlos si ya no estan efectivamente instalados. Muchos son bibliotecas o metapaquetes sin directorio propio, lo que es esperable.'
fi

if [ "$recientes" -gt 0 ]; then
    finding Info 'Instalaciones de software en los ultimos 30 dias' \
        -c 'GestionDeCambios' -a "$recientes paquetes" \
        -d "Se registraron $recientes instalaciones o actualizaciones recientes. Cada una debe corresponder a un cambio aprobado y trazable." \
        -e "$(safe_str "${lista_recientes#; }" 1500)" \
        -k 'CAM-01|SW-03' \
        -r 'Contrastar esta lista contra los registros de cambio aprobados (RFC/tickets). Toda instalacion sin cambio asociado constituye una desviacion de SW-03.'
fi

if [ "$antiguos" -gt 0 ]; then
    finding Low 'Software sin actualizacion desde hace mas de dos anios' \
        -c 'CicloDeVida' -a "$antiguos paquetes" \
        -d "$antiguos paquetes no registran instalacion ni actualizacion en mas de $dias_abandono dias. Puede tratarse de software estable o de software abandonado sin mantenimiento de seguridad." \
        -e "$(safe_str "${lista_antiguos#; }" 1500)" \
        -k 'VUL-01|INV-01' \
        -r 'Verificar para cada paquete si existe una version soportada mas reciente y si el proveedor mantiene el producto. Ver tambien el colector L4-05 de ciclo de vida.'
fi

if [ "$paquetes_usuario" -gt 0 ]; then
    finding Medium 'Software instalado en el ambito de usuario' \
        -c 'ControlDeInstalacion' -a "$paquetes_usuario paquetes" \
        -d "$paquetes_usuario paquetes estan instalados en el ambito de usuario (flatpak --user o equivalente). Este tipo de instalacion no requiere privilegios administrativos y suele quedar fuera del inventario y del alcance de los controles corporativos." \
        -k 'SW-03|INV-01' \
        -r 'Restringir la instalacion de paquetes por usuario en servidores de produccion e incorporar estos artefactos al inventario formal de activos de software.'
fi

# ---------------------------------------------------------------------------
# Metricas
# ---------------------------------------------------------------------------
metric TotalPaquetes "$total" n
metric PaquetesSinPublicador "$sin_publicador" n
metric PaquetesEnRiesgo "$en_riesgo" n
metric PaquetesUsuario "$paquetes_usuario" n
metric SinRutaDeterminada "$sin_ruta" n
metric ConRutaVerificada "$con_ruta_verificada" n
metric ConDescripcion "$con_descripcion" n
metric SinClasificar "$sin_clasificar" n
metric AplicacionesNegocio "$apps_negocio" n
metric InstalacionesUltimos30Dias "$recientes" n
metric GestorPaquetes "$(detect_pkg_family)"

emit_result
