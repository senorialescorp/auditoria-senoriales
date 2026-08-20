#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# L4-06_ea-baseline.sh
# Capa L4 - ARTEFACTOS DE SOFTWARE.
#
# LINEA BASE DE ARQUITECTURA EMPRESARIAL Y CONFORMIDAD DE ROLES
#
# Este colector no busca vulnerabilidades: audita la ARQUITECTURA. Contrasta lo
# que el servidor ES contra lo que la organizacion DECLARO que deberia ser en
# config/arquitectura.json, y responde tres preguntas de auditoria de sistemas:
#
#   1. Cada artefacto instalado, que rol cumple?
#   2. Ese rol corresponde al proposito declarado de este servidor?
#   3. Cada aplicacion de negocio tiene dueno, descripcion y ubicacion conocida?
#
# Correlaciona ademas cada artefacto con los servicios que ejecuta y los puertos
# que expone, para construir el mapa de la capa de aplicacion.
#
# Criterios de auditoria -> INV-01, SW-03, ARQ-01, ARQ-02, INV-03, ARQ-03
#
# EQUIVALENCIAS respecto de L4-06_EA-Baseline.ps1:
#   Win32_Service.PathName    -> ExecStart de las unidades systemd
#   Get-NetTCPConnection      -> ss -tlnp
#   Correlacion por directorio -> identica: se indexa por el directorio del binario
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/audit_core.sh"

collector_init 'L4-06' 'Linea base de arquitectura empresarial y conformidad de roles' 'L4' \
    'INV-01|SW-03|ARQ-01|ARQ-02|INV-03|ARQ-03' false \
    'Clasifica cada artefacto por rol y capa de arquitectura, y evalua su alineacion con el rol declarado del servidor.'
maybe_emit_manifest "${1:-}"

if [ -z "${AUDIT_ARQUITECTURA:-}" ] || [ ! -r "$AUDIT_ARQUITECTURA" ]; then
    gap 'No se cargo config/arquitectura.json; no es posible evaluar la linea base de arquitectura.'
    collector_status 'NoData'
    emit_result
    exit 0
fi

rol_declarado=$(arq '.RolServidor.RolDeclarado' 'No declarado')
entorno=$(arq '.RolServidor.Entorno' 'No declarado')
nombre_srv=$(arq '.RolServidor.Nombre' "$AUDIT_HOSTNAME")
propietario_srv=$(arq '.RolServidor.Propietario' 'DEFINIR')
max_sin_clasificar=$(arq '.Conformidad.MaxPorcentajeSinClasificar' '25')
exigir_catalogo=$(arq '.Conformidad.ExigirCatalogoCompleto' 'false')
exigir_propietario=$(arq '.Conformidad.ExigirPropietario' 'false')

sev_rol_no_esperado=$(arq '.Conformidad.Severidades.RolNoEsperado' 'High')
sev_app_no_catalogada=$(arq '.Conformidad.Severidades.AplicacionNoCatalogada' 'Medium')
sev_sin_clasificar=$(arq '.Conformidad.Severidades.SinClasificar' 'Low')
sev_sin_propietario=$(arq '.Conformidad.Severidades.SinPropietario' 'Medium')

# Listas de roles como cadena delimitada por '|', con delimitador al inicio y al
# final, para que la pertenencia se compruebe con una coincidencia exacta y no
# por prefijo ('Runtime' no debe coincidir con 'RuntimeExtendido').
roles_esperados="|$(arq_json '.RolServidor.RolesEsperados' | jq -r '.[]?' 2>/dev/null | tr '\n' '|')"
roles_no_esperados="|$(arq_json '.RolServidor.RolesNoEsperados' | jq -r '.[]?' 2>/dev/null | tr '\n' '|')"

# en_lista <valor> <lista delimitada por '|'>
en_lista() {
    case $2 in *"|$1|"*) return 0 ;; *) return 1 ;; esac
}

TMP_RAW=$(mktemp);   TMP_TSV=$(mktemp);   TMP_CLASS=$(mktemp)
TMP_SVC=$(mktemp);   TMP_PORT=$(mktemp);  TMP_ART=$(mktemp)
trap 'rm -f "$TMP_RAW" "$TMP_TSV" "$TMP_CLASS" "$TMP_SVC" "$TMP_PORT" "$TMP_ART" 2>/dev/null' EXIT

# ---------------------------------------------------------------------------
# 1. Indices de correlacion: servicios y puertos por directorio de binario
# ---------------------------------------------------------------------------
if [ "$(detect_init_system)" = 'systemd' ]; then
    systemctl list-units --type=service --all --no-legend --no-pager 2>/dev/null |
    awk '{print $1}' | grep '\.service$' |
    while read -r unidad; do
        linea=$(systemctl show "$unidad" -p ExecStart --value 2>/dev/null)
        exe=$(printf '%s' "$linea" | sed -nE 's/.*path=([^ ;]+).*/\1/p' | head -1)
        [ -n "$exe" ] || exe=$(printf '%s' "$linea" | awk '{print $1}' | sed 's/^[-@:+!]*//')
        case $exe in /*) ;; *) continue ;; esac
        estado=$(systemctl is-active "$unidad" 2>/dev/null)
        printf '%s\t%s\t%s\n' "$(dirname "$exe")" "$unidad" "$estado" >> "$TMP_SVC"
    done
else
    gap 'Sistema de init sin soporte de correlacion; no se asociaron servicios a los artefactos.'
fi

# Puertos en escucha por directorio del binario propietario
if has_cmd ss; then
    # -H omite el encabezado; -p requiere privilegios para ver el proceso ajeno
    ss -tlnpH 2>/dev/null | while read -r estado recvq sendq local remoto proceso resto; do
        pid=$(printf '%s' "$proceso" | sed -nE 's/.*pid=([0-9]+).*/\1/p' | head -1)
        [ -n "$pid" ] || continue
        exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
        [ -n "$exe" ] || continue
        exe=${exe% (deleted)}
        puerto=${local##*:}
        printf '%s\t%s\n' "$(dirname "$exe")" "$puerto" >> "$TMP_PORT"
    done
    if ! is_root; then
        gap 'La correlacion de puertos con su binario propietario requiere privilegios de root; la columna PuertosExpuestos puede estar incompleta.'
    fi
else
    gap 'La herramienta "ss" no esta disponible; no se correlacionaron puertos en escucha con los artefactos.'
fi

# ---------------------------------------------------------------------------
# 2. Construccion de la linea base: un registro por artefacto
# ---------------------------------------------------------------------------
installed_software_raw > "$TMP_RAW" 2>/dev/null
if [ ! -s "$TMP_RAW" ]; then
    gap 'Inventario base no disponible; la linea base de arquitectura queda sin artefactos.'
fi

load_pkg_prefix_map

jq -r '[(.DisplayName + "|" + (.DisplayVersion // "")),
        .DisplayName, (.Publisher // ""), (.InstallLocation // "")] | @tsv' \
    < "$TMP_RAW" > "$TMP_TSV" 2>/dev/null

classify_batch < "$TMP_TSV" > "$TMP_CLASS" 2>/dev/null

# Datos completos del crudo para la fusion
jq -r '[(.DisplayName + "|" + (.DisplayVersion // "")),
        .DisplayName, (.DisplayVersion // ""), (.Publisher // ""),
        (.InstallDate // ""), (.InstallLocation // ""), (.Comments // "")] | @tsv' \
    < "$TMP_RAW" > "$TMP_TSV.full" 2>/dev/null

awk -F'\t' 'NR==FNR { c[$1]=$0; next }
{
    clave=$1
    split((clave in c) ? c[clave] : (clave "\tSinClasificar\tSin clasificar\tNo determinada\t\tfalse\t\t\t\t\tSin coincidencia"), r, "\t")
    printf "%s", $0
    for (i=2; i<=11; i++) printf "\t%s", r[i]
    printf "\n"
}' "$TMP_CLASS" "$TMP_TSV.full" > "$TMP_TSV.merged"

total_artefactos=0
alineados=0
no_alineados=0;      lista_no_alin=''
rol_no_declarado=0;  roles_nd=''
sin_clasificar=0;    lista_sin_clas=''
con_ruta_verif=0
negocio_sin_catalogo=0; lista_neg_sc=''
apps_detectadas=''

# Contadores por capa y por rol, para el mapa de la linea base
declare -A CAPA_N ROL_N 2>/dev/null || true

while IFS=$'\t' read -r clave nombre version publicador fecha_inst ruta_decl comentarios \
                       rolid rolnombre capaea roldesc encatalogo appid appnombre \
                       propietario criticidad origen_rol; do
    [ -n "$nombre" ] || continue
    total_artefactos=$((total_artefactos + 1))

    resolve_install_path "$ruta_decl" "$nombre" ''
    ruta=$RIP_RUTA
    [ "$RIP_VERIFICADA" -eq 1 ] && con_ruta_verif=$((con_ruta_verif + 1))

    desc_catalogo=''
    [ "$encatalogo" = 'true' ] && desc_catalogo=$roldesc
    get_software_description "$comentarios" "$roldesc" "$desc_catalogo"

    # --- Correlacion con servicios y puertos ---
    servicios=''; puertos=''
    if [ -n "$ruta" ]; then
        if [ -s "$TMP_SVC" ]; then
            servicios=$(awk -F'\t' -v d="$ruta" '
                $1 == d || index($1, d "/") == 1 { printf "%s [%s]; ", $2, $3 }' "$TMP_SVC")
        fi
        if [ -s "$TMP_PORT" ]; then
            puertos=$(awk -F'\t' -v d="$ruta" '
                $1 == d || index($1, d "/") == 1 { print $2 }' "$TMP_PORT" | sort -un | tr '\n' ',' | sed 's/,$//')
        fi
    fi

    # --- Alineacion con el rol declarado del servidor ---
    if [ "$rolid" = 'SinClasificar' ]; then
        alineacion='Sin clasificar'
        sin_clasificar=$((sin_clasificar + 1))
        [ "$sin_clasificar" -le 20 ] && lista_sin_clas="$lista_sin_clas; $nombre"
    elif en_lista "$rolid" "$roles_no_esperados"; then
        alineacion='NO ALINEADO'
        no_alineados=$((no_alineados + 1))
        [ "$no_alineados" -le 15 ] && lista_no_alin="$lista_no_alin | $nombre [$rolnombre] => ${ruta:-ruta no determinada}"
    elif en_lista "$rolid" "$roles_esperados"; then
        alineacion='Alineado'
        alineados=$((alineados + 1))
    else
        alineacion='Rol no declarado en la linea base'
        rol_no_declarado=$((rol_no_declarado + 1))
        case " $roles_nd " in *" $rolnombre "*) ;; *) roles_nd="$roles_nd $rolnombre" ;; esac
    fi

    # Aplicacion de negocio detectada fuera del catalogo
    if [ "$rolid" = 'AplicacionNegocio' ] && [ "$encatalogo" != 'true' ]; then
        negocio_sin_catalogo=$((negocio_sin_catalogo + 1))
        [ "$negocio_sin_catalogo" -le 15 ] && lista_neg_sc="$lista_neg_sc | $nombre => ${ruta:-sin ruta}"
    fi
    if [ "$encatalogo" = 'true' ] && [ -n "$appid" ]; then
        case " $apps_detectadas " in *" $appid "*) ;; *) apps_detectadas="$apps_detectadas $appid" ;; esac
    fi

    CAPA_N["$capaea"]=$(( ${CAPA_N["$capaea"]:-0} + 1 ))
    ROL_N["$rolnombre"]=$(( ${ROL_N["$rolnombre"]:-0} + 1 ))

    rec Artefacto "$nombre" \
        Version "$version" \
        Descripcion "$GSD_TEXTO" \
        OrigenDescripcion "$GSD_ORIGEN" \
        RutaInstalacion "$ruta" \
        RutaVerificada:b "$RIP_VERIFICADA" \
        OrigenRuta "$RIP_ORIGEN" \
        CapaEA "$capaea" \
        RolArquitectonico "$rolnombre" \
        RolId "$rolid" \
        Alineacion "$alineacion" \
        AplicacionNegocio "$appnombre" \
        EnCatalogoEA:b "$encatalogo" \
        Propietario "$propietario" \
        Criticidad "$criticidad" \
        Publicador "$(safe_str "$publicador" 128)" \
        ServiciosAsociados "$(safe_str "${servicios%; }" 400)" \
        PuertosExpuestos "$puertos" \
        FechaInstalacion "$fecha_inst"

done < "$TMP_TSV.merged"

rm -f "$TMP_TSV.full" "$TMP_TSV.merged" 2>/dev/null

# ---------------------------------------------------------------------------
# 3. Verificacion del catalogo: aplicaciones declaradas vs encontradas
# ---------------------------------------------------------------------------
no_encontradas=''
n_no_encontradas=0
n_catalogo=0

while IFS=$'\t' read -r appid patron nombre_app capaea_app desc_app propietario_app criticidad_app; do
    [ -n "$appid" ] || continue
    n_catalogo=$((n_catalogo + 1))

    encontrada=0
    case " $apps_detectadas " in *" $appid "*) encontrada=1 ;; esac

    # Segunda pasada: buscar el patron tambien en rutas de servicios y en el
    # sistema de archivos, porque muchas aplicaciones de negocio en Linux se
    # despliegan por tarball y no figuran en el gestor de paquetes.
    if [ "$encontrada" -eq 0 ] && [ -n "$patron" ]; then
        if [ -s "$TMP_SVC" ] && awk -F'\t' -v p="$patron" 'tolower($0) ~ tolower(p) {found=1} END{exit !found}' "$TMP_SVC"; then
            encontrada=1
        else
            for base in /opt /srv /usr/local /var/www /usr/sap; do
                [ -d "$base" ] || continue
                if find "$base" -maxdepth 2 -iregex ".*\(${patron}\).*" -print -quit 2>/dev/null | grep -q .; then
                    encontrada=1; break
                fi
            done
        fi
    fi

    if [ "$encontrada" -eq 1 ]; then
        alin='Declarada y detectada'
    else
        alin='Declarada, NO detectada'
        n_no_encontradas=$((n_no_encontradas + 1))
        no_encontradas="$no_encontradas | $appid: patron '$patron'"
    fi

    rec Artefacto "[CATALOGO] $nombre_app" \
        Version '' \
        Descripcion "$(safe_str "$desc_app" 400)" \
        OrigenDescripcion 'Catalogo de arquitectura' \
        RutaInstalacion '' \
        RutaVerificada:b false \
        OrigenRuta '' \
        CapaEA "$capaea_app" \
        RolArquitectonico 'Aplicacion de negocio (declarada)' \
        RolId 'AplicacionNegocio' \
        Alineacion "$alin" \
        AplicacionNegocio "$nombre_app" \
        EnCatalogoEA:b true \
        Propietario "$propietario_app" \
        Criticidad "$criticidad_app" \
        Publicador '' \
        ServiciosAsociados '' \
        PuertosExpuestos '' \
        FechaInstalacion ''
done < <(arq_json '.Aplicaciones' |
         jq -r '.[] | [.Id, .Patron, .Nombre, (.CapaEA // ""), (.Descripcion // ""),
                       (.Propietario // ""), (.Criticidad // "")] | @tsv' 2>/dev/null)

if [ "$n_no_encontradas" -gt 0 ]; then
    finding Medium 'Aplicaciones declaradas en el catalogo que no se detectaron en el servidor' \
        -c 'LineaBaseEA' -a "$n_no_encontradas aplicaciones" \
        -d "El catalogo de arquitectura declara $n_no_encontradas aplicacion(es) que no fueron encontradas ni en el gestor de paquetes, ni en las unidades de servicio, ni en las rutas de despliegue habituales. O la aplicacion no reside en este servidor, o su patron de deteccion esta mal definido, o se despliega por un mecanismo que el inventario gestionado no cubre (copia manual, contenedor, recurso de red)." \
        -e "$(safe_str "${no_encontradas# | }" 1200)" \
        -k 'INV-01|SW-03' \
        -r 'Confirmar con el responsable si la aplicacion reside efectivamente en este activo. Si reside, ajustar el patron de deteccion en config/arquitectura.json o incluir su ruta de despliegue en UnmanagedScan.Rutas para que el colector L4-03 la levante.'
fi

# ---------------------------------------------------------------------------
# 4. Conformidad de roles con el proposito declarado del servidor
# ---------------------------------------------------------------------------
if [ "$no_alineados" -gt 0 ]; then
    finding "$sev_rol_no_esperado" 'Artefactos con rol no alineado al proposito declarado del servidor' \
        -c 'ConformidadArquitectonica' -a "$no_alineados artefactos" \
        -d "El servidor esta declarado como '$rol_declarado' en entorno de $entorno. Se detectaron $no_alineados artefactos cuyo rol arquitectonico figura entre los NO esperados para este proposito. Cada uno amplia la superficie de ataque sin aportar a la funcion del activo." \
        -e "$(safe_str "${lista_no_alin# | }" 1500)" \
        -k 'ARQ-02|SW-03|ARQ-01|ARQ-03' \
        -r 'Para cada artefacto: documentar la justificacion funcional o retirarlo. Si el rol es legitimo para este servidor, incorporarlo a RolesEsperados en config/arquitectura.json y dejar constancia de la decision arquitectonica.'
fi

if [ "$rol_no_declarado" -gt 0 ]; then
    finding Low 'Roles presentes que la linea base no clasifica como esperados ni prohibidos' \
        -c 'LineaBaseEA' -a "$rol_no_declarado artefactos" \
        -d 'Estos artefactos fueron clasificados por la taxonomia, pero su rol no figura ni en RolesEsperados ni en RolesNoEsperados del rol declarado del servidor. La linea base esta incompleta para ellos.' \
        -e "$(safe_str "${roles_nd# }" 800)" \
        -k 'INV-01|ARQ-01|ARQ-02' \
        -r 'Completar RolesEsperados / RolesNoEsperados en config/arquitectura.json para que la linea base cubra el 100% de los roles presentes.'
fi

# ---------------------------------------------------------------------------
# 5. Aplicaciones de negocio no catalogadas
# ---------------------------------------------------------------------------
if [ "$exigir_catalogo" = 'true' ] && [ "$negocio_sin_catalogo" -gt 0 ]; then
    finding "$sev_app_no_catalogada" 'Aplicaciones de negocio detectadas que no figuran en el catalogo de arquitectura' \
        -c 'LineaBaseEA' -a "$negocio_sin_catalogo aplicaciones" \
        -d 'Estas aplicaciones cumplen un rol de negocio pero no estan declaradas en el catalogo, por lo que carecen de propietario, criticidad y clasificacion de datos formalmente asignados.' \
        -e "$(safe_str "${lista_neg_sc# | }" 1500)" \
        -k 'INV-01|INV-02|INV-03' \
        -r 'Incorporar cada aplicacion al bloque Aplicaciones de config/arquitectura.json con propietario, proposito, criticidad y clasificacion de datos.'
fi

# ---------------------------------------------------------------------------
# 6. Artefactos sin clasificar (calidad de la linea base)
# ---------------------------------------------------------------------------
pct_sin_clasificar=$(pct "$sin_clasificar" "$total_artefactos")
metric PorcentajeSinClasificar "$pct_sin_clasificar" n

if num_gt "$pct_sin_clasificar" "$max_sin_clasificar"; then
    finding "$sev_sin_clasificar" 'Cobertura insuficiente de la taxonomia de roles arquitectonicos' \
        -c 'LineaBaseEA' -a "$sin_clasificar de $total_artefactos artefactos ($pct_sin_clasificar%)" \
        -d "El $pct_sin_clasificar% de los artefactos no pudo clasificarse en ningun rol de la taxonomia; el maximo tolerado es $max_sin_clasificar%. Una linea base con este nivel de indefinicion no permite afirmar que el servidor cumple su proposito arquitectonico." \
        -e "$(safe_str "${lista_sin_clas#; }" 1500)" \
        -k 'INV-01|ARQ-01|ARQ-02' \
        -r 'Ampliar la taxonomia Roles en config/arquitectura.json con patrones que cubran estos artefactos, o clasificarlos manualmente incorporandolos al catalogo de aplicaciones.'
fi

# ---------------------------------------------------------------------------
# 7. Gobierno: propietarios declarados
# ---------------------------------------------------------------------------
if [ "$exigir_propietario" = 'true' ]; then
    sin_dueno=$(arq_json '.Aplicaciones' |
        jq -r '.[] | select((.Propietario // "") == "" or .Propietario == "DEFINIR") | .Id' 2>/dev/null |
        tr '\n' ' ')
    if [ -n "$(safe_str "$sin_dueno")" ]; then
        finding "$sev_sin_propietario" 'Aplicaciones de negocio sin propietario asignado' \
            -c 'GobiernoDeActivos' -a "$(safe_str "$sin_dueno" 200)" \
            -d 'Sin propietario declarado no hay responsable de autorizar cambios, aprobar accesos, definir la clasificacion de la informacion ni asumir el riesgo residual del activo.' \
            -k 'INV-01|INV-02|INV-03|ACC-02' \
            -r 'Asignar propietario y responsable tecnico a cada aplicacion en config/arquitectura.json, y formalizarlo en el inventario de activos del SGSI.'
    fi
fi

if [ "$propietario_srv" = 'DEFINIR' ] || [ -z "$propietario_srv" ]; then
    finding Medium 'El servidor no tiene propietario declarado en la linea base' \
        -c 'GobiernoDeActivos' -a "$nombre_srv" \
        -d 'El bloque RolServidor de config/arquitectura.json mantiene el propietario sin definir. El activo no tiene responsable formal identificado.' \
        -k 'INV-01|INV-02' \
        -r 'Completar Propietario, ResponsableTecnico y UnidadNegocio en config/arquitectura.json.'
fi

# ---------------------------------------------------------------------------
# 8. Distribucion por capa de arquitectura (mapa de la linea base)
# ---------------------------------------------------------------------------
for capa in "${!CAPA_N[@]}"; do
    [ -n "$capa" ] || continue
    metric "Capa_$capa" "${CAPA_N[$capa]}" n
done
for rol in "${!ROL_N[@]}"; do
    [ -n "$rol" ] || continue
    clave=$(printf '%s' "$rol" | tr -c '[:alnum:]' '_')
    metric "Rol_$clave" "${ROL_N[$rol]}" n
done

n_detectadas=$(printf '%s' "$apps_detectadas" | wc -w)

metric TotalArtefactos "$total_artefactos" n
metric Alineados "$alineados" n
metric NoAlineados "$no_alineados" n
metric SinClasificar "$sin_clasificar" n
metric ConRutaVerificada "$con_ruta_verif" n
metric AplicacionesCatalogo "$n_catalogo" n
metric AplicacionesDetectadas "${n_detectadas:-0}" n
metric RolServidorDeclarado "$rol_declarado"
metric EntornoDeclarado "$entorno"

emit_result
