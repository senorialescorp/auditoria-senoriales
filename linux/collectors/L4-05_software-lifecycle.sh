#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# L4-05_software-lifecycle.sh
# Capa L4 - ARTEFACTOS DE SOFTWARE.
#
# Evaluacion del ciclo de vida del software instalado: fin de soporte (EOL),
# versiones duplicadas o divergentes y concentracion de proveedores. Cierra el
# circuito entre el inventario (INV-01) y la gestion de vulnerabilidades
# tecnicas (VUL-01).
#
# Criterios de auditoria -> SW-02, VUL-01, INV-01, SW-03, SW-04
#
# ADICION respecto de la version Windows: se evalua tambien el fin de soporte de
# la PROPIA DISTRIBUCION, que en Linux es el determinante principal de si el
# activo sigue recibiendo parches de seguridad.
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/audit_core.sh"

collector_init 'L4-05' 'Ciclo de vida y soporte del software instalado' 'L4' \
    'SW-02|VUL-01|INV-01|SW-03|SW-04' false \
    'Deteccion de software fuera de soporte, version de la distribucion, paquetes huerfanos y analisis de dependencia de proveedores.'
maybe_emit_manifest "${1:-}"

TMP_RAW=$(mktemp)
TMP_TSV=$(mktemp)
TMP_EOL=$(mktemp)
trap 'rm -f "$TMP_RAW" "$TMP_TSV" "$TMP_EOL" 2>/dev/null' EXIT

installed_software_raw > "$TMP_RAW" 2>/dev/null
if [ ! -s "$TMP_RAW" ]; then
    gap 'No se pudo obtener el inventario base del gestor de paquetes.'
    collector_status 'NoData'
    emit_result
    exit 0
fi

jq -r '[.DisplayName, (.DisplayVersion // ""), (.Publisher // ""), (.InstallDate // "")] | @tsv' \
    < "$TMP_RAW" > "$TMP_TSV" 2>/dev/null

total_paquetes=$(grep -c . "$TMP_TSV")
hoy_epoch=$(date +%s)

# Catalogo EOL a TSV: patron | fecha | severidad | nota
cfg_json '.EndOfLife' | jq -r '.[] | [.Patron, .EOL, .Severidad, .Nota] | @tsv' \
    > "$TMP_EOL" 2>/dev/null

# ---------------------------------------------------------------------------
# 1. Fin de soporte de la propia distribucion
# ---------------------------------------------------------------------------
so_nombre=$(os_release_field PRETTY_NAME)
so_id=$(os_release_field ID)
so_ver=$(os_release_field VERSION_ID)
etiqueta_so="$so_id $so_ver $so_nombre"

so_eol=''
so_sev=''
so_nota=''
while IFS=$'\t' read -r patron fecha sev nota; do
    [ -n "$patron" ] || continue
    printf '%s' "$etiqueta_so" | grep -qiE "$patron" 2>/dev/null || continue
    so_eol=$fecha; so_sev=$sev; so_nota=$nota
    break
done < "$TMP_EOL"

estado_so='Soportado / no catalogado'
if [ -n "$so_eol" ]; then
    eol_epoch=$(date -d "$so_eol" +%s 2>/dev/null)
    if [ -n "$eol_epoch" ] && [ "$eol_epoch" -lt "$hoy_epoch" ]; then
        estado_so='FUERA DE SOPORTE'
        dias=$(( (hoy_epoch - eol_epoch) / 86400 ))
        finding "${so_sev:-Critical}" "Distribucion fuera de soporte: $so_nombre" \
            -c 'CicloDeVida' -a "$so_nombre" \
            -d "$so_nota Fin de soporte: $so_eol (hace $dias dias). Una distribucion sin soporte deja de recibir parches de seguridad para el kernel y para todo el software del repositorio base: es la deficiencia de ciclo de vida de mayor alcance posible, porque afecta a todos los componentes del activo a la vez." \
            -e "PRETTY_NAME=$so_nombre | ID=$so_id | VERSION_ID=$so_ver" \
            -k 'SW-02|VUL-01|INV-04' \
            -r 'Planificar la migracion a una version soportada como prioridad. Si la migracion no es viable a corto plazo, contratar el soporte extendido del proveedor (ELS/ESM/LTSS) y documentar la aceptacion del riesgo con controles compensatorios y fecha limite.'
    else
        estado_so='Soportado'
    fi
fi

rec Nombre "[DISTRIBUCION] $so_nombre" Version "$so_ver" Publicador "$so_id" \
    Estado "$estado_so" FechaFinSoporte "$so_eol" DiasDesdeEOL:n 0 \
    Severidad "$so_sev" Nota "$(safe_str "$so_nota" 400)" FechaInstalacion ''

metric DistribucionEstado "$estado_so"
metric Distribucion "$so_nombre"

# ---------------------------------------------------------------------------
# 2. Evaluacion de cada paquete contra el catalogo EOL
# ---------------------------------------------------------------------------
fuera_soporte=0
proximo_vencer=0

while IFS=$'\t' read -r nombre version publicador fecha_inst; do
    [ -n "$nombre" ] || continue
    etiqueta="$nombre $version"

    estado='Soportado / no catalogado'
    fecha_eol=''; nota=''; sev=''; dias_eol=0

    while IFS=$'\t' read -r patron f s n; do
        [ -n "$patron" ] || continue
        printf '%s' "$etiqueta" | grep -qiE "$patron" 2>/dev/null || continue
        fecha_eol=$f; sev=$s; nota=$n
        eol_epoch=$(date -d "$f" +%s 2>/dev/null)
        if [ -n "$eol_epoch" ]; then
            if [ "$eol_epoch" -lt "$hoy_epoch" ]; then
                estado='FUERA DE SOPORTE'
                dias_eol=$(( (hoy_epoch - eol_epoch) / 86400 ))
            elif [ $(( (eol_epoch - hoy_epoch) / 86400 )) -lt 180 ]; then
                estado='Soporte proximo a vencer'
            else
                estado='Soportado'
            fi
        fi
        break
    done < "$TMP_EOL"

    # Solo se registran los paquetes con algo que decir: volcar los 2000
    # paquetes soportados duplicaria el inventario de L4-01 sin aportar.
    case $estado in
        'Soportado / no catalogado') continue ;;
    esac

    rec Nombre "$nombre" Version "$version" Publicador "$(safe_str "$publicador" 128)" \
        Estado "$estado" FechaFinSoporte "$fecha_eol" DiasDesdeEOL:n "$dias_eol" \
        Severidad "$sev" Nota "$(safe_str "$nota" 400)" FechaInstalacion "$fecha_inst"

    if [ "$estado" = 'FUERA DE SOPORTE' ]; then
        fuera_soporte=$((fuera_soporte + 1))
        finding "${sev:-High}" "Software fuera de soporte del proveedor: $nombre" \
            -c 'CicloDeVida' -a "$nombre $version" \
            -d "Fin de soporte: $fecha_eol (hace $dias_eol dias). $nota Un producto sin soporte no recibe correcciones para las vulnerabilidades descubiertas despues de esa fecha." \
            -e "Publicador: $publicador | Instalado: $fecha_inst" \
            -k 'SW-02|VUL-01|INV-01|SW-03' \
            -r 'Actualizar a una version soportada. Si la migracion no es viable a corto plazo, documentar la aceptacion del riesgo con aprobacion de la direccion, definir controles compensatorios (aislamiento de red, control de aplicaciones) y fijar una fecha limite de remediacion.'
    elif [ "$estado" = 'Soporte proximo a vencer' ]; then
        proximo_vencer=$((proximo_vencer + 1))
        finding Low "Fin de soporte proximo: $nombre" \
            -c 'CicloDeVida' -a "$nombre $version" \
            -d "El soporte finaliza el $fecha_eol (en menos de 180 dias). $nota" \
            -k 'SW-02|VUL-01|INV-01' \
            -r 'Incluir la migracion en el plan anual de mantenimiento antes de la fecha de fin de soporte.'
    fi
done < "$TMP_TSV"

# ---------------------------------------------------------------------------
# 3. Versiones multiples del mismo producto
# ---------------------------------------------------------------------------
#
# En Linux la coexistencia de versiones se manifiesta como paquetes con el mismo
# nombre base y sufijo de version distinto (python3.9 / python3.11, php7.4 /
# php8.2, openjdk-11 / openjdk-17). Se agrupan quitando el sufijo numerico.
duplicados=$(awk -F'\t' '{
    base = $1
    gsub(/[-.]?[0-9]+([.][0-9]+)*$/, "", base)
    if (base == "" || length(base) < 3) next
    if (!(base in vistos)) { vistos[base] = $1; n[base] = 1 }
    else if (vistos[base] != $1) { vistos[base] = vistos[base] ", " $1; n[base]++ }
}
END { for (b in n) if (n[b] > 1) print b "\t" n[b] "\t" vistos[b] }' "$TMP_TSV" | sort)

n_duplicados=0
lista_dup=''
while IFS=$'\t' read -r base cuantos versiones; do
    [ -n "$base" ] || continue
    n_duplicados=$((n_duplicados + 1))
    [ "$n_duplicados" -le 12 ] && lista_dup="$lista_dup | $base: $versiones"
    rec Nombre "$base" Version "$(safe_str "$versiones" 300)" Publicador '' \
        Estado 'Versiones multiples' FechaFinSoporte '' DiasDesdeEOL:n 0 \
        Severidad 'Low' Nota "Coexisten $cuantos variantes" FechaInstalacion ''
done <<< "$duplicados"

if [ "$n_duplicados" -gt 0 ]; then
    finding Low 'Coexistencia de multiples versiones del mismo producto' \
        -c 'CicloDeVida' -a "$n_duplicados productos" \
        -d 'La convivencia de varias versiones dificulta la gestion de parches: una version antigua puede permanecer vulnerable aunque la nueva ya este corregida, y las aplicaciones pueden estar enlazadas contra la version obsoleta sin que se advierta.' \
        -e "$(safe_str "${lista_dup# | }" 1500)" \
        -k 'SW-02|VUL-01|INV-01' \
        -r 'Desinstalar las versiones obsoletas tras confirmar con ldd o con el gestor de alternativas que ninguna aplicacion depende de ellas.'
fi

# ---------------------------------------------------------------------------
# 4. Paquetes huerfanos: instalados pero ya sin repositorio que los mantenga
# ---------------------------------------------------------------------------
#
# Es una condicion propia de Linux sin equivalente en el original: un paquete
# cuyo repositorio de origen desaparecio deja de recibir parches aunque el
# sistema siga soportado.
huerfanos=0
case $(detect_pkg_family) in
    deb)
        if has_cmd apt-mark; then
            # Paquetes sin candidato de instalacion en ningun repositorio activo
            huerfanos=$(apt list --installed 2>/dev/null | grep -c '\[installed,local\]' 2>/dev/null)
        fi ;;
    rpm)
        if has_cmd dnf; then
            native_capture 120 dnf -q --cacheonly list extras
            huerfanos=$(printf '%s\n' "$NC_OUT" | awk 'NF==3 && $1 !~ /^(Extra|Last)/' | grep -c . 2>/dev/null)
        fi ;;
esac

if [ "${huerfanos:-0}" -gt 0 ]; then
    rec Nombre '[HUERFANOS]' Version '' Publicador '' \
        Estado 'Sin repositorio de origen' FechaFinSoporte '' DiasDesdeEOL:n 0 \
        Severidad 'Medium' Nota "$huerfanos paquetes instalados sin repositorio que los provea" FechaInstalacion ''

    finding Medium 'Paquetes instalados sin repositorio de origen activo' \
        -c 'CicloDeVida' -a "$huerfanos paquetes" \
        -d "$huerfanos paquetes estan instalados pero ningun repositorio configurado los ofrece actualmente. Fueron instalados manualmente desde un archivo, o su repositorio de origen fue retirado. En cualquiera de los dos casos dejaron de recibir actualizaciones de seguridad, aunque el resto del sistema siga parcheandose con normalidad." \
        -k 'SW-02|SW-04|VUL-01' \
        -r 'Revisar cada paquete: reinstalarlo desde un repositorio vigente, actualizarlo manualmente desde el proveedor, o retirarlo si ya no cumple una funcion. Incorporarlos al seguimiento manual de vulnerabilidades mientras permanezcan.'
fi

# ---------------------------------------------------------------------------
# 5. Concentracion de proveedores (insumo para SW-04)
# ---------------------------------------------------------------------------
proveedores=$(awk -F'\t' '$3 != "" { print $3 }' "$TMP_TSV" | sort | uniq -c | sort -rn | head -25)
n_proveedores=$(awk -F'\t' '$3 != "" { print $3 }' "$TMP_TSV" | sort -u | grep -c . 2>/dev/null)

while read -r cuenta nombre_prov; do
    [ -n "$nombre_prov" ] || continue
    rec Nombre "[PROVEEDOR] $(safe_str "$nombre_prov" 200)" Version '' \
        Publicador "$(safe_str "$nombre_prov" 200)" Estado 'Resumen de proveedor' \
        FechaFinSoporte '' DiasDesdeEOL:n 0 Severidad '' \
        Nota "$cuenta paquetes instalados" FechaInstalacion ''
done <<< "$proveedores"

# ---------------------------------------------------------------------------
# Metricas
# ---------------------------------------------------------------------------
metric ProductosEvaluados "$total_paquetes" n
metric FueraDeSoporte "$fuera_soporte" n
metric ProximosAVencer "$proximo_vencer" n
metric ProductosDuplicados "$n_duplicados" n
metric ProveedoresDistintos "${n_proveedores:-0}" n
metric PaquetesHuerfanos "${huerfanos:-0}" n
metric PorcentajeFueraSoporte "$(pct "$fuera_soporte" "$total_paquetes")" n

emit_result
