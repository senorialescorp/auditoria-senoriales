#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# audit.sh
# Orquestador de la suite de auditoria de sistemas y arquitectura empresarial.
# Equivalente Linux de Invoke-Audit.ps1.
#
# Ejecuta los colectores organizados por capas, consolida hallazgos, calcula el
# riesgo agregado ponderado, mapea la evidencia contra los criterios de
# auditoria y genera el expediente de salida con hashes de integridad.
#
# LA SUITE ES DE SOLO LECTURA: no modifica la configuracion del servidor. No
# instala paquetes, no refresca indices del gestor y no reinicia servicios.
#
# USO
#   ./audit.sh                       Ejecucion completa con todos los entregables
#   ./audit.sh --software-only       Solo la capa prioritaria L4
#   ./audit.sh --layer L2,L4         Limita a las capas indicadas
#   ./audit.sh --collector L4-01     Limita a colectores concretos
#   ./audit.sh --quick               Omite los colectores de mayor costo
#   ./audit.sh --no-report           Solo datos: sin HTML, XLSX ni DOCX
#   ./audit.sh --purge               Elimina ejecuciones anteriores al periodo
#   ./audit.sh --run-id LINEA-BASE   Fija el identificador de la corrida
#
# Se recomienda ejecutar con privilegios de root para obtener cobertura
# completa; sin elevacion la suite degrada y reporta las brechas de evidencia
# como parte de los entregables, en lugar de aparentar cobertura total.
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Argumentos
# ---------------------------------------------------------------------------
FILTRO_CAPA=''
FILTRO_COLECTOR=''
MODO_RAPIDO=0
SOLO_SOFTWARE=0
SIN_REPORTE=0
PURGAR=0
RUN_ID=''
OUTPUT_ROOT=''

uso() { sed -n '4,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [ "$#" -gt 0 ]; do
    case $1 in
        --layer|-l)       FILTRO_CAPA=$2; shift 2 ;;
        --collector|-c)   FILTRO_COLECTOR=$2; shift 2 ;;
        --quick|-q)       MODO_RAPIDO=1; shift ;;
        --software-only)  SOLO_SOFTWARE=1; shift ;;
        --no-report)      SIN_REPORTE=1; shift ;;
        --purge)          PURGAR=1; shift ;;
        --run-id)         RUN_ID=$2; shift 2 ;;
        --output)         OUTPUT_ROOT=$2; shift 2 ;;
        --help|-h)        uso ;;
        *) echo "Argumento no reconocido: $1" >&2; echo "Use --help para ver las opciones." >&2; exit 2 ;;
    esac
done

# ---------------------------------------------------------------------------
# Carga del nucleo y de la configuracion
# ---------------------------------------------------------------------------
CORE="$SCRIPT_DIR/lib/audit_core.sh"
[ -r "$CORE" ] || { echo "ERROR: no se encontro el nucleo en $CORE" >&2; exit 1; }
# shellcheck source=lib/audit_core.sh
. "$CORE"

export AUDIT_CONFIG="$SCRIPT_DIR/config/audit.config.json"
export AUDIT_CRITERIOS="$SCRIPT_DIR/config/criterios.auditoria.json"
export AUDIT_ARQUITECTURA="$SCRIPT_DIR/config/arquitectura.json"

[ -r "$AUDIT_CONFIG" ]    || { echo "ERROR: no se encontro la configuracion en $AUDIT_CONFIG" >&2; exit 1; }
[ -r "$AUDIT_CRITERIOS" ] || { echo "ERROR: no se encontro el catalogo de criterios en $AUDIT_CRITERIOS" >&2; exit 1; }
if [ ! -r "$AUDIT_ARQUITECTURA" ]; then
    echo "AVISO: no se encontro config/arquitectura.json. La clasificacion por rol arquitectonico quedara deshabilitada." >&2
    unset AUDIT_ARQUITECTURA
fi

for f in "$AUDIT_CONFIG" "$AUDIT_CRITERIOS" ${AUDIT_ARQUITECTURA:+"$AUDIT_ARQUITECTURA"}; do
    jq -e . "$f" >/dev/null 2>&1 || { echo "ERROR: $f no es JSON valido." >&2; exit 1; }
done

# ---------------------------------------------------------------------------
# Contexto
# ---------------------------------------------------------------------------
init_audit_context "$SCRIPT_DIR" "$OUTPUT_ROOT" "$RUN_ID"

TMP_RES="$(mktemp -d)"
trap 'rm -rf "$TMP_RES" 2>/dev/null' EXIT

# Extractos de configuracion volcados a archivos reales. jq --slurpfile recibe
# aqui rutas normales y no sustituciones de proceso: /dev/fd/N no es legible en
# todos los entornos (contenedores sin /proc montado, jq de otra plataforma), y
# una consolidacion que fallara en silencio vaciaria el expediente completo.
# Los resultados de los colectores viven en su propio subdirectorio: el glob
# de consolidacion no debe recoger los extractos de configuracion.
RES_DIR="$TMP_RES/res"
mkdir -p "$RES_DIR"

CFG_CAPAS="$TMP_RES/cfg_capas.json"
CFG_CAPAS_FULL="$TMP_RES/cfg_capas_full.json"
CFG_CRIT="$TMP_RES/cfg_criterios.json"
jq '[.Layers[] | {Id, Peso, Nombre, Descripcion, Orden}]' "$AUDIT_CONFIG"    > "$CFG_CAPAS"
jq '[.Layers[]]'                                          "$AUDIT_CONFIG"    > "$CFG_CAPAS_FULL"
jq '{Grupos, Criterios}'                                  "$AUDIT_CRITERIOS" > "$CFG_CRIT"

printf '\n%s===============================================================%s\n' "$C_CYAN" "$C_RESET"
printf '%s  AUDITORIA DE SISTEMAS Y ARQUITECTURA EMPRESARIAL%s\n' "$C_CYAN" "$C_RESET"
printf '%s  Mapeo por capas con prioridad en artefactos de software%s\n' "$C_CYAN" "$C_RESET"
printf '%s===============================================================%s\n' "$C_CYAN" "$C_RESET"
printf '  Servidor : %s\n' "$AUDIT_HOSTNAME"
printf '  Sistema  : %s\n' "$(os_release_field PRETTY_NAME)"
printf '  Ejecucion: %s\n' "$AUDIT_RUN_ID"
printf '  Usuario  : %s\n' "$AUDIT_RUNAS"
if is_root; then
    printf '  Elevado  : %sSi%s\n' "$C_GREEN" "$C_RESET"
else
    printf '  Elevado  : %sNO - cobertura parcial%s\n' "$C_YELLOW" "$C_RESET"
fi
printf '  Salida   : %s\n\n' "$AUDIT_RUN_PATH"

if ! is_root; then
    audit_log WARN ORQ 'Sesion sin privilegios de root. Varios criterios no podran evidenciarse por completo; las brechas quedaran registradas en el reporte.'
fi

# ---------------------------------------------------------------------------
# Descubrimiento de colectores
# ---------------------------------------------------------------------------
COLECTORES_DIR="$SCRIPT_DIR/collectors"
[ -d "$COLECTORES_DIR" ] || { echo "ERROR: no se encontraron colectores en $COLECTORES_DIR" >&2; exit 1; }

[ "$SOLO_SOFTWARE" -eq 1 ] && FILTRO_CAPA='L4'

# Colectores de mayor costo, omitidos en modo rapido
COSTOSOS='L4-03 L9-01'

PLAN="$TMP_RES/plan.tsv"
: > "$PLAN"

for archivo in "$COLECTORES_DIR"/*.sh; do
    [ -f "$archivo" ] || continue
    manifiesto=$("$archivo" --manifest 2>/dev/null)
    if [ -z "$manifiesto" ] || ! printf '%s' "$manifiesto" | jq -e . >/dev/null 2>&1; then
        audit_log ERROR ORQ "No se pudo leer el manifiesto de $(basename "$archivo")."
        continue
    fi

    id=$(printf '%s' "$manifiesto" | jq -r '.Id')
    capa=$(printf '%s' "$manifiesto" | jq -r '.Layer')
    nombre=$(printf '%s' "$manifiesto" | jq -r '.Nombre')
    requiere_root=$(printf '%s' "$manifiesto" | jq -r '.RequiereRoot')

    # Filtro por capa
    if [ -n "$FILTRO_CAPA" ]; then
        case ",$FILTRO_CAPA," in *",$capa,"*) ;; *) continue ;; esac
    fi
    # Filtro por colector
    if [ -n "$FILTRO_COLECTOR" ]; then
        case ",$FILTRO_COLECTOR," in *",$id,"*) ;; *) continue ;; esac
    fi
    # Modo rapido
    if [ "$MODO_RAPIDO" -eq 1 ]; then
        case " $COSTOSOS " in
            *" $id "*)
                audit_log INFO ORQ "Modo rapido: se omite $id ($nombre)."
                continue ;;
        esac
    fi

    printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$capa" "$nombre" "$requiere_root" "$archivo" >> "$PLAN"
done

sort -o "$PLAN" "$PLAN"
n_plan=$(grep -c . "$PLAN" 2>/dev/null)
if [ "${n_plan:-0}" -eq 0 ]; then
    echo "ERROR: ningun colector coincide con los filtros indicados." >&2
    exit 1
fi

printf '%sColectores a ejecutar: %s%s\n\n' "$C_WHITE" "$n_plan" "$C_RESET"

# ---------------------------------------------------------------------------
# Ejecucion
# ---------------------------------------------------------------------------
inicio_total=$(date +%s)

while IFS=$'\t' read -r id capa nombre requiere_root archivo; do
    [ -n "$id" ] || continue
    printf '%s-> [%s] %s%s\n' "$C_WHITE" "$id" "$nombre" "$C_RESET"

    if [ "$requiere_root" = 'true' ] && ! is_root; then
        audit_log WARN "$id" 'Requiere elevacion. Se omite.'
        jq -nc --arg id "$id" --arg capa "$capa" --arg nombre "$nombre" \
            '{Meta:{Id:$id,Layer:$capa,Nombre:$nombre,Criterios:[],Descripcion:""},
              Status:"SkippedNoRoot", Records:[], RecordCount:0, Findings:[], Metrics:{},
              Gaps:["Colector omitido: requiere privilegios de root."], DuracionSeg:0}' \
            > "$RES_DIR/$id.json"
        continue
    fi

    t0=$(date +%s)
    salida="$TMP_RES/$id.raw"
    errores="$TMP_RES/$id.err"

    if "$archivo" > "$salida" 2> "$errores"; then rc=0; else rc=$?; fi
    dur=$(( $(date +%s) - t0 ))

    if [ "$rc" -ne 0 ] || [ ! -s "$salida" ] || ! jq -e . "$salida" >/dev/null 2>&1; then
        msg=$(head -3 "$errores" 2>/dev/null | tr '\n' ' ')
        printf '   %sERROR: %s%s\n' "$C_RED" "${msg:-el colector no devolvio un resultado valido}" "$C_RESET"
        audit_log ERROR "$id" "Fallo (codigo $rc): ${msg:-sin salida valida}" quiet
        jq -nc --arg id "$id" --arg capa "$capa" --arg nombre "$nombre" \
               --arg err "${msg:-el colector no devolvio un resultado valido}" --argjson d "$dur" \
            '{Meta:{Id:$id,Layer:$capa,Nombre:$nombre,Criterios:[],Descripcion:""},
              Status:"Failed", Records:[], RecordCount:0, Findings:[], Metrics:{},
              Gaps:["Fallo en la ejecucion: " + $err], DuracionSeg:$d}' \
            > "$RES_DIR/$id.json"
        continue
    fi

    jq -c --argjson d "$dur" '. + {DuracionSeg:$d}' "$salida" > "$RES_DIR/$id.json"

    n_reg=$(jq -r '.RecordCount' "$RES_DIR/$id.json")
    n_hall=$(jq -r '.Findings | length' "$RES_DIR/$id.json")
    n_crit=$(jq -r '[.Findings[] | select(.Severity=="Critical" or .Severity=="High")] | length' "$RES_DIR/$id.json")

    color=$C_GREEN; [ "$n_crit" -gt 0 ] && color=$C_YELLOW
    printf '   %sOK  %s registros | %s hallazgos (%s altos/criticos) | %ss%s\n' \
        "$color" "$n_reg" "$n_hall" "$n_crit" "$dur" "$C_RESET"

    # Persistir los datos crudos del colector
    if [ "$n_reg" -gt 0 ]; then
        export_artifact "$id" "$(jq -c '.Records' "$RES_DIR/$id.json")" Both >/dev/null
    fi

    jq -r '.Gaps[]?' "$RES_DIR/$id.json" 2>/dev/null | while IFS= read -r g; do
        [ -n "$g" ] && audit_log WARN "$id" "Brecha de evidencia: $g" quiet
    done
    audit_log OK "$id" "Completado en ${dur}s con $n_reg registros y $n_hall hallazgos." quiet

    rm -f "$salida" "$errores" 2>/dev/null
done < "$PLAN"

duracion_total=$(( $(date +%s) - inicio_total ))

# ---------------------------------------------------------------------------
# Consolidacion
# ---------------------------------------------------------------------------
printf '\n%sConsolidando resultados...%s\n' "$C_WHITE" "$C_RESET"

TODOS="$TMP_RES/todos.json"
jq -s '.' "$RES_DIR"/*.json > "$TODOS" 2>/dev/null

# --- Hallazgos, ordenados por severidad, capa y colector ---
HALLAZGOS="$TMP_RES/hallazgos.json"
jq '[.[].Findings[]?] | sort_by(-.SeverityRank, .Layer, .CollectorId)' "$TODOS" > "$HALLAZGOS"

# --- Riesgo agregado ponderado por capa ---
RIESGO="$TMP_RES/riesgo.json"
jq -n \
    --slurpfile capas "$CFG_CAPAS" \
    --slurpfile hall "$HALLAZGOS" '
    ($capas[0]) as $L
    | ($hall[0]) as $H
    | ({"Critical":10,"High":6,"Medium":3,"Low":1,"Info":0}) as $pts
    | ([$L[] | {key:.Id, value:.Peso}] | from_entries) as $pesos
    | ($H | map({
          layer: .Layer,
          puntos: (($pts[.Severity] // 0) * ($pesos[.Layer] // 1.0))
      })) as $P
    | {
        total: ([$P[].puntos] | add // 0 | . * 10 | round / 10),
        porCapa: ($P | group_by(.layer)
                     | map({key: .[0].layer, value: ([.[].puntos] | add | . * 10 | round / 10)})
                     | from_entries)
      }' > "$RIESGO"

riesgo_total=$(jq -r '.total' "$RIESGO")
nivel_riesgo=$(awk -v r="$riesgo_total" 'BEGIN{
    if (r >= 200) print "CRITICO";
    else if (r >= 100) print "ALTO";
    else if (r >= 40) print "MEDIO";
    else if (r > 0) print "BAJO";
    else print "SIN HALLAZGOS" }')

# --- Cobertura de criterios de auditoria ---
COBERTURA="$TMP_RES/cobertura.json"
jq -n \
    --slurpfile crit "$CFG_CRIT" \
    --slurpfile todos "$TODOS" \
    --slurpfile hall "$HALLAZGOS" '
    ($crit[0]) as $C
    | ($todos[0]) as $T
    | ($hall[0]) as $H
    | ([$T[] | select(.Status == "Completed") | .Meta.Id]) as $ejecutados
    | ([$C.Grupos[] | {key:.Id, value:(.Id + " - " + .Nombre)}] | from_entries) as $dominios
    | [ $C.Criterios[] |
        . as $c
        | ([$c.Colectores[] | select(. as $x | $ejecutados | index($x))]) as $ej
        | ([$H[] | select(.Criterios | index($c.Id))]) as $hc
        | {
            Criterio: $c.Id,
            Dominio: ($dominios[$c.Grupo] // $c.Grupo),
            Titulo: $c.Titulo,
            Objetivo: $c.Objetivo,
            Capas: ($c.Capas | join(", ")),
            Colectores: ($c.Colectores | join(", ")),
            ColectoresEjecutados: ($ej | join(", ")),
            NivelCobertura: $c.Cobertura,
            Estado: (if ($ej | length) == 0 then "Sin evidencia"
                     elif ($ej | length) < ($c.Colectores | length) then "Evidencia parcial"
                     else "Evidenciado" end),
            Conformidad: (if ($ej | length) == 0 then "No evaluado"
                          elif ([$hc[] | select(.Severity=="Critical" or .Severity=="High")] | length) > 0 then "No conforme"
                          elif ([$hc[] | select(.Severity=="Medium" or .Severity=="Low")] | length) > 0 then "Conforme con observaciones"
                          else "Conforme" end),
            TotalHallazgos: ($hc | length),
            Criticos: ([$hc[] | select(.Severity=="Critical")] | length),
            Altos: ([$hc[] | select(.Severity=="High")] | length)
          } ]' > "$COBERTURA"

# --- Brechas de evidencia ---
BRECHAS="$TMP_RES/brechas.json"
jq '[.[] | . as $r | (.Gaps // [])[] | {Colector: $r.Meta.Id, Capa: $r.Meta.Layer, Brecha: .}]' \
    "$TODOS" > "$BRECHAS"

# --- Resumen por capa ---
CAPAS="$TMP_RES/capas.json"
jq -n \
    --slurpfile cfgl "$CFG_CAPAS_FULL" \
    --slurpfile todos "$TODOS" \
    --slurpfile hall "$HALLAZGOS" \
    --slurpfile riesgo "$RIESGO" '
    ($cfgl[0]) as $L | ($todos[0]) as $T | ($hall[0]) as $H | ($riesgo[0].porCapa) as $R
    | [ $L | sort_by(.Orden)[] |
        . as $l
        | ([$T[] | select(.Meta.Layer == $l.Id)]) as $rs
        | ([$H[] | select(.Layer == $l.Id)]) as $hs
        | {
            Capa: $l.Id, Nombre: $l.Nombre, Descripcion: $l.Descripcion,
            Peso: $l.Peso, Orden: $l.Orden,
            Colectores: ($rs | length),
            ColectoresOK: ([$rs[] | select(.Status=="Completed")] | length),
            Registros: ([$rs[].RecordCount] | add // 0),
            Hallazgos: ($hs | length),
            Criticos: ([$hs[] | select(.Severity=="Critical")] | length),
            Altos:    ([$hs[] | select(.Severity=="High")] | length),
            Medios:   ([$hs[] | select(.Severity=="Medium")] | length),
            Bajos:    ([$hs[] | select(.Severity=="Low")] | length),
            PuntajeRiesgo: ($R[$l.Id] // 0)
          } ]' > "$CAPAS"

# --- Metricas consolidadas ---
METRICAS="$TMP_RES/metricas.json"
jq '[.[] | . as $r | (.Metrics // {}) | to_entries[] |
     {key: ($r.Meta.Id + "." + .key), value: .value}] | from_entries' "$TODOS" > "$METRICAS"

# --- Resumen general ---
RESUMEN="$TMP_RES/resumen.json"
jq -n \
    --slurpfile todos "$TODOS" --slurpfile hall "$HALLAZGOS" \
    --slurpfile cob "$COBERTURA" --slurpfile bre "$BRECHAS" \
    --slurpfile met "$METRICAS" \
    --arg runid "$AUDIT_RUN_ID" --arg servidor "$AUDIT_HOSTNAME" \
    --arg dominio "$AUDIT_DOMAIN" --arg usuario "$AUDIT_RUNAS" \
    --argjson elevado "$(if is_root; then printf true; else printf false; fi)" \
    --arg inicio "$AUDIT_START_TIME" --arg fin "$(date +%Y-%m-%dT%H:%M:%S)" \
    --argjson dur "$duracion_total" \
    --arg marco "$(cfg '.Scope.Marco')" --arg org "$(cfg '.Scope.Organizacion')" \
    --argjson riesgo "$riesgo_total" --arg nivel "$nivel_riesgo" \
    --arg so "$(os_release_field PRETTY_NAME)" --arg kernel "$(uname -r)" '
    ($todos[0]) as $T | ($hall[0]) as $H | ($cob[0]) as $C | ($bre[0]) as $B
    | {
        RunId: $runid, Servidor: $servidor, Dominio: $dominio,
        SistemaOperativo: $so, Kernel: $kernel,
        EjecutadoPor: $usuario, Elevado: $elevado,
        Inicio: $inicio, Fin: $fin, DuracionSegundos: $dur,
        Marco: $marco, Organizacion: $org,
        ColectoresTotal: ($T | length),
        ColectoresOK: ([$T[] | select(.Status=="Completed")] | length),
        ColectoresFallidos: ([$T[] | select(.Status=="Failed")] | length),
        ColectoresOmitidos: ([$T[] | select(.Status | startswith("Skipped"))] | length),
        RegistrosTotal: ([$T[].RecordCount] | add // 0),
        HallazgosTotal: ($H | length),
        Criticos:     ([$H[] | select(.Severity=="Critical")] | length),
        Altos:        ([$H[] | select(.Severity=="High")] | length),
        Medios:       ([$H[] | select(.Severity=="Medium")] | length),
        Bajos:        ([$H[] | select(.Severity=="Low")] | length),
        Informativos: ([$H[] | select(.Severity=="Info")] | length),
        PuntajeRiesgo: $riesgo, NivelRiesgo: $nivel,
        CriteriosEvaluados: ([$C[] | select(.Estado != "Sin evidencia")] | length),
        CriteriosTotal: ($C | length),
        CriteriosNoConformes: ([$C[] | select(.Conformidad == "No conforme")] | length),
        BrechasEvidencia: ($B | length),
        Metricas: $met[0]
      }' > "$RESUMEN"

# ---------------------------------------------------------------------------
# Exportacion de los entregables de datos
# ---------------------------------------------------------------------------
export_artifact 'HALLAZGOS'           "$(cat "$HALLAZGOS")"  Both >/dev/null
export_artifact 'COBERTURA-CRITERIOS' "$(cat "$COBERTURA")"  Both >/dev/null
export_artifact 'RESUMEN-CAPAS'       "$(cat "$CAPAS")"      Both >/dev/null
export_artifact 'BRECHAS-EVIDENCIA'   "$(cat "$BRECHAS")"    Both >/dev/null
export_artifact 'RESUMEN'             "[$(cat "$RESUMEN")]"  Both >/dev/null

# Inventario de software consolidado (entregable clave de la capa L4)
if [ -f "$RES_DIR/L4-01.json" ]; then
    inv=$(jq -c '.Records' "$RES_DIR/L4-01.json")
    [ "$inv" != '[]' ] && export_artifact 'INVENTARIO-SOFTWARE' "$inv" Both >/dev/null
fi

# Linea base de arquitectura empresarial (entregable del mapeo EA)
if [ -f "$RES_DIR/L4-06.json" ]; then
    ea=$(jq -c '.Records' "$RES_DIR/L4-06.json")
    [ "$ea" != '[]' ] && export_artifact 'LINEA-BASE-ARQUITECTURA' "$ea" Both >/dev/null
fi

# Glosario de los criterios efectivamente citados
GLOSARIO="$TMP_RES/glosario.json"
jq -n \
    --slurpfile crit "$CFG_CRIT" \
    --slurpfile hall "$HALLAZGOS" --slurpfile todos "$TODOS" '
    ($crit[0]) as $C | ($hall[0]) as $H | ($todos[0]) as $T
    | ( [$H[].Criterios[]?] + [$T[].Meta.Criterios[]?] | unique ) as $citados
    | ([$C.Grupos[] | {key:.Id, value:(.Id + " - " + .Nombre)}] | from_entries) as $dom
    | [ $C.Criterios[] | select(.Id as $i | $citados | index($i)) |
        { Criterio: .Id, Dominio: ($dom[.Grupo] // .Grupo), Titulo: .Titulo,
          Descripcion: .Descripcion, Objetivo: .Objetivo, Cobertura: .Cobertura,
          Capas: (.Capas | join(", ")), Colectores: (.Colectores | join(", ")) } ]' \
    > "$GLOSARIO"
[ "$(jq 'length' "$GLOSARIO")" -gt 0 ] && export_artifact 'GLOSARIO-CRITERIOS' "$(cat "$GLOSARIO")" Both >/dev/null

# Trazabilidad de la ejecucion
TRAZA="$TMP_RES/traza.json"
jq '[.[] | {Colector: .Meta.Id, Capa: .Meta.Layer, Nombre: .Meta.Nombre,
            Descripcion: .Meta.Descripcion,
            Criterios: ((.Meta.Criterios // []) | join("; ")),
            Estado: .Status, Registros: .RecordCount,
            Hallazgos: (.Findings | length), DuracionSeg: (.DuracionSeg // 0)}]
    | sort_by(.Colector)' "$TODOS" > "$TRAZA"
export_artifact 'TRAZABILIDAD' "$(cat "$TRAZA")" Both >/dev/null

# ---------------------------------------------------------------------------
# Entregables: ficha HTML, libro Excel y ficha Word
# ---------------------------------------------------------------------------
RUTA_HTML=''; RUTA_XLSX=''; RUTA_DOCX=''

if [ "$SIN_REPORTE" -eq 0 ]; then
    export AUDIT_RESUMEN="$RESUMEN"      AUDIT_HALLAZGOS="$HALLAZGOS"
    export AUDIT_CAPAS="$CAPAS"          AUDIT_COBERTURA="$COBERTURA"
    export AUDIT_BRECHAS="$BRECHAS"      AUDIT_GLOSARIO="$GLOSARIO"
    export AUDIT_TRAZA="$TRAZA"          AUDIT_TODOS="$TODOS"

    # 1. Libro de Excel con el detalle completo
    if [ -x "$SCRIPT_DIR/reports/new_audit_excel.sh" ]; then
        if RUTA_XLSX=$("$SCRIPT_DIR/reports/new_audit_excel.sh" 2>"$TMP_RES/xlsx.err"); then
            register_artifact "$RUTA_XLSX"
            printf '%sLibro de Excel  : %s%s\n' "$C_GREEN" "$RUTA_XLSX" "$C_RESET"
        else
            printf '%sNo se pudo generar el libro de Excel: %s%s\n' "$C_RED" "$(head -2 "$TMP_RES/xlsx.err" | tr '\n' ' ')" "$C_RESET"
            audit_log ERROR EXCEL "$(head -3 "$TMP_RES/xlsx.err" | tr '\n' ' ')" quiet
            RUTA_XLSX=''
        fi
    fi

    # 2. Ficha imprimible en HTML
    if [ -x "$SCRIPT_DIR/reports/new_audit_ficha.sh" ]; then
        export AUDIT_ARCHIVO_EXCEL="$RUTA_XLSX"
        if RUTA_HTML=$("$SCRIPT_DIR/reports/new_audit_ficha.sh" 2>"$TMP_RES/html.err"); then
            register_artifact "$RUTA_HTML"
            printf '%sFicha imprimible: %s%s\n' "$C_GREEN" "$RUTA_HTML" "$C_RESET"
        else
            printf '%sNo se pudo generar la ficha: %s%s\n' "$C_RED" "$(head -2 "$TMP_RES/html.err" | tr '\n' ' ')" "$C_RESET"
            audit_log ERROR FICHA "$(head -3 "$TMP_RES/html.err" | tr '\n' ' ')" quiet
            RUTA_HTML=''
        fi
    fi

    # 3. Ficha en Word, para entregarse como reporte formal.
    #    Se alimenta del expediente ya escrito en raw/, no de los objetos vivos,
    #    por lo que debe ejecutarse despues de que el resto este en disco.
    if [ -x "$SCRIPT_DIR/reports/new_audit_ficha_docx.sh" ]; then
        if RUTA_DOCX=$("$SCRIPT_DIR/reports/new_audit_ficha_docx.sh" 2>"$TMP_RES/docx.err"); then
            register_artifact "$RUTA_DOCX"
            printf '%sFicha Word      : %s%s\n' "$C_GREEN" "$RUTA_DOCX" "$C_RESET"
        else
            printf '%sNo se pudo generar la ficha Word: %s%s\n' "$C_RED" "$(head -2 "$TMP_RES/docx.err" | tr '\n' ' ')" "$C_RESET"
            audit_log ERROR FICHADOCX "$(head -3 "$TMP_RES/docx.err" | tr '\n' ' ')" quiet
            RUTA_DOCX=''
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Manifiesto de integridad de la evidencia (cadena de custodia)
# ---------------------------------------------------------------------------
jq -s '.' "$AUDIT_ARTIFACTS_FILE" > "$TMP_RES/artefactos.json" 2>/dev/null \
    || printf '[]' > "$TMP_RES/artefactos.json"

jq -n \
    --arg runid "$AUDIT_RUN_ID" --arg servidor "$AUDIT_HOSTNAME" \
    --arg generado "$(date +%Y-%m-%dT%H:%M:%S)" --arg por "$AUDIT_RUNAS" \
    --arg marco "$(cfg '.Scope.Marco')" \
    --slurpfile art "$TMP_RES/artefactos.json" '
    { RunId: $runid, Servidor: $servidor, GeneradoEl: $generado,
      GeneradoPor: $por, Marco: $marco, Artefactos: ($art[0] // []) }' \
    > "$AUDIT_RUN_PATH/MANIFIESTO-INTEGRIDAD.json"

# ---------------------------------------------------------------------------
# Purga de ejecuciones antiguas
# ---------------------------------------------------------------------------
if [ "$PURGAR" -eq 1 ]; then
    retencion=$(cfg '.Report.RetencionDias' '180')
    raiz_salida=$(dirname "$AUDIT_RUN_PATH")
    eliminadas=0
    for d in "$raiz_salida"/*; do
        [ -d "$d" ] || continue
        [ "$d" = "$AUDIT_RUN_PATH" ] && continue
        if [ -n "$(find "$d" -maxdepth 0 -mtime "+$retencion" 2>/dev/null)" ]; then
            rm -rf "$d" && eliminadas=$((eliminadas + 1))
        fi
    done
    printf '%sPurga: %s ejecuciones anteriores a %s dias eliminadas.%s\n' \
        "$C_DIM" "$eliminadas" "$retencion" "$C_RESET"
fi

# ---------------------------------------------------------------------------
# Resumen en consola
# ---------------------------------------------------------------------------
case $nivel_riesgo in
    CRITICO|ALTO) color_riesgo=$C_RED ;;
    MEDIO)        color_riesgo=$C_YELLOW ;;
    *)            color_riesgo=$C_GREEN ;;
esac

r() { jq -r ".$1" "$RESUMEN"; }

printf '\n%s===============================================================%s\n' "$C_CYAN" "$C_RESET"
printf '%s  RESUMEN DE LA AUDITORIA%s\n' "$C_CYAN" "$C_RESET"
printf '%s===============================================================%s\n' "$C_CYAN" "$C_RESET"
printf '  Duracion          : %s s\n' "$duracion_total"
printf '  Colectores        : %s ejecutados / %s fallidos / %s omitidos\n' \
    "$(r ColectoresOK)" "$(r ColectoresFallidos)" "$(r ColectoresOmitidos)"
printf '  Registros         : %s\n\n' "$(r RegistrosTotal)"
printf '  Hallazgos totales : %s\n' "$(r HallazgosTotal)"

pinta() {
    local etiqueta=$1 valor=$2 color=$3
    [ "$valor" -eq 0 ] 2>/dev/null && color=$C_DIM
    printf '    %-16s: %s%s%s\n' "$etiqueta" "$color" "$valor" "$C_RESET"
}
pinta 'Criticos'     "$(r Criticos)"     "$C_RED"
pinta 'Altos'        "$(r Altos)"        "$C_RED"
pinta 'Medios'       "$(r Medios)"       "$C_YELLOW"
pinta 'Bajos'        "$(r Bajos)"        "$C_GRAY"
pinta 'Informativos' "$(r Informativos)" "$C_DIM"

printf '\n  Puntaje de riesgo : %s%s  [%s]%s\n' "$color_riesgo" "$riesgo_total" "$nivel_riesgo" "$C_RESET"
printf '  Criterios         : %s/%s evidenciados, %s no conformes\n' \
    "$(r CriteriosEvaluados)" "$(r CriteriosTotal)" "$(r CriteriosNoConformes)"
brechas_n=$(r BrechasEvidencia)
if [ "$brechas_n" -gt 0 ]; then
    printf '  Brechas evidencia : %s%s%s\n' "$C_YELLOW" "$brechas_n" "$C_RESET"
else
    printf '  Brechas evidencia : %s\n' "$brechas_n"
fi

printf '\n%s  Riesgo por capa:%s\n' "$C_WHITE" "$C_RESET"
jq -r '.[] | select(.Colectores > 0) |
    [.Capa, .Nombre, (.PuntajeRiesgo|tostring), (.Hallazgos|tostring),
     (.Criticos|tostring), (.Altos|tostring)] | @tsv' "$CAPAS" |
tr -d '\r' | sort -t$'\t' -k3,3 -rn |
while IFS=$'\t' read -r capa nombre puntaje hall crit alto; do
    marca=''; color=$C_GRAY
    if [ "$capa" = 'L4' ]; then marca=' <- PRIORITARIA'; color=$C_CYAN
    elif [ "${crit:-0}" -gt 0 ]; then color=$C_RED
    elif [ "${alto:-0}" -gt 0 ]; then color=$C_YELLOW
    fi
    printf '    %s%s  %-42.42s riesgo %6s  (%s hallazgos)%s%s\n' \
        "$color" "$capa" "$nombre" "$puntaje" "$hall" "$marca" "$C_RESET"
done

printf '\n%s  Evidencia: %s%s\n' "$C_GREEN" "$AUDIT_RUN_PATH" "$C_RESET"
printf '%s  Registro : %s%s\n' "$C_DIM" "$AUDIT_LOG_FILE" "$C_RESET"
printf '%s===============================================================%s\n\n' "$C_CYAN" "$C_RESET"

audit_log OK ORQ "Auditoria finalizada. Riesgo=$riesgo_total ($nivel_riesgo). Hallazgos=$(r HallazgosTotal)." quiet

# Codigo de salida para integracion con monitoreo:
#   0 sin hallazgos altos ni criticos | 1 hay altos | 2 hay criticos
if [ "$(r Criticos)" -gt 0 ]; then exit 2
elif [ "$(r Altos)" -gt 0 ]; then exit 1
else exit 0
fi
