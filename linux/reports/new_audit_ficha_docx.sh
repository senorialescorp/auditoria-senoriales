#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# new_audit_ficha_docx.sh
# Genera la ficha de auditoria del servidor en formato .docx (equivalente de
# Reports/New-AuditFichaDocx.ps1).
#
# Equivalente en Word de new_audit_ficha.sh. Produce un documento A4 de dos a
# tres paginas, apto para entregarse como reporte formal, imprimirse o firmarse.
#
# A diferencia de new_audit_ficha.sh --que recibe los datos vivos de la corrida--
# este script se alimenta del expediente ya escrito en disco (Output/<RunId>/raw).
# Eso permite emitir la ficha de cualquier corrida pasada sin volver a auditar
# el servidor.
#
# No requiere Word ni LibreOffice: el .docx se construye como paquete OOXML
# mediante lib/docx_writer.sh.
#
# USO
#   ./new_audit_ficha_docx.sh                 Ultima corrida con expediente
#   ./new_audit_ficha_docx.sh <RunId>         Corrida concreta
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/audit_core.sh"
. "$SCRIPT_DIR/../lib/docx_writer.sh"

RAIZ="$(cd "$SCRIPT_DIR/.." && pwd)"
export AUDIT_ARQUITECTURA="${AUDIT_ARQUITECTURA:-$RAIZ/config/arquitectura.json}"

if ! zip_available; then
    echo "No hay forma de crear el contenedor ZIP del .docx: se requiere 'zip' o 'python3'." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Localizacion del expediente
# ---------------------------------------------------------------------------
RUN_ID=${1:-${AUDIT_RUN_ID:-}}
OUT_ROOT="$RAIZ/Output"

if [ -n "${AUDIT_RUN_PATH:-}" ] && [ -d "$AUDIT_RUN_PATH/raw" ]; then
    RUN_PATH=$AUDIT_RUN_PATH
    RUN_ID=$(basename "$RUN_PATH")
else
    [ -d "$OUT_ROOT" ] || { echo "No existe la carpeta de salida: $OUT_ROOT" >&2; exit 1; }
    if [ -z "$RUN_ID" ]; then
        RUN_ID=$(for d in "$OUT_ROOT"/*; do
                     [ -f "$d/raw/RESUMEN.json" ] && printf '%s\t%s\n' "$(stat -c %Y "$d" 2>/dev/null)" "$(basename "$d")"
                 done | sort -rn | head -1 | cut -f2)
        [ -n "$RUN_ID" ] || { echo "No se encontro ninguna corrida con expediente en $OUT_ROOT" >&2; exit 1; }
    fi
    RUN_PATH="$OUT_ROOT/$RUN_ID"
fi

RAW="$RUN_PATH/raw"
[ -d "$RAW" ] || { echo "La corrida '$RUN_ID' no tiene carpeta raw/: $RAW" >&2; exit 1; }

leer_json() {
    local f="$RAW/$1"
    if [ -s "$f" ] && jq -e . "$f" >/dev/null 2>&1; then cat "$f"; else printf '[]'; fi
}

RESUMEN_JSON=$(leer_json 'RESUMEN.json')
# RESUMEN.json se exporta como arreglo de un elemento
RESUMEN_JSON=$(printf '%s' "$RESUMEN_JSON" | jq -c 'if type == "array" then .[0] else . end')
[ -n "$RESUMEN_JSON" ] && [ "$RESUMEN_JSON" != 'null' ] || { echo "Falta el archivo de evidencia: $RAW/RESUMEN.json" >&2; exit 1; }

CAPAS_JSON=$(leer_json 'RESUMEN-CAPAS.json')
HALL_JSON=$(leer_json 'HALLAZGOS.json')
COB_JSON=$(leer_json 'COBERTURA-CRITERIOS.json')
BRE_JSON=$(leer_json 'BRECHAS-EVIDENCIA.json')
ARQ_JSON=$(leer_json 'LINEA-BASE-ARQUITECTURA.json')

S() { printf '%s' "$RESUMEN_JSON" | jq -r "$1 // empty"; }
M() { printf '%s' "$RESUMEN_JSON" | jq -r ".Metricas[\"$1\"] // empty"; }

servidor=$(S .Servidor)
elevado=$(S .Elevado)
nivel=$(S .NivelRiesgo)

# ---------------------------------------------------------------------------
# Rol declarado: se prefiere el catalogo, con respaldo en las metricas
# ---------------------------------------------------------------------------
rol_declarado=$(arq '.RolServidor.RolDeclarado' '')
entorno=$(arq '.RolServidor.Entorno' '')
criticidad=$(arq '.RolServidor.Criticidad' 'No declarada')
clasif_datos=$(arq '.RolServidor.ClasificacionDatos' 'No declarada')
propietario=$(arq '.RolServidor.Propietario' 'DEFINIR')
responsable=$(arq '.RolServidor.ResponsableTecnico' 'DEFINIR')
unidad=$(arq '.RolServidor.UnidadNegocio' 'DEFINIR')

[ -n "$rol_declarado" ] || rol_declarado=$(M 'L4-06.RolServidorDeclarado')
[ -n "$rol_declarado" ] || rol_declarado='No declarado'
[ -n "$entorno" ] || entorno=$(M 'L4-06.EntornoDeclarado')
[ -n "$entorno" ] || entorno='No declarado'

fmt_pendiente() {
    if [ -z "$1" ] || [ "$1" = 'DEFINIR' ]; then printf 'SIN ASIGNAR'; else printf '%s' "$1"; fi
}
recortar() {
    local t=$1 max=$2
    if [ ${#t} -le "$max" ]; then printf '%s' "$t"; else printf '%s...' "${t:0:$((max-3))}"; fi
}

# ---------------------------------------------------------------------------
# Preparacion de datos
# ---------------------------------------------------------------------------
ARTEF=$(printf '%s' "$ARQ_JSON" | jq -c '[.[] | select((.Artefacto // "") | startswith("[CATALOGO]") | not)]')
n_artef=$(printf '%s' "$ARTEF" | jq 'length')
n_alin=$(printf '%s' "$ARTEF" | jq '[.[] | select(.Alineacion == "Alineado")] | length')
n_no_alin=$(printf '%s' "$ARTEF" | jq '[.[] | select(.Alineacion == "NO ALINEADO")] | length')
n_sin_clas=$(printf '%s' "$ARTEF" | jq '[.[] | select(.RolId == "SinClasificar")] | length')

ACCIONABLES=$(printf '%s' "$HALL_JSON" | jq -c '[.[] | select(.Severity == "Critical" or .Severity == "High")] | sort_by(-.SeverityRank)')
n_acc=$(printf '%s' "$ACCIONABLES" | jq 'length')

case $nivel in
    CRITICO|ALTO) color_riesgo='C0272D'; fondo_riesgo='FDECEC' ;;
    MEDIO)        color_riesgo='8A6D00'; fondo_riesgo='FDF6E3' ;;
    *)            color_riesgo='1A7F4B'; fondo_riesgo='EAF6EF' ;;
esac

# ---------------------------------------------------------------------------
# Construccion del documento
# ---------------------------------------------------------------------------
docx_reset

# --- Cabecera ---
if [ "$elevado" = 'true' ]; then privilegios='Root'; else privilegios='Estandar (sin elevacion)'; fi
derecha=$(printf 'Corrida: %s\nEmitida: %s\nPrivilegios: %s' "$(S .RunId)" "$(date '+%d/%m/%Y %H:%M')" "$privilegios")

docx_add "$(docx_titulo 'Ficha de auditoria de sistemas' \
    "Servidor $servidor  |  $rol_declarado" "$derecha")"

# --- Veredicto ---
docx_add "$(printf '%s\tRiesgo - %s\t%s\t%s\n%s\tCriticos\tC0272D\t\n%s\tAltos\tE06C00\t\n%s\tMedios\t8A6D00\t\n%s\tBajos\t2C7BB6\t\n%s\tArtefactos\t\t\n' \
    "$(S .PuntajeRiesgo)" "$nivel" "$color_riesgo" "$fondo_riesgo" \
    "$(S .Criticos)" "$(S .Altos)" "$(S .Medios)" "$(S .Bajos)" "$n_artef" | docx_indicadores)"

if [ "$elevado" != 'true' ]; then
    docx_add "$(docx_nota 'Alcance limitado:' \
        "la auditoria se ejecuto sin privilegios de root. $(S .BrechasEvidencia) verificaciones no pudieron completarse y quedan detalladas al final de este documento. Para un expediente formal, reejecutar con una cuenta con privilegios.")"
fi

# --- Identificacion del activo ---
docx_add "$(docx_seccion 'Identificacion del activo')"
docx_add "$(printf '%s\t%s\t%s\t%s\n' \
    'Servidor'         "$servidor"                        'Entorno'                "$entorno" \
    'Dominio'          "$(S .Dominio)"                    'Criticidad'             "$criticidad" \
    'Rol declarado'    "$rol_declarado"                   'Clasificacion de datos' "$clasif_datos" \
    'Sistema operativo' "$(S .SistemaOperativo)"          'Kernel'                 "$(S .Kernel)" \
    'Propietario'      "$(fmt_pendiente "$propietario")"  'Responsable tecnico'    "$(fmt_pendiente "$responsable")" \
    'Unidad de negocio' "$(fmt_pendiente "$unidad")"      'Ejecutado por'          "$(S .EjecutadoPor)" |
    docx_tabla "$(printf 'Campo\tValor\tCampo\tValor')" '17 33 17 33' 8.3 clave)"

# --- Plataforma y estado operativo ---
docx_add "$(docx_seccion 'Plataforma y estado operativo')"
if [ "$(M 'L2-01.ReinicioPendiente')" = 'true' ]; then
    reinicio='Si - parches aplicados sin efecto'
else
    reinicio='No'
fi
docx_add "$(printf '%s\t%s\t%s\t%s\n' \
    'Motor de base de datos' "$(M 'L3-01.MotorBaseDatos')"        'Servidor web'      "$(M 'L3-01.ServidorWeb')" \
    'CPU logicos'            "$(M 'L1-01.CPULogicos')"            'Memoria total'     "$(M 'L1-01.MemoriaTotalGB') GB" \
    'Virtualizacion'         "$(M 'L1-01.Virtualizacion')"        'Memoria libre'     "$(M 'L9-01.MemoriaPorcentajeLibre')%" \
    'Uptime'                 "$(M 'L2-01.UptimeDias') dias"       'Reinicio pendiente' "$reinicio" \
    'Ultimo parche'          "$(M 'L2-02.UltimoParche') ($(M 'L2-02.DiasDesdeUltimoParche') dias)" \
                                                                  'Actualizaciones pendientes' "$(M 'L2-02.ActualizacionesPendientes')" \
    'Antimalware / MAC'      "$(M 'L2-03.ControlAccesoObligatorio')" 'Firewall'       "$(M 'L2-03.FirewallMotor')" \
    'Servicios en ejecucion' "$(M 'L5-01.ServiciosEnEjecucion') de $(M 'L5-01.TotalServicios')" \
                                                                  'Puertos TCP en escucha' "$(M 'L7-01.PuertosTCPEscucha')" \
    'Paquetes instalados'    "$(M 'L4-01.TotalPaquetes')"         'Fuera de soporte'  "$(M 'L4-05.FueraDeSoporte') ($(M 'L4-05.PorcentajeFueraSoporte')%)" |
    docx_tabla "$(printf 'Campo\tValor\tCampo\tValor')" '17 33 17 33' 8.3 clave)"

# --- Perfil arquitectonico ---
docx_add "$(docx_seccion 'Perfil arquitectonico')"
if [ "$n_artef" -gt 0 ]; then
    pct=$(awk -v a="$n_alin" -v t="$n_artef" 'BEGIN{printf "%d", (a/t)*100}')
    docx_add "$(printf '%s\t%s\t%s\t%s\n' \
        'Artefactos clasificados' "$(( n_artef - n_sin_clas )) de $n_artef" 'Alineados al rol' "$n_alin ($pct%)" \
        'No alineados'            "$n_no_alin"                              'Sin clasificar'   "$n_sin_clas" |
        docx_tabla "$(printf 'Campo\tValor\tCampo\tValor')" '22 28 22 28' 8.3 clave)"

    docx_add "$(docx_parrafo 'Distribucion por capa de arquitectura empresarial:' 8.5 '5B6673')"
    max_capa=$(printf '%s' "$ARTEF" | jq -r 'group_by(.CapaEA) | map(length) | max // 1')
    docx_add "$(printf '%s' "$ARTEF" |
        jq -r --argjson m "$max_capa" 'group_by(.CapaEA) | map({n: .[0].CapaEA, c: length}) | sort_by(-.c)[] |
               [.n, (.c|tostring), ((.c / $m)|tostring), "", ""] | @tsv' |
        docx_barras)"
else
    docx_add "$(docx_parrafo 'Linea base de arquitectura no disponible en esta corrida.' 9 '5B6673' cursiva)"
fi

# --- Riesgo por capa ---
docx_add "$(docx_seccion 'Riesgo por capa')"
max_r=$(printf '%s' "$CAPAS_JSON" | jq -r '[.[] | select(.Colectores > 0) | .PuntajeRiesgo] | max // 1 | if . == 0 then 1 else . end')
docx_add "$(printf '%s' "$CAPAS_JSON" |
    jq -r --argjson m "$max_r" 'sort_by(.Orden)[] | select(.Colectores > 0) |
           [ (.Capa + "  " + .Nombre), (.PuntajeRiesgo|tostring),
             ((.PuntajeRiesgo / $m)|tostring),
             ((.Hallazgos|tostring) + " hallazgos"),
             (if .Capa == "L4" then "si" else "" end) ] | @tsv' |
    docx_barras)"

# --- Hallazgos que exigen accion (pagina nueva) ---
docx_add "$(docx_salto_pagina)"
docx_add "$(docx_seccion "Hallazgos que exigen accion ($n_acc)")"

if [ "$n_acc" -eq 0 ]; then
    docx_add "$(docx_parrafo 'No se identificaron hallazgos criticos ni altos en el alcance evaluado.' 9 '1A7F4B')"
else
    docx_add "$(printf '%s' "$ACCIONABLES" |
        jq -r '.[] |
            (if .Severity == "Critical" then "@C0272D#CRIT" else "@E06C00#ALTO" end) as $sev |
            [ $sev, .Layer,
              (.Title          | if length > 90  then .[0:87]  + "..." else . end),
              (.CriteriosTexto | if length > 22  then .[0:19]  + "..." else . end),
              (.Recommendation | if length > 190 then .[0:187] + "..." else . end) ] | @tsv' |
        docx_tabla "$(printf 'Sev.\tCapa\tHallazgo\tCriterios\tAccion requerida')" '7 6 32 11 44' 8)"
fi

# --- Desviaciones arquitectonicas ---
if [ "$n_no_alin" -gt 0 ]; then
    docx_add "$(docx_seccion "Desviaciones arquitectonicas ($n_no_alin)")"
    docx_add "$(docx_parrafo "Artefactos cuyo rol no corresponde al proposito declarado del servidor ($rol_declarado, entorno de $entorno). Cada uno amplia la superficie de ataque sin aportar a la funcion del activo." 8.5 '5B6673')"
    docx_add "$(printf '%s' "$ARTEF" |
        jq -r '[.[] | select(.Alineacion == "NO ALINEADO")][0:20][] |
            [ .Artefacto, (.Version // ""), .RolArquitectonico,
              ((if (.RutaInstalacion // "") == "" then "ruta no determinada" else .RutaInstalacion end)
               | if length > 60 then .[0:57] + "..." else . end) ] | @tsv' |
        docx_tabla "$(printf 'Artefacto\tVersion\tRol detectado\tUbicacion')" '30 12 22 36' 8)"
    if [ "$n_no_alin" -gt 20 ]; then
        docx_add "$(docx_parrafo "Se muestran 20 de $n_no_alin. Listado completo en la hoja Arquitectura del libro de Excel adjunto." 7.5 '5B6673' cursiva)"
    fi
fi

# --- Conformidad por dominio ---
if [ "$(printf '%s' "$COB_JSON" | jq 'length')" -gt 0 ]; then
    docx_add "$(docx_seccion 'Conformidad por dominio de criterios')"
    docx_add "$(printf '%s' "$COB_JSON" |
        jq -r 'group_by(.Dominio) | sort_by(.[0].Dominio)[] |
            [ .[0].Dominio, (length|tostring),
              ([.[] | select(.Conformidad == "Conforme")] | length | tostring),
              ([.[] | select(.Conformidad == "Conforme con observaciones")] | length | tostring),
              ([.[] | select(.Conformidad == "No conforme")] | length | tostring),
              ([.[] | select(.Conformidad == "No evaluado")] | length | tostring) ] | @tsv' |
        docx_tabla "$(printf 'Dominio\tCriterios\tConformes\tCon observaciones\tNo conformes\tSin evaluar')" \
            '34 11 13 20 12 10' 8)"
fi

# --- Brechas de evidencia ---
n_bre=$(printf '%s' "$BRE_JSON" | jq 'length')
if [ "$n_bre" -gt 0 ]; then
    docx_add "$(docx_seccion "Brechas de evidencia ($n_bre)")"
    docx_add "$(docx_parrafo 'Verificaciones que no pudieron completarse. Se documentan de forma explicita para que el alcance real del expediente quede constatado, en lugar de aparentar cobertura total.' 8.5 '5B6673')"
    docx_add "$(printf '%s' "$BRE_JSON" |
        jq -r '.[] | [ (.Colector // ""), (.Capa // ""),
                       ((.Brecha // .Motivo // .Detalle // .Descripcion // "")
                        | if length > 200 then .[0:197] + "..." else . end) ] | @tsv' |
        docx_tabla "$(printf 'Colector\tCapa\tVerificacion que no pudo completarse')" '11 8 81' 8)"
fi

# --- Cierre ---
docx_add "$(docx_firmas)"
docx_add "$(docx_parrafo "Auditoria de solo lectura. $(S .RegistrosTotal) registros de evidencia recolectados por $(S .ColectoresOK) colectores en $(S .DuracionSegundos) segundos. Detalle completo en el libro de Excel y los CSV de la carpeta de la corrida." 7.5 '5B6673')"

# ---------------------------------------------------------------------------
# Emision
# ---------------------------------------------------------------------------
DESTINO="$RUN_PATH/Ficha-${servidor}-${RUN_ID}.docx"
PIE="Ficha de auditoria - $servidor - corrida $RUN_ID"

if docx_finish "$DESTINO" "Ficha de auditoria - $servidor" 'Suite de Auditoria de Artefactos' "$PIE"; then
    printf '%s\n' "$DESTINO"
else
    echo "No se pudo empaquetar el archivo .docx." >&2
    exit 1
fi
