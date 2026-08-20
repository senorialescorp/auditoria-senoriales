#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# new_audit_ficha.sh
# Genera la ficha imprimible de auditoria del servidor (equivalente de
# Reports/New-AuditFicha.ps1).
#
# Documento de una a dos paginas en formato A4, disenado para imprimirse o
# exportarse a PDF desde el navegador (Ctrl+P). Contiene la identificacion del
# activo, el veredicto, el perfil arquitectonico y los hallazgos que exigen
# accion. El detalle completo vive en el libro de Excel.
#
# Recibe las rutas de los datos consolidados por variables de entorno y emite
# por stdout la ruta del archivo generado.
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/audit_core.sh"

: "${AUDIT_RESUMEN:?falta AUDIT_RESUMEN}"
: "${AUDIT_RUN_PATH:?falta AUDIT_RUN_PATH}"
HALLAZGOS=${AUDIT_HALLAZGOS:-/dev/null}
CAPAS=${AUDIT_CAPAS:-/dev/null}
COBERTURA=${AUDIT_COBERTURA:-/dev/null}
TODOS=${AUDIT_TODOS:-/dev/null}

R() { jq -r "$1 // empty" "$AUDIT_RESUMEN"; }
E() { html_escape "$1"; }

servidor=$(R .Servidor)
runid=$(R .RunId)
elevado=$(R .Elevado)
nivel=$(R .NivelRiesgo)
puntaje=$(R .PuntajeRiesgo)

# --- Datos declarados en la linea base de arquitectura ---
rol_declarado=$(arq '.RolServidor.RolDeclarado' 'No declarado')
entorno=$(arq '.RolServidor.Entorno' 'No declarado')
criticidad=$(arq '.RolServidor.Criticidad' 'No declarada')
clasif_datos=$(arq '.RolServidor.ClasificacionDatos' 'No declarada')
propietario=$(arq '.RolServidor.Propietario' 'DEFINIR')
responsable=$(arq '.RolServidor.ResponsableTecnico' 'DEFINIR')
unidad=$(arq '.RolServidor.UnidadNegocio' 'DEFINIR')

pendiente() {
    if [ -z "$1" ] || [ "$1" = 'DEFINIR' ]; then
        printf '<span class="pend">SIN ASIGNAR</span>'
    else
        printf '%s' "$(E "$1")"
    fi
}

case $nivel in
    CRITICO|ALTO) clase_riesgo='r-crit' ;;
    MEDIO)        clase_riesgo='r-med' ;;
    *)            clase_riesgo='r-ok' ;;
esac

# --- Artefactos de la linea base de arquitectura ---
ART_TMP=$(mktemp)
trap 'rm -f "$ART_TMP" 2>/dev/null' EXIT
if [ -s "$TODOS" ]; then
    jq -c '[.[] | select(.Meta.Id == "L4-06" and .Status == "Completed") | .Records[]?
           | select(.Artefacto | startswith("[CATALOGO]") | not)]' "$TODOS" > "$ART_TMP" 2>/dev/null
fi
[ -s "$ART_TMP" ] || printf '[]' > "$ART_TMP"

n_artef=$(jq 'length' "$ART_TMP")
n_alineados=$(jq '[.[] | select(.Alineacion == "Alineado")] | length' "$ART_TMP")
n_no_alin=$(jq '[.[] | select(.Alineacion == "NO ALINEADO")] | length' "$ART_TMP")
n_sin_clas=$(jq '[.[] | select(.RolId == "SinClasificar")] | length' "$ART_TMP")

# Total de software inventariado (capa L4-01)
total_sw=0
if [ -s "$TODOS" ]; then
    total_sw=$(jq '[.[] | select(.Meta.Id == "L4-01") | .RecordCount] | add // 0' "$TODOS")
fi

n_accionables=$(jq '[.[] | select(.Severity == "Critical" or .Severity == "High")] | length' "$HALLAZGOS" 2>/dev/null || printf 0)

DESTINO="$AUDIT_RUN_PATH/Ficha-${servidor}-${runid}.html"

# ---------------------------------------------------------------------------
# Documento
# ---------------------------------------------------------------------------
{
cat <<'HEAD'
<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8">
HEAD
printf '<title>Ficha de auditoria - %s</title>\n' "$(E "$servidor")"
cat <<'CSS'
<style>
@page { size: A4; margin: 12mm 10mm; }
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:"Segoe UI",Arial,sans-serif;font-size:9.5pt;line-height:1.4;color:#1a1f26;background:#e9ecef}
.hoja{width:210mm;min-height:297mm;margin:0 auto;background:#fff;padding:10mm 9mm}

h1{font-size:15pt;font-weight:700;letter-spacing:-.2px}
h2{font-size:10pt;font-weight:700;color:#1f4e79;text-transform:uppercase;letter-spacing:.7px;
   border-bottom:1.5pt solid #1f4e79;padding-bottom:2pt;margin:9pt 0 5pt}
h3{font-size:9pt;font-weight:700;margin:6pt 0 3pt;color:#374151}

.cab{display:flex;justify-content:space-between;align-items:flex-start;
     border-bottom:2.5pt solid #1f4e79;padding-bottom:6pt;margin-bottom:3pt}
.cab .sub{font-size:8.5pt;color:#5b6673;margin-top:2pt}
.cab .der{text-align:right;font-size:8pt;color:#5b6673;line-height:1.5}
.cab .der b{color:#1a1f26}

.veredicto{display:flex;gap:5pt;margin:7pt 0}
.vbox{flex:1;border:1pt solid #d5dae0;border-radius:3pt;padding:5pt 6pt;text-align:center}
.vbox .n{font-size:17pt;font-weight:700;line-height:1.1}
.vbox .l{font-size:6.8pt;color:#5b6673;text-transform:uppercase;letter-spacing:.4px;margin-top:1pt}
.vbox.r-crit{background:#fdecec;border-color:#c0272d} .vbox.r-crit .n{color:#c0272d}
.vbox.r-med{background:#fdf6e3;border-color:#c9a000}  .vbox.r-med .n{color:#8a6d00}
.vbox.r-ok{background:#eaf6ef;border-color:#1a7f4b}   .vbox.r-ok .n{color:#1a7f4b}
.vbox.crit .n{color:#c0272d} .vbox.alto .n{color:#e06c00}
.vbox.medio .n{color:#8a6d00} .vbox.bajo .n{color:#2c7bb6}

table{width:100%;border-collapse:collapse;font-size:8.3pt}
th{background:#eef2f6;text-align:left;padding:3pt 4pt;border:.5pt solid #d5dae0;
   font-weight:700;color:#1f4e79;font-size:7.8pt;text-transform:uppercase;letter-spacing:.3px}
td{padding:3pt 4pt;border:.5pt solid #d5dae0;vertical-align:top}
.ident td:first-child{width:33%;background:#f7f9fb;font-weight:600}
.pend{color:#c0272d;font-weight:700}

.sev{display:inline-block;padding:.5pt 4pt;border-radius:2pt;font-size:7pt;
     font-weight:700;color:#fff;white-space:nowrap}
.s-crit{background:#c0272d} .s-alto{background:#e06c00}
.s-med{background:#c9a000}  .s-bajo{background:#2c7bb6}

.dosc{display:flex;gap:7pt}
.dosc>div{flex:1}

.barras td{border:none;padding:1.5pt 0;font-size:8pt}
.barras .bn{width:32%} .barras .bv{width:12%;text-align:right;font-weight:700;padding-right:4pt}
.barra{height:7pt;background:#eef2f6;border-radius:2pt;overflow:hidden}
.barra i{display:block;height:100%;background:#1f4e79}
.barra i.prio{background:#c0272d}

.nota{background:#fdf6e3;border-left:2.5pt solid #c9a000;padding:4pt 6pt;font-size:8pt;margin:5pt 0}
.pie{margin-top:8pt;padding-top:4pt;border-top:.5pt solid #d5dae0;
     font-size:7.2pt;color:#5b6673;display:flex;justify-content:space-between}
.firma{margin-top:10pt;display:flex;gap:14pt}
.firma div{flex:1;border-top:.5pt solid #4b5563;padding-top:2pt;font-size:7.5pt;color:#5b6673;text-align:center}

.salto{page-break-before:always}
tr,td,th{page-break-inside:avoid}
@media print{body{background:#fff}.hoja{margin:0;padding:0;width:auto;min-height:0}.noimp{display:none}}
.noimp{position:fixed;top:8px;right:8px;background:#1f4e79;color:#fff;border:none;
       padding:7px 13px;border-radius:4px;font-size:12px;cursor:pointer;font-family:inherit}
</style>
</head><body>
<button class="noimp" onclick="window.print()">Imprimir / Guardar PDF</button>
<div class="hoja">
CSS

# ---------------------------------------------------------------------------
# Cabecera
# ---------------------------------------------------------------------------
printf '<div class="cab"><div>\n'
printf '<h1>Ficha de auditoria de sistemas</h1>\n'
printf '<div class="sub">Servidor <b>%s</b> &middot; %s</div>\n' "$(E "$servidor")" "$(E "$rol_declarado")"
printf '</div><div class="der">\n'
printf 'Corrida <b>%s</b><br>\n' "$(E "$runid")"
printf 'Fecha <b>%s</b><br>\n' "$(date '+%Y-%m-%d %H:%M')"
if [ "$elevado" = 'true' ]; then priv='Root'; else priv='Estandar'; fi
printf 'Privilegios <b>%s</b>\n' "$priv"
printf '</div></div>\n'

# ---------------------------------------------------------------------------
# Veredicto
# ---------------------------------------------------------------------------
printf '<div class="veredicto">\n'
printf '<div class="vbox %s"><div class="n">%s</div><div class="l">Riesgo &middot; %s</div></div>\n' \
    "$clase_riesgo" "$puntaje" "$(E "$nivel")"
printf '<div class="vbox crit"><div class="n">%s</div><div class="l">Criticos</div></div>\n'  "$(R .Criticos)"
printf '<div class="vbox alto"><div class="n">%s</div><div class="l">Altos</div></div>\n'     "$(R .Altos)"
printf '<div class="vbox medio"><div class="n">%s</div><div class="l">Medios</div></div>\n'   "$(R .Medios)"
printf '<div class="vbox bajo"><div class="n">%s</div><div class="l">Bajos</div></div>\n'     "$(R .Bajos)"
printf '<div class="vbox"><div class="n">%s</div><div class="l">Artefactos</div></div>\n'     "$total_sw"
printf '</div>\n'

if [ "$elevado" != 'true' ]; then
    printf '<div class="nota"><b>Alcance limitado:</b> ejecutada sin privilegios de root. %s verificaciones no pudieron completarse; ver la hoja <i>Brechas Evidencia</i> del libro adjunto. Para expediente formal, reejecutar con una cuenta con privilegios.</div>\n' \
        "$(R .BrechasEvidencia)"
fi

# ---------------------------------------------------------------------------
# Identificacion + perfil arquitectonico
# ---------------------------------------------------------------------------
printf '<div class="dosc"><div>\n'
printf '<h2>Identificacion del activo</h2>\n<table class="ident">\n'
printf '<tr><td>Servidor</td><td>%s</td></tr>\n' "$(E "$servidor")"
dom=$(R .Dominio); [ -n "$dom" ] || dom='Sin dominio'
printf '<tr><td>Dominio</td><td>%s</td></tr>\n' "$(E "$dom")"
printf '<tr><td>Sistema operativo</td><td>%s</td></tr>\n' "$(E "$(R .SistemaOperativo)")"
printf '<tr><td>Kernel</td><td>%s</td></tr>\n' "$(E "$(R .Kernel)")"
printf '<tr><td>Rol declarado</td><td>%s</td></tr>\n' "$(E "$rol_declarado")"
printf '<tr><td>Entorno</td><td>%s</td></tr>\n' "$(E "$entorno")"
printf '<tr><td>Criticidad</td><td>%s</td></tr>\n' "$(E "$criticidad")"
printf '<tr><td>Clasificacion datos</td><td>%s</td></tr>\n' "$(E "$clasif_datos")"
printf '<tr><td>Propietario</td><td>%s</td></tr>\n' "$(pendiente "$propietario")"
printf '<tr><td>Responsable tecnico</td><td>%s</td></tr>\n' "$(pendiente "$responsable")"
printf '<tr><td>Unidad de negocio</td><td>%s</td></tr>\n' "$(pendiente "$unidad")"
printf '</table></div>\n'

printf '<div>\n<h2>Perfil arquitectonico</h2>\n'
if [ "$n_artef" -gt 0 ]; then
    pct_alin=$(awk -v a="$n_alineados" -v t="$n_artef" 'BEGIN{printf "%d", (a/t)*100}')
    printf '<table class="ident">\n'
    printf '<tr><td>Artefactos clasificados</td><td>%s de %s</td></tr>\n' "$(( n_artef - n_sin_clas ))" "$n_artef"
    printf '<tr><td>Alineados al rol</td><td>%s (%s%%)</td></tr>\n' "$n_alineados" "$pct_alin"
    if [ "$n_no_alin" -gt 0 ]; then
        printf '<tr><td>No alineados</td><td><span class="pend">%s</span></td></tr>\n' "$n_no_alin"
    else
        printf '<tr><td>No alineados</td><td>0</td></tr>\n'
    fi
    printf '<tr><td>Sin clasificar</td><td>%s</td></tr>\n' "$n_sin_clas"
    printf '</table>\n'

    printf '<h3>Distribucion por capa de arquitectura</h3>\n<table class="barras">\n'
    max_capa=$(jq -r 'group_by(.CapaEA) | map(length) | max // 1' "$ART_TMP")
    jq -r 'group_by(.CapaEA) | map({n: .[0].CapaEA, c: length}) | sort_by(-.c)[] |
           [.n, (.c|tostring)] | @tsv' "$ART_TMP" | tr -d '\r' |
    while IFS=$'\t' read -r nombre cuenta; do
        w=$(awk -v c="$cuenta" -v m="$max_capa" 'BEGIN{printf "%d", (c/m)*100}')
        printf '<tr><td class="bn">%s</td><td class="bv">%s</td><td><div class="barra"><i style="width:%s%%"></i></div></td></tr>\n' \
            "$(E "$nombre")" "$cuenta" "$w"
    done
    printf '</table>\n'
else
    printf '<p style="font-size:8pt;color:#5b6673">Linea base de arquitectura no disponible en esta corrida.</p>\n'
fi
printf '</div></div>\n'

# ---------------------------------------------------------------------------
# Riesgo por capa
# ---------------------------------------------------------------------------
printf '<h2>Riesgo por capa</h2>\n<table class="barras">\n'
max_r=$(jq -r '[.[].PuntajeRiesgo] | max // 1 | if . == 0 then 1 else . end' "$CAPAS" 2>/dev/null || printf 1)
jq -r 'sort_by(.Orden)[] | select(.Colectores > 0) |
       [.Capa, .Nombre, (.PuntajeRiesgo|tostring), (.Hallazgos|tostring)] | @tsv' "$CAPAS" 2>/dev/null | tr -d '\r' |
while IFS=$'\t' read -r capa nombre puntaje hall; do
    w=$(awk -v p="$puntaje" -v m="$max_r" 'BEGIN{printf "%d", (p/m)*100}')
    if [ "$capa" = 'L4' ]; then
        cls='prio'; etq="<b>$(E "$nombre")</b>"
    else
        cls=''; etq=$(E "$nombre")
    fi
    printf '<tr><td class="bn">%s %s</td><td class="bv">%s</td><td><div class="barra"><i class="%s" style="width:%s%%"></i></div></td><td style="width:22%%;font-size:7.5pt;color:#5b6673">%s hallazgos</td></tr>\n' \
        "$(E "$capa")" "$etq" "$puntaje" "$cls" "$w" "$hall"
done
printf '</table>\n'

# ---------------------------------------------------------------------------
# Hallazgos que exigen accion
# ---------------------------------------------------------------------------
printf '<h2>Hallazgos que exigen accion (%s)</h2>\n' "$n_accionables"
if [ "$n_accionables" -eq 0 ]; then
    printf '<p style="font-size:8.5pt;color:#1a7f4b;font-weight:600">No se identificaron hallazgos criticos ni altos en el alcance evaluado.</p>\n'
else
    printf '<table>\n<thead><tr><th style="width:8%%">Sev.</th><th style="width:6%%">Capa</th><th style="width:34%%">Hallazgo</th><th style="width:22%%">Activo</th><th style="width:11%%">Criterios</th><th style="width:19%%">Accion requerida</th></tr></thead><tbody>\n'
    # La recomendacion y el activo se recortan: el texto completo esta en el Excel
    jq -r '[.[] | select(.Severity == "Critical" or .Severity == "High")][] |
        [ .Severity, .Layer, .Title,
          (.Asset      | if length > 70  then .[0:67]  + "..." else . end),
          .CriteriosTexto,
          (.Recommendation | if length > 155 then .[0:152] + "..." else . end) ] | @tsv' \
        "$HALLAZGOS" 2>/dev/null | tr -d '\r' |
    while IFS=$'\t' read -r sev capa titulo activo criterios reco; do
        if [ "$sev" = 'Critical' ]; then cls='s-crit'; et='CRIT'; else cls='s-alto'; et='ALTO'; fi
        printf '<tr><td><span class="sev %s">%s</span></td><td>%s</td><td><b>%s</b></td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
            "$cls" "$et" "$(E "$capa")" "$(E "$titulo")" "$(E "$activo")" "$(E "$criterios")" "$(E "$reco")"
    done
    printf '</tbody></table>\n'
fi

# ---------------------------------------------------------------------------
# Desviaciones arquitectonicas
# ---------------------------------------------------------------------------
if [ "$n_no_alin" -gt 0 ]; then
    printf '<h2>Desviaciones arquitectonicas (%s)</h2>\n' "$n_no_alin"
    printf '<p style="font-size:8pt;color:#5b6673;margin-bottom:3pt">Artefactos cuyo rol no corresponde al proposito declarado del servidor (%s, entorno de %s).</p>\n' \
        "$(E "$rol_declarado")" "$(E "$entorno")"
    printf '<table>\n<thead><tr><th style="width:32%%">Artefacto</th><th style="width:22%%">Rol detectado</th><th style="width:46%%">Ubicacion</th></tr></thead><tbody>\n'
    jq -r '[.[] | select(.Alineacion == "NO ALINEADO")][0:18][] |
           [.Artefacto, .RolArquitectonico, (.RutaInstalacion // "")] | @tsv' "$ART_TMP" | tr -d '\r' |
    while IFS=$'\t' read -r artefacto rol ruta; do
        if [ -n "$ruta" ]; then
            celda_ruta=$(E "$ruta")
        else
            celda_ruta='<i style="color:#8894a3">ruta no determinada</i>'
        fi
        printf '<tr><td><b>%s</b></td><td>%s</td><td style="font-family:Consolas,monospace;font-size:7.5pt">%s</td></tr>\n' \
            "$(E "$artefacto")" "$(E "$rol")" "$celda_ruta"
    done
    printf '</tbody></table>\n'
    if [ "$n_no_alin" -gt 18 ]; then
        printf '<p style="font-size:7.5pt;color:#5b6673;margin-top:2pt">Se muestran 18 de %s. Listado completo en la hoja <i>Arquitectura</i> del libro adjunto.</p>\n' "$n_no_alin"
    fi
fi

# ---------------------------------------------------------------------------
# Conformidad por dominio de criterios
# ---------------------------------------------------------------------------
printf '<h2>Conformidad por dominio de criterios</h2>\n<table>\n'
printf '<thead><tr><th style="width:34%%">Dominio</th><th style="width:11%%">Criterios</th><th style="width:13%%">Conformes</th><th style="width:20%%">Con observaciones</th><th style="width:12%%">No conformes</th><th style="width:10%%">Sin evaluar</th></tr></thead><tbody>\n'
jq -r 'group_by(.Dominio) | sort_by(.[0].Dominio)[] |
    [ .[0].Dominio, (length|tostring),
      ([.[] | select(.Conformidad == "Conforme")] | length | tostring),
      ([.[] | select(.Conformidad == "Conforme con observaciones")] | length | tostring),
      ([.[] | select(.Conformidad == "No conforme")] | length | tostring),
      ([.[] | select(.Conformidad == "No evaluado")] | length | tostring) ] | @tsv' \
    "$COBERTURA" 2>/dev/null | tr -d '\r' |
while IFS=$'\t' read -r dominio total cf ob nc ne; do
    if [ "${nc:-0}" -gt 0 ]; then celda_nc="<span class=\"pend\">$nc</span>"; else celda_nc='0'; fi
    printf '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
        "$(E "$dominio")" "$total" "$cf" "$ob" "$celda_nc" "$ne"
done
printf '</tbody></table>\n'

# ---------------------------------------------------------------------------
# Cierre
# ---------------------------------------------------------------------------
printf '<div class="firma"><div>Elaborado por</div><div>Revisado por</div><div>Responsable del activo</div></div>\n'
printf '<div class="pie">\n'
if [ -n "${AUDIT_ARCHIVO_EXCEL:-}" ]; then
    nombre_excel=$(basename "$AUDIT_ARCHIVO_EXCEL")
else
    nombre_excel='libro de Excel adjunto'
fi
printf '<span>Detalle completo: <b>%s</b></span>\n' "$(E "$nombre_excel")"
printf '<span>Auditoria de solo lectura &middot; %s registros &middot; %s colectores</span>\n' \
    "$(R .RegistrosTotal)" "$(R .ColectoresOK)"
printf '</div>\n</div></body></html>\n'
} > "$DESTINO"

printf '%s\n' "$DESTINO"
