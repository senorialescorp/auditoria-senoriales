#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# xlsx_writer.sh
# Generador de archivos .xlsx nativo (equivalente de Modules/AuditCore/ExcelWriter.psm1).
#
# Escribe el formato OOXML (SpreadsheetML) directamente y lo empaqueta como ZIP.
# NO requiere LibreOffice, ni python-openpyxl, ni ninguna otra dependencia:
# importante porque en un servidor de produccion normalmente no existe ninguna,
# y porque instalar dependencias en el activo auditado contradice el principio
# de que la auditoria no debe alterar el sistema.
#
# Soporta: multiples hojas, encabezado con formato, ancho de columna,
# inmovilizar paneles, autofiltro, tipos numericos y ajuste de texto.
#
# USO
#   . lib/xlsx_writer.sh
#   xlsx_init
#   xlsx_sheet 'Hallazgos' "$json_array" 'Id,Severidad,Titulo' '16,11,45'
#   xlsx_finish '/ruta/salida.xlsx' 'Titulo del libro' 'Autor'
#
# El paso de datos es un arreglo JSON de objetos; las columnas se declaran por
# nombre y en orden. La generacion del XML de cada hoja se delega a jq en una
# sola invocacion por hoja: hacerlo en bash celda por celda seria varios ordenes
# de magnitud mas lento en un inventario de miles de filas.
# ---------------------------------------------------------------------------

XLSX_DIR=''
XLSX_N=0
XLSX_NOMBRES=()

xlsx_init() {
    XLSX_DIR=$(mktemp -d)
    XLSX_N=0
    XLSX_NOMBRES=()
    mkdir -p "$XLSX_DIR/_rels" "$XLSX_DIR/docProps" \
             "$XLSX_DIR/xl/_rels" "$XLSX_DIR/xl/worksheets"
}

xlsx_cleanup() { [ -n "$XLSX_DIR" ] && rm -rf "$XLSX_DIR" 2>/dev/null; XLSX_DIR=''; }

# Programa jq que convierte un arreglo de objetos en el XML de una hoja.
_xlsx_sheet_jq() {
    cat <<'JQEOF'
def colname($n):
  def go($k; $acc):
    if $k <= 0 then $acc
    else ((($k - 1) % 26)) as $r
      | go((($k - 1 - $r) / 26 | floor); ([65 + $r] | implode) + $acc)
    end;
  go($n; "");

def celda($v; $ref):
  if $v == null then ""
  elif ($v | type) == "number" then
    "<c r=\"" + $ref + "\" s=\"2\"><v>" + ($v | tostring) + "</v></c>"
  elif ($v | type) == "boolean" then
    "<c r=\"" + $ref + "\" s=\"2\" t=\"inlineStr\"><is><t>" + (if $v then "Si" else "No" end) + "</t></is></c>"
  else
    ( if ($v | type) == "array" then ($v | map(tostring) | join("; "))
      elif ($v | type) == "object" then ($v | tojson)
      else ($v | tostring) end ) as $s
    | if $s == "" then ""
      else "<c r=\"" + $ref + "\" s=\"2\" t=\"inlineStr\"><is><t xml:space=\"preserve\">"
           + ($s | @html) + "</t></is></c>"
      end
  end;

($cols | length) as $nc
| ($nc | colname(.)) as $ultcol
| (. | length) as $nfilas

# <cols>: anchos de columna
| ( "<cols>" +
    ( [ range(0; $nc) | . as $i |
        "<col min=\"" + (($i+1)|tostring) + "\" max=\"" + (($i+1)|tostring) +
        "\" width=\"" + (($anchos[$i] // 18) | tostring) + "\" customWidth=\"1\"/>" ]
      | join("") ) + "</cols>" ) as $colsxml

# Fila de encabezado (estilo 1)
| ( "<row r=\"1\" ht=\"28\" customHeight=\"1\">" +
    ( [ range(0; $nc) | . as $i |
        "<c r=\"" + (($i+1)|colname(.)) + "1\" s=\"1\" t=\"inlineStr\"><is><t xml:space=\"preserve\">"
        + ($cols[$i] | @html) + "</t></is></c>" ]
      | join("") ) + "</row>" ) as $encabezado

# Filas de datos
| ( [ to_entries[] | .key as $r | .value as $obj |
      "<row r=\"" + (($r + 2)|tostring) + "\">" +
      ( [ range(0; $nc) | . as $i |
          celda($obj[$cols[$i]]; (($i+1)|colname(.)) + (($r+2)|tostring)) ]
        | join("") ) + "</row>" ]
    | join("") ) as $filas

| "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
+ "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">"
+ "<sheetViews><sheetView workbookViewId=\"0\">"
+ "<pane ySplit=\"1\" topLeftCell=\"A2\" activePane=\"bottomLeft\" state=\"frozen\"/>"
+ "</sheetView></sheetViews>"
+ $colsxml
+ "<sheetData>" + $encabezado + $filas + "</sheetData>"
+ "<autoFilter ref=\"A1:" + $ultcol + (([$nfilas + 1, 1] | max) | tostring) + "\"/>"
+ "</worksheet>"
JQEOF
}

# xlsx_sheet <nombre> <json_array> <columnas_csv> [anchos_csv]
#
# Si se omiten las columnas se toman las claves del primer objeto.
# Si se omiten los anchos se calcula uno aproximado por longitud de contenido.
xlsx_sheet() {
    local nombre=$1 datos=$2 columnas=${3:-} anchos=${4:-}

    [ -n "$datos" ] || datos='[]'
    printf '%s' "$datos" | jq -e 'type == "array"' >/dev/null 2>&1 || datos='[]'

    # Excel limita el nombre de hoja a 31 caracteres y prohibe : \ / ? * [ ]
    nombre=$(printf '%s' "$nombre" | tr ':\\/?*[]' '-------')
    nombre=${nombre:0:31}

    local cols_json anchos_json
    if [ -n "$columnas" ]; then
        cols_json=$(printf '%s' "$columnas" | jq -Rc 'split(",") | map(gsub("^\\s+|\\s+$";""))')
    else
        cols_json=$(printf '%s' "$datos" | jq -c 'if length > 0 then (.[0] | keys_unsorted) else ["(sin datos)"] end')
    fi

    if [ -n "$anchos" ]; then
        anchos_json=$(printf '%s' "$anchos" | jq -Rc 'split(",") | map(tonumber? // 18)')
    else
        # Ancho por contenido, acotado entre 10 y 60, muestreando las primeras 80 filas
        anchos_json=$(printf '%s' "$datos" | jq -c --argjson cols "$cols_json" '
            . as $d | [ $cols[] | . as $c |
                ([ ($c | length) ] + [ $d[0:80][] | (.[$c] // "" | tostring | length) ] | max) as $m
                | ([[$m + 2, 10] | max, 60] | min) ]')
    fi

    XLSX_N=$((XLSX_N + 1))
    XLSX_NOMBRES+=("$nombre")

    printf '%s' "$datos" |
        jq -r --argjson cols "$cols_json" --argjson anchos "$anchos_json" \
           "$(_xlsx_sheet_jq)" > "$XLSX_DIR/xl/worksheets/sheet$XLSX_N.xml"
}

# xlsx_finish <destino> [titulo] [autor]
xlsx_finish() {
    local destino=$1 titulo=${2:-Auditoria} autor=${3:-Suite de Auditoria}
    local i fecha
    fecha=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    [ "$XLSX_N" -gt 0 ] || { xlsx_cleanup; return 1; }

    # --- [Content_Types].xml ---
    {
        printf '%s' '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        printf '%s' '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        printf '%s' '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        printf '%s' '<Default Extension="xml" ContentType="application/xml"/>'
        printf '%s' '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        printf '%s' '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        printf '%s' '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
        for i in $(seq 1 "$XLSX_N"); do
            printf '<Override PartName="/xl/worksheets/sheet%s.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' "$i"
        done
        printf '%s' '</Types>'
    } > "$XLSX_DIR/[Content_Types].xml"

    # --- _rels/.rels ---
    {
        printf '%s' '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        printf '%s' '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        printf '%s' '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        printf '%s' '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
        printf '%s' '</Relationships>'
    } > "$XLSX_DIR/_rels/.rels"

    # --- docProps/core.xml ---
    {
        printf '%s' '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        printf '%s' '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        printf '%s' 'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
        printf '%s' 'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        printf '<dc:title>%s</dc:title>' "$(xml_escape "$titulo")"
        printf '<dc:creator>%s</dc:creator>' "$(xml_escape "$autor")"
        printf '<cp:lastModifiedBy>%s</cp:lastModifiedBy>' "$(xml_escape "$autor")"
        printf '<dcterms:created xsi:type="dcterms:W3CDTF">%s</dcterms:created>' "$fecha"
        printf '<dcterms:modified xsi:type="dcterms:W3CDTF">%s</dcterms:modified>' "$fecha"
        printf '%s' '</cp:coreProperties>'
    } > "$XLSX_DIR/docProps/core.xml"

    # --- xl/workbook.xml ---
    {
        printf '%s' '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        printf '%s' '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        printf '%s' 'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
        for i in $(seq 1 "$XLSX_N"); do
            printf '<sheet name="%s" sheetId="%s" r:id="rId%s"/>' \
                "$(xml_escape "${XLSX_NOMBRES[$((i-1))]}")" "$i" "$i"
        done
        printf '%s' '</sheets></workbook>'
    } > "$XLSX_DIR/xl/workbook.xml"

    # --- xl/_rels/workbook.xml.rels ---
    {
        printf '%s' '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        printf '%s' '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        for i in $(seq 1 "$XLSX_N"); do
            printf '<Relationship Id="rId%s" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet%s.xml"/>' "$i" "$i"
        done
        printf '<Relationship Id="rId%s" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>' "$((XLSX_N + 1))"
        printf '%s' '</Relationships>'
    } > "$XLSX_DIR/xl/_rels/workbook.xml.rels"

    # --- xl/styles.xml ---
    # s=0 normal | s=1 encabezado (negrita, blanco sobre azul) | s=2 celda con ajuste
    cat > "$XLSX_DIR/xl/styles.xml" <<'STYEOF'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="10"/><name val="Calibri"/></font><font><b/><sz val="10"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font></fonts><fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF1F4E79"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="2"><border><left/><right/><top/><bottom/><diagonal/></border><border><left style="thin"><color rgb="FFD0D7DE"/></left><right style="thin"><color rgb="FFD0D7DE"/></right><top style="thin"><color rgb="FFD0D7DE"/></top><bottom style="thin"><color rgb="FFD0D7DE"/></bottom><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="left" vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>
STYEOF

    if zip_dir "$XLSX_DIR" "$destino"; then
        xlsx_cleanup
        return 0
    fi
    xlsx_cleanup
    return 1
}
