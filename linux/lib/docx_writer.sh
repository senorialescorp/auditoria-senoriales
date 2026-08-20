#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# docx_writer.sh
# Generador de archivos .docx nativo (equivalente de Modules/AuditCore/WordWriter.psm1).
#
# Escribe el formato OOXML (WordprocessingML) directamente y lo empaqueta como
# ZIP. NO requiere LibreOffice, pandoc ni python-docx: importante porque en un
# servidor de produccion normalmente no existe ninguno, y porque instalar
# dependencias en el activo auditado contradice el principio de que la auditoria
# no debe alterar el sistema.
#
# Mismo criterio de diseno que lib/xlsx_writer.sh.
#
# Soporta: titulos, parrafos, tablas con encabezado y sombreado, filas de
# indicadores, barras de proporcion, notas destacadas, bloque de firmas, salto
# de pagina y pie con numeracion.
# ---------------------------------------------------------------------------

# --- Constantes de pagina (A4, en twips: 1 mm = 56.7 twips) ----------------
DOCX_PG_ANCHO=11906     # A4 ancho
DOCX_PG_ALTO=16838      # A4 alto
DOCX_PG_MARGEN=680      # 12 mm izquierda/derecha
DOCX_PG_MARGENV=720     # 12.7 mm arriba/abajo
DOCX_ANCHO_UTIL=$(( DOCX_PG_ANCHO - 2 * DOCX_PG_MARGEN ))   # 10546

# --- Paleta (coherente con la ficha HTML de la suite) ----------------------
C_AZUL='1F4E79'; C_TINTA='1A1F26'; C_GRISW='5B6673'
C_BORDE='D5DAE0'; C_FONDO='EEF2F6'
C_CRIT='C0272D'; C_ALTO='E06C00'; C_MEDIOW='8A6D00'
C_BAJO='2C7BB6'; C_OKW='1A7F4B'

# Acumulador de bloques del documento
DOCX_BLOQUES=''
docx_add() { DOCX_BLOQUES="$DOCX_BLOQUES$1"; }
docx_reset() { DOCX_BLOQUES=''; }

# ---------------------------------------------------------------------------
# Primitivas
# ---------------------------------------------------------------------------

# w_runprops [puntos] [color] [negrita] [cursiva] [mono] [espaciado]
# Word usa medios puntos para el tamano de fuente.
w_runprops() {
    local pts=${1:-9.5} color=${2:-$C_TINTA} negrita=${3:-} cursiva=${4:-} mono=${5:-} esp=${6:-0}
    local sz; sz=$(awk -v p="$pts" 'BEGIN{printf "%d", p*2}')
    printf '<w:rPr>'
    [ -n "$mono" ]    && printf '<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/>'
    [ -n "$negrita" ] && printf '<w:b/>'
    [ -n "$cursiva" ] && printf '<w:i/>'
    printf '<w:color w:val="%s"/><w:sz w:val="%s"/><w:szCs w:val="%s"/>' "$color" "$sz" "$sz"
    [ "$esp" -ne 0 ] 2>/dev/null && printf '<w:spacing w:val="%s"/>' "$esp"
    printf '</w:rPr>'
}

# w_run <texto> <props>
w_run() {
    printf '<w:r>%s<w:t xml:space="preserve">%s</w:t></w:r>' "${2:-}" "$(xml_escape "${1:-}")"
}

# w_parrafo <contenido> [alineacion] [espacio_antes] [espacio_despues]
#           [borde_inferior_color] [grosor_borde] [sombreado] [sangria] [salto_pagina]
w_parrafo() {
    local contenido=${1:-} alin=${2:-left} antes=${3:-0} despues=${4:-60}
    local borde=${5:-} grosor=${6:-8} sombra=${7:-} sangria=${8:-0} salto=${9:-}
    printf '<w:p><w:pPr>'
    [ -n "$salto" ]  && printf '<w:pageBreakBefore/>'
    [ -n "$sombra" ] && printf '<w:shd w:val="clear" w:color="auto" w:fill="%s"/>' "$sombra"
    [ -n "$borde" ]  && printf '<w:pBdr><w:bottom w:val="single" w:sz="%s" w:space="2" w:color="%s"/></w:pBdr>' "$grosor" "$borde"
    [ "$sangria" -ne 0 ] 2>/dev/null && printf '<w:ind w:left="%s"/>' "$sangria"
    printf '<w:spacing w:before="%s" w:after="%s"/><w:jc w:val="%s"/></w:pPr>%s</w:p>' \
        "$antes" "$despues" "$alin" "$contenido"
}

# w_celda <contenido> <ancho_twips> [sombreado] [sin_bordes] [alineacion_v]
w_celda() {
    local contenido=${1:-} ancho=${2:-1000} sombra=${3:-} sin_bordes=${4:-} valign=${5:-top}
    printf '<w:tc><w:tcPr><w:tcW w:w="%s" w:type="dxa"/>' "$ancho"
    [ -n "$sin_bordes" ] && printf '<w:tcBorders><w:top w:val="nil"/><w:left w:val="nil"/><w:bottom w:val="nil"/><w:right w:val="nil"/></w:tcBorders>'
    [ -n "$sombra" ] && printf '<w:shd w:val="clear" w:color="auto" w:fill="%s"/>' "$sombra"
    printf '<w:vAlign w:val="%s"/></w:tcPr>%s</w:tc>' "$valign" "$contenido"
}

# w_tabla_apertura <anchos separados por espacio> [sin_bordes]
w_tabla_apertura() {
    local anchos=$1 sin_bordes=${2:-} a lado
    printf '<w:tbl><w:tblPr><w:tblW w:w="5000" w:type="pct"/>'
    if [ -n "$sin_bordes" ]; then
        printf '<w:tblBorders><w:top w:val="nil"/><w:left w:val="nil"/><w:bottom w:val="nil"/><w:right w:val="nil"/><w:insideH w:val="nil"/><w:insideV w:val="nil"/></w:tblBorders>'
    else
        printf '<w:tblBorders>'
        for lado in top left bottom right insideH insideV; do
            printf '<w:%s w:val="single" w:sz="4" w:space="0" w:color="%s"/>' "$lado" "$C_BORDE"
        done
        printf '</w:tblBorders>'
    fi
    printf '<w:tblCellMar><w:top w:w="60" w:type="dxa"/><w:left w:w="80" w:type="dxa"/><w:bottom w:w="60" w:type="dxa"/><w:right w:w="80" w:type="dxa"/></w:tblCellMar>'
    printf '<w:tblLayout w:type="fixed"/></w:tblPr><w:tblGrid>'
    for a in $anchos; do printf '<w:gridCol w:w="%s"/>' "$a"; done
    printf '</w:tblGrid>'
}

# w_anchos <porcentajes separados por espacio> -> anchos en twips que suman el ancho util
w_anchos() {
    printf '%s\n' "$@" | tr ' ' '\n' | awk -v util="$DOCX_ANCHO_UTIL" '
        { p[NR]=$1 } END {
            acum=0
            for (i=1; i<=NR; i++) {
                if (i == NR) w = util - acum
                else { w = int((p[i]/100.0) * util); acum += w }
                printf "%d ", w
            }
        }'
}

# ---------------------------------------------------------------------------
# Bloques de alto nivel
# ---------------------------------------------------------------------------

# docx_titulo <texto> [subtitulo] [texto_derecha_multilinea]
docx_titulo() {
    local texto=$1 sub=${2:-} der=${3:-}
    local anchos; anchos=$(w_anchos 68 32)
    set -- $anchos
    local a1=$1 a2=$2
    local izq der_xml linea

    izq=$(w_parrafo "$(w_run "$texto" "$(w_runprops 16 "$C_TINTA" b)")" left 0 20)
    [ -n "$sub" ] && izq="$izq$(w_parrafo "$(w_run "$sub" "$(w_runprops 9 "$C_GRISW")")" left 0 0)"

    der_xml=''
    while IFS= read -r linea; do
        [ -n "$(safe_str "$linea")" ] || continue
        der_xml="$der_xml$(w_parrafo "$(w_run "$linea" "$(w_runprops 8 "$C_GRISW")")" right 0 10)"
    done <<< "$der"
    [ -n "$der_xml" ] || der_xml=$(w_parrafo '')

    {
        w_tabla_apertura "$a1 $a2" sinbordes
        printf '<w:tr>'
        w_celda "$izq" "$a1" '' sinbordes
        w_celda "$der_xml" "$a2" '' sinbordes
        printf '</w:tr></w:tbl>'
        # Regla gruesa bajo la cabecera
        w_parrafo '' left 0 140 "$C_AZUL" 20
    }
}

docx_seccion() {
    w_parrafo "$(w_run "$(printf '%s' "$1" | tr 'a-záéíóúñ' 'A-ZÁÉÍÓÚÑ')" "$(w_runprops 10 "$C_AZUL" b '' '' 14)")" \
        left 180 70 "$C_AZUL" 12
}

# docx_parrafo <texto> [puntos] [color] [cursiva]
docx_parrafo() {
    w_parrafo "$(w_run "$1" "$(w_runprops "${2:-9}" "${3:-$C_TINTA}" '' "${4:-}")")" both 0 80
}

docx_nota() {
    local titulo=$1 texto=$2 c
    c=$(w_run "$titulo" "$(w_runprops 9 '7A5C00' b)")
    c="$c$(w_run " $texto" "$(w_runprops 9 '5C4700')")"
    w_parrafo "$c" both 60 110 '' 8 'FDF6E3' 80
}

# docx_indicadores <n>  seguido de n grupos: valor, etiqueta, color, fondo
# Se pasan por stdin como TSV: valor<TAB>etiqueta<TAB>color<TAB>fondo
docx_indicadores() {
    local filas=() linea
    # Se descarta un CR final: las filas suelen llegar de jq por tuberia
    while IFS= read -r linea; do linea=${linea%$'\r'}; [ -n "$linea" ] && filas+=("$linea"); done
    local n=${#filas[@]}
    [ "$n" -gt 0 ] || return 0

    local base=$(( 100 / n )) pcts='' i
    for ((i=0; i<n; i++)); do pcts="$pcts $base"; done
    local anchos; anchos=$(w_anchos $pcts)
    set -- $anchos

    w_tabla_apertura "$anchos"
    printf '<w:tr>'
    i=0
    for linea in "${filas[@]}"; do
        i=$((i + 1))
        local valor etiqueta color fondo ancho c
        IFS=$'\t' read -r valor etiqueta color fondo <<< "$linea"
        [ -n "$color" ] || color=$C_TINTA
        [ -n "$fondo" ] || fondo='FFFFFF'
        ancho=$(eval "printf '%s' \"\${$i}\"")
        c=$(w_parrafo "$(w_run "$valor" "$(w_runprops 17 "$color" b)")" center 0 10)
        c="$c$(w_parrafo "$(w_run "$(printf '%s' "$etiqueta" | tr 'a-z' 'A-Z')" "$(w_runprops 7 "$C_GRISW" '' '' '' 8)")" center 0 0)"
        w_celda "$c" "$ancho" "$fondo"
    done
    printf '</w:tr></w:tbl>'
    w_parrafo '' left 0 40
}

# docx_tabla <encabezados_tsv> <porcentajes> [puntos] [primera_columna_clave]
# Las filas se leen de stdin como TSV. Un campo puede llevar el prefijo
# "@COLOR#" para pintar la primera celda de la fila (severidad).
docx_tabla() {
    local encabezados=$1 pcts=$2 puntos=${3:-8.3} clave=${4:-}
    local anchos; anchos=$(w_anchos $pcts)
    local -a A
    read -ra A <<< "$anchos"
    local nc=${#A[@]}

    w_tabla_apertura "$anchos"

    # Encabezado, marcado para repetirse en cada pagina
    printf '<w:tr><w:trPr><w:tblHeader/><w:cantSplit/></w:trPr>'
    local i=0 h
    while IFS= read -r h; do
        [ "$i" -lt "$nc" ] || break
        w_celda "$(w_parrafo "$(w_run "$(printf '%s' "$h" | tr 'a-z' 'A-Z')" "$(w_runprops 7.4 "$C_AZUL" b '' '' 6)")" left 0 0)" \
            "${A[$i]}" "$C_FONDO"
        i=$((i + 1))
    done < <(printf '%s' "$encabezados" | tr '\t' '\n')
    printf '</w:tr>'

    # Filas
    local linea
    while IFS= read -r linea; do
        linea=${linea%$'\r'}
        [ -n "$linea" ] || continue
        local color_fila=''
        case $linea in
            @*#*) color_fila=${linea#@}; color_fila=${color_fila%%#*}; linea=${linea#@*#} ;;
        esac
        printf '<w:tr><w:trPr><w:cantSplit/></w:trPr>'
        local -a campos
        IFS=$'\t' read -ra campos <<< "$linea"
        for ((i=0; i<nc; i++)); do
            local valor=${campos[$i]:-} color=$C_TINTA props fondo=''
            if [ "$i" -eq 0 ]; then
                [ -n "$color_fila" ] && color=$color_fila
                if [ -n "$clave" ]; then fondo='F7F9FB'; fi
            fi
            if [ "$i" -eq 0 ] && { [ -n "$clave" ] || [ -n "$color_fila" ]; }; then
                props=$(w_runprops "$puntos" "$color" b)
            else
                props=$(w_runprops "$puntos" "$color")
            fi
            w_celda "$(w_parrafo "$(w_run "$valor" "$props")" left 0 0)" "${A[$i]}" "$fondo"
        done
        printf '</w:tr>'
    done
    printf '</w:tbl>'
    w_parrafo '' left 0 40
}

# docx_barras: filas por stdin como TSV: nombre<TAB>valor<TAB>proporcion(0..1)<TAB>nota<TAB>destacar
docx_barras() {
    local anchos; anchos=$(w_anchos 34 8 44 14)
    local -a A; read -ra A <<< "$anchos"

    w_tabla_apertura "$anchos" sinbordes
    local linea
    while IFS= read -r linea; do
        linea=${linea%$'\r'}
        [ -n "$linea" ] || continue
        local nombre valor prop nota destacar
        IFS=$'\t' read -r nombre valor prop nota destacar <<< "$linea"

        printf '<w:tr><w:trPr><w:cantSplit/></w:trPr>'

        local props
        if [ -n "$destacar" ]; then props=$(w_runprops 8.3 "$C_TINTA" b); else props=$(w_runprops 8.3); fi
        w_celda "$(w_parrafo "$(w_run "$nombre" "$props")" left 0 0)" "${A[0]}" '' sinbordes
        w_celda "$(w_parrafo "$(w_run "$valor" "$(w_runprops 8.3 "$C_TINTA" b)")" right 0 0)" "${A[1]}" '' sinbordes

        # Barra: tabla anidada de dos celdas (lleno / vacio)
        local w_lleno w_vacio color_barra
        w_lleno=$(awk -v a="${A[2]}" -v p="${prop:-0}" 'BEGIN{
            if (p < 0) p = 0; if (p > 1) p = 1;
            v = int(a * p); if (v < 20 && p > 0) v = 20; print v }')
        w_vacio=$(( ${A[2]} - w_lleno ))
        [ "$w_vacio" -lt 0 ] && w_vacio=0
        color_barra=$C_AZUL
        [ -n "$destacar" ] && color_barra=$C_CRIT

        local barra
        barra=$( {
            w_tabla_apertura "$(( w_lleno > 0 ? w_lleno : 1 )) $(( w_vacio > 0 ? w_vacio : 1 ))" sinbordes
            printf '<w:tr><w:trPr><w:trHeight w:val="120" w:hRule="exact"/></w:trPr>'
            if [ "$w_lleno" -gt 0 ]; then
                w_celda "$(w_parrafo '' left 0 0)" "$w_lleno" "$color_barra" sinbordes
            else
                w_celda "$(w_parrafo '' left 0 0)" 1 '' sinbordes
            fi
            if [ "$w_vacio" -gt 0 ]; then
                w_celda "$(w_parrafo '' left 0 0)" "$w_vacio" "$C_FONDO" sinbordes
            else
                w_celda "$(w_parrafo '' left 0 0)" 1 '' sinbordes
            fi
            printf '</w:tr></w:tbl>'
            # Una celda que contiene una tabla necesita un parrafo vacio al final
            w_parrafo '' left 0 0
        } )
        w_celda "$barra" "${A[2]}" '' sinbordes center
        w_celda "$(w_parrafo "$(w_run "$nota" "$(w_runprops 7.5 "$C_GRISW")")" left 0 0)" "${A[3]}" '' sinbordes
        printf '</w:tr>'
    done
    printf '</w:tbl>'
    w_parrafo '' left 0 40
}

docx_firmas() {
    local etiquetas=("$@")
    [ ${#etiquetas[@]} -gt 0 ] || etiquetas=('Elaborado por' 'Revisado por' 'Responsable del activo')
    local n=${#etiquetas[@]} base=$(( 100 / ${#etiquetas[@]} )) pcts='' i
    for ((i=0; i<n; i++)); do pcts="$pcts $base"; done
    local anchos; anchos=$(w_anchos $pcts)
    local -a A; read -ra A <<< "$anchos"

    w_parrafo '' left 300 0
    w_tabla_apertura "$anchos" sinbordes
    printf '<w:tr>'
    for ((i=0; i<n; i++)); do
        local c
        c=$(w_parrafo '' left 0 40 '4B5563' 6)
        c="$c$(w_parrafo "$(w_run "${etiquetas[$i]}" "$(w_runprops 7.5 "$C_GRISW")")" center 0 0)"
        w_celda "$c" "${A[$i]}" '' sinbordes
    done
    printf '</w:tr></w:tbl>'
}

docx_salto_pagina() { w_parrafo '' left 0 0 '' 8 '' 0 salto; }

# ---------------------------------------------------------------------------
# Emision del paquete
# ---------------------------------------------------------------------------

# docx_finish <destino> [titulo] [autor] [pie_izquierda]
docx_finish() {
    local destino=$1 titulo=${2:-Documento} autor=${3:-Suite de Auditoria} pie=${4:-}
    local dir; dir=$(mktemp -d)
    local fecha; fecha=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    mkdir -p "$dir/_rels" "$dir/docProps" "$dir/word/_rels"

    cat > "$dir/[Content_Types].xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>
EOF

    cat > "$dir/_rels/.rels" <<'EOF'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>
EOF

    cat > "$dir/word/_rels/document.xml.rels" <<'EOF'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/></Relationships>
EOF

    cat > "$dir/word/styles.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI" w:eastAsia="Segoe UI" w:cs="Segoe UI"/><w:sz w:val="19"/><w:szCs w:val="19"/><w:lang w:val="es-GT"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="60" w:line="240" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults><w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style></w:styles>
EOF

    # Pie de pagina con numeracion "Pagina X de Y"
    {
        printf '%s' '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        printf '%s' '<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        printf '<w:p><w:pPr><w:pBdr><w:top w:val="single" w:sz="4" w:space="2" w:color="%s"/></w:pBdr>' "$C_BORDE"
        printf '<w:tabs><w:tab w:val="right" w:pos="%s"/></w:tabs>' "$DOCX_ANCHO_UTIL"
        printf '%s' '<w:spacing w:before="60" w:after="0"/></w:pPr>'
        local rpr; rpr=$(printf '<w:rPr><w:color w:val="%s"/><w:sz w:val="14"/></w:rPr>' "$C_GRISW")
        printf '<w:r>%s<w:t xml:space="preserve">%s</w:t></w:r>' "$rpr" "$(xml_escape "$pie")"
        printf '<w:r>%s<w:tab/><w:t xml:space="preserve">Pagina </w:t></w:r>' "$rpr"
        printf '<w:r>%s<w:fldChar w:fldCharType="begin"/></w:r>' "$rpr"
        printf '<w:r>%s<w:instrText xml:space="preserve">PAGE</w:instrText></w:r>' "$rpr"
        printf '<w:r>%s<w:fldChar w:fldCharType="end"/></w:r>' "$rpr"
        printf '<w:r>%s<w:t xml:space="preserve"> de </w:t></w:r>' "$rpr"
        printf '<w:r>%s<w:fldChar w:fldCharType="begin"/></w:r>' "$rpr"
        printf '<w:r>%s<w:instrText xml:space="preserve">NUMPAGES</w:instrText></w:r>' "$rpr"
        printf '<w:r>%s<w:fldChar w:fldCharType="end"/></w:r>' "$rpr"
        printf '%s' '</w:p></w:ftr>'
    } > "$dir/word/footer1.xml"

    {
        printf '%s' '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        printf '%s' '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        printf '%s' 'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
        printf '%s' 'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        printf '<dc:title>%s</dc:title><dc:creator>%s</dc:creator><cp:lastModifiedBy>%s</cp:lastModifiedBy>' \
            "$(xml_escape "$titulo")" "$(xml_escape "$autor")" "$(xml_escape "$autor")"
        printf '<dcterms:created xsi:type="dcterms:W3CDTF">%s</dcterms:created>' "$fecha"
        printf '<dcterms:modified xsi:type="dcterms:W3CDTF">%s</dcterms:modified>' "$fecha"
        printf '%s' '</cp:coreProperties>'
    } > "$dir/docProps/core.xml"

    cat > "$dir/docProps/app.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><Application>Suite de Auditoria - docx_writer</Application><Company></Company></Properties>
EOF

    {
        printf '%s' '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        printf '%s' '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
        printf '%s' 'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body>'
        printf '%s' "$DOCX_BLOQUES"
        printf '%s' '<w:sectPr><w:footerReference w:type="default" r:id="rId2"/>'
        printf '<w:pgSz w:w="%s" w:h="%s"/>' "$DOCX_PG_ANCHO" "$DOCX_PG_ALTO"
        printf '<w:pgMar w:top="%s" w:right="%s" w:bottom="%s" w:left="%s" w:header="340" w:footer="340" w:gutter="0"/>' \
            "$DOCX_PG_MARGENV" "$DOCX_PG_MARGEN" "$DOCX_PG_MARGENV" "$DOCX_PG_MARGEN"
        printf '%s' '<w:cols w:space="708"/><w:docGrid w:linePitch="360"/></w:sectPr>'
        printf '%s' '</w:body></w:document>'
    } > "$dir/word/document.xml"

    if zip_dir "$dir" "$destino"; then
        rm -rf "$dir"
        return 0
    fi
    rm -rf "$dir"
    return 1
}
