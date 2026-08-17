<#
    ExcelWriter.psm1

    Generador de archivos .xlsx nativo.

    Escribe el formato OOXML (SpreadsheetML) directamente sobre un contenedor
    ZIP usando System.IO.Compression. NO requiere Microsoft Excel instalado,
    ni el modulo ImportExcel, ni interoperabilidad COM: importante porque en un
    servidor de produccion normalmente no existe ninguno de los tres, y porque
    instalar dependencias en el activo auditado contradice el principio de que
    la auditoria no debe alterar el sistema.

    Soporta: multiples hojas, encabezado con formato, ancho de columna,
    inmovilizar paneles, autofiltro, tipos numericos y ajuste de texto.
#>

Add-Type -AssemblyName System.IO.Compression      -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# Utilidades internas
# ---------------------------------------------------------------------------

function ConvertTo-XmlText {
    param([AllowNull()]$Valor)
    if ($null -eq $Valor) { return '' }
    $s = [string]$Valor

    # Excel rechaza los caracteres de control salvo tabulacion, LF y CR
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $s.ToCharArray()) {
        $code = [int]$ch
        if ($code -lt 32 -and $code -ne 9 -and $code -ne 10 -and $code -ne 13) { continue }
        $null = $sb.Append($ch)
    }
    $s = $sb.ToString()

    return $s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'",'&apos;')
}

function Get-ColumnName {
    param([int]$Index)   # 1 -> A, 27 -> AA
    $n = $Index
    $nombre = ''
    while ($n -gt 0) {
        $resto = ($n - 1) % 26
        $nombre = [char](65 + $resto) + $nombre
        $n = [int](($n - $resto - 1) / 26)
    }
    return $nombre
}

function Test-EsNumero {
    param($Valor)
    if ($null -eq $Valor) { return $false }
    if ($Valor -is [bool]) { return $false }
    if ($Valor -is [int] -or $Valor -is [long] -or $Valor -is [double] -or
        $Valor -is [decimal] -or $Valor -is [single]) { return $true }
    return $false
}

# ---------------------------------------------------------------------------
# Construccion de una hoja
# ---------------------------------------------------------------------------

function New-SheetXml {
    param(
        [object[]]$Datos,
        [string[]]$Columnas,
        [int[]]$Anchos,
        [switch]$SinEncabezado
    )

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
    $null = $sb.Append('<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">')

    # Ancho de columnas
    if ($Anchos -and $Anchos.Count -gt 0) {
        $null = $sb.Append('<cols>')
        for ($i = 0; $i -lt $Anchos.Count; $i++) {
            $null = $sb.Append(('<col min="{0}" max="{0}" width="{1}" customWidth="1"/>' -f ($i+1), $Anchos[$i]))
        }
        $null = $sb.Append('</cols>')
    }

    $null = $sb.Append('<sheetData>')
    $fila = 1

    # Encabezado (estilo 1: negrita sobre fondo)
    if (-not $SinEncabezado) {
        $null = $sb.Append(('<row r="{0}" ht="28" customHeight="1">' -f $fila))
        for ($c = 0; $c -lt $Columnas.Count; $c++) {
            $ref = (Get-ColumnName ($c+1)) + $fila
            $null = $sb.Append(('<c r="{0}" s="1" t="inlineStr"><is><t xml:space="preserve">{1}</t></is></c>' -f `
                $ref, (ConvertTo-XmlText $Columnas[$c])))
        }
        $null = $sb.Append('</row>')
        $fila++
    }

    foreach ($d in $Datos) {
        $null = $sb.Append(('<row r="{0}">' -f $fila))
        for ($c = 0; $c -lt $Columnas.Count; $c++) {
            $valor = $null
            if ($d -is [hashtable]) { $valor = $d[$Columnas[$c]] }
            else {
                $prop = $d.PSObject.Properties[$Columnas[$c]]
                if ($prop) { $valor = $prop.Value }
            }
            if ($null -eq $valor -or "$valor" -eq '') { continue }

            if ($valor -is [System.Array]) { $valor = ($valor -join '; ') }

            $ref = (Get-ColumnName ($c+1)) + $fila
            if (Test-EsNumero $valor) {
                $num = ([string]$valor) -replace ',', '.'
                $null = $sb.Append(('<c r="{0}" s="2"><v>{1}</v></c>' -f $ref, $num))
            } else {
                $null = $sb.Append(('<c r="{0}" s="2" t="inlineStr"><is><t xml:space="preserve">{1}</t></is></c>' -f `
                    $ref, (ConvertTo-XmlText $valor)))
            }
        }
        $null = $sb.Append('</row>')
        $fila++
    }

    $null = $sb.Append('</sheetData>')

    # Inmovilizar la fila de encabezado y activar autofiltro
    if (-not $SinEncabezado -and $Columnas.Count -gt 0) {
        $ultima = (Get-ColumnName $Columnas.Count) + [string]([math]::Max($fila-1,1))
        $null = $sb.Append(('<autoFilter ref="A1:{0}"/>' -f $ultima))
    }
    $null = $sb.Append('</worksheet>')

    # sheetView con panel congelado debe ir antes de sheetData
    $vista = if (-not $SinEncabezado) {
        '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>'
    } else { '' }

    return $sb.ToString().Replace(
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' + $vista)
}

# ---------------------------------------------------------------------------
# API publica
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Genera un archivo .xlsx con una o varias hojas.

.PARAMETER Hojas
    Arreglo de hashtables, una por hoja:
      @{ Nombre='Hallazgos'; Datos=$objetos; Columnas=@('A','B'); Anchos=@(20,60) }
    Si se omite Columnas, se toman las propiedades del primer objeto.
    Si se omite Anchos, se calcula un ancho aproximado por contenido.
#>
function Export-ToExcel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object[]]$Hojas,
        [string]$Titulo = 'Auditoria',
        [string]$Autor  = 'Suite de Auditoria'
    )

    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }

    $enc = New-Object System.Text.UTF8Encoding($false)
    $zip = $null

    try {
        $fs  = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew)
        $zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)

        function Add-Entrada {
            param([string]$Nombre, [string]$Contenido)
            $e = $zip.CreateEntry($Nombre, [System.IO.Compression.CompressionLevel]::Optimal)
            $s = $e.Open()
            $bytes = $enc.GetBytes($Contenido)
            $s.Write($bytes, 0, $bytes.Length)
            $s.Dispose()
        }

        # --- Normalizar hojas y resolver columnas / anchos ---
        $prep = @()
        $idx  = 1
        foreach ($h in $Hojas) {
            $datos = @($h.Datos)
            $cols  = if ($h.Columnas) { @($h.Columnas) }
                     elseif ($datos.Count -gt 0) { @($datos[0].PSObject.Properties.Name) }
                     else { @('(sin datos)') }

            $anchos = if ($h.Anchos) { @($h.Anchos) } else {
                @($cols | ForEach-Object {
                    $col = $_
                    $max = $col.Length
                    foreach ($d in ($datos | Select-Object -First 80)) {
                        $p = $d.PSObject.Properties[$col]
                        if ($p -and $p.Value) {
                            $l = ([string]$p.Value).Length
                            if ($l -gt $max) { $max = $l }
                        }
                    }
                    [math]::Min([math]::Max($max + 2, 10), 60)
                })
            }

            # Excel limita el nombre de hoja a 31 caracteres y prohibe : \ / ? * [ ]
            $nombre = ($h.Nombre -replace '[:\\/\?\*\[\]]', '-')
            if ($nombre.Length -gt 31) { $nombre = $nombre.Substring(0,31) }

            $prep += [pscustomobject]@{
                Nombre = $nombre; Datos = $datos; Columnas = $cols; Anchos = $anchos; Indice = $idx
            }
            $idx++
        }

        # --- [Content_Types].xml ---
        $ct = New-Object System.Text.StringBuilder
        $null = $ct.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
        $null = $ct.Append('<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">')
        $null = $ct.Append('<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>')
        $null = $ct.Append('<Default Extension="xml" ContentType="application/xml"/>')
        $null = $ct.Append('<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>')
        $null = $ct.Append('<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>')
        $null = $ct.Append('<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>')
        foreach ($p in $prep) {
            $null = $ct.Append(('<Override PartName="/xl/worksheets/sheet{0}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' -f $p.Indice))
        }
        $null = $ct.Append('</Types>')
        Add-Entrada '[Content_Types].xml' $ct.ToString()

        # --- _rels/.rels ---
        Add-Entrada '_rels/.rels' (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>' +
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>' +
            '</Relationships>')

        # --- docProps/core.xml ---
        $fecha = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssZ')
        Add-Entrada 'docProps/core.xml' (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" ' +
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" ' +
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">' +
            "<dc:title>$(ConvertTo-XmlText $Titulo)</dc:title>" +
            "<dc:creator>$(ConvertTo-XmlText $Autor)</dc:creator>" +
            "<cp:lastModifiedBy>$(ConvertTo-XmlText $Autor)</cp:lastModifiedBy>" +
            "<dcterms:created xsi:type=`"dcterms:W3CDTF`">$fecha</dcterms:created>" +
            "<dcterms:modified xsi:type=`"dcterms:W3CDTF`">$fecha</dcterms:modified>" +
            '</cp:coreProperties>')

        # --- xl/workbook.xml ---
        $wb = New-Object System.Text.StringBuilder
        $null = $wb.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
        $null = $wb.Append('<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" ')
        $null = $wb.Append('xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>')
        foreach ($p in $prep) {
            $null = $wb.Append(('<sheet name="{0}" sheetId="{1}" r:id="rId{1}"/>' -f (ConvertTo-XmlText $p.Nombre), $p.Indice))
        }
        $null = $wb.Append('</sheets></workbook>')
        Add-Entrada 'xl/workbook.xml' $wb.ToString()

        # --- xl/_rels/workbook.xml.rels ---
        $rels = New-Object System.Text.StringBuilder
        $null = $rels.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
        $null = $rels.Append('<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">')
        foreach ($p in $prep) {
            $null = $rels.Append(('<Relationship Id="rId{0}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{0}.xml"/>' -f $p.Indice))
        }
        $null = $rels.Append(('<Relationship Id="rId{0}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>' -f ($prep.Count + 1)))
        $null = $rels.Append('</Relationships>')
        Add-Entrada 'xl/_rels/workbook.xml.rels' $rels.ToString()

        # --- xl/styles.xml ---
        # s=0 normal | s=1 encabezado (negrita, blanco sobre azul) | s=2 celda con ajuste
        Add-Entrada 'xl/styles.xml' (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
            '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' +
            '<fonts count="2">' +
              '<font><sz val="10"/><name val="Calibri"/></font>' +
              '<font><b/><sz val="10"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>' +
            '</fonts>' +
            '<fills count="3">' +
              '<fill><patternFill patternType="none"/></fill>' +
              '<fill><patternFill patternType="gray125"/></fill>' +
              '<fill><patternFill patternType="solid"><fgColor rgb="FF1F4E79"/><bgColor indexed="64"/></patternFill></fill>' +
            '</fills>' +
            '<borders count="2">' +
              '<border><left/><right/><top/><bottom/><diagonal/></border>' +
              '<border><left style="thin"><color rgb="FFD0D7DE"/></left><right style="thin"><color rgb="FFD0D7DE"/></right>' +
              '<top style="thin"><color rgb="FFD0D7DE"/></top><bottom style="thin"><color rgb="FFD0D7DE"/></bottom><diagonal/></border>' +
            '</borders>' +
            '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>' +
            '<cellXfs count="3">' +
              '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>' +
              '<xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1">' +
                '<alignment horizontal="left" vertical="center" wrapText="1"/></xf>' +
              '<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1">' +
                '<alignment vertical="top" wrapText="1"/></xf>' +
            '</cellXfs>' +
            '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>' +
            '</styleSheet>')

        # --- Hojas ---
        foreach ($p in $prep) {
            $xml = New-SheetXml -Datos $p.Datos -Columnas $p.Columnas -Anchos $p.Anchos
            Add-Entrada ('xl/worksheets/sheet{0}.xml' -f $p.Indice) $xml
        }
    }
    finally {
        if ($zip) { $zip.Dispose() }
        if ($fs)  { $fs.Dispose() }
    }

    return $Path
}

Export-ModuleMember -Function 'Export-ToExcel'
