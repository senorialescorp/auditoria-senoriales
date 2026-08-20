<#
    WordWriter.psm1

    Generador de archivos .docx nativo.

    Escribe el formato OOXML (WordprocessingML) directamente sobre un contenedor
    ZIP usando System.IO.Compression. NO requiere Microsoft Word instalado, ni
    interoperabilidad COM, ni modulos externos: importante porque en este
    servidor Word no esta instalado (solo quedan restos de Office14 y la clase
    COM Word.Application no esta registrada), y porque instalar dependencias en
    el activo auditado contradice el principio de que la auditoria no debe
    alterar el sistema.

    Mismo criterio de diseno que ExcelWriter.psm1.

    Soporta: titulos, parrafos, tablas con encabezado y sombreado, filas de
    indicadores, barras de proporcion, notas destacadas, bloque de firmas,
    salto de pagina, encabezado y pie con numeracion.
#>

Add-Type -AssemblyName System.IO.Compression              -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.IO.Compression.FileSystem   -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# Constantes de pagina (A4, en twips: 1 mm = 56.7 twips)
# ---------------------------------------------------------------------------

$script:PG_ANCHO   = 11906   # A4 ancho
$script:PG_ALTO    = 16838   # A4 alto
$script:PG_MARGEN  = 680     # 12 mm izquierda/derecha
$script:PG_MARGENV = 720     # 12.7 mm arriba/abajo
$script:ANCHO_UTIL = $script:PG_ANCHO - (2 * $script:PG_MARGEN)   # 10546

# Paleta (coherente con la ficha HTML de la suite)
$script:C_AZUL   = '1F4E79'
$script:C_TINTA  = '1A1F26'
$script:C_GRIS   = '5B6673'
$script:C_BORDE  = 'D5DAE0'
$script:C_FONDO  = 'EEF2F6'
$script:C_CRIT   = 'C0272D'
$script:C_ALTO   = 'E06C00'
$script:C_MEDIO  = '8A6D00'
$script:C_BAJO   = '2C7BB6'
$script:C_OK     = '1A7F4B'

# ---------------------------------------------------------------------------
# Utilidades internas
# ---------------------------------------------------------------------------

function ConvertTo-WordText {
    param([AllowNull()]$Valor)
    if ($null -eq $Valor) { return '' }
    $s = [string]$Valor

    # Word rechaza los caracteres de control salvo tabulacion, LF y CR
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $s.ToCharArray()) {
        $code = [int]$ch
        if ($code -lt 32 -and $code -ne 9 -and $code -ne 10 -and $code -ne 13) { continue }
        $null = $sb.Append($ch)
    }
    $s = $sb.ToString()

    return $s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'",'&apos;')
}

<#
    Construye las propiedades de una corrida de texto (run).
    Tamano en puntos; Word usa medios puntos.
#>
function New-RunProps {
    param(
        [double]$Puntos = 9.5,
        [string]$Color  = $script:C_TINTA,
        [switch]$Negrita,
        [switch]$Cursiva,
        [switch]$Mono,
        [int]$Espaciado = 0     # letter-spacing en twips
    )
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append('<w:rPr>')
    if ($Mono) {
        $null = $sb.Append('<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/>')
    }
    if ($Negrita) { $null = $sb.Append('<w:b/>') }
    if ($Cursiva) { $null = $sb.Append('<w:i/>') }
    $null = $sb.Append(('<w:color w:val="{0}"/>' -f $Color))
    $null = $sb.Append(('<w:sz w:val="{0}"/>' -f [int]($Puntos * 2)))
    $null = $sb.Append(('<w:szCs w:val="{0}"/>' -f [int]($Puntos * 2)))
    if ($Espaciado -ne 0) { $null = $sb.Append(('<w:spacing w:val="{0}"/>' -f $Espaciado)) }
    $null = $sb.Append('</w:rPr>')
    return $sb.ToString()
}

function New-Run {
    param(
        [string]$Texto,
        [string]$Props = ''
    )
    return ('<w:r>{0}<w:t xml:space="preserve">{1}</w:t></w:r>' -f $Props, (ConvertTo-WordText $Texto))
}

<#
    Parrafo generico.
    $Alineacion: left | center | right | both
#>
function New-Parrafo {
    param(
        [string]$Contenido,                 # runs ya construidos
        [string]$Alineacion = 'left',
        [int]$EspacioAntes  = 0,            # twips
        [int]$EspacioDespues= 60,
        [string]$BordeInferior = '',        # color hex o vacio
        [int]$GrosorBorde   = 8,            # en 1/8 de punto
        [string]$Sombreado  = '',
        [int]$SangriaIzq    = 0,
        [switch]$SaltoPaginaAntes
    )
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append('<w:p><w:pPr>')
    if ($SaltoPaginaAntes) { $null = $sb.Append('<w:pageBreakBefore/>') }
    if ($Sombreado) { $null = $sb.Append(('<w:shd w:val="clear" w:color="auto" w:fill="{0}"/>' -f $Sombreado)) }
    if ($BordeInferior) {
        $null = $sb.Append(('<w:pBdr><w:bottom w:val="single" w:sz="{0}" w:space="2" w:color="{1}"/></w:pBdr>' -f $GrosorBorde, $BordeInferior))
    }
    if ($SangriaIzq -ne 0) { $null = $sb.Append(('<w:ind w:left="{0}"/>' -f $SangriaIzq)) }
    $null = $sb.Append(('<w:spacing w:before="{0}" w:after="{1}"/>' -f $EspacioAntes, $EspacioDespues))
    $null = $sb.Append(('<w:jc w:val="{0}"/>' -f $Alineacion))
    $null = $sb.Append('</w:pPr>')
    $null = $sb.Append($Contenido)
    $null = $sb.Append('</w:p>')
    return $sb.ToString()
}

function New-Celda {
    param(
        [string]$Contenido,     # parrafos ya construidos
        [int]$Ancho,            # twips
        [string]$Sombreado = '',
        [switch]$SinBordes,
        [string]$AlineacionV = 'top'
    )
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append('<w:tc><w:tcPr>')
    $null = $sb.Append(('<w:tcW w:w="{0}" w:type="dxa"/>' -f $Ancho))
    if ($SinBordes) {
        $null = $sb.Append('<w:tcBorders><w:top w:val="nil"/><w:left w:val="nil"/><w:bottom w:val="nil"/><w:right w:val="nil"/></w:tcBorders>')
    }
    if ($Sombreado) { $null = $sb.Append(('<w:shd w:val="clear" w:color="auto" w:fill="{0}"/>' -f $Sombreado)) }
    $null = $sb.Append(('<w:vAlign w:val="{0}"/>' -f $AlineacionV))
    $null = $sb.Append('</w:tcPr>')
    $null = $sb.Append($Contenido)
    $null = $sb.Append('</w:tc>')
    return $sb.ToString()
}

function New-TablaApertura {
    param(
        [int[]]$Anchos,
        [switch]$SinBordes
    )
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append('<w:tbl><w:tblPr>')
    $null = $sb.Append('<w:tblW w:w="5000" w:type="pct"/>')
    if ($SinBordes) {
        $null = $sb.Append('<w:tblBorders><w:top w:val="nil"/><w:left w:val="nil"/><w:bottom w:val="nil"/><w:right w:val="nil"/><w:insideH w:val="nil"/><w:insideV w:val="nil"/></w:tblBorders>')
    } else {
        $b = '<w:tblBorders>'
        foreach ($lado in 'top','left','bottom','right','insideH','insideV') {
            $b += ('<w:{0} w:val="single" w:sz="4" w:space="0" w:color="{1}"/>' -f $lado, $script:C_BORDE)
        }
        $b += '</w:tblBorders>'
        $null = $sb.Append($b)
    }
    $null = $sb.Append('<w:tblCellMar><w:top w:w="60" w:type="dxa"/><w:left w:w="80" w:type="dxa"/><w:bottom w:w="60" w:type="dxa"/><w:right w:w="80" w:type="dxa"/></w:tblCellMar>')
    $null = $sb.Append('<w:tblLayout w:type="fixed"/>')
    $null = $sb.Append('</w:tblPr><w:tblGrid>')
    foreach ($a in $Anchos) { $null = $sb.Append(('<w:gridCol w:w="{0}"/>' -f $a)) }
    $null = $sb.Append('</w:tblGrid>')
    return $sb.ToString()
}

<#
    Convierte un arreglo de porcentajes en anchos de twips que suman el ancho util.
#>
function ConvertTo-Anchos {
    param([int[]]$Porcentajes)
    $anchos = @()
    $acum = 0
    for ($i = 0; $i -lt $Porcentajes.Count; $i++) {
        if ($i -eq $Porcentajes.Count - 1) {
            $anchos += ($script:ANCHO_UTIL - $acum)
        } else {
            $w = [int](($Porcentajes[$i] / 100.0) * $script:ANCHO_UTIL)
            $anchos += $w
            $acum += $w
        }
    }
    return $anchos
}

# ---------------------------------------------------------------------------
# Bloques de alto nivel
# ---------------------------------------------------------------------------

function Add-Titulo {
    param([string]$Texto, [string]$Subtitulo = '', [string]$Derecha = '')

    $anchos = ConvertTo-Anchos @(68, 32)
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append((New-TablaApertura -Anchos $anchos -SinBordes))
    $null = $sb.Append('<w:tr>')

    $izq = New-Parrafo -Contenido (New-Run -Texto $Texto -Props (New-RunProps -Puntos 16 -Negrita -Color $script:C_TINTA)) -EspacioDespues 20
    if ($Subtitulo) {
        $izq += New-Parrafo -Contenido (New-Run -Texto $Subtitulo -Props (New-RunProps -Puntos 9 -Color $script:C_GRIS)) -EspacioDespues 0
    }
    $null = $sb.Append((New-Celda -Contenido $izq -Ancho $anchos[0] -SinBordes))

    $der = ''
    foreach ($linea in ($Derecha -split "`n")) {
        if ($linea.Trim() -eq '') { continue }
        $der += New-Parrafo -Contenido (New-Run -Texto $linea -Props (New-RunProps -Puntos 8 -Color $script:C_GRIS)) -Alineacion 'right' -EspacioDespues 10
    }
    if (-not $der) { $der = New-Parrafo -Contenido '' }
    $null = $sb.Append((New-Celda -Contenido $der -Ancho $anchos[1] -SinBordes))

    $null = $sb.Append('</w:tr></w:tbl>')

    # Regla gruesa bajo la cabecera
    $null = $sb.Append((New-Parrafo -Contenido '' -BordeInferior $script:C_AZUL -GrosorBorde 20 -EspacioDespues 140))
    return $sb.ToString()
}

function Add-Seccion {
    param([string]$Texto)
    return New-Parrafo -Contenido (New-Run -Texto $Texto.ToUpper() -Props (New-RunProps -Puntos 10 -Negrita -Color $script:C_AZUL -Espaciado 14)) `
        -EspacioAntes 180 -EspacioDespues 70 -BordeInferior $script:C_AZUL -GrosorBorde 12
}

function Add-Parrafo {
    param([string]$Texto, [double]$Puntos = 9, [string]$Color = $script:C_TINTA, [switch]$Cursiva)
    $p = if ($Cursiva) { New-RunProps -Puntos $Puntos -Color $Color -Cursiva } else { New-RunProps -Puntos $Puntos -Color $Color }
    return New-Parrafo -Contenido (New-Run -Texto $Texto -Props $p) -Alineacion 'both' -EspacioDespues 80
}

function Add-Nota {
    param([string]$Titulo, [string]$Texto)
    $c = New-Run -Texto $Titulo -Props (New-RunProps -Puntos 9 -Negrita -Color '7A5C00')
    $c += New-Run -Texto (' ' + $Texto) -Props (New-RunProps -Puntos 9 -Color '5C4700')
    return New-Parrafo -Contenido $c -Sombreado 'FDF6E3' -EspacioAntes 60 -EspacioDespues 110 -SangriaIzq 80 -Alineacion 'both'
}

<#
    Fila de indicadores. $Items: arreglo de hashtables @{ Valor=; Etiqueta=; Color= }
#>
function Add-Indicadores {
    param([object[]]$Items)

    $pct = @()
    $base = [int](100 / $Items.Count)
    for ($i = 0; $i -lt $Items.Count; $i++) { $pct += $base }
    $anchos = ConvertTo-Anchos $pct

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append((New-TablaApertura -Anchos $anchos))
    $null = $sb.Append('<w:tr>')
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $it = $Items[$i]
        $color = if ($it.Color) { $it.Color } else { $script:C_TINTA }
        $fondo = if ($it.Fondo) { $it.Fondo } else { 'FFFFFF' }
        $c  = New-Parrafo -Contenido (New-Run -Texto ([string]$it.Valor) -Props (New-RunProps -Puntos 17 -Negrita -Color $color)) -Alineacion 'center' -EspacioDespues 10
        $c += New-Parrafo -Contenido (New-Run -Texto ([string]$it.Etiqueta).ToUpper() -Props (New-RunProps -Puntos 7 -Color $script:C_GRIS -Espaciado 8)) -Alineacion 'center' -EspacioDespues 0
        $null = $sb.Append((New-Celda -Contenido $c -Ancho $anchos[$i] -Sombreado $fondo))
    }
    $null = $sb.Append('</w:tr></w:tbl>')
    $null = $sb.Append((New-Parrafo -Contenido '' -EspacioDespues 40))
    return $sb.ToString()
}

<#
    Tabla de datos.
    $Encabezados: string[]  |  $Filas: arreglo de string[]  |  $Porcentajes: int[]
    $ColoresFila: opcional, arreglo paralelo a $Filas con el color de la 1a celda.
#>
function Add-Tabla {
    param(
        [string[]]$Encabezados,
        [object[]]$Filas,
        [int[]]$Porcentajes,
        [object[]]$ColoresFila = @(),
        [double]$Puntos = 8.3,
        [switch]$PrimeraColumnaClave
    )

    if (-not $Porcentajes -or $Porcentajes.Count -ne $Encabezados.Count) {
        $base = [int](100 / $Encabezados.Count)
        $Porcentajes = @()
        for ($i = 0; $i -lt $Encabezados.Count; $i++) { $Porcentajes += $base }
    }
    $anchos = ConvertTo-Anchos $Porcentajes

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append((New-TablaApertura -Anchos $anchos))

    # Encabezado, marcado para repetirse en cada pagina
    $null = $sb.Append('<w:tr><w:trPr><w:tblHeader/><w:cantSplit/></w:trPr>')
    for ($c = 0; $c -lt $Encabezados.Count; $c++) {
        $p = New-Parrafo -Contenido (New-Run -Texto $Encabezados[$c].ToUpper() -Props (New-RunProps -Puntos 7.4 -Negrita -Color $script:C_AZUL -Espaciado 6)) -EspacioDespues 0
        $null = $sb.Append((New-Celda -Contenido $p -Ancho $anchos[$c] -Sombreado $script:C_FONDO))
    }
    $null = $sb.Append('</w:tr>')

    $idx = 0
    foreach ($fila in $Filas) {
        $null = $sb.Append('<w:tr><w:trPr><w:cantSplit/></w:trPr>')
        $celdas = @($fila)
        for ($c = 0; $c -lt $Encabezados.Count; $c++) {
            $valor = if ($c -lt $celdas.Count) { $celdas[$c] } else { '' }

            $esClave = ($PrimeraColumnaClave -and $c -eq 0)
            $color = $script:C_TINTA
            if ($c -eq 0 -and $ColoresFila.Count -gt $idx -and $ColoresFila[$idx]) { $color = $ColoresFila[$idx] }

            $props = if ($esClave -or ($c -eq 0 -and $color -ne $script:C_TINTA)) {
                New-RunProps -Puntos $Puntos -Negrita -Color $color
            } else {
                New-RunProps -Puntos $Puntos -Color $color
            }
            $fondo = if ($esClave) { 'F7F9FB' } else { '' }
            $p = New-Parrafo -Contenido (New-Run -Texto ([string]$valor) -Props $props) -EspacioDespues 0
            $null = $sb.Append((New-Celda -Contenido $p -Ancho $anchos[$c] -Sombreado $fondo))
        }
        $null = $sb.Append('</w:tr>')
        $idx++
    }
    $null = $sb.Append('</w:tbl>')
    $null = $sb.Append((New-Parrafo -Contenido '' -EspacioDespues 40))
    return $sb.ToString()
}

<#
    Tabla de barras de proporcion, dibujadas con celdas sombreadas.
    $Items: @{ Nombre=; Valor=; Proporcion=(0..1); Nota=; Destacar=$true/$false }
#>
function Add-Barras {
    param([object[]]$Items, [int]$Segmentos = 40)

    $anchos = ConvertTo-Anchos @(34, 8, 44, 14)
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append((New-TablaApertura -Anchos $anchos -SinBordes))

    foreach ($it in $Items) {
        $null = $sb.Append('<w:tr><w:trPr><w:cantSplit/></w:trPr>')

        $props = if ($it.Destacar) { New-RunProps -Puntos 8.3 -Negrita } else { New-RunProps -Puntos 8.3 }
        $p = New-Parrafo -Contenido (New-Run -Texto ([string]$it.Nombre) -Props $props) -EspacioDespues 0
        $null = $sb.Append((New-Celda -Contenido $p -Ancho $anchos[0] -SinBordes))

        $p = New-Parrafo -Contenido (New-Run -Texto ([string]$it.Valor) -Props (New-RunProps -Puntos 8.3 -Negrita)) -Alineacion 'right' -EspacioDespues 0
        $null = $sb.Append((New-Celda -Contenido $p -Ancho $anchos[1] -SinBordes))

        # Barra: tabla anidada de dos celdas (lleno / vacio)
        $prop = [math]::Max([math]::Min([double]$it.Proporcion, 1.0), 0.0)
        $wLleno = [int]($anchos[2] * $prop)
        if ($wLleno -lt 20 -and $prop -gt 0) { $wLleno = 20 }
        $wVacio = $anchos[2] - $wLleno
        $colorBarra = if ($it.Destacar) { $script:C_CRIT } else { $script:C_AZUL }

        $barra = New-Object System.Text.StringBuilder
        $null = $barra.Append((New-TablaApertura -Anchos @($(if($wLleno -gt 0){$wLleno}else{1}), $(if($wVacio -gt 0){$wVacio}else{1})) -SinBordes))
        $null = $barra.Append('<w:tr><w:trPr><w:trHeight w:val="120" w:hRule="exact"/></w:trPr>')
        if ($wLleno -gt 0) {
            $null = $barra.Append((New-Celda -Contenido (New-Parrafo -Contenido '' -EspacioDespues 0) -Ancho $wLleno -Sombreado $colorBarra -SinBordes))
        } else {
            $null = $barra.Append((New-Celda -Contenido (New-Parrafo -Contenido '' -EspacioDespues 0) -Ancho 1 -SinBordes))
        }
        if ($wVacio -gt 0) {
            $null = $barra.Append((New-Celda -Contenido (New-Parrafo -Contenido '' -EspacioDespues 0) -Ancho $wVacio -Sombreado $script:C_FONDO -SinBordes))
        } else {
            $null = $barra.Append((New-Celda -Contenido (New-Parrafo -Contenido '' -EspacioDespues 0) -Ancho 1 -SinBordes))
        }
        $null = $barra.Append('</w:tr></w:tbl>')
        # Una celda que contiene tabla necesita un parrafo vacio al final
        $null = $barra.Append((New-Parrafo -Contenido '' -EspacioDespues 0))

        $null = $sb.Append((New-Celda -Contenido $barra.ToString() -Ancho $anchos[2] -SinBordes -AlineacionV 'center'))

        $p = New-Parrafo -Contenido (New-Run -Texto ([string]$it.Nota) -Props (New-RunProps -Puntos 7.5 -Color $script:C_GRIS)) -EspacioDespues 0
        $null = $sb.Append((New-Celda -Contenido $p -Ancho $anchos[3] -SinBordes))

        $null = $sb.Append('</w:tr>')
    }
    $null = $sb.Append('</w:tbl>')
    $null = $sb.Append((New-Parrafo -Contenido '' -EspacioDespues 40))
    return $sb.ToString()
}

function Add-Firmas {
    param([string[]]$Etiquetas = @('Elaborado por','Revisado por','Responsable del activo'))

    $pct = @()
    $base = [int](100 / $Etiquetas.Count)
    foreach ($e in $Etiquetas) { $pct += $base }
    $anchos = ConvertTo-Anchos $pct

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append((New-Parrafo -Contenido '' -EspacioAntes 300 -EspacioDespues 0))
    $null = $sb.Append((New-TablaApertura -Anchos $anchos -SinBordes))
    $null = $sb.Append('<w:tr>')
    for ($i = 0; $i -lt $Etiquetas.Count; $i++) {
        $c  = New-Parrafo -Contenido '' -BordeInferior '4B5563' -GrosorBorde 6 -EspacioDespues 40
        $c += New-Parrafo -Contenido (New-Run -Texto $Etiquetas[$i] -Props (New-RunProps -Puntos 7.5 -Color $script:C_GRIS)) -Alineacion 'center' -EspacioDespues 0
        $null = $sb.Append((New-Celda -Contenido $c -Ancho $anchos[$i] -SinBordes))
    }
    $null = $sb.Append('</w:tr></w:tbl>')
    return $sb.ToString()
}

function Add-SaltoPagina {
    return New-Parrafo -Contenido '' -SaltoPaginaAntes -EspacioDespues 0
}

# ---------------------------------------------------------------------------
# API publica
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Genera un archivo .docx a partir de bloques ya construidos con las
    funciones Add-* de este modulo.

.PARAMETER Bloques
    Arreglo de cadenas con XML de WordprocessingML (parrafos y tablas).

.PARAMETER PieIzquierda
    Texto del pie de pagina. La numeracion "Pagina X de Y" se agrega a la derecha.

.EXAMPLE
    $b = @()
    $b += Add-Titulo -Texto 'Ficha de auditoria' -Subtitulo 'SRV-SAP'
    $b += Add-Seccion 'Identificacion'
    $b += Add-Tabla -Encabezados @('Campo','Valor') -Filas @(,@('Servidor','SRV-SAP'))
    Export-ToWord -Path 'C:\temp\ficha.docx' -Bloques $b -Titulo 'Ficha'
#>
function Export-ToWord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$Bloques,
        [string]$Titulo = 'Documento',
        [string]$Autor  = 'Suite de Auditoria',
        [string]$PieIzquierda = ''
    )

    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }

    $enc = New-Object System.Text.UTF8Encoding($false)
    $zip = $null
    $fs  = $null

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

        # --- [Content_Types].xml ---
        Add-Entrada '[Content_Types].xml' (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' +
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' +
            '<Default Extension="xml" ContentType="application/xml"/>' +
            '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>' +
            '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>' +
            '<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>' +
            '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>' +
            '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>' +
            '</Types>')

        # --- _rels/.rels ---
        Add-Entrada '_rels/.rels' (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>' +
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>' +
            '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>' +
            '</Relationships>')

        # --- word/_rels/document.xml.rels ---
        Add-Entrada 'word/_rels/document.xml.rels' (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>' +
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>' +
            '</Relationships>')

        # --- word/styles.xml ---
        Add-Entrada 'word/styles.xml' (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
            '<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">' +
            '<w:docDefaults><w:rPrDefault><w:rPr>' +
            '<w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI" w:eastAsia="Segoe UI" w:cs="Segoe UI"/>' +
            '<w:sz w:val="19"/><w:szCs w:val="19"/><w:lang w:val="es-GT"/>' +
            '</w:rPr></w:rPrDefault>' +
            '<w:pPrDefault><w:pPr><w:spacing w:after="60" w:line="240" w:lineRule="auto"/></w:pPr></w:pPrDefault>' +
            '</w:docDefaults>' +
            '<w:style w:type="paragraph" w:default="1" w:styleId="Normal">' +
            '<w:name w:val="Normal"/><w:qFormat/></w:style>' +
            '</w:styles>')

        # --- word/footer1.xml ---
        $pieTxt = ConvertTo-WordText $PieIzquierda
        Add-Entrada 'word/footer1.xml' (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
            '<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">' +
            '<w:p><w:pPr><w:pBdr><w:top w:val="single" w:sz="4" w:space="2" w:color="' + $script:C_BORDE + '"/></w:pBdr>' +
            '<w:tabs><w:tab w:val="right" w:pos="' + $script:ANCHO_UTIL + '"/></w:tabs>' +
            '<w:spacing w:before="60" w:after="0"/></w:pPr>' +
            '<w:r><w:rPr><w:color w:val="' + $script:C_GRIS + '"/><w:sz w:val="14"/></w:rPr>' +
            '<w:t xml:space="preserve">' + $pieTxt + '</w:t></w:r>' +
            '<w:r><w:rPr><w:color w:val="' + $script:C_GRIS + '"/><w:sz w:val="14"/></w:rPr><w:tab/>' +
            '<w:t xml:space="preserve">Pagina </w:t></w:r>' +
            '<w:r><w:rPr><w:color w:val="' + $script:C_GRIS + '"/><w:sz w:val="14"/></w:rPr>' +
            '<w:fldChar w:fldCharType="begin"/></w:r>' +
            '<w:r><w:rPr><w:color w:val="' + $script:C_GRIS + '"/><w:sz w:val="14"/></w:rPr>' +
            '<w:instrText xml:space="preserve">PAGE</w:instrText></w:r>' +
            '<w:r><w:rPr><w:color w:val="' + $script:C_GRIS + '"/><w:sz w:val="14"/></w:rPr>' +
            '<w:fldChar w:fldCharType="end"/></w:r>' +
            '<w:r><w:rPr><w:color w:val="' + $script:C_GRIS + '"/><w:sz w:val="14"/></w:rPr>' +
            '<w:t xml:space="preserve"> de </w:t></w:r>' +
            '<w:r><w:rPr><w:color w:val="' + $script:C_GRIS + '"/><w:sz w:val="14"/></w:rPr>' +
            '<w:fldChar w:fldCharType="begin"/></w:r>' +
            '<w:r><w:rPr><w:color w:val="' + $script:C_GRIS + '"/><w:sz w:val="14"/></w:rPr>' +
            '<w:instrText xml:space="preserve">NUMPAGES</w:instrText></w:r>' +
            '<w:r><w:rPr><w:color w:val="' + $script:C_GRIS + '"/><w:sz w:val="14"/></w:rPr>' +
            '<w:fldChar w:fldCharType="end"/></w:r>' +
            '</w:p></w:ftr>')

        # --- docProps ---
        $fecha = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssZ')
        Add-Entrada 'docProps/core.xml' (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" ' +
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" ' +
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">' +
            '<dc:title>' + (ConvertTo-WordText $Titulo) + '</dc:title>' +
            '<dc:creator>' + (ConvertTo-WordText $Autor) + '</dc:creator>' +
            '<cp:lastModifiedBy>' + (ConvertTo-WordText $Autor) + '</cp:lastModifiedBy>' +
            '<dcterms:created xsi:type="dcterms:W3CDTF">' + $fecha + '</dcterms:created>' +
            '<dcterms:modified xsi:type="dcterms:W3CDTF">' + $fecha + '</dcterms:modified>' +
            '</cp:coreProperties>')

        Add-Entrada 'docProps/app.xml' (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
            '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" ' +
            'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">' +
            '<Application>Suite de Auditoria - WordWriter</Application>' +
            '<Company></Company>' +
            '</Properties>')

        # --- word/document.xml ---
        $doc = New-Object System.Text.StringBuilder
        $null = $doc.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
        $null = $doc.Append('<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">')
        $null = $doc.Append('<w:body>')
        foreach ($b in $Bloques) { $null = $doc.Append($b) }
        $null = $doc.Append('<w:sectPr>')
        $null = $doc.Append('<w:footerReference w:type="default" r:id="rId2" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>')
        $null = $doc.Append(('<w:pgSz w:w="{0}" w:h="{1}"/>' -f $script:PG_ANCHO, $script:PG_ALTO))
        $null = $doc.Append(('<w:pgMar w:top="{0}" w:right="{1}" w:bottom="{0}" w:left="{1}" w:header="340" w:footer="340" w:gutter="0"/>' -f $script:PG_MARGENV, $script:PG_MARGEN))
        $null = $doc.Append('<w:cols w:space="708"/><w:docGrid w:linePitch="360"/>')
        $null = $doc.Append('</w:sectPr>')
        $null = $doc.Append('</w:body></w:document>')
        Add-Entrada 'word/document.xml' $doc.ToString()
    }
    finally {
        if ($zip) { $zip.Dispose() }
        if ($fs)  { $fs.Dispose() }
    }

    return $Path
}

Export-ModuleMember -Function Export-ToWord, Add-Titulo, Add-Seccion, Add-Parrafo, Add-Nota,
    Add-Indicadores, Add-Tabla, Add-Barras, Add-Firmas, Add-SaltoPagina, ConvertTo-Anchos
