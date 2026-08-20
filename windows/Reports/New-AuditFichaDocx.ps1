<#
.SYNOPSIS
    Genera la ficha de auditoria del servidor en formato .docx.

.DESCRIPTION
    Equivalente en Word de New-AuditFicha.ps1. Produce un documento A4 de dos a
    tres paginas, apto para entregarse como reporte formal, imprimirse o
    firmarse.

    A diferencia de New-AuditFicha.ps1 —que recibe los objetos vivos de la
    corrida— este script se alimenta del expediente ya escrito en disco
    (Output\<RunId>\raw\*.json). Eso permite emitir la ficha de cualquier
    corrida pasada sin volver a auditar el servidor.

    No requiere Microsoft Word: el .docx se construye como paquete OOXML
    mediante Modules\AuditCore\WordWriter.psm1.

.PARAMETER RunId
    Identificador de la corrida. Si se omite, toma la mas reciente de Output\.

.PARAMETER AuditRoot
    Raiz de la suite. Por omision, la carpeta padre de este script.

.PARAMETER OutputPath
    Carpeta destino. Por omision, la propia carpeta de la corrida.

.EXAMPLE
    .\New-AuditFichaDocx.ps1
    .\New-AuditFichaDocx.ps1 -RunId LINEA-BASE-20260813
#>
[CmdletBinding()]
param(
    [string]$RunId,
    [string]$AuditRoot,
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Contexto
# ---------------------------------------------------------------------------

if (-not $AuditRoot) { $AuditRoot = Split-Path $PSScriptRoot -Parent }
$outRoot = Join-Path $AuditRoot 'Output'

if (-not (Test-Path $outRoot)) { throw "No existe la carpeta de salida: $outRoot" }

if (-not $RunId) {
    $ultima = Get-ChildItem $outRoot -Directory |
              Where-Object { Test-Path (Join-Path $_.FullName 'raw\RESUMEN.json') } |
              Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $ultima) { throw "No se encontro ninguna corrida con expediente en $outRoot" }
    $RunId = $ultima.Name
}

$runPath = Join-Path $outRoot $RunId
$rawPath = Join-Path $runPath 'raw'
if (-not (Test-Path $rawPath)) { throw "La corrida '$RunId' no tiene carpeta raw\: $rawPath" }
if (-not $OutputPath) { $OutputPath = $runPath }

Import-Module (Join-Path $AuditRoot 'Modules\AuditCore\WordWriter.psm1') -Force -DisableNameChecking

function Read-Json {
    param([string]$Nombre, [switch]$Opcional)
    $f = Join-Path $rawPath $Nombre
    if (-not (Test-Path $f)) {
        if ($Opcional) { return @() }
        throw "Falta el archivo de evidencia: $f"
    }
    $txt = Get-Content $f -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($txt)) { return @() }
    return ($txt | ConvertFrom-Json)
}

$Resumen   = Read-Json 'RESUMEN.json'
$Capas     = @(Read-Json 'RESUMEN-CAPAS.json'      -Opcional)
$Hallazgos = @(Read-Json 'HALLAZGOS.json'          -Opcional)
$Cobertura = @(Read-Json 'COBERTURA-CRITERIOS.json' -Opcional)
$Brechas   = @(Read-Json 'BRECHAS-EVIDENCIA.json'  -Opcional)
$Arq       = @(Read-Json 'LINEA-BASE-ARQUITECTURA.json' -Opcional)

# Rol declarado del servidor: preferir el catalogo, con respaldo en las metricas
$rolDeclarado = 'No declarado'
$entorno      = 'No declarado'
$criticidad   = 'No declarada'
$clasifDatos  = 'No declarada'
$propietario  = 'DEFINIR'
$responsable  = 'DEFINIR'
$unidad       = 'DEFINIR'

$cfgArq = Join-Path $AuditRoot 'Config\Arquitectura.psd1'
if (Test-Path $cfgArq) {
    try {
        $datos = Import-PowerShellDataFile -Path $cfgArq
        if ($datos.RolServidor) {
            $rs = $datos.RolServidor
            if ($rs.RolDeclarado)       { $rolDeclarado = $rs.RolDeclarado }
            if ($rs.Entorno)            { $entorno      = $rs.Entorno }
            if ($rs.Criticidad)         { $criticidad   = $rs.Criticidad }
            if ($rs.ClasificacionDatos) { $clasifDatos  = $rs.ClasificacionDatos }
            if ($rs.Propietario)        { $propietario  = $rs.Propietario }
            if ($rs.ResponsableTecnico) { $responsable  = $rs.ResponsableTecnico }
            if ($rs.UnidadNegocio)      { $unidad       = $rs.UnidadNegocio }
        }
    } catch {
        Write-Warning "No se pudo leer Arquitectura.psd1; se usaran las metricas del resumen."
    }
}
$m = $Resumen.Metricas
if ($rolDeclarado -eq 'No declarado' -and $m.'L4-06.RolServidorDeclarado') { $rolDeclarado = $m.'L4-06.RolServidorDeclarado' }
if ($entorno      -eq 'No declarado' -and $m.'L4-06.EntornoDeclarado')     { $entorno      = $m.'L4-06.EntornoDeclarado' }

function Fmt-Pendiente {
    param([string]$Valor)
    if (-not $Valor -or $Valor -eq 'DEFINIR') { return 'SIN ASIGNAR' }
    return $Valor
}

# ---------------------------------------------------------------------------
# Preparacion de datos
# ---------------------------------------------------------------------------

$artefactos    = @($Arq | Where-Object { $_.Artefacto -and $_.Artefacto -notlike '`[CATALOGO`]*' })
$noAlineados   = @($artefactos | Where-Object { $_.Alineacion -eq 'NO ALINEADO' })
$sinClasificar = @($artefactos | Where-Object { $_.RolId -eq 'SinClasificar' })
$alineados     = @($artefactos | Where-Object { $_.Alineacion -eq 'Alineado' })

$accionables = @($Hallazgos | Where-Object { $_.Severity -in @('Critical','High') } |
                 Sort-Object SeverityRank -Descending)

$colorRiesgo = switch ("$($Resumen.NivelRiesgo)") {
    'CRITICO' { 'C0272D' } 'ALTO' { 'C0272D' } 'MEDIO' { '8A6D00' } default { '1A7F4B' }
}
$fondoRiesgo = switch ("$($Resumen.NivelRiesgo)") {
    'CRITICO' { 'FDECEC' } 'ALTO' { 'FDECEC' } 'MEDIO' { 'FDF6E3' } default { 'EAF6EF' }
}

function Recortar {
    param([string]$Texto, [int]$Max)
    if (-not $Texto) { return '' }
    if ($Texto.Length -le $Max) { return $Texto }
    return $Texto.Substring(0, $Max - 3) + '...'
}

# ---------------------------------------------------------------------------
# Construccion del documento
# ---------------------------------------------------------------------------

$b = @()

# --- Cabecera ---
$privilegios = if ($Resumen.Elevado) { 'Administrativos' } else { 'Estandar (sin elevacion)' }
$derecha = "Corrida: $($Resumen.RunId)`nEmitida: $(Get-Date -Format 'dd/MM/yyyy HH:mm')`nPrivilegios: $privilegios"

$b += Add-Titulo -Texto 'Ficha de auditoria de sistemas' `
                 -Subtitulo "Servidor $($Resumen.Servidor)  |  $rolDeclarado" `
                 -Derecha $derecha

# --- Veredicto ---
$b += Add-Indicadores -Items @(
    @{ Valor = $Resumen.PuntajeRiesgo; Etiqueta = "Riesgo - $($Resumen.NivelRiesgo)"; Color = $colorRiesgo; Fondo = $fondoRiesgo }
    @{ Valor = $Resumen.Criticos;   Etiqueta = 'Criticos';   Color = 'C0272D' }
    @{ Valor = $Resumen.Altos;      Etiqueta = 'Altos';      Color = 'E06C00' }
    @{ Valor = $Resumen.Medios;     Etiqueta = 'Medios';     Color = '8A6D00' }
    @{ Valor = $Resumen.Bajos;      Etiqueta = 'Bajos';      Color = '2C7BB6' }
    @{ Valor = $artefactos.Count;   Etiqueta = 'Artefactos' }
)

if (-not $Resumen.Elevado) {
    $b += Add-Nota -Titulo 'Alcance limitado:' -Texto ("la auditoria se ejecuto sin privilegios administrativos. " +
        "$($Resumen.BrechasEvidencia) verificaciones no pudieron completarse y quedan detalladas al final de este documento. " +
        "Para un expediente formal, reejecutar con una cuenta administrativa.")
}

# --- Identificacion del activo ---
$b += Add-Seccion 'Identificacion del activo'
$b += Add-Tabla -Encabezados @('Campo','Valor','Campo','Valor') -Porcentajes @(17,33,17,33) -PrimeraColumnaClave -Filas @(
    ,@('Servidor',      "$($Resumen.Servidor)",  'Entorno',              $entorno)
    ,@('Dominio',       $(if ($Resumen.Dominio) { $Resumen.Dominio } else { 'Workgroup' }), 'Criticidad', $criticidad)
    ,@('Rol declarado', $rolDeclarado,           'Clasificacion de datos', $clasifDatos)
    ,@('Sistema operativo', "$($m.'L2-01.SO')",  'Compilacion',          "$($m.'L2-01.Build')")
    ,@('Propietario',   (Fmt-Pendiente $propietario), 'Responsable tecnico', (Fmt-Pendiente $responsable))
    ,@('Unidad de negocio', (Fmt-Pendiente $unidad), 'Ejecutado por',     "$($Resumen.EjecutadoPor)")
)

# --- Plataforma ---
$b += Add-Seccion 'Plataforma y estado operativo'
$reinicio = if ($m.'L2-01.ReinicioPendiente') { 'Si - parches aplicados sin efecto' } else { 'No' }
$b += Add-Tabla -Encabezados @('Campo','Valor','Campo','Valor') -Porcentajes @(17,33,17,33) -PrimeraColumnaClave -Filas @(
    ,@('Motor de base de datos', "$($m.'L3-01.SQLServer')", 'Servidor web', "IIS $($m.'L3-01.IIS')")
    ,@('CPU logicos', "$($m.'L1-01.CPULogicos')",           'Memoria total', "$($m.'L1-01.MemoriaTotalGB') GB")
    ,@('Virtualizacion', "$($m.'L1-01.Virtualizacion')",    'Memoria libre', "$($m.'L9-01.MemoriaPorcentajeLibre')%")
    ,@('Uptime', "$($m.'L2-01.UptimeDias') dias",           'Reinicio pendiente', $reinicio)
    ,@('Ultimo parche', "$($m.'L2-02.UltimoParche') ($($m.'L2-02.DiasDesdeUltimoParche') dias)", 'Actualizaciones pendientes', "$($m.'L2-02.ActualizacionesPendientes')")
    ,@('Antimalware', "$($m.'L2-03.Antimalware')",          'Perfiles de firewall activos', "$($m.'L2-03.PerfilesFirewallActivos') de 3")
    ,@('Servicios en ejecucion', "$($m.'L5-01.ServiciosEnEjecucion') de $($m.'L5-01.TotalServicios')", 'Puertos TCP en escucha', "$($m.'L7-01.PuertosTCPEscucha')")
    ,@('Paquetes instalados', "$($m.'L4-01.TotalPaquetes')", 'Fuera de soporte', "$($m.'L4-05.FueraDeSoporte') ($($m.'L4-05.PorcentajeFueraSoporte')%)")
)

# --- Perfil arquitectonico ---
$b += Add-Seccion 'Perfil arquitectonico'
if ($artefactos.Count -gt 0) {
    $pct = [math]::Round(($alineados.Count / $artefactos.Count) * 100, 0)
    $b += Add-Tabla -Encabezados @('Campo','Valor','Campo','Valor') -Porcentajes @(22,28,22,28) -PrimeraColumnaClave -Filas @(
        ,@('Artefactos clasificados', "$($artefactos.Count - $sinClasificar.Count) de $($artefactos.Count)", 'Alineados al rol', "$($alineados.Count) ($pct%)")
        ,@('No alineados', "$($noAlineados.Count)", 'Sin clasificar', "$($sinClasificar.Count)")
    )

    $b += Add-Parrafo -Texto 'Distribucion por capa de arquitectura empresarial:' -Puntos 8.5 -Color '5B6673'
    $grupos = @($artefactos | Group-Object CapaEA | Sort-Object Count -Descending)
    $maxCapa = 1
    foreach ($g in $grupos) { if ($g.Count -gt $maxCapa) { $maxCapa = $g.Count } }
    $items = @()
    foreach ($g in $grupos) {
        $items += @{ Nombre = $g.Name; Valor = $g.Count; Proporcion = ($g.Count / $maxCapa); Nota = '' }
    }
    $b += Add-Barras -Items $items
} else {
    $b += Add-Parrafo -Texto 'Linea base de arquitectura no disponible en esta corrida.' -Cursiva -Color '5B6673'
}

# --- Riesgo por capa ---
$b += Add-Seccion 'Riesgo por capa'
$capasAct = @($Capas | Where-Object { $_.Colectores -gt 0 } | Sort-Object Orden)
if ($capasAct.Count -gt 0) {
    $maxR = 1
    foreach ($c in $capasAct) { if ($c.PuntajeRiesgo -gt $maxR) { $maxR = $c.PuntajeRiesgo } }
    $items = @()
    foreach ($c in $capasAct) {
        $items += @{
            Nombre     = "$($c.Capa)  $($c.Nombre)"
            Valor      = $c.PuntajeRiesgo
            Proporcion = ($c.PuntajeRiesgo / $maxR)
            Nota       = "$($c.Hallazgos) hallazgos"
            Destacar   = ($c.Capa -eq 'L4')
        }
    }
    $b += Add-Barras -Items $items
}

# --- Hallazgos que exigen accion (pagina nueva) ---
$b += Add-SaltoPagina
$b += Add-Seccion "Hallazgos que exigen accion ($($accionables.Count))"

if ($accionables.Count -eq 0) {
    $b += Add-Parrafo -Texto 'No se identificaron hallazgos criticos ni altos en el alcance evaluado.' -Color '1A7F4B'
} else {
    $filas   = @()
    $colores = @()
    foreach ($h in $accionables) {
        $etq = if ($h.Severity -eq 'Critical') { 'CRIT' } else { 'ALTO' }
        $colores += $(if ($h.Severity -eq 'Critical') { 'C0272D' } else { 'E06C00' })
        $filas += ,@(
            $etq,
            "$($h.Layer)",
            (Recortar "$($h.Title)" 90),
            (Recortar "$($h.CriteriosTexto)" 22),
            (Recortar "$($h.Recommendation)" 190)
        )
    }
    $b += Add-Tabla -Encabezados @('Sev.','Capa','Hallazgo','Criterios','Accion requerida') `
                    -Porcentajes @(7,6,32,11,44) -Filas $filas -ColoresFila $colores -Puntos 8
}

# --- Desviaciones arquitectonicas ---
if ($noAlineados.Count -gt 0) {
    $b += Add-Seccion "Desviaciones arquitectonicas ($($noAlineados.Count))"
    $b += Add-Parrafo -Texto ("Artefactos cuyo rol no corresponde al proposito declarado del servidor " +
        "($rolDeclarado, entorno de $entorno). Cada uno amplia la superficie de ataque sin aportar a la funcion del activo.") `
        -Puntos 8.5 -Color '5B6673'

    $filas = @()
    foreach ($n in ($noAlineados | Select-Object -First 20)) {
        $ruta = if ($n.RutaInstalacion) { "$($n.RutaInstalacion)" } else { 'ruta no determinada' }
        $filas += ,@("$($n.Artefacto)", "$($n.Version)", "$($n.RolArquitectonico)", (Recortar $ruta 60))
    }
    $b += Add-Tabla -Encabezados @('Artefacto','Version','Rol detectado','Ubicacion') `
                    -Porcentajes @(30,12,22,36) -Filas $filas -Puntos 8
    if ($noAlineados.Count -gt 20) {
        $b += Add-Parrafo -Texto "Se muestran 20 de $($noAlineados.Count). Listado completo en la hoja Arquitectura del libro de Excel adjunto." `
              -Puntos 7.5 -Color '5B6673' -Cursiva
    }
}

# --- Conformidad por dominio ---
if ($Cobertura.Count -gt 0) {
    $b += Add-Seccion 'Conformidad por dominio de criterios'
    $filas = @()
    foreach ($g in ($Cobertura | Group-Object Dominio | Sort-Object Name)) {
        $cf = @($g.Group | Where-Object { $_.Conformidad -eq 'Conforme' }).Count
        $ob = @($g.Group | Where-Object { $_.Conformidad -eq 'Conforme con observaciones' }).Count
        $nc = @($g.Group | Where-Object { $_.Conformidad -eq 'No conforme' }).Count
        $ne = @($g.Group | Where-Object { $_.Conformidad -eq 'No evaluado' }).Count
        $filas += ,@("$($g.Name)", "$($g.Count)", "$cf", "$ob", "$nc", "$ne")
    }
    $b += Add-Tabla -Encabezados @('Dominio','Criterios','Conformes','Con observaciones','No conformes','Sin evaluar') `
                    -Porcentajes @(34,11,13,20,12,10) -Filas $filas -Puntos 8
}

# --- Brechas de evidencia ---
if ($Brechas.Count -gt 0) {
    $b += Add-Seccion "Brechas de evidencia ($($Brechas.Count))"
    $b += Add-Parrafo -Texto ('Verificaciones que no pudieron completarse. Se documentan de forma explicita ' +
        'para que el alcance real del expediente quede constatado, en lugar de aparentar cobertura total.') `
        -Puntos 8.5 -Color '5B6673'
    $filas = @()
    foreach ($br in $Brechas) {
        # El colector emite los campos Colector / Capa / Brecha; se aceptan alias por
        # compatibilidad con expedientes de versiones anteriores de la suite.
        $col = if ($br.Colector) { "$($br.Colector)" } elseif ($br.CollectorId) { "$($br.CollectorId)" } else { '' }
        $cap = if ($br.Capa) { "$($br.Capa)" } else { '' }
        $txt = if ($br.Brecha)   { "$($br.Brecha)" }
               elseif ($br.Motivo)  { "$($br.Motivo)" }
               elseif ($br.Detalle) { "$($br.Detalle)" }
               else { "$($br.Descripcion)" }
        $filas += ,@($col, $cap, (Recortar $txt 200))
    }
    $b += Add-Tabla -Encabezados @('Colector','Capa','Verificacion que no pudo completarse') `
                    -Porcentajes @(11,8,81) -Filas $filas -Puntos 8
}

# --- Cierre ---
$b += Add-Firmas
$b += Add-Parrafo -Texto ("Auditoria de solo lectura. $($Resumen.RegistrosTotal) registros de evidencia recolectados por " +
    "$($Resumen.ColectoresOK) colectores en $($Resumen.DuracionSegundos) segundos. " +
    "Detalle completo en el libro de Excel y los CSV de la carpeta de la corrida.") `
    -Puntos 7.5 -Color '5B6673'

# ---------------------------------------------------------------------------
# Emision
# ---------------------------------------------------------------------------

$destino = Join-Path $OutputPath ("Ficha-{0}-{1}.docx" -f $Resumen.Servidor, $Resumen.RunId)
$pie = "Ficha de auditoria - $($Resumen.Servidor) - corrida $($Resumen.RunId)"

Export-ToWord -Path $destino -Bloques $b -Titulo "Ficha de auditoria - $($Resumen.Servidor)" `
              -Autor 'Suite de Auditoria de Artefactos' -PieIzquierda $pie | Out-Null

Write-Host "Ficha generada: $destino" -ForegroundColor Green
return $destino
