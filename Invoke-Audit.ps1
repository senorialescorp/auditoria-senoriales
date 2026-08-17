<#
.SYNOPSIS
    Orquestador de la suite de auditoria de sistemas y arquitectura empresarial.

.DESCRIPTION
    Ejecuta los colectores organizados por capas, consolida hallazgos,
    calcula el riesgo agregado ponderado, mapea la evidencia contra los
    criterios de auditoria y genera el expediente de salida con hashes de
    integridad.

    La suite es de SOLO LECTURA: no modifica configuracion del servidor.

.PARAMETER Layer
    Limita la ejecucion a una o varias capas (L1..L9).

.PARAMETER Collector
    Limita la ejecucion a colectores especificos por Id (p.ej. L4-01).

.PARAMETER Quick
    Omite los colectores de mayor costo (escaneo de binarios y muestreo
    de rendimiento prolongado).

.PARAMETER SoftwareOnly
    Ejecuta unicamente la capa prioritaria L4 (artefactos de software).

.PARAMETER NoReport
    Genera unicamente los datos, sin la ficha ni el libro de Excel.

.PARAMETER Purge
    Elimina ejecuciones anteriores mas antiguas que Report.RetencionDias.

.EXAMPLE
    .\Invoke-Audit.ps1
    Ejecucion completa: genera la ficha imprimible y el libro de Excel.

.EXAMPLE
    .\Invoke-Audit.ps1 -SoftwareOnly
    Solo el inventario y analisis de artefactos de software.

.EXAMPLE
    .\Invoke-Audit.ps1 -Layer L2,L4 -Verbose

.NOTES
    Requiere Windows PowerShell 5.1 o superior.
    Se recomienda ejecutar con privilegios administrativos para obtener
    cobertura completa; sin elevacion la suite degrada y reporta las
    brechas de evidencia como parte de los entregables.
#>
[CmdletBinding()]
param(
    [ValidateSet('L1','L2','L3','L4','L5','L6','L7','L8','L9')]
    [string[]]$Layer,

    [string[]]$Collector,

    [switch]$Quick,
    [switch]$SoftwareOnly,
    [switch]$NoReport,
    [switch]$Purge,

    [string]$OutputRoot,
    [string]$RunId
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# ---------------------------------------------------------------------------
# Carga del nucleo y de la configuracion
# ---------------------------------------------------------------------------
$modulePath = Join-Path $scriptRoot 'Modules\AuditCore\AuditCore.psm1'
if (-not (Test-Path $modulePath)) { throw "No se encontro el modulo AuditCore en: $modulePath" }
Import-Module $modulePath -Force -DisableNameChecking

$configPath  = Join-Path $scriptRoot 'Config\Audit.config.psd1'
$mappingPath = Join-Path $scriptRoot 'Config\Criterios.Auditoria.psd1'
$arqPath     = Join-Path $scriptRoot 'Config\Arquitectura.psd1'
if (-not (Test-Path $configPath))  { throw "No se encontro la configuracion en: $configPath" }
if (-not (Test-Path $mappingPath)) { throw "No se encontro el catalogo de criterios en: $mappingPath" }

$config  = Import-PowerShellDataFile -Path $configPath
$mapping = Import-PowerShellDataFile -Path $mappingPath

$arquitectura = $null
if (Test-Path $arqPath) {
    $arquitectura = Import-PowerShellDataFile -Path $arqPath
} else {
    Write-Warning "No se encontro Config\Arquitectura.psd1. La clasificacion por rol arquitectonico quedara deshabilitada."
}

# ---------------------------------------------------------------------------
# Contexto
# ---------------------------------------------------------------------------
$ctx = Initialize-AuditContext -RootPath $scriptRoot -OutputRoot $OutputRoot -RunId $RunId -Config $config

Write-Host ''
Write-Host '===============================================================' -ForegroundColor Cyan
Write-Host '  AUDITORIA DE SISTEMAS Y ARQUITECTURA EMPRESARIAL' -ForegroundColor Cyan
Write-Host '  Mapeo por capas con prioridad en artefactos de software' -ForegroundColor Cyan
Write-Host '===============================================================' -ForegroundColor Cyan
Write-Host ("  Servidor : {0}" -f $ctx.Hostname)
Write-Host ("  Ejecucion: {0}" -f $ctx.RunId)
Write-Host ("  Usuario  : {0}" -f $ctx.RunAs)
Write-Host ("  Elevado  : {0}" -f $(if ($ctx.IsAdmin) { 'Si' } else { 'NO - cobertura parcial' })) `
    -ForegroundColor $(if ($ctx.IsAdmin) { 'Green' } else { 'Yellow' })
Write-Host ("  Salida   : {0}" -f $ctx.RunPath)
Write-Host ''

if (-not $ctx.IsAdmin) {
    Write-AuditLog -Level WARN -Source 'ORQ' -Message 'Sesion sin privilegios administrativos. Varios criterios no podran evidenciarse por completo; las brechas quedaran registradas en el reporte.'
}

# ---------------------------------------------------------------------------
# Descubrimiento de colectores
# ---------------------------------------------------------------------------
$collectorDir = Join-Path $scriptRoot 'Collectors'
$archivos = @(Get-ChildItem -Path $collectorDir -Filter '*.ps1' -File -ErrorAction SilentlyContinue | Sort-Object Name)

if ($archivos.Count -eq 0) { throw "No se encontraron colectores en: $collectorDir" }

# Filtros
if ($SoftwareOnly) { $Layer = @('L4') }

$colectoresCostosos = @('L4-03','L9-01')

# Un colector recibe -Arquitectura solo si declara ese parametro. Asi los
# colectores existentes siguen funcionando sin modificarlos.
function Get-CollectorArgs {
    param([string]$Path, [hashtable]$Base)
    $args = $Base.Clone()
    try {
        $cmd = Get-Command -Name $Path -CommandType ExternalScript -ErrorAction Stop
        if ($cmd.Parameters.ContainsKey('Arquitectura') -and $arquitectura) {
            $args['Arquitectura'] = $arquitectura
        }
    } catch { }
    return $args
}

$plan = New-Object System.Collections.ArrayList
foreach ($f in $archivos) {
    try {
        $m = & $f.FullName -Manifest -Config $config
    } catch {
        Write-AuditLog -Level ERROR -Source 'ORQ' -Message "No se pudo leer el manifiesto de $($f.Name): $($_.Exception.Message)"
        continue
    }
    if (-not $m) { continue }

    if ($Layer     -and $m.Layer -notin $Layer)   { continue }
    if ($Collector -and $m.Id    -notin $Collector) { continue }
    if ($Quick     -and $m.Id -in $colectoresCostosos) {
        Write-AuditLog -Level INFO -Source 'ORQ' -Message "Modo rapido: se omite $($m.Id) ($($m.Nombre))."
        continue
    }

    $null = $plan.Add([pscustomobject]@{ File = $f.FullName; Meta = $m })
}

if ($plan.Count -eq 0) { throw 'Ningun colector coincide con los filtros indicados.' }

Write-Host ("Colectores a ejecutar: {0}" -f $plan.Count) -ForegroundColor White
Write-Host ''

# ---------------------------------------------------------------------------
# Ejecucion
# ---------------------------------------------------------------------------
$resultados     = New-Object System.Collections.ArrayList
$todosHallazgos = New-Object System.Collections.ArrayList
$inicioTotal    = Get-Date

foreach ($item in $plan) {
    $m = $item.Meta
    $etiqueta = "[{0}] {1}" -f $m.Id, $m.Nombre
    Write-Host ("-> {0}" -f $etiqueta) -ForegroundColor White

    if ($m.RequiereAdmin -and -not $ctx.IsAdmin) {
        Write-AuditLog -Level WARN -Source $m.Id -Message 'Requiere elevacion. Se omite.'
        $null = $resultados.Add([pscustomobject]@{
            Meta = $m; Status = 'SkippedNoAdmin'; Records = @(); RecordCount = 0
            Findings = @(); Metrics = @{}; Gaps = @('Colector omitido: requiere privilegios administrativos.')
            CollectedAt = Get-Date; DuracionSeg = 0
        })
        continue
    }

    $t0 = Get-Date
    try {
        $argumentos = Get-CollectorArgs -Path $item.File -Base @{ Config = $config }
        $r = & $item.File @argumentos

        if (-not $r) {
            throw 'El colector no devolvio un resultado.'
        }

        $dur = [math]::Round(((Get-Date) - $t0).TotalSeconds, 2)
        $r | Add-Member -NotePropertyName DuracionSeg -NotePropertyValue $dur -Force

        $null = $resultados.Add($r)
        foreach ($h in @($r.Findings)) { $null = $todosHallazgos.Add($h) }

        # Persistir datos crudos del colector
        if (@($r.Records).Count -gt 0) {
            $null = Export-AuditArtifact -Data @($r.Records) -Name $m.Id -Format Both
        }

        $criticos = @($r.Findings | Where-Object { $_.Severity -in @('Critical','High') }).Count
        $color = if ($criticos -gt 0) { 'Yellow' } else { 'Green' }
        Write-Host ("   OK  {0} registros | {1} hallazgos ({2} altos/criticos) | {3}s" -f `
            @($r.Records).Count, @($r.Findings).Count, $criticos, $dur) -ForegroundColor $color

        foreach ($g in @($r.Gaps)) {
            Write-AuditLog -Level WARN -Source $m.Id -Message ("Brecha de evidencia: {0}" -f $g) -Quiet
        }
        Write-AuditLog -Level OK -Source $m.Id -Message ("Completado en {0}s con {1} registros y {2} hallazgos." -f $dur, @($r.Records).Count, @($r.Findings).Count) -Quiet
    }
    catch {
        $dur = [math]::Round(((Get-Date) - $t0).TotalSeconds, 2)
        Write-Host ("   ERROR: {0}" -f $_.Exception.Message) -ForegroundColor Red
        Write-AuditLog -Level ERROR -Source $m.Id -Message ("Fallo: {0} | {1}" -f $_.Exception.Message, $_.ScriptStackTrace) -Quiet
        $null = $resultados.Add([pscustomobject]@{
            Meta = $m; Status = 'Failed'; Records = @(); RecordCount = 0
            Findings = @(); Metrics = @{}; Gaps = @("Fallo en la ejecucion: $($_.Exception.Message)")
            CollectedAt = Get-Date; DuracionSeg = $dur
        })
    }
}

$duracionTotal = [math]::Round(((Get-Date) - $inicioTotal).TotalSeconds, 1)

# ---------------------------------------------------------------------------
# Consolidacion
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host 'Consolidando resultados...' -ForegroundColor White

$hallazgos = @($todosHallazgos | Sort-Object `
    @{ Expression = 'SeverityRank'; Descending = $true },
    @{ Expression = 'Layer';        Descending = $false },
    @{ Expression = 'CollectorId';  Descending = $false })

# Riesgo agregado ponderado por capa
$pesosCapa = @{}
foreach ($l in $config.Layers) { $pesosCapa[$l.Id] = [double]$l.Peso }

$puntosSeveridad = @{ 'Critical' = 10; 'High' = 6; 'Medium' = 3; 'Low' = 1; 'Info' = 0 }

$riesgoTotal = 0.0
$riesgoPorCapa = @{}
foreach ($h in $hallazgos) {
    $peso = if ($pesosCapa.ContainsKey($h.Layer)) { $pesosCapa[$h.Layer] } else { 1.0 }
    $pts  = $puntosSeveridad[$h.Severity] * $peso
    $riesgoTotal += $pts
    if (-not $riesgoPorCapa.ContainsKey($h.Layer)) { $riesgoPorCapa[$h.Layer] = 0.0 }
    $riesgoPorCapa[$h.Layer] += $pts
}
$riesgoTotal = [math]::Round($riesgoTotal, 1)

$nivelRiesgo = if ($riesgoTotal -ge 200) { 'CRITICO' }
               elseif ($riesgoTotal -ge 100) { 'ALTO' }
               elseif ($riesgoTotal -ge 40)  { 'MEDIO' }
               elseif ($riesgoTotal -gt 0)   { 'BAJO' }
               else { 'SIN HALLAZGOS' }

# Cobertura de criterios de auditoria
$colectoresEjecutados = @($resultados | Where-Object { $_.Status -eq 'Completed' } | ForEach-Object { $_.Meta.Id })
$cobertura = New-Object System.Collections.ArrayList

$nombreGrupo = @{}
foreach ($g in $mapping.Grupos) { $nombreGrupo[$g.Id] = "$($g.Id) - $($g.Nombre)" }

foreach ($c in $mapping.Criterios) {
    $ejecutados = @($c.Colectores | Where-Object { $_ -in $colectoresEjecutados })
    $hallazgosCrit = @($hallazgos | Where-Object { $c.Id -in $_.Criterios })

    $estado = if ($ejecutados.Count -eq 0) { 'Sin evidencia' }
              elseif ($ejecutados.Count -lt @($c.Colectores).Count) { 'Evidencia parcial' }
              else { 'Evidenciado' }

    $conformidad = if ($estado -eq 'Sin evidencia') { 'No evaluado' }
                   elseif (@($hallazgosCrit | Where-Object { $_.Severity -in @('Critical','High') }).Count -gt 0) { 'No conforme' }
                   elseif (@($hallazgosCrit | Where-Object { $_.Severity -in @('Medium','Low') }).Count -gt 0) { 'Conforme con observaciones' }
                   else { 'Conforme' }

    $null = $cobertura.Add([pscustomobject]@{
        Criterio       = $c.Id
        Dominio        = $(if ($nombreGrupo.ContainsKey($c.Grupo)) { $nombreGrupo[$c.Grupo] } else { $c.Grupo })
        Titulo         = $c.Titulo
        Objetivo       = $c.Objetivo
        Capas          = ($c.Capas -join ', ')
        Colectores     = ($c.Colectores -join ', ')
        ColectoresEjecutados = ($ejecutados -join ', ')
        NivelCobertura = $c.Cobertura
        Estado         = $estado
        Conformidad    = $conformidad
        TotalHallazgos = $hallazgosCrit.Count
        Criticos       = @($hallazgosCrit | Where-Object { $_.Severity -eq 'Critical' }).Count
        Altos          = @($hallazgosCrit | Where-Object { $_.Severity -eq 'High' }).Count
    })
}

# Brechas de evidencia
$brechas = New-Object System.Collections.ArrayList
foreach ($r in $resultados) {
    foreach ($g in @($r.Gaps)) {
        $null = $brechas.Add([pscustomobject]@{
            Colector = $r.Meta.Id; Capa = $r.Meta.Layer; Brecha = $g
        })
    }
}

# Resumen por capa
$resumenCapas = New-Object System.Collections.ArrayList
foreach ($l in ($config.Layers | Sort-Object Orden)) {
    $rs = @($resultados | Where-Object { $_.Meta.Layer -eq $l.Id })
    $hs = @($hallazgos  | Where-Object { $_.Layer -eq $l.Id })
    $null = $resumenCapas.Add([pscustomobject]@{
        Capa           = $l.Id
        Nombre         = $l.Nombre
        Descripcion    = $l.Descripcion
        Peso           = $l.Peso
        Orden          = $l.Orden
        Colectores     = $rs.Count
        ColectoresOK   = @($rs | Where-Object { $_.Status -eq 'Completed' }).Count
        Registros      = [int](@($rs | Measure-Object -Property RecordCount -Sum).Sum)
        Hallazgos      = $hs.Count
        Criticos       = @($hs | Where-Object { $_.Severity -eq 'Critical' }).Count
        Altos          = @($hs | Where-Object { $_.Severity -eq 'High' }).Count
        Medios         = @($hs | Where-Object { $_.Severity -eq 'Medium' }).Count
        Bajos          = @($hs | Where-Object { $_.Severity -eq 'Low' }).Count
        PuntajeRiesgo  = if ($riesgoPorCapa.ContainsKey($l.Id)) { [math]::Round($riesgoPorCapa[$l.Id],1) } else { 0 }
    })
}

# Metricas consolidadas
$metricasGlobales = @{}
foreach ($r in $resultados) {
    foreach ($k in @($r.Metrics.Keys)) {
        $metricasGlobales["$($r.Meta.Id).$k"] = $r.Metrics[$k]
    }
}

$resumen = [pscustomobject]@{
    RunId              = $ctx.RunId
    Servidor           = $ctx.Hostname
    Dominio            = $ctx.Domain
    EjecutadoPor       = $ctx.RunAs
    Elevado            = $ctx.IsAdmin
    Inicio             = $ctx.StartTime.ToString('s')
    Fin                = (Get-Date).ToString('s')
    DuracionSegundos   = $duracionTotal
    Marco              = $config.Scope.Marco
    Organizacion       = $config.Scope.Organizacion
    ColectoresTotal    = $resultados.Count
    ColectoresOK       = @($resultados | Where-Object { $_.Status -eq 'Completed' }).Count
    ColectoresFallidos = @($resultados | Where-Object { $_.Status -eq 'Failed' }).Count
    ColectoresOmitidos = @($resultados | Where-Object { $_.Status -like 'Skipped*' }).Count
    RegistrosTotal     = [int](@($resultados | Measure-Object -Property RecordCount -Sum).Sum)
    HallazgosTotal     = $hallazgos.Count
    Criticos           = @($hallazgos | Where-Object { $_.Severity -eq 'Critical' }).Count
    Altos              = @($hallazgos | Where-Object { $_.Severity -eq 'High' }).Count
    Medios             = @($hallazgos | Where-Object { $_.Severity -eq 'Medium' }).Count
    Bajos              = @($hallazgos | Where-Object { $_.Severity -eq 'Low' }).Count
    Informativos       = @($hallazgos | Where-Object { $_.Severity -eq 'Info' }).Count
    PuntajeRiesgo      = $riesgoTotal
    NivelRiesgo        = $nivelRiesgo
    CriteriosEvaluados = @($cobertura | Where-Object { $_.Estado -ne 'Sin evidencia' }).Count
    CriteriosTotal     = @($cobertura).Count
    CriteriosNoConformes = @($cobertura | Where-Object { $_.Conformidad -eq 'No conforme' }).Count
    BrechasEvidencia   = $brechas.Count
    Metricas           = $metricasGlobales
}

# ---------------------------------------------------------------------------
# Exportacion
# ---------------------------------------------------------------------------
$null = Export-AuditArtifact -Data $hallazgos              -Name 'HALLAZGOS'          -Format Both
$null = Export-AuditArtifact -Data @($cobertura)           -Name 'COBERTURA-CRITERIOS' -Format Both
$null = Export-AuditArtifact -Data @($resumenCapas)        -Name 'RESUMEN-CAPAS'      -Format Both
$null = Export-AuditArtifact -Data @($brechas)             -Name 'BRECHAS-EVIDENCIA'  -Format Both
$null = Export-AuditArtifact -Data @($resumen)             -Name 'RESUMEN'            -Format Both

# Inventario de software consolidado (entregable clave de la capa L4)
$invSoftware = @($resultados | Where-Object { $_.Meta.Id -eq 'L4-01' } | ForEach-Object { $_.Records })
if ($invSoftware.Count -gt 0) {
    $null = Export-AuditArtifact -Data $invSoftware -Name 'INVENTARIO-SOFTWARE' -Format Both
}

# Linea base de arquitectura empresarial (entregable del mapeo EA)
$eaBaseline = @($resultados | Where-Object { $_.Meta.Id -eq 'L4-06' } | ForEach-Object { $_.Records })
if ($eaBaseline.Count -gt 0) {
    $null = Export-AuditArtifact -Data $eaBaseline -Name 'LINEA-BASE-ARQUITECTURA' -Format Both
}

# Glosario de criterios citados, como entregable independiente
$glosario = @()
if ($mapping -and $mapping.Criterios) {
    $citados = New-Object System.Collections.Generic.HashSet[string]
    foreach ($h in $hallazgos)   { foreach ($c in @($h.Criterios))      { if ($c) { $null = $citados.Add([string]$c) } } }
    foreach ($r in $resultados)  { foreach ($c in @($r.Meta.Criterios)) { if ($c) { $null = $citados.Add([string]$c) } } }

    $glosario = @($mapping.Criterios | Where-Object { $citados.Contains([string]$_.Id) } | ForEach-Object {
        [pscustomobject]@{
            Criterio    = $_.Id
            Dominio     = $(if ($nombreGrupo.ContainsKey($_.Grupo)) { $nombreGrupo[$_.Grupo] } else { $_.Grupo })
            Titulo      = $_.Titulo
            Descripcion = $_.Descripcion
            Objetivo    = $_.Objetivo
            Cobertura   = $_.Cobertura
            Capas       = ($_.Capas -join ', ')
            Colectores  = ($_.Colectores -join ', ')
        }
    })
    if ($glosario.Count -gt 0) {
        $null = Export-AuditArtifact -Data $glosario -Name 'GLOSARIO-CRITERIOS' -Format Both
    }
}

# Manifiesto de integridad de la evidencia (cadena de custodia)
$manifiesto = [pscustomobject]@{
    RunId       = $ctx.RunId
    Servidor    = $ctx.Hostname
    GeneradoEl  = (Get-Date).ToString('s')
    GeneradoPor = $ctx.RunAs
    Marco       = $config.Scope.Marco
    Artefactos  = @($ctx.Artifacts)
}
$manifiestoPath = Join-Path $ctx.RunPath 'MANIFIESTO-INTEGRIDAD.json'
Write-Utf8File -Path $manifiestoPath -Content ($manifiesto | ConvertTo-Json -Depth 5)

# ---------------------------------------------------------------------------
# Entregables: libro de Excel y ficha imprimible
# ---------------------------------------------------------------------------
$excelPath = $null
$fichaPath = $null

if (-not $NoReport) {

    # 1. Libro de Excel con el detalle completo
    $excelScript = Join-Path $scriptRoot 'Reports\New-AuditExcel.ps1'
    if (Test-Path $excelScript) {
        try {
            $excelPath = & $excelScript -Resumen $resumen -Hallazgos $hallazgos `
                -Capas @($resumenCapas) -Cobertura @($cobertura) -Brechas @($brechas) `
                -Resultados @($resultados) -Glosario @($glosario) `
                -Config $config -Arquitectura $arquitectura -OutputPath $ctx.RunPath

            $sha = ''
            try { $sha = (Get-FileHash -LiteralPath $excelPath -Algorithm SHA256).Hash } catch { }
            $null = $ctx.Artifacts.Add([pscustomobject]@{
                File = Split-Path $excelPath -Leaf; Path = $excelPath; SHA256 = $sha
                Bytes = (Get-Item -LiteralPath $excelPath).Length
            })
            Write-Host ("Libro de Excel : {0}" -f $excelPath) -ForegroundColor Green
        } catch {
            Write-Host ("No se pudo generar el libro de Excel: {0}" -f $_.Exception.Message) -ForegroundColor Red
            Write-AuditLog -Level ERROR -Source 'EXCEL' -Message ("{0} | {1}" -f $_.Exception.Message, $_.ScriptStackTrace) -Quiet
        }
    }

    # 2. Ficha imprimible
    $fichaScript = Join-Path $scriptRoot 'Reports\New-AuditFicha.ps1'
    if (Test-Path $fichaScript) {
        try {
            $fichaPath = & $fichaScript -Resumen $resumen -Hallazgos $hallazgos `
                -Capas @($resumenCapas) -Cobertura @($cobertura) -Brechas @($brechas) `
                -Resultados @($resultados) -Config $config -Arquitectura $arquitectura `
                -ArchivoExcel ([string]$excelPath) -OutputPath $ctx.RunPath
            Write-Host ("Ficha imprimible: {0}" -f $fichaPath) -ForegroundColor Green
        } catch {
            Write-Host ("No se pudo generar la ficha: {0}" -f $_.Exception.Message) -ForegroundColor Red
            Write-AuditLog -Level ERROR -Source 'FICHA' -Message ("{0} | {1}" -f $_.Exception.Message, $_.ScriptStackTrace) -Quiet
        }
    }

    # 3. Ficha en Word, para entregarse como reporte formal.
    #    Se alimenta del expediente ya escrito en raw\, no de los objetos vivos, por lo
    #    que debe ejecutarse despues de que el resto de los artefactos esten en disco.
    $docxScript = Join-Path $scriptRoot 'Reports\New-AuditFichaDocx.ps1'
    if (Test-Path $docxScript) {
        try {
            $docxPath = & $docxScript -RunId $ctx.RunId -AuditRoot $scriptRoot -OutputPath $ctx.RunPath
            Write-Host ("Ficha Word: {0}" -f $docxPath) -ForegroundColor Green
        } catch {
            Write-Host ("No se pudo generar la ficha Word: {0}" -f $_.Exception.Message) -ForegroundColor Red
            Write-AuditLog -Level ERROR -Source 'FICHADOCX' -Message ("{0} | {1}" -f $_.Exception.Message, $_.ScriptStackTrace) -Quiet
        }
    }
}

# ---------------------------------------------------------------------------
# Purga de ejecuciones antiguas
# ---------------------------------------------------------------------------
if ($Purge) {
    $retencion = if ($config.Report.RetencionDias) { [int]$config.Report.RetencionDias } else { 180 }
    $limite = (Get-Date).AddDays(-$retencion)
    $raizSalida = Split-Path $ctx.RunPath -Parent
    $eliminadas = 0
    foreach ($d in (Get-ChildItem -Path $raizSalida -Directory -ErrorAction SilentlyContinue)) {
        if ($d.FullName -eq $ctx.RunPath) { continue }
        if ($d.CreationTime -lt $limite) {
            try { Remove-Item -LiteralPath $d.FullName -Recurse -Force -Confirm:$false; $eliminadas++ } catch { }
        }
    }
    Write-Host ("Purga: {0} ejecuciones anteriores a {1} dias eliminadas." -f $eliminadas, $retencion) -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Resumen en consola
# ---------------------------------------------------------------------------
$colorRiesgo = switch ($nivelRiesgo) {
    'CRITICO' { 'Red' } 'ALTO' { 'Red' } 'MEDIO' { 'Yellow' } 'BAJO' { 'Green' } default { 'Green' }
}

Write-Host ''
Write-Host '===============================================================' -ForegroundColor Cyan
Write-Host '  RESUMEN DE LA AUDITORIA' -ForegroundColor Cyan
Write-Host '===============================================================' -ForegroundColor Cyan
Write-Host ("  Duracion          : {0} s" -f $duracionTotal)
Write-Host ("  Colectores        : {0} ejecutados / {1} fallidos / {2} omitidos" -f `
    $resumen.ColectoresOK, $resumen.ColectoresFallidos, $resumen.ColectoresOmitidos)
Write-Host ("  Registros         : {0}" -f $resumen.RegistrosTotal)
Write-Host ''
Write-Host ("  Hallazgos totales : {0}" -f $resumen.HallazgosTotal)
Write-Host ("    Criticos        : {0}" -f $resumen.Criticos)      -ForegroundColor $(if ($resumen.Criticos) {'Red'} else {'Gray'})
Write-Host ("    Altos           : {0}" -f $resumen.Altos)         -ForegroundColor $(if ($resumen.Altos) {'Red'} else {'Gray'})
Write-Host ("    Medios          : {0}" -f $resumen.Medios)        -ForegroundColor $(if ($resumen.Medios) {'Yellow'} else {'Gray'})
Write-Host ("    Bajos           : {0}" -f $resumen.Bajos)         -ForegroundColor Gray
Write-Host ("    Informativos    : {0}" -f $resumen.Informativos)  -ForegroundColor DarkGray
Write-Host ''
Write-Host ("  Puntaje de riesgo : {0}  [{1}]" -f $riesgoTotal, $nivelRiesgo) -ForegroundColor $colorRiesgo
Write-Host ("  Criterios         : {0}/{1} evidenciados, {2} no conformes" -f `
    $resumen.CriteriosEvaluados, $resumen.CriteriosTotal, $resumen.CriteriosNoConformes)
Write-Host ("  Brechas evidencia : {0}" -f $resumen.BrechasEvidencia) -ForegroundColor $(if ($brechas.Count) {'Yellow'} else {'Gray'})
Write-Host ''
Write-Host '  Riesgo por capa:' -ForegroundColor White
foreach ($c in ($resumenCapas | Sort-Object PuntajeRiesgo -Descending)) {
    if ($c.Colectores -eq 0) { continue }
    $marca = if ($c.Capa -eq 'L4') { ' <- PRIORITARIA' } else { '' }
    Write-Host ("    {0}  {1,-42} riesgo {2,6}  ({3} hallazgos){4}" -f `
        $c.Capa, $c.Nombre.Substring(0, [math]::Min(42, $c.Nombre.Length)), $c.PuntajeRiesgo, $c.Hallazgos, $marca) `
        -ForegroundColor $(if ($c.Capa -eq 'L4') {'Cyan'} elseif ($c.Criticos -gt 0) {'Red'} elseif ($c.Altos -gt 0) {'Yellow'} else {'Gray'})
}
Write-Host ''
Write-Host ("  Evidencia: {0}" -f $ctx.RunPath) -ForegroundColor Green
Write-Host ("  Registro : {0}" -f $ctx.LogFile) -ForegroundColor DarkGray
Write-Host '===============================================================' -ForegroundColor Cyan
Write-Host ''

Write-AuditLog -Level OK -Source 'ORQ' -Message ("Auditoria finalizada. Riesgo={0} ({1}). Hallazgos={2}." -f $riesgoTotal, $nivelRiesgo, $hallazgos.Count) -Quiet

# Objeto de retorno para automatizacion / integracion con monitoreo
[pscustomobject]@{
    Resumen    = $resumen
    Hallazgos  = $hallazgos
    Capas      = @($resumenCapas)
    Cobertura  = @($cobertura)
    Glosario   = @($glosario)
    Brechas    = @($brechas)
    RutaSalida = $ctx.RunPath
    RutaExcel  = $excelPath
    RutaFicha  = $fichaPath
    RutaLog    = $ctx.LogFile
}
