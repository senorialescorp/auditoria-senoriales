<#
    L4-05_Software-Lifecycle.ps1
    Capa L4 - ARTEFACTOS DE SOFTWARE.

    Evaluacion del ciclo de vida del software instalado: fin de soporte (EOL),
    versiones duplicadas o divergentes y concentracion de proveedores.
    Cierra el circuito entre el inventario (INV-01) y la gestion de
    vulnerabilidades tecnicas (VUL-01).

    Criterios de auditoria -> VUL-01, INV-01, SW-03, SW-04
#>
param([switch]$Manifest, [hashtable]$Config)

$meta = @{
    Id            = 'L4-05'
    Nombre        = 'Ciclo de vida y soporte del software instalado'
    Layer         = 'L4'
    Criterios     = @('SW-02','VUL-01','INV-01','SW-03','SW-04')
    RequiereAdmin = $false
    Descripcion   = 'Deteccion de software fuera de soporte, versiones duplicadas y analisis de dependencia de proveedores.'
}
if ($Manifest) { return [pscustomobject]$meta }

$records  = New-Object System.Collections.ArrayList
$findings = New-Object System.Collections.ArrayList
$gaps     = New-Object System.Collections.ArrayList
$metrics  = @{}

$software = @()
try {
    $software = @(Get-InstalledSoftwareRaw)
} catch {
    $null = $gaps.Add("No se pudo obtener el inventario base: $($_.Exception.Message)")
}

if ($software.Count -eq 0) {
    return New-CollectorResult -Meta $meta -Records @() -Findings @() -Metrics @{} `
        -Gaps $gaps.ToArray() -Status 'NoData'
}

$catalogoEol = @()
if ($Config -and $Config.EndOfLife) { $catalogoEol = @($Config.EndOfLife) }

$hoy = Get-Date

# ---------------------------------------------------------------------------
# 1. Evaluacion contra el catalogo de fin de soporte
# ---------------------------------------------------------------------------
$eolDetectados = New-Object System.Collections.ArrayList

foreach ($app in $software) {
    $etiqueta = ("{0} {1}" -f $app.DisplayName, $app.DisplayVersion).Trim()
    $estado   = 'Soportado / no catalogado'
    $fechaEol = $null
    $nota     = ''
    $sev      = ''

    foreach ($regla in $catalogoEol) {
        if ($etiqueta -match $regla.Patron) {
            $fechaEol = [datetime]$regla.EOL
            $nota     = [string]$regla.Nota
            $sev      = [string]$regla.Severidad
            $estado   = if ($fechaEol -lt $hoy) { 'FUERA DE SOPORTE' }
                        elseif (($fechaEol - $hoy).TotalDays -lt 180) { 'Soporte proximo a vencer' }
                        else { 'Soportado' }
            break
        }
    }

    $registro = [pscustomobject]@{
        Nombre         = $app.DisplayName
        Version        = $app.DisplayVersion
        Publicador     = $app.Publisher
        Estado         = $estado
        FechaFinSoporte = if ($fechaEol) { $fechaEol.ToString('yyyy-MM-dd') } else { '' }
        DiasDesdeEOL   = if ($fechaEol -and $fechaEol -lt $hoy) { [int]($hoy - $fechaEol).TotalDays } else { $null }
        Severidad      = $sev
        Nota           = $nota
        FechaInstalacion = if ($app.InstallDate) { $app.InstallDate.ToString('yyyy-MM-dd') } else { '' }
    }
    $null = $records.Add($registro)

    if ($estado -eq 'FUERA DE SOPORTE') { $null = $eolDetectados.Add($registro) }
    elseif ($estado -eq 'Soporte proximo a vencer') {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'Low' -Category 'CicloDeVida' `
            -Title ("Fin de soporte proximo: {0}" -f $app.DisplayName) `
            -Asset $etiqueta `
            -Detail ("El soporte finaliza el {0} (en menos de 180 dias). {1}" -f $fechaEol.ToString('yyyy-MM-dd'), $nota) `
            -Criterios @('SW-02','VUL-01','INV-01') `
            -Recommendation 'Incluir la migracion en el plan anual de mantenimiento antes de la fecha de fin de soporte.'))
    }
}

# Un hallazgo por cada producto fuera de soporte: son no conformidades individuales
foreach ($e in $eolDetectados) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity $(if ($e.Severidad) { $e.Severidad } else { 'High' }) -Category 'CicloDeVida' `
        -Title ("Software fuera de soporte del proveedor: {0}" -f $e.Nombre) `
        -Asset ("{0} {1}" -f $e.Nombre, $e.Version) `
        -Detail ("Fin de soporte: {0} (hace {1} dias). {2} Un producto sin soporte no recibe correcciones para vulnerabilidades descubiertas despues de esa fecha." -f $e.FechaFinSoporte, $e.DiasDesdeEOL, $e.Nota) `
        -Evidence ("Publicador: {0} | Instalado: {1}" -f $e.Publicador, $e.FechaInstalacion) `
        -Criterios @('SW-02','VUL-01','INV-01','SW-03') `
        -Recommendation 'Actualizar a una version soportada. Si la migracion no es viable a corto plazo, documentar la aceptacion del riesgo con aprobacion de la direccion, definir controles compensatorios (aislamiento de red, control de aplicaciones) y fijar una fecha limite de remediacion.'))
}

# ---------------------------------------------------------------------------
# 2. Versiones multiples del mismo producto
# ---------------------------------------------------------------------------
$duplicados = $software |
    Group-Object { ($_.DisplayName -replace '\s+\d[\d\.]*\s*$','').Trim().ToLowerInvariant() } |
    Where-Object { ($_.Group | Select-Object -ExpandProperty DisplayVersion -Unique).Count -gt 1 }

foreach ($g in $duplicados) {
    $versiones = @($g.Group | Select-Object -ExpandProperty DisplayVersion -Unique | Where-Object { $_ })
    if ($versiones.Count -lt 2) { continue }
    $null = $records.Add([pscustomobject]@{
        Nombre = $g.Group[0].DisplayName; Version = ($versiones -join ' / ')
        Publicador = $g.Group[0].Publisher; Estado = 'Versiones multiples'
        FechaFinSoporte = ''; DiasDesdeEOL = $null; Severidad = 'Low'
        Nota = "Coexisten $($versiones.Count) versiones"; FechaInstalacion = ''
    })
}

if (@($duplicados).Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'Low' -Category 'CicloDeVida' `
        -Title 'Coexistencia de multiples versiones del mismo producto' `
        -Asset ("{0} productos" -f @($duplicados).Count) `
        -Detail 'La convivencia de varias versiones dificulta la gestion de parches: una version antigua puede permanecer vulnerable aunque la nueva ya este corregida.' `
        -Evidence ((@($duplicados) | Select-Object -First 12 | ForEach-Object {
            "$($_.Group[0].DisplayName): " + (($_.Group | Select-Object -ExpandProperty DisplayVersion -Unique) -join ', ')
        }) -join ' | ') `
        -Criterios @('SW-02','VUL-01','INV-01') `
        -Recommendation 'Desinstalar las versiones obsoletas tras confirmar que ninguna aplicacion depende de ellas.'))
}

# ---------------------------------------------------------------------------
# 3. Concentracion de proveedores (insumo para SW-04 cadena de suministro)
# ---------------------------------------------------------------------------
$porPublicador = $software | Where-Object { $_.Publisher } |
                 Group-Object Publisher | Sort-Object Count -Descending

foreach ($p in ($porPublicador | Select-Object -First 25)) {
    $null = $records.Add([pscustomobject]@{
        Nombre = "[Proveedor] $($p.Name)"; Version = ''; Publicador = $p.Name
        Estado = 'Resumen de proveedor'; FechaFinSoporte = ''; DiasDesdeEOL = $null
        Severidad = ''; Nota = "$($p.Count) productos instalados"; FechaInstalacion = ''
    })
}

# ---------------------------------------------------------------------------
# Metricas
# ---------------------------------------------------------------------------
$metrics['ProductosEvaluados']  = $software.Count
$metrics['FueraDeSoporte']      = $eolDetectados.Count
$metrics['ProductosDuplicados'] = @($duplicados).Count
$metrics['ProveedoresDistintos'] = @($porPublicador).Count
$metrics['PorcentajeFueraSoporte'] = if ($software.Count -gt 0) {
    [math]::Round(($eolDetectados.Count / $software.Count) * 100, 1)
} else { 0 }

New-CollectorResult -Meta $meta -Records $records.ToArray() -Findings $findings.ToArray() `
    -Metrics $metrics -Gaps $gaps.ToArray()
