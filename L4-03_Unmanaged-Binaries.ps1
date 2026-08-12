<#
    L4-03_Unmanaged-Binaries.ps1
    Capa L4 - ARTEFACTOS DE SOFTWARE.

    Descubrimiento de binarios y scripts que residen en el servidor sin haber
    pasado por un mecanismo de instalacion gestionado (software portable,
    utilitarios copiados a mano, scripts operativos). Es la evidencia central
    del control SW-03 y del fenomeno de shadow IT.

    Criterios de auditoria -> SW-03, INV-03, SW-05, SW-05
#>
param([switch]$Manifest, [hashtable]$Config)

$meta = @{
    Id            = 'L4-03'
    Nombre        = 'Binarios y scripts no gestionados (shadow IT)'
    Layer         = 'L4'
    Criterios     = @('SW-03','INV-03','SW-05')
    RequiereAdmin = $false
    Descripcion   = 'Escaneo de rutas configuradas en busca de ejecutables y scripts fuera de un instalador, con verificacion de firma digital.'
}
if ($Manifest) { return [pscustomobject]$meta }

$records  = New-Object System.Collections.ArrayList
$findings = New-Object System.Collections.ArrayList
$gaps     = New-Object System.Collections.ArrayList
$metrics  = @{}

$cfg = if ($Config -and $Config.UnmanagedScan) { $Config.UnmanagedScan } else { $null }
if (-not $cfg -or -not $cfg.Habilitado) {
    $null = $gaps.Add('El escaneo de binarios no gestionados esta deshabilitado en Audit.config.psd1 (UnmanagedScan.Habilitado).')
    return New-CollectorResult -Meta $meta -Records @() -Findings @() -Metrics @{} `
        -Gaps $gaps.ToArray() -Status 'Skipped'
}

$rutas       = @($cfg.Rutas)
$excluidas   = @($cfg.RutasExcluidas)
$extensiones = @($cfg.Extensiones)
$profundidad = [int]$cfg.ProfundidadMax
$maxArchivos = [int]$cfg.MaxArchivos
$calcHash    = [bool]$cfg.CalcularHash
$tamMinKB    = 0
if ($Config.Thresholds -and $Config.Thresholds.TamMinBinarioPortableKB) {
    $tamMinKB = [int]$Config.Thresholds.TamMinBinarioPortableKB
}

$confiables = @()
if ($Config.PublicadoresConfiables) { $confiables = @($Config.PublicadoresConfiables) }

# Ubicaciones de instalacion conocidas: un binario aqui probablemente provino
# de un instalador legitimo y se correlaciona con el inventario de L4-01.
$rutasGestionadas = @(
    "$env:ProgramFiles"
    "${env:ProgramFiles(x86)}"
    "$env:SystemRoot"
    "$env:ProgramData\chocolatey"
)

function Test-RutaExcluida {
    param([string]$Ruta)
    foreach ($ex in $excluidas) {
        if ([string]::IsNullOrWhiteSpace($ex)) { continue }
        if ($ex -match '\*') {
            if ($Ruta -like $ex) { return $true }
        } elseif ($Ruta -like "$ex*") { return $true }
    }
    return $false
}

$archivosEvaluados = 0
$limiteAlcanzado   = $false
$rutasOmitidas     = New-Object System.Collections.ArrayList

foreach ($raiz in $rutas) {
    if ($limiteAlcanzado) { break }
    if (-not (Test-Path -LiteralPath $raiz)) { continue }

    try {
        $archivos = Get-ChildItem -LiteralPath $raiz -Recurse -File -Depth $profundidad -Force -ErrorAction SilentlyContinue |
                    Where-Object { $extensiones -contains $_.Extension.ToLowerInvariant() }
    } catch {
        $null = $rutasOmitidas.Add("$raiz ($($_.Exception.Message))")
        continue
    }

    foreach ($f in $archivos) {
        if ($archivosEvaluados -ge $maxArchivos) { $limiteAlcanzado = $true; break }
        if (Test-RutaExcluida -Ruta $f.FullName) { continue }
        if ($f.Extension -in @('.exe','.dll') -and ($f.Length / 1KB) -lt $tamMinKB) { continue }

        $archivosEvaluados++

        $esScript = $f.Extension -in @('.ps1','.bat','.cmd','.vbs','.py')
        $sig = if ($esScript -and $f.Extension -notin @('.ps1')) {
            # Solo .ps1 admite Authenticode entre los tipos de script
            [pscustomobject]@{ SignatureStatus='NotApplicable'; Signer=''; SignerIsMS=$false
                               SHA256=''; FileVersion=''; ProductName=''; Company='' }
        } else {
            Get-SignatureInfo -Path $f.FullName -IncludeHash:$calcHash
        }

        $enRutaGestionada = $false
        foreach ($rg in $rutasGestionadas) {
            if ($rg -and $f.FullName -like "$rg*") { $enRutaGestionada = $true; break }
        }

        $publicadorConfiable = $false
        foreach ($c in $confiables) {
            if ($sig.Signer -like "*$c*" -or $sig.Company -like "*$c*") { $publicadorConfiable = $true; break }
        }

        $clasificacion =
            if ($sig.SignatureStatus -eq 'Valid' -and $publicadorConfiable) { 'Firmado - publicador confiable' }
            elseif ($sig.SignatureStatus -eq 'Valid') { 'Firmado - publicador no catalogado' }
            elseif ($sig.SignatureStatus -eq 'NotApplicable') { 'Script sin mecanismo de firma' }
            elseif ($sig.SignatureStatus -eq 'NotSigned') { 'Sin firma digital' }
            else { "Firma invalida ($($sig.SignatureStatus))" }

        $null = $records.Add([pscustomobject]@{
            Ruta            = $f.FullName
            Nombre          = $f.Name
            Extension       = $f.Extension
            TamanoKB        = [math]::Round($f.Length / 1KB, 1)
            UltimaEscritura = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm')
            Creado          = $f.CreationTime.ToString('yyyy-MM-dd')
            EstadoFirma     = $sig.SignatureStatus
            Firmante        = ConvertTo-SafeString $sig.Signer 200
            Compania        = ConvertTo-SafeString $sig.Company 120
            Producto        = ConvertTo-SafeString $sig.ProductName 120
            VersionArchivo  = $sig.FileVersion
            SHA256          = $sig.SHA256
            Clasificacion   = $clasificacion
            EnRutaGestionada = $enRutaGestionada
        })
    }
}

$metrics['ArchivosEvaluados'] = $archivosEvaluados
$metrics['LimiteAlcanzado']   = $limiteAlcanzado

if ($limiteAlcanzado) {
    $null = $gaps.Add("Se alcanzo el tope de $maxArchivos archivos definido en UnmanagedScan.MaxArchivos. La cobertura del escaneo es PARCIAL; ajuste el limite o reduzca las rutas para obtener cobertura completa.")
    Write-AuditLog -Level WARN -Source $meta.Id -Message "Cobertura parcial: se alcanzo el tope de $maxArchivos archivos."
}
if ($rutasOmitidas.Count -gt 0) {
    $null = $gaps.Add("Rutas no accesibles durante el escaneo: " + ($rutasOmitidas -join ' | '))
}

# ---------------------------------------------------------------------------
# Hallazgos
# ---------------------------------------------------------------------------
$sinFirma = @($records | Where-Object {
    $_.EstadoFirma -eq 'NotSigned' -and $_.Extension -in @('.exe','.dll','.msi')
})
if ($sinFirma.Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'High' -Category 'IntegridadDeSoftware' `
        -Title 'Ejecutables sin firma digital fuera de rutas de instalacion gestionadas' `
        -Asset ("{0} archivos" -f $sinFirma.Count) `
        -Detail ("Se identificaron {0} ejecutables o bibliotecas sin firma Authenticode. Sin firma no es posible verificar el origen ni la integridad del artefacto, ni detectar su alteracion posterior." -f $sinFirma.Count) `
        -Evidence (($sinFirma | Select-Object -First 15 | ForEach-Object { "$($_.Ruta) [$($_.TamanoKB) KB]" }) -join ' | ') `
        -Criterios @('SW-03','ARQ-01') `
        -Recommendation 'Verificar el origen de cada binario, reinstalarlo desde una fuente oficial firmada y aplicar control de aplicaciones (AppLocker/WDAC) en modo de exigir firma para rutas de trabajo.'))
}

$firmaInvalida = @($records | Where-Object {
    $_.EstadoFirma -in @('HashMismatch','NotTrusted','UnknownError')
})
if ($firmaInvalida.Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'Critical' -Category 'IntegridadDeSoftware' `
        -Title 'Archivos con firma digital invalida o no confiable' `
        -Asset ("{0} archivos" -f $firmaInvalida.Count) `
        -Detail 'Una firma con HashMismatch indica que el archivo fue modificado despues de ser firmado. NotTrusted indica una cadena de certificacion no reconocida. Ambos escenarios son indicadores de compromiso que requieren analisis inmediato.' `
        -Evidence (($firmaInvalida | Select-Object -First 15 | ForEach-Object { "$($_.Ruta) => $($_.EstadoFirma)" }) -join ' | ') `
        -Criterios @('SW-03','VUL-02','REG-02') `
        -Recommendation 'Aislar los archivos afectados, calcular su hash y contrastarlo con la fuente oficial. Escalar al proceso de gestion de incidentes si la discrepancia se confirma.'))
}

$scriptsSueltos = @($records | Where-Object { $_.Extension -in @('.ps1','.bat','.cmd','.vbs') })
if ($scriptsSueltos.Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'Medium' -Category 'CodigoOperativo' `
        -Title 'Scripts operativos sin control de versiones ni firma' `
        -Asset ("{0} scripts" -f $scriptsSueltos.Count) `
        -Detail ("Se identificaron {0} scripts (.ps1/.bat/.cmd/.vbs) en las rutas auditadas. El codigo operativo no firmado y sin trazabilidad puede ser modificado sin deteccion y suele ejecutarse con privilegios elevados." -f $scriptsSueltos.Count) `
        -Evidence (($scriptsSueltos | Select-Object -First 15 | ForEach-Object { $_.Ruta }) -join ' | ') `
        -Criterios @('SW-05','SW-03','CAM-01') `
        -Recommendation 'Trasladar el codigo operativo a un repositorio con control de versiones, firmarlo con un certificado de la organizacion y establecer ExecutionPolicy en AllSigned.'))
}

# Binarios en directorios escribibles por cualquier usuario: riesgo de secuestro
$rutasRiesgosas = @($records | Where-Object {
    $_.Ruta -match '(?i)\\(temp|tmp|downloads|public|appdata\\local\\temp)\\' -and $_.Extension -in @('.exe','.dll','.msi')
})
if ($rutasRiesgosas.Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'High' -Category 'ControlDeAplicaciones' `
        -Title 'Ejecutables alojados en directorios temporales o de escritura general' `
        -Asset ("{0} archivos" -f $rutasRiesgosas.Count) `
        -Detail 'Los ejecutables situados en rutas escribibles por usuarios sin privilegios son el vector habitual de persistencia y de secuestro de DLL. Ninguna aplicacion de produccion deberia ejecutarse desde estas ubicaciones.' `
        -Evidence (($rutasRiesgosas | Select-Object -First 15 | ForEach-Object { $_.Ruta }) -join ' | ') `
        -Criterios @('SW-03','SW-05') `
        -Recommendation 'Eliminar los binarios que no correspondan a una necesidad operativa y bloquear la ejecucion desde rutas escribibles mediante AppLocker o WDAC.'))
}

$metrics['SinFirma']            = $sinFirma.Count
$metrics['FirmaInvalida']       = $firmaInvalida.Count
$metrics['Scripts']             = $scriptsSueltos.Count
$metrics['EnRutasRiesgosas']    = $rutasRiesgosas.Count
$metrics['FirmadosConfiables']  = @($records | Where-Object { $_.Clasificacion -eq 'Firmado - publicador confiable' }).Count

New-CollectorResult -Meta $meta -Records $records.ToArray() -Findings $findings.ToArray() `
    -Metrics $metrics -Gaps $gaps.ToArray()
