<#
    L5-01_Services.ps1
    Capa L5 - Servicios y procesos.
    Criterios de auditoria -> ARQ-01, ACC-02, SW-03, SW-05
#>
param([switch]$Manifest, [hashtable]$Config)

$meta = @{
    Id            = 'L5-01'
    Nombre        = 'Servicios Windows y configuracion de ejecucion'
    Layer         = 'L5'
    Criterios     = @('ARQ-01','ACC-02','SW-03','SW-05')
    RequiereAdmin = $false
    Descripcion   = 'Inventario de servicios con analisis de rutas sin comillas, cuentas privilegiadas y binarios fuera de rutas estandar.'
}
if ($Manifest) { return [pscustomobject]$meta }

$records  = New-Object System.Collections.ArrayList
$findings = New-Object System.Collections.ArrayList
$gaps     = New-Object System.Collections.ArrayList
$metrics  = @{}

$rutasEstandar = @("$env:SystemRoot", "$env:ProgramFiles", "${env:ProgramFiles(x86)}")

try {
    $servicios = Get-CimInstance Win32_Service -ErrorAction Stop
} catch {
    $null = $gaps.Add("Win32_Service no accesible: $($_.Exception.Message)")
    return New-CollectorResult -Meta $meta -Records @() -Findings @() -Metrics @{} `
        -Gaps $gaps.ToArray() -Status 'Failed'
}

$sinComillas    = New-Object System.Collections.ArrayList
$privilegiados  = New-Object System.Collections.ArrayList
$fueraEstandar  = New-Object System.Collections.ArrayList

foreach ($s in $servicios) {
    $pathName = [string]$s.PathName
    $exe = ''
    if ($pathName -match '^\s*"([^"]+)"') { $exe = $Matches[1] }
    else {
        $m = [regex]::Match($pathName, '^\s*(\S+\.exe)', 'IgnoreCase')
        $exe = if ($m.Success) { $m.Groups[1].Value } else { ($pathName -split '\s+')[0] }
    }
    $exe = [Environment]::ExpandEnvironmentVariables($exe)

    # Ruta sin comillas con espacios -> secuestro de ruta de servicio no citada
    $rutaVulnerable = $false
    if ($pathName -and $pathName.Trim() -notmatch '^"' -and $exe -match '\s') {
        # Excluye svchost y binarios del sistema sin argumentos problematicos
        if ($exe -notlike "$env:SystemRoot\System32\*") { $rutaVulnerable = $true }
    }

    $enRutaEstandar = $false
    foreach ($r in $rutasEstandar) {
        if ($r -and $exe -like "$r*") { $enRutaEstandar = $true; break }
    }

    $cuenta = [string]$s.StartName
    $esPrivilegiado = $cuenta -match '(?i)^(LocalSystem|\.\\Administrator|.*\\Administrator)$'

    $registro = [pscustomobject]@{
        Nombre          = $s.Name
        NombreMostrado  = ConvertTo-SafeString $s.DisplayName 150
        Estado          = $s.State
        TipoInicio      = $s.StartMode
        Cuenta          = $cuenta
        RutaImagen      = ConvertTo-SafeString $pathName 500
        Ejecutable      = $exe
        EnRutaEstandar  = $enRutaEstandar
        RutaSinComillas = $rutaVulnerable
        Descripcion     = ConvertTo-SafeString $s.Description 300
        PID             = $s.ProcessId
    }
    $null = $records.Add($registro)

    if ($rutaVulnerable)                                { $null = $sinComillas.Add($registro) }
    if ($esPrivilegiado -and $s.StartMode -ne 'Disabled') { $null = $privilegiados.Add($registro) }
    if (-not $enRutaEstandar -and $exe -and $s.StartMode -ne 'Disabled') { $null = $fueraEstandar.Add($registro) }
}

# --- Hallazgos --------------------------------------------------------------
if ($sinComillas.Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'High' -Category 'EscaladaDePrivilegios' `
        -Title 'Servicios con ruta de imagen sin comillas y espacios' `
        -Asset ("{0} servicios" -f $sinComillas.Count) `
        -Detail 'Cuando la ruta del ejecutable contiene espacios y no esta entrecomillada, Windows intenta ejecutar cada segmento previo. Si un directorio intermedio es escribible, permite ejecutar codigo arbitrario con los privilegios del servicio.' `
        -Evidence (($sinComillas | Select-Object -First 12 | ForEach-Object { "$($_.Nombre) => $($_.RutaImagen)" }) -join ' | ') `
        -Criterios @('ARQ-01','ACC-02') `
        -Recommendation 'Entrecomillar la ruta de imagen de cada servicio afectado y verificar los permisos NTFS de los directorios intermedios.'))
}

if ($fueraEstandar.Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'Medium' -Category 'SoftwareNoGestionado' `
        -Title 'Servicios ejecutando binarios fuera de las rutas de instalacion estandar' `
        -Asset ("{0} servicios" -f $fueraEstandar.Count) `
        -Detail 'Estos servicios ejecutan binarios que no residen en Windows ni en Archivos de programa, lo que sugiere software desplegado sin instalador o fuera del proceso de gestion de cambios.' `
        -Evidence (($fueraEstandar | Select-Object -First 12 | ForEach-Object { "$($_.Nombre) => $($_.Ejecutable)" }) -join ' | ') `
        -Criterios @('SW-03','ARQ-01') `
        -Recommendation 'Correlacionar cada servicio con el inventario de software autorizado (colector L4-01) y confirmar su firma digital (colector L4-04).'))
}

if ($privilegiados.Count -gt 0) {
    $noSistema = @($privilegiados | Where-Object { -not $_.EnRutaEstandar })
    if ($noSistema.Count -gt 0) {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'High' -Category 'Privilegios' `
            -Title 'Servicios de terceros ejecutandose como LocalSystem' `
            -Asset ("{0} servicios" -f $noSistema.Count) `
            -Detail 'Servicios cuyo binario no proviene de rutas del sistema se ejecutan con la cuenta de mayor privilegio del equipo. Una vulnerabilidad en ellos implica compromiso total del servidor.' `
            -Evidence (($noSistema | Select-Object -First 12 | ForEach-Object { "$($_.Nombre) [$($_.Cuenta)] => $($_.Ejecutable)" }) -join ' | ') `
            -Criterios @('ACC-02','ARQ-01') `
            -Recommendation 'Aplicar el principio de privilegio minimo: migrar a cuentas de servicio gestionadas (gMSA) o a NetworkService/LocalService cuando el producto lo soporte.'))
    }
}

# Servicios detenidos con inicio automatico: indicio de configuracion degradada
$autoDetenidos = @($records | Where-Object { $_.TipoInicio -eq 'Auto' -and $_.Estado -eq 'Stopped' })
if ($autoDetenidos.Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'Low' -Category 'Operacion' `
        -Title 'Servicios con inicio automatico que se encuentran detenidos' `
        -Asset ("{0} servicios" -f $autoDetenidos.Count) `
        -Detail 'Un servicio configurado para iniciar automaticamente pero detenido puede indicar una falla no atendida o la desactivacion manual de un control de seguridad.' `
        -Evidence (($autoDetenidos | Select-Object -First 12 | ForEach-Object { $_.Nombre }) -join ', ') `
        -Criterios @('REG-02','ARQ-01') `
        -Recommendation 'Revisar el registro de eventos del sistema para cada servicio y determinar si la interrupcion es intencional y esta documentada.'))
}

# Cuentas de servicio con credenciales de dominio o de usuario nominal
$cuentasNominales = @($records | Where-Object {
    $_.Cuenta -and
    $_.Cuenta -notmatch '(?i)^(LocalSystem|NT AUTHORITY\\|NT SERVICE\\|LocalService|NetworkService)' -and
    $_.TipoInicio -ne 'Disabled'
})
if ($cuentasNominales.Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'Medium' -Category 'Privilegios' `
        -Title 'Servicios configurados con cuentas nominales o de dominio' `
        -Asset ("{0} servicios" -f $cuentasNominales.Count) `
        -Detail 'Las cuentas nominales usadas como cuentas de servicio almacenan credenciales en el LSA, rara vez rotan su contrasena y dificultan la atribucion de acciones.' `
        -Evidence (($cuentasNominales | Select-Object -First 12 | ForEach-Object { "$($_.Nombre) [$($_.Cuenta)]" }) -join ' | ') `
        -Criterios @('ACC-02','ACC-01','ACC-03') `
        -Recommendation 'Migrar a cuentas de servicio administradas de grupo (gMSA) con rotacion automatica de contrasena, o a cuentas de servicio dedicadas con rotacion documentada.'))
}

$metrics['TotalServicios']       = $records.Count
$metrics['ServiciosEnEjecucion'] = @($records | Where-Object { $_.Estado -eq 'Running' }).Count
$metrics['RutasSinComillas']     = $sinComillas.Count
$metrics['FueraDeRutaEstandar']  = $fueraEstandar.Count
$metrics['ComoLocalSystem']      = $privilegiados.Count

New-CollectorResult -Meta $meta -Records $records.ToArray() -Findings $findings.ToArray() `
    -Metrics $metrics -Gaps $gaps.ToArray()
