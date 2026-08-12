<#
    L4-04_Software-Integrity.ps1
    Capa L4 - ARTEFACTOS DE SOFTWARE.

    Verificacion de integridad y procedencia de los binarios que efectivamente
    se ejecutan en el servidor: imagenes de servicios y de procesos activos.
    Produce ademas la linea base de hashes para comparacion entre ejecuciones.

    Criterios de auditoria -> SW-03, ARQ-01, VUL-02, CAM-01
#>
param([switch]$Manifest, [hashtable]$Config)

$meta = @{
    Id            = 'L4-04'
    Nombre        = 'Integridad y procedencia de binarios en ejecucion'
    Layer         = 'L4'
    Criterios     = @('SW-03','ARQ-01','VUL-02','CAM-01')
    RequiereAdmin = $false
    Descripcion   = 'Firma digital y hash SHA256 de las imagenes de servicios y procesos; genera linea base comparable.'
}
if ($Manifest) { return [pscustomobject]$meta }

$records  = New-Object System.Collections.ArrayList
$findings = New-Object System.Collections.ArrayList
$gaps     = New-Object System.Collections.ArrayList
$metrics  = @{}

$confiables = @()
if ($Config -and $Config.PublicadoresConfiables) { $confiables = @($Config.PublicadoresConfiables) }

function Test-PublicadorConfiable {
    param([string]$Firmante, [string]$Compania)
    foreach ($c in $confiables) {
        if ($Firmante -like "*$c*" -or $Compania -like "*$c*") { return $true }
    }
    return $false
}

$rutasVistas = @{}

function Add-Binario {
    param([string]$Ruta, [string]$Contexto, [string]$Detalle)

    if ([string]::IsNullOrWhiteSpace($Ruta)) { return }
    $clave = $Ruta.ToLowerInvariant()
    if ($rutasVistas.ContainsKey($clave)) {
        $rutasVistas[$clave].Contextos += "; $Contexto"
        return
    }

    $sig = Get-SignatureInfo -Path $Ruta -IncludeHash
    if (-not $sig.Exists) { return }

    $confiable = Test-PublicadorConfiable -Firmante $sig.Signer -Compania $sig.Company

    $obj = [pscustomobject]@{
        Ruta            = $Ruta
        Nombre          = Split-Path $Ruta -Leaf
        Contextos       = $Contexto
        Detalle         = ConvertTo-SafeString $Detalle 300
        EstadoFirma     = $sig.SignatureStatus
        Firmante        = ConvertTo-SafeString $sig.Signer 200
        Compania        = ConvertTo-SafeString $sig.Company 120
        Producto        = ConvertTo-SafeString $sig.ProductName 120
        VersionArchivo  = $sig.FileVersion
        ConSelloTiempo  = $sig.TimeStamped
        PublicadorConfiable = $confiable
        SHA256          = $sig.SHA256
        TamanoKB        = $sig.SizeKB
        UltimaEscritura = if ($sig.LastWriteTime) { $sig.LastWriteTime.ToString('yyyy-MM-dd HH:mm') } else { '' }
    }
    $rutasVistas[$clave] = $obj
    $null = $records.Add($obj)
}

# ---------------------------------------------------------------------------
# 1. Imagenes de servicios Windows
# ---------------------------------------------------------------------------
try {
    foreach ($svc in (Get-CimInstance Win32_Service -ErrorAction Stop)) {
        $pathName = [string]$svc.PathName
        if (-not $pathName) { continue }

        # Extraer el ejecutable del PathName, con o sin comillas
        $exe = $null
        if ($pathName -match '^\s*"([^"]+)"') { $exe = $Matches[1] }
        else {
            $m = [regex]::Match($pathName, '^\s*(\S+\.exe)', 'IgnoreCase')
            if ($m.Success) { $exe = $m.Groups[1].Value }
            else { $exe = ($pathName -split '\s+')[0] }
        }
        if ($exe) {
            $exe = [Environment]::ExpandEnvironmentVariables($exe)
            Add-Binario -Ruta $exe -Contexto "Servicio: $($svc.Name)" `
                -Detalle ("Estado={0} Inicio={1} Cuenta={2}" -f $svc.State, $svc.StartMode, $svc.StartName)
        }
    }
} catch { $null = $gaps.Add("Enumeracion de servicios fallida: $($_.Exception.Message)") }

# ---------------------------------------------------------------------------
# 2. Imagenes de procesos en ejecucion
# ---------------------------------------------------------------------------
try {
    $procesos = Get-Process -ErrorAction SilentlyContinue
    $sinAcceso = 0
    foreach ($p in $procesos) {
        $ruta = $null
        try { $ruta = $p.Path } catch { $sinAcceso++; continue }
        if ($ruta) {
            Add-Binario -Ruta $ruta -Contexto "Proceso: $($p.ProcessName)" `
                -Detalle ("PID={0} Memoria={1}MB" -f $p.Id, [math]::Round($p.WorkingSet64/1MB,1))
        } else { $sinAcceso++ }
    }
    if ($sinAcceso -gt 0) {
        $null = $gaps.Add("No se pudo resolver la ruta de $sinAcceso procesos (habitual sin privilegios elevados: procesos de sistema y de otras sesiones).")
    }
} catch { $null = $gaps.Add("Get-Process fallo: $($_.Exception.Message)") }

# ---------------------------------------------------------------------------
# Hallazgos
# ---------------------------------------------------------------------------
$noFirmados = @($records | Where-Object { $_.EstadoFirma -eq 'NotSigned' })
if ($noFirmados.Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'High' -Category 'IntegridadDeSoftware' `
        -Title 'Servicios o procesos ejecutando binarios sin firma digital' `
        -Asset ("{0} binarios" -f $noFirmados.Count) `
        -Detail ("{0} imagenes en ejecucion carecen de firma Authenticode. Estos binarios operan con los privilegios de su contexto sin que sea posible verificar su origen ni detectar modificaciones." -f $noFirmados.Count) `
        -Evidence (($noFirmados | Select-Object -First 15 | ForEach-Object { "$($_.Ruta) <= $($_.Contextos)" }) -join ' | ') `
        -Criterios @('SW-03','ARQ-01') `
        -Recommendation 'Identificar el proveedor de cada binario y exigir entregables firmados. Registrar el hash SHA256 como linea base y monitorear su cambio entre ejecuciones de auditoria.'))
}

$hashMismatch = @($records | Where-Object { $_.EstadoFirma -eq 'HashMismatch' })
if ($hashMismatch.Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'Critical' -Category 'IndicadorDeCompromiso' `
        -Title 'Binario en ejecucion alterado despues de su firma' `
        -Asset ("{0} binarios" -f $hashMismatch.Count) `
        -Detail 'El estado HashMismatch indica que el contenido del archivo no corresponde a lo que su firma digital certifica: el binario fue modificado tras ser firmado. Debe tratarse como un posible indicador de compromiso.' `
        -Evidence (($hashMismatch | Select-Object -First 10 | ForEach-Object { "$($_.Ruta) SHA256=$($_.SHA256) <= $($_.Contextos)" }) -join ' | ') `
        -Criterios @('SW-03','VUL-02','REG-02') `
        -Recommendation 'Activar el procedimiento de gestion de incidentes: aislar el binario, preservar la evidencia con su hash y contrastarlo contra la fuente original del proveedor.'))
}

$noConfiables = @($records | Where-Object {
    $_.EstadoFirma -eq 'Valid' -and -not $_.PublicadorConfiable
})
if ($noConfiables.Count -gt 0) {
    $publicadores = @($noConfiables | Select-Object -ExpandProperty Firmante -Unique)
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'Low' -Category 'Procedencia' `
        -Title 'Binarios firmados por publicadores no incluidos en la lista de confianza' `
        -Asset ("{0} binarios de {1} publicadores" -f $noConfiables.Count, $publicadores.Count) `
        -Detail 'Estos artefactos tienen firma valida pero su publicador no figura en la lista de proveedores aprobados de la configuracion. No es necesariamente una desviacion, pero requiere validacion del inventario autorizado.' `
        -Evidence (($publicadores | Select-Object -First 15) -join ' | ') `
        -Criterios @('INV-01','SW-03','SW-04') `
        -Recommendation 'Revisar cada publicador con el responsable del activo y actualizar la lista PublicadoresConfiables en Audit.config.psd1 para reducir el ruido en ejecuciones posteriores.'))
}

$sinSello = @($records | Where-Object { $_.EstadoFirma -eq 'Valid' -and -not $_.ConSelloTiempo })
if ($sinSello.Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'Info' -Category 'IntegridadDeSoftware' `
        -Title 'Binarios firmados sin sello de tiempo' `
        -Asset ("{0} binarios" -f $sinSello.Count) `
        -Detail 'Sin sello de tiempo, la firma deja de ser verificable cuando el certificado del publicador expira, lo que impide validar la integridad del artefacto a futuro.' `
        -Criterios @('SW-03') `
        -Recommendation 'Solicitar al proveedor entregables con sello de tiempo (RFC 3161) en los criterios de aceptacion de software.'))
}

$metrics['BinariosAnalizados']    = $records.Count
$metrics['SinFirma']              = $noFirmados.Count
$metrics['FirmaAlterada']         = $hashMismatch.Count
$metrics['PublicadorNoConfiable'] = $noConfiables.Count
$metrics['FirmadosValidos']       = @($records | Where-Object { $_.EstadoFirma -eq 'Valid' }).Count

New-CollectorResult -Meta $meta -Records $records.ToArray() -Findings $findings.ToArray() `
    -Metrics $metrics -Gaps $gaps.ToArray()
