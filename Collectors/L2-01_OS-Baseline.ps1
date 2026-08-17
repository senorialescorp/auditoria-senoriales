<#
    L2-01_OS-Baseline.ps1
    Capa L2 - Sistema operativo: linea base e identidad del SO.
    Criterios de auditoria -> INV-01, ARQ-01, ARQ-04
#>
param([switch]$Manifest, [hashtable]$Config)

$meta = @{
    Id            = 'L2-01'
    Nombre        = 'Linea base del sistema operativo'
    Layer         = 'L2'
    Criterios     = @('INV-01','ARQ-01','ARQ-04')
    RequiereAdmin = $false
    Descripcion   = 'Version del SO, licenciamiento, tiempo de actividad, zona horaria y sincronizacion de reloj.'
}
if ($Manifest) { return [pscustomobject]$meta }

$records  = New-Object System.Collections.ArrayList
$findings = New-Object System.Collections.ArrayList
$gaps     = New-Object System.Collections.ArrayList
$metrics  = @{}

$umbrales = if ($Config -and $Config.Thresholds) { $Config.Thresholds } else { @{ DiasMaxSinReinicio = 60 } }

# --- Identidad del SO -------------------------------------------------------
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $uptime = (Get-Date) - $os.LastBootUpTime

    $null = $records.Add([pscustomobject]@{
        Categoria        = 'SistemaOperativo'
        Elemento         = 'Version'
        Valor            = $os.Caption
        Detalle          = ("Build {0} / Version {1}" -f $os.BuildNumber, $os.Version)
    })
    $null = $records.Add([pscustomobject]@{
        Categoria = 'SistemaOperativo'; Elemento = 'Arquitectura'
        Valor = $os.OSArchitecture; Detalle = "ServicePack $($os.ServicePackMajorVersion).$($os.ServicePackMinorVersion)"
    })
    $null = $records.Add([pscustomobject]@{
        Categoria = 'SistemaOperativo'; Elemento = 'FechaInstalacion'
        Valor = $os.InstallDate.ToString('yyyy-MM-dd'); Detalle = ("{0} dias de antiguedad" -f ((Get-Date) - $os.InstallDate).Days)
    })
    $null = $records.Add([pscustomobject]@{
        Categoria = 'SistemaOperativo'; Elemento = 'UltimoArranque'
        Valor = $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm'); Detalle = ("{0} dias de actividad continua" -f [math]::Round($uptime.TotalDays,1))
    })
    $null = $records.Add([pscustomobject]@{
        Categoria = 'SistemaOperativo'; Elemento = 'DirectorioSistema'
        Valor = $os.SystemDirectory; Detalle = "Idioma $($os.OSLanguage)"
    })

    $metrics['SO']          = [string]$os.Caption
    $metrics['Build']       = [string]$os.BuildNumber
    $metrics['UptimeDias']  = [math]::Round($uptime.TotalDays, 1)

    if ($uptime.TotalDays -gt $umbrales.DiasMaxSinReinicio) {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'Medium' -Category 'Parcheo' `
            -Title 'Tiempo de actividad excesivo sin reinicio' `
            -Asset $env:COMPUTERNAME `
            -Detail ("El servidor lleva {0} dias sin reiniciarse (umbral: {1}). Los parches de kernel y de componentes en uso no se aplican de forma efectiva hasta el reinicio." -f [math]::Round($uptime.TotalDays,1), $umbrales.DiasMaxSinReinicio) `
            -Evidence ("LastBootUpTime={0}" -f $os.LastBootUpTime) `
            -Criterios @('VUL-01','ARQ-01') `
            -Recommendation 'Programar una ventana de mantenimiento para reinicio y verificar que la aplicacion efectiva de parches forme parte del procedimiento de cambios.'))
    }

    # Windows Server con Experiencia de Escritorio vs Core (superficie de ataque)
    if ($os.Caption -match '(?i)server' -and $os.OperatingSystemSKU -notin @(12,13,14,39,40,41)) {
        $null = $records.Add([pscustomobject]@{
            Categoria = 'SistemaOperativo'; Elemento = 'Instalacion'
            Valor = 'Server con Experiencia de Escritorio'
            Detalle = 'Mayor superficie de ataque que una instalacion Server Core.'
        })
    }
}
catch { $null = $gaps.Add("Win32_OperatingSystem no disponible: $($_.Exception.Message)") }

# --- Licenciamiento / activacion -------------------------------------------
try {
    $lic = Get-CimInstance SoftwareLicensingProduct -ErrorAction Stop |
           Where-Object { $_.PartialProductKey -and $_.Name -match '(?i)windows' } |
           Select-Object -First 1
    if ($lic) {
        $estado = switch ([int]$lic.LicenseStatus) {
            0 {'Sin licencia'} 1 {'Con licencia'} 2 {'Periodo de gracia inicial'}
            3 {'Periodo de gracia adicional'} 4 {'Gracia por no autenticidad'}
            5 {'Notificacion'} 6 {'Gracia extendida'} default {'Desconocido'}
        }
        $null = $records.Add([pscustomobject]@{
            Categoria = 'Licenciamiento'; Elemento = 'EstadoActivacion'
            Valor = $estado; Detalle = [string]$lic.Description
        })
        $metrics['Activacion'] = $estado

        if ([int]$lic.LicenseStatus -ne 1) {
            $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                -Severity 'Medium' -Category 'Cumplimiento' `
                -Title 'Sistema operativo sin licencia valida' `
                -Asset $env:COMPUTERNAME `
                -Detail ("Estado de activacion: {0}. Un sistema no activado puede perder acceso a actualizaciones y expone a la organizacion a incumplimiento contractual." -f $estado) `
                -Criterios @('INV-04','VUL-01') `
                -Recommendation 'Regularizar la licencia con el area de activos de TI antes del cierre de la auditoria.'))
        }
    }
} catch { $null = $gaps.Add('No fue posible consultar el estado de licenciamiento (SoftwareLicensingProduct).') }

# --- Zona horaria y sincronizacion de reloj (ARQ-04) -----------------------
try {
    $tz = Get-CimInstance Win32_TimeZone -ErrorAction SilentlyContinue
    if ($tz) {
        $null = $records.Add([pscustomobject]@{
            Categoria = 'Tiempo'; Elemento = 'ZonaHoraria'
            Valor = $tz.Caption; Detalle = "Bias $($tz.Bias) min"
        })
    }

    $w32 = Get-Service -Name W32Time -ErrorAction SilentlyContinue
    $ntpType   = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -Name Type   -ErrorAction SilentlyContinue).Type
    $ntpServer = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -Name NtpServer -ErrorAction SilentlyContinue).NtpServer

    $null = $records.Add([pscustomobject]@{
        Categoria = 'Tiempo'; Elemento = 'ServicioW32Time'
        Valor = if ($w32) { "$($w32.Status) / $($w32.StartType)" } else { 'No encontrado' }
        Detalle = "Tipo=$ntpType Servidor=$ntpServer"
    })
    $metrics['SincronizacionTiempo'] = if ($w32) { [string]$w32.Status } else { 'Ausente' }

    if (-not $w32 -or $w32.Status -ne 'Running') {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'High' -Category 'Registro' `
            -Title 'Servicio de sincronizacion de tiempo detenido o ausente' `
            -Asset 'W32Time' `
            -Detail 'Sin sincronizacion de reloj los registros de eventos pierden valor probatorio y la correlacion forense entre sistemas deja de ser fiable.' `
            -Evidence ("Estado={0}" -f $(if ($w32) { $w32.Status } else { 'N/D' })) `
            -Criterios @('ARQ-04','REG-01') `
            -Recommendation 'Habilitar e iniciar el servicio W32Time con arranque automatico y apuntarlo a una fuente NTP autorizada de la organizacion.'))
    }
    elseif ([string]::IsNullOrWhiteSpace($ntpServer)) {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'Low' -Category 'Registro' `
            -Title 'Fuente NTP no declarada explicitamente' `
            -Asset 'W32Time' `
            -Detail 'El servicio de tiempo no tiene un servidor NTP configurado de forma explicita.' `
            -Criterios @('ARQ-04') `
            -Recommendation 'Configurar la jerarquia de tiempo hacia una fuente autorizada y documentarla en la linea base.'))
    }
} catch { $null = $gaps.Add("Consulta de configuracion de tiempo fallida: $($_.Exception.Message)") }

# --- Entorno de ejecucion de PowerShell (relevante para SW-05) ------------
try {
    $null = $records.Add([pscustomobject]@{
        Categoria = 'Plataforma'; Elemento = 'PowerShell'
        Valor = $PSVersionTable.PSVersion.ToString(); Detalle = "Edicion $($PSVersionTable.PSEdition)"
    })
    $polUsuario = Get-ExecutionPolicy -Scope CurrentUser -ErrorAction SilentlyContinue
    $polMaquina = Get-ExecutionPolicy -Scope LocalMachine -ErrorAction SilentlyContinue
    $null = $records.Add([pscustomobject]@{
        Categoria = 'Plataforma'; Elemento = 'ExecutionPolicy'
        Valor = "LocalMachine=$polMaquina"; Detalle = "CurrentUser=$polUsuario"
    })

    if ($polMaquina -in @('Unrestricted','Bypass')) {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'Medium' -Category 'Hardening' `
            -Title 'Politica de ejecucion de PowerShell permisiva' `
            -Asset 'LocalMachine' `
            -Detail ("ExecutionPolicy en ambito LocalMachine es '{0}', lo que permite ejecutar scripts sin firma ni advertencia." -f $polMaquina) `
            -Criterios @('SW-05','SW-03') `
            -Recommendation 'Establecer AllSigned o RemoteSigned mediante directiva de grupo y firmar los scripts operativos con un certificado de la organizacion.'))
    }
} catch { }

# --- Estado de reinicio pendiente ------------------------------------------
try {
    $pendiente = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pendiente += 'CBS' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pendiente += 'WindowsUpdate' }
    $pfro = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
    if ($pfro -and $pfro.PendingFileRenameOperations) { $pendiente += 'PendingFileRename' }

    $null = $records.Add([pscustomobject]@{
        Categoria = 'Estado'; Elemento = 'ReinicioPendiente'
        Valor = if ($pendiente.Count) { 'Si' } else { 'No' }
        Detalle = ($pendiente -join ', ')
    })
    $metrics['ReinicioPendiente'] = ($pendiente.Count -gt 0)

    if ($pendiente.Count -gt 0) {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'Medium' -Category 'Parcheo' `
            -Title 'Reinicio pendiente: parches aplicados pero no efectivos' `
            -Asset $env:COMPUTERNAME `
            -Detail ("Indicadores detectados: {0}. Hasta que se reinicie, las correcciones instaladas no protegen al sistema." -f ($pendiente -join ', ')) `
            -Criterios @('VUL-01','CAM-01') `
            -Recommendation 'Coordinar el reinicio dentro de la proxima ventana de mantenimiento aprobada.'))
    }
} catch { }

New-CollectorResult -Meta $meta -Records $records.ToArray() -Findings $findings.ToArray() `
    -Metrics $metrics -Gaps $gaps.ToArray()
