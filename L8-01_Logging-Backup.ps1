<#
    L8-01_Logging-Backup.ps1
    Capa L8 - Datos, registro y resiliencia.
    Criterios de auditoria -> REG-01, REG-02, CAP-02, CAP-03, DAT-01, DAT-03
#>
param([switch]$Manifest, [hashtable]$Config)

$meta = @{
    Id            = 'L8-01'
    Nombre        = 'Registro de eventos, respaldo y resiliencia'
    Layer         = 'L8'
    Criterios     = @('REG-01','REG-02','CAP-02','CAP-03','DAT-01','DAT-03')
    RequiereAdmin = $false
    Descripcion   = 'Configuracion y salud de los registros de eventos, instantaneas de volumen, respaldos y capacidad de almacenamiento.'
}
if ($Manifest) { return [pscustomobject]$meta }

$records  = New-Object System.Collections.ArrayList
$findings = New-Object System.Collections.ArrayList
$gaps     = New-Object System.Collections.ArrayList
$metrics  = @{}

$umbrales = @{ PorcentajeDiscoLibreMin = 15; PorcentajeDiscoLibreCrit = 8 }
if ($Config -and $Config.Thresholds) {
    foreach ($k in @('PorcentajeDiscoLibreMin','PorcentajeDiscoLibreCrit')) {
        if ($Config.Thresholds.ContainsKey($k)) { $umbrales[$k] = [int]$Config.Thresholds[$k] }
    }
}

# ---------------------------------------------------------------------------
# 1. Configuracion de los registros de eventos (REG-01)
# ---------------------------------------------------------------------------
$logsCriticos = @('Security','System','Application','Windows PowerShell',
                  'Microsoft-Windows-PowerShell/Operational',
                  'Microsoft-Windows-Windows Defender/Operational',
                  'Microsoft-Windows-TaskScheduler/Operational')

foreach ($nombre in $logsCriticos) {
    try {
        $log = Get-WinEvent -ListLog $nombre -ErrorAction Stop
        $tamMB    = [math]::Round($log.MaximumSizeInBytes / 1MB, 1)
        $usadoMB  = [math]::Round($log.FileSize / 1MB, 1)

        $null = $records.Add([pscustomobject]@{
            Categoria    = 'RegistroEventos'
            Elemento     = $nombre
            Valor        = $(if ($log.IsEnabled) { 'Habilitado' } else { 'Deshabilitado' })
            Detalle      = ("MaxMB={0} UsadoMB={1} Modo={2} Registros={3}" -f $tamMB, $usadoMB, $log.LogMode, $log.RecordCount)
            Estado       = $(if ($log.IsEnabled) { 'OK' } else { 'FALLA' })
        })

        if (-not $log.IsEnabled) {
            $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                -Severity 'High' -Category 'Registro' `
                -Title ("Registro de eventos deshabilitado: {0}" -f $nombre) `
                -Asset $nombre `
                -Detail 'Un canal de registro deshabilitado elimina la trazabilidad de los eventos que cubre e impide la deteccion y la investigacion posterior.' `
                -Criterios @('REG-01','REG-02') `
                -Recommendation 'Habilitar el canal de registro y verificar que ninguna directiva de grupo lo este desactivando.'))
        }

        # Security con tamano insuficiente pierde evidencia por rotacion
        if ($nombre -eq 'Security' -and $tamMB -lt 128) {
            $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                -Severity 'Medium' -Category 'Registro' `
                -Title 'Tamano insuficiente del registro de seguridad' `
                -Asset 'Security' `
                -Detail ("El registro de seguridad tiene un tamano maximo de {0} MB. En un servidor con actividad normal esto implica una retencion de pocos dias, insuficiente para investigar un incidente detectado tardiamente." -f $tamMB) `
                -Criterios @('REG-01','REG-03') `
                -Recommendation 'Ampliar el tamano a 512 MB o mas y, preferentemente, reenviar los eventos a una plataforma central de registro (SIEM o WEF) con retencion acorde a la politica.'))
        }

        # Modo de retencion que puede detener el registro
        if ($log.LogMode -eq 'Retain') {
            $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                -Severity 'Medium' -Category 'Registro' `
                -Title ("Registro '{0}' configurado para no sobrescribir eventos" -f $nombre) `
                -Asset $nombre `
                -Detail 'Con el modo Retain, al llenarse el registro se dejan de capturar eventos nuevos. Un atacante puede provocar el desbordamiento deliberadamente para cegar la auditoria.' `
                -Criterios @('REG-01') `
                -Recommendation 'Configurar archivado automatico al llenarse (AutoBackup) junto con el reenvio a una plataforma central de registro.'))
        }
    } catch {
        $null = $records.Add([pscustomobject]@{
            Categoria='RegistroEventos'; Elemento=$nombre; Valor='No accesible'
            Detalle=$_.Exception.Message; Estado='N/D'
        })
    }
}

# Reenvio de eventos a coleccion centralizada
try {
    $wef = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager' -ErrorAction SilentlyContinue
    $tieneWEF = ($wef -and ($wef.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }).Count -gt 0)
    $null = $records.Add([pscustomobject]@{
        Categoria='RegistroEventos'; Elemento='ReenvioCentralizado(WEF)'
        Valor=$(if ($tieneWEF) {'Configurado'} else {'No configurado'})
        Detalle=''; Estado=$(if ($tieneWEF) {'OK'} else {'ADVERTENCIA'})
    })
    $metrics['ReenvioEventos'] = $tieneWEF

    if (-not $tieneWEF) {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'Medium' -Category 'Registro' `
            -Title 'Sin reenvio de registros a una plataforma centralizada' `
            -Asset $env:COMPUTERNAME `
            -Detail 'Los registros permanecen unicamente en el propio servidor. Un atacante con privilegios administrativos puede borrarlos, y la correlacion entre sistemas no es posible.' `
            -Criterios @('REG-01','REG-02','REG-03') `
            -Recommendation 'Configurar Windows Event Forwarding o un agente de SIEM que remita los canales criticos a una plataforma centralizada con retencion e integridad protegidas.'))
    }
} catch { }

# Eventos de borrado de registro (indicador de anti-forense)
try {
    $borrados = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 10 -ErrorAction Stop
    if (@($borrados).Count -gt 0) {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'High' -Category 'IndicadorDeCompromiso' `
            -Title 'Se detectaron borrados del registro de seguridad' `
            -Asset 'Security (Evento 1102)' `
            -Detail ("Se encontraron {0} eventos de borrado del registro de auditoria. El borrado del registro de seguridad es una tecnica anti-forense y debe justificarse formalmente en todos los casos." -f @($borrados).Count) `
            -Evidence ((@($borrados) | Select-Object -First 5 | ForEach-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm') }) -join '; ') `
            -Criterios @('REG-01','REG-03','REG-02') `
            -Recommendation 'Investigar cada evento: identificar la cuenta responsable y contrastar con las ventanas de mantenimiento autorizadas. Escalar a gestion de incidentes si no hay justificacion.'))
    }
} catch {
    $null = $gaps.Add('No se pudo consultar el registro de seguridad (requiere privilegios administrativos).')
}

# ---------------------------------------------------------------------------
# 2. Instantaneas de volumen y respaldo (CAP-02 / CAP-03)
# ---------------------------------------------------------------------------
try {
    $shadows = Get-CimInstance Win32_ShadowCopy -ErrorAction Stop
    $metrics['InstantaneasVolumen'] = @($shadows).Count
    foreach ($s in @($shadows | Select-Object -First 20)) {
        $null = $records.Add([pscustomobject]@{
            Categoria='Instantanea'; Elemento=[string]$s.VolumeName
            Valor=$s.InstallDate.ToString('yyyy-MM-dd HH:mm'); Detalle=[string]$s.ID; Estado='Info'
        })
    }
    if (@($shadows).Count -eq 0) {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'Low' -Category 'Resiliencia' `
            -Title 'Sin instantaneas de volumen disponibles' `
            -Asset $env:COMPUTERNAME `
            -Detail 'No existen instantaneas de volumen. No constituye por si mismo una deficiencia si el respaldo se realiza por otro medio, pero elimina la opcion de recuperacion rapida ante borrado accidental o ransomware.' `
            -Criterios @('CAP-02','CAP-03') `
            -Recommendation 'Confirmar que existe una estrategia de respaldo documentada y probada que cubra este servidor.'))
    }
} catch { $null = $gaps.Add('Win32_ShadowCopy no accesible (puede requerir elevacion).') }

# Estado del servicio y del historial de Windows Server Backup
try {
    $wbSvc = Get-Service -Name 'wbengine' -ErrorAction SilentlyContinue
    $null = $records.Add([pscustomobject]@{
        Categoria='Respaldo'; Elemento='Servicio wbengine'
        Valor=$(if ($wbSvc) { [string]$wbSvc.Status } else { 'No instalado' })
        Detalle=$(if ($wbSvc) { [string]$wbSvc.StartType } else { 'Windows Server Backup no presente' })
        Estado='Info'
    })

    $backupEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Backup'; StartTime=(Get-Date).AddDays(-30)} -MaxEvents 20 -ErrorAction Stop
    $ultimoBackup = @($backupEvents | Sort-Object TimeCreated -Descending | Select-Object -First 1)
    if ($ultimoBackup.Count -gt 0) {
        $null = $records.Add([pscustomobject]@{
            Categoria='Respaldo'; Elemento='UltimoEventoRespaldo'
            Valor=$ultimoBackup[0].TimeCreated.ToString('yyyy-MM-dd HH:mm')
            Detalle=("Id={0}" -f $ultimoBackup[0].Id); Estado='Info'
        })
        $metrics['UltimoRespaldo'] = $ultimoBackup[0].TimeCreated.ToString('yyyy-MM-dd')
    }
} catch {
    $null = $gaps.Add('Sin registros de Windows Server Backup en los ultimos 30 dias. Si el respaldo lo realiza una herramienta de terceros, verificarlo por fuera de esta auditoria.')
}

# ---------------------------------------------------------------------------
# 3. Capacidad de almacenamiento (CAP-01)
# ---------------------------------------------------------------------------
try {
    foreach ($v in (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop)) {
        if (-not $v.Size -or $v.Size -eq 0) { continue }
        $pctLibre = [math]::Round(($v.FreeSpace / $v.Size) * 100, 1)
        $libreGB  = [math]::Round($v.FreeSpace / 1GB, 2)
        $totalGB  = [math]::Round($v.Size / 1GB, 2)

        $estado = if ($pctLibre -lt $umbrales.PorcentajeDiscoLibreCrit) { 'CRITICO' }
                  elseif ($pctLibre -lt $umbrales.PorcentajeDiscoLibreMin) { 'ADVERTENCIA' }
                  else { 'OK' }

        $null = $records.Add([pscustomobject]@{
            Categoria='Capacidad'; Elemento=("Volumen {0}" -f $v.DeviceID)
            Valor=("{0}% libre" -f $pctLibre)
            Detalle=("{0} GB libres de {1} GB" -f $libreGB, $totalGB); Estado=$estado
        })

        if ($estado -ne 'OK') {
            $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                -Severity $(if ($estado -eq 'CRITICO') {'High'} else {'Medium'}) -Category 'Capacidad' `
                -Title ("Espacio libre insuficiente en el volumen {0}" -f $v.DeviceID) `
                -Asset ([string]$v.DeviceID) `
                -Detail ("Espacio libre: {0}% ({1} GB de {2} GB). Umbral de advertencia: {3}%, umbral critico: {4}%. La falta de espacio compromete el registro de eventos, la aplicacion de parches y la disponibilidad del servicio." -f $pctLibre, $libreGB, $totalGB, $umbrales.PorcentajeDiscoLibreMin, $umbrales.PorcentajeDiscoLibreCrit) `
                -Criterios @('CAP-01','REG-01') `
                -Recommendation 'Liberar espacio, ampliar el volumen y establecer alertas de capacidad con umbral preventivo en la plataforma de monitoreo.'))
        }
    }
} catch { $null = $gaps.Add("Consulta de volumenes fallida: $($_.Exception.Message)") }

# ---------------------------------------------------------------------------
# 4. Higiene de archivos temporales (DAT-01)
# ---------------------------------------------------------------------------
foreach ($tmp in @("$env:SystemRoot\Temp", $env:TEMP)) {
    try {
        if (-not (Test-Path -LiteralPath $tmp)) { continue }
        $archivos = @(Get-ChildItem -LiteralPath $tmp -Recurse -File -Force -Depth 2 -ErrorAction SilentlyContinue)
        $tamMB = [math]::Round((($archivos | Measure-Object Length -Sum).Sum) / 1MB, 1)
        $antiguos = @($archivos | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-90) })

        $null = $records.Add([pscustomobject]@{
            Categoria='Temporales'; Elemento=$tmp
            Valor=("{0} archivos, {1} MB" -f $archivos.Count, $tamMB)
            Detalle=("{0} con mas de 90 dias" -f $antiguos.Count)
            Estado=$(if ($antiguos.Count -gt 500) {'ADVERTENCIA'} else {'OK'})
        })

        if ($antiguos.Count -gt 500) {
            $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                -Severity 'Low' -Category 'HigieneDeDatos' `
                -Title 'Acumulacion de archivos temporales antiguos' `
                -Asset $tmp `
                -Detail ("{0} archivos con mas de 90 dias ocupan {1} MB. Los temporales pueden contener fragmentos de informacion sensible y consumen capacidad sin proposito." -f $antiguos.Count, $tamMB) `
                -Criterios @('DAT-01','CAP-01') `
                -Recommendation 'Establecer una tarea de limpieza automatica de temporales alineada con la politica de retencion y eliminacion de informacion.'))
        }
    } catch { }
}

New-CollectorResult -Meta $meta -Records $records.ToArray() -Findings $findings.ToArray() `
    -Metrics $metrics -Gaps $gaps.ToArray()
