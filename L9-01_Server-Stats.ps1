<#
    L9-01_Server-Stats.ps1
    Capa L9 - Rendimiento y capacidad ("stats del server").

    Toma una muestra de contadores de rendimiento con varias lecturas para
    evitar conclusiones a partir de un unico instante, y correlaciona el
    consumo con los artefactos de software que lo originan (enlace con L4).

    Criterios de auditoria -> CAP-01, REG-02, AUD-01
#>
param(
    [switch]$Manifest,
    [hashtable]$Config,
    [int]$Muestras = 5,
    [int]$IntervaloSeg = 2
)

$meta = @{
    Id            = 'L9-01'
    Nombre        = 'Estadisticas de rendimiento y capacidad del servidor'
    Layer         = 'L9'
    Criterios     = @('CAP-01','REG-02','AUD-01')
    RequiereAdmin = $false
    Descripcion   = 'Muestreo de CPU, memoria, disco y red; top de procesos por consumo y correlacion con el software instalado.'
}
if ($Manifest) { return [pscustomobject]$meta }

$records  = New-Object System.Collections.ArrayList
$findings = New-Object System.Collections.ArrayList
$gaps     = New-Object System.Collections.ArrayList
$metrics  = @{}

$umbrales = @{ PorcentajeCpuSostenidoMax = 85; PorcentajeMemoriaLibreMin = 12 }
if ($Config -and $Config.Thresholds) {
    foreach ($k in @('PorcentajeCpuSostenidoMax','PorcentajeMemoriaLibreMin')) {
        if ($Config.Thresholds.ContainsKey($k)) { $umbrales[$k] = [int]$Config.Thresholds[$k] }
    }
}

function Add-Stat {
    param([string]$Grupo, [string]$Metrica, $Valor, [string]$Unidad = '', [string]$Detalle = '', [string]$Estado = 'Info')
    $null = $records.Add([pscustomobject]@{
        Grupo   = $Grupo
        Metrica = $Metrica
        Valor   = $Valor
        Unidad  = $Unidad
        Detalle = ConvertTo-SafeString $Detalle 300
        Estado  = $Estado
    })
}

# ---------------------------------------------------------------------------
# 1. Muestreo de contadores de rendimiento
# ---------------------------------------------------------------------------
$contadores = @(
    '\Processor(_Total)\% Processor Time'
    '\Memory\Available MBytes'
    '\Memory\% Committed Bytes In Use'
    '\PhysicalDisk(_Total)\% Disk Time'
    '\PhysicalDisk(_Total)\Avg. Disk Queue Length'
    '\System\Processor Queue Length'
    '\System\Context Switches/sec'
)

$muestrasCpu = @()
$muestrasMem = @()

try {
    $datos = Get-Counter -Counter $contadores -SampleInterval $IntervaloSeg -MaxSamples $Muestras -ErrorAction Stop

    $porContador = @{}
    foreach ($set in $datos) {
        foreach ($s in $set.CounterSamples) {
            $nombre = $s.Path -replace '^\\\\[^\\]+', ''
            if (-not $porContador.ContainsKey($nombre)) { $porContador[$nombre] = New-Object System.Collections.ArrayList }
            $null = $porContador[$nombre].Add([double]$s.CookedValue)
        }
    }

    foreach ($c in $porContador.Keys) {
        $vals = @($porContador[$c])
        if ($vals.Count -eq 0) { continue }
        $stats = $vals | Measure-Object -Average -Maximum -Minimum
        $etiqueta = ($c -split '\\')[-1]
        $grupo = if ($c -match 'Processor') { 'CPU' }
                 elseif ($c -match 'Memory') { 'Memoria' }
                 elseif ($c -match 'Disk')   { 'Disco' }
                 else { 'Sistema' }

        Add-Stat $grupo $etiqueta ([math]::Round($stats.Average,2)) '' `
            ("min={0} max={1} muestras={2}" -f [math]::Round($stats.Minimum,2), [math]::Round($stats.Maximum,2), $vals.Count)

        if ($c -match '% Processor Time')  { $muestrasCpu = $vals }
        if ($c -match 'Available MBytes')  { $muestrasMem = $vals }
    }
    $metrics['MuestrasTomadas'] = $Muestras
}
catch {
    $null = $gaps.Add("Get-Counter fallo: $($_.Exception.Message). Se usara una lectura puntual via CIM.")
    try {
        $cpu = (Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average
        Add-Stat 'CPU' 'LoadPercentage' $cpu '%' 'Lectura puntual (Win32_Processor)'
        $muestrasCpu = @([double]$cpu)
    } catch { }
}

# ---------------------------------------------------------------------------
# 2. Memoria
# ---------------------------------------------------------------------------
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $totalMB  = [math]::Round($os.TotalVisibleMemorySize / 1KB, 0)
    $libreMB  = [math]::Round($os.FreePhysicalMemory / 1KB, 0)
    $usadoMB  = $totalMB - $libreMB
    $pctLibre = if ($totalMB -gt 0) { [math]::Round(($libreMB / $totalMB) * 100, 1) } else { 0 }

    Add-Stat 'Memoria' 'TotalFisica'   $totalMB 'MB'
    Add-Stat 'Memoria' 'EnUso'         $usadoMB 'MB' ("{0}% del total" -f [math]::Round(100-$pctLibre,1))
    Add-Stat 'Memoria' 'Disponible'    $libreMB 'MB' ("{0}% libre" -f $pctLibre) `
        $(if ($pctLibre -lt $umbrales.PorcentajeMemoriaLibreMin) {'ADVERTENCIA'} else {'OK'})

    $swapTotal = [math]::Round(($os.TotalVirtualMemorySize - $os.TotalVisibleMemorySize) / 1KB, 0)
    Add-Stat 'Memoria' 'ArchivoPaginacion' $swapTotal 'MB'

    $metrics['MemoriaTotalMB']       = $totalMB
    $metrics['MemoriaDisponibleMB']  = $libreMB
    $metrics['MemoriaPorcentajeLibre'] = $pctLibre

    if ($pctLibre -lt $umbrales.PorcentajeMemoriaLibreMin) {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'Medium' -Category 'Capacidad' `
            -Title 'Memoria disponible por debajo del umbral operativo' `
            -Asset $env:COMPUTERNAME `
            -Detail ("Memoria disponible: {0} MB de {1} MB ({2}% libre). El umbral definido es {3}%. La presion de memoria degrada el rendimiento y puede provocar interrupciones del servicio." -f $libreMB, $totalMB, $pctLibre, $umbrales.PorcentajeMemoriaLibreMin) `
            -Criterios @('CAP-01') `
            -Recommendation 'Identificar los procesos con mayor consumo, evaluar la ampliacion de memoria y configurar alertas preventivas de capacidad.'))
    }
} catch { $null = $gaps.Add("Lectura de memoria fallida: $($_.Exception.Message)") }

# ---------------------------------------------------------------------------
# 3. Evaluacion de CPU sostenida
# ---------------------------------------------------------------------------
if ($muestrasCpu.Count -gt 0) {
    $st = $muestrasCpu | Measure-Object -Average -Maximum
    $promedio = [math]::Round($st.Average, 1)
    $metrics['CPUPromedio'] = $promedio
    $metrics['CPUMaximo']   = [math]::Round($st.Maximum, 1)

    if ($promedio -gt $umbrales.PorcentajeCpuSostenidoMax) {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'Medium' -Category 'Capacidad' `
            -Title 'Uso sostenido de CPU por encima del umbral' `
            -Asset $env:COMPUTERNAME `
            -Detail ("Promedio de {0}% durante {1} muestras (maximo {2}%). El umbral definido es {3}%." -f $promedio, $muestrasCpu.Count, [math]::Round($st.Maximum,1), $umbrales.PorcentajeCpuSostenidoMax) `
            -Criterios @('CAP-01','REG-02') `
            -Recommendation 'Correlacionar con el top de procesos de este mismo colector, revisar el dimensionamiento del servidor y descartar actividad no autorizada como causa del consumo.'))
    }
}

# ---------------------------------------------------------------------------
# 4. Top de procesos por consumo, correlacionado con el software instalado
# ---------------------------------------------------------------------------
try {
    $procesos = Get-Process -ErrorAction SilentlyContinue

    foreach ($p in ($procesos | Sort-Object WorkingSet64 -Descending | Select-Object -First 15)) {
        $ruta = ''
        $compania = ''
        try { $ruta = $p.Path; $compania = $p.Company } catch { }
        Add-Stat 'TopMemoria' $p.ProcessName ([math]::Round($p.WorkingSet64/1MB,1)) 'MB' `
            ("PID={0} Hilos={1} Compania={2} Ruta={3}" -f $p.Id, $p.Threads.Count, $compania, $ruta)
    }

    foreach ($p in ($procesos | Sort-Object CPU -Descending | Select-Object -First 15)) {
        if ($null -eq $p.CPU) { continue }
        $ruta = ''
        try { $ruta = $p.Path } catch { }
        Add-Stat 'TopCPU' $p.ProcessName ([math]::Round($p.CPU,1)) 'seg CPU acumulados' `
            ("PID={0} Ruta={1}" -f $p.Id, $ruta)
    }

    # Measure-Object no admite un scriptblock como -Property en PS 5.1:
    # se proyecta el valor con Select-Object antes de sumar.
    $totalHilos = (@($procesos) | Select-Object @{n='H';e={$_.Threads.Count}} |
                   Measure-Object -Property H -Sum).Sum
    $totalHandles = (@($procesos) | Measure-Object HandleCount -Sum).Sum

    $metrics['TotalProcesos'] = @($procesos).Count
    $metrics['TotalHilos']    = [int]$totalHilos

    Add-Stat 'Sistema' 'ProcesosActivos' @($procesos).Count ''
    Add-Stat 'Sistema' 'HilosTotales'    ([int]$totalHilos) ''
    Add-Stat 'Sistema' 'Identificadores' ([int]$totalHandles) ''
} catch { $null = $gaps.Add("Enumeracion de procesos fallida: $($_.Exception.Message)") }

# ---------------------------------------------------------------------------
# 5. Disco: capacidad y latencia
# ---------------------------------------------------------------------------
try {
    foreach ($v in (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop)) {
        if (-not $v.Size -or $v.Size -eq 0) { continue }
        $pctLibre = [math]::Round(($v.FreeSpace / $v.Size) * 100, 1)
        Add-Stat 'Disco' ("Volumen {0}" -f $v.DeviceID) $pctLibre '% libre' `
            ("{0} GB libres de {1} GB" -f [math]::Round($v.FreeSpace/1GB,2), [math]::Round($v.Size/1GB,2)) `
            $(if ($pctLibre -lt 15) {'ADVERTENCIA'} else {'OK'})
    }
} catch { }

try {
    $latencia = Get-Counter -Counter '\PhysicalDisk(_Total)\Avg. Disk sec/Transfer' -MaxSamples 3 -SampleInterval 1 -ErrorAction Stop
    $prom = ($latencia.CounterSamples | Measure-Object CookedValue -Average).Average
    $ms = [math]::Round($prom * 1000, 2)
    Add-Stat 'Disco' 'LatenciaPromedio' $ms 'ms' 'Referencia: > 25 ms indica saturacion de E/S' `
        $(if ($ms -gt 25) {'ADVERTENCIA'} else {'OK'})
    $metrics['LatenciaDiscoMs'] = $ms
} catch { }

# ---------------------------------------------------------------------------
# 6. Red
# ---------------------------------------------------------------------------
try {
    foreach ($a in (Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' })) {
        Add-Stat 'Red' $a.Name ([math]::Round($a.LinkSpeed.Split(' ')[0], 0)) $a.LinkSpeed.Split(' ')[1] `
            ("MAC={0} Driver={1}" -f $a.MacAddress, $a.DriverVersion)
    }

    $estadisticas = Get-NetAdapterStatistics -ErrorAction SilentlyContinue
    foreach ($s in $estadisticas) {
        Add-Stat 'Red' ("{0} - trafico" -f $s.Name) `
            ([math]::Round($s.ReceivedBytes/1GB,2)) 'GB recibidos' `
            ("Enviados: {0} GB | Descartes entrada: {1}" -f [math]::Round($s.SentBytes/1GB,2), $s.ReceivedDiscardedPackets)
    }
} catch { }

# ---------------------------------------------------------------------------
# 7. Tiempo de actividad y estabilidad
# ---------------------------------------------------------------------------
try {
    $os = Get-CimInstance Win32_OperatingSystem
    $uptime = (Get-Date) - $os.LastBootUpTime
    Add-Stat 'Sistema' 'TiempoActividad' ([math]::Round($uptime.TotalDays,2)) 'dias' `
        ("Ultimo arranque: {0}" -f $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm'))
    $metrics['UptimeDias'] = [math]::Round($uptime.TotalDays,2)

    # Reinicios inesperados en 30 dias (evento 6008)
    try {
        $inesperados = @(Get-WinEvent -FilterHashtable @{LogName='System'; Id=6008; StartTime=(Get-Date).AddDays(-30)} -ErrorAction Stop)
        Add-Stat 'Sistema' 'ApagadosInesperados30d' $inesperados.Count '' `
            (($inesperados | Select-Object -First 5 | ForEach-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm') }) -join '; ') `
            $(if ($inesperados.Count -gt 0) {'ADVERTENCIA'} else {'OK'})

        if ($inesperados.Count -gt 0) {
            $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                -Severity 'Medium' -Category 'Disponibilidad' `
                -Title 'Apagados inesperados registrados en los ultimos 30 dias' `
                -Asset $env:COMPUTERNAME `
                -Detail ("Se registraron {0} eventos de apagado inesperado (ID 6008). Indican fallas de hardware, energia o del sistema que afectan la disponibilidad del servicio." -f $inesperados.Count) `
                -Evidence (($inesperados | Select-Object -First 5 | ForEach-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm') }) -join '; ') `
                -Criterios @('REG-02','CAP-03','CAP-01') `
                -Recommendation 'Investigar la causa raiz de cada evento y verificar la cobertura del sistema de alimentacion ininterrumpida y del plan de continuidad.'))
        }
    } catch { $null = $gaps.Add('No se pudo consultar el registro System para eventos de apagado inesperado.') }
} catch { }

New-CollectorResult -Meta $meta -Records $records.ToArray() -Findings $findings.ToArray() `
    -Metrics $metrics -Gaps $gaps.ToArray()
