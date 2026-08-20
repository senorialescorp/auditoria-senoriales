<#
    L5-02_Autoruns-Tasks.ps1
    Capa L5 - Persistencia y automatizacion.
    Criterios de auditoria -> SW-03, REG-02, CAM-02, ARQ-01
#>
param([switch]$Manifest, [hashtable]$Config)

$meta = @{
    Id            = 'L5-02'
    Nombre        = 'Tareas programadas y puntos de autoarranque'
    Layer         = 'L5'
    Criterios     = @('SW-03','REG-02','CAM-02','ARQ-01')
    RequiereAdmin = $false
    Descripcion   = 'Tareas programadas de terceros, claves Run del registro y carpetas de inicio.'
}
if ($Manifest) { return [pscustomobject]$meta }

$records  = New-Object System.Collections.ArrayList
$findings = New-Object System.Collections.ArrayList
$gaps     = New-Object System.Collections.ArrayList
$metrics  = @{}

function Add-Autorun {
    param(
        [string]$Tipo, [string]$Nombre, [string]$Comando,
        [string]$Contexto = '', [string]$Estado = '', [string]$Origen = '', [string]$Notas = ''
    )
    $null = $records.Add([pscustomobject]@{
        Tipo     = $Tipo
        Nombre   = ConvertTo-SafeString $Nombre 200
        Comando  = ConvertTo-SafeString $Comando 600
        Contexto = ConvertTo-SafeString $Contexto 120
        Estado   = $Estado
        Origen   = $Origen
        Notas    = ConvertTo-SafeString $Notas 300
    })
}

# ---------------------------------------------------------------------------
# 1. Tareas programadas
# ---------------------------------------------------------------------------
$tareasTerceros = New-Object System.Collections.ArrayList
try {
    $tareas = Get-ScheduledTask -ErrorAction Stop
    foreach ($t in $tareas) {
        # Las tareas bajo \Microsoft\ son del sistema; interesan las de terceros
        $esSistema = $t.TaskPath -like '\Microsoft\*'

        $acciones = @()
        foreach ($a in @($t.Actions)) {
            if ($a.PSObject.Properties['Execute'] -and $a.Execute) {
                $acciones += ("{0} {1}" -f $a.Execute, $a.Arguments).Trim()
            }
        }
        $comando = ($acciones -join ' ; ')

        $principal = ''
        try { $principal = "$($t.Principal.UserId) [$($t.Principal.RunLevel)]" } catch { }

        Add-Autorun -Tipo 'TareaProgramada' -Nombre ("{0}{1}" -f $t.TaskPath, $t.TaskName) `
            -Comando $comando -Contexto $principal -Estado ([string]$t.State) `
            -Origen $(if ($esSistema) { 'Sistema' } else { 'Terceros' }) `
            -Notas ([string]$t.Description)

        if (-not $esSistema -and $t.State -ne 'Disabled') {
            $null = $tareasTerceros.Add([pscustomobject]@{
                Nombre = "$($t.TaskPath)$($t.TaskName)"; Comando = $comando
                Principal = $principal; Estado = [string]$t.State
            })
        }
    }
    $metrics['TotalTareas']        = @($tareas).Count
    $metrics['TareasDeTerceros']   = $tareasTerceros.Count
} catch { $null = $gaps.Add("Get-ScheduledTask fallo: $($_.Exception.Message)") }

if ($tareasTerceros.Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'Medium' -Category 'Automatizacion' `
        -Title 'Tareas programadas de terceros activas en el servidor' `
        -Asset ("{0} tareas" -f $tareasTerceros.Count) `
        -Detail 'Cada tarea programada de terceros ejecuta codigo de forma automatica y desatendida. Constituyen tanto un mecanismo operativo legitimo como el vector de persistencia mas utilizado; deben estar inventariadas y aprobadas.' `
        -Evidence (($tareasTerceros | Select-Object -First 15 | ForEach-Object { "$($_.Nombre) => $($_.Comando)" }) -join ' | ') `
        -Criterios @('SW-03','CAM-02','REG-02') `
        -Recommendation 'Documentar cada tarea en el procedimiento operativo del servidor: proposito, responsable, cuenta de ejecucion y frecuencia. Deshabilitar las que no tengan dueno identificable.'))

    # Tareas con privilegio maximo
    $altoPrivilegio = @($tareasTerceros | Where-Object { $_.Principal -match 'Highest' -or $_.Principal -match '(?i)SYSTEM' })
    if ($altoPrivilegio.Count -gt 0) {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'High' -Category 'Privilegios' `
            -Title 'Tareas programadas de terceros con privilegios maximos' `
            -Asset ("{0} tareas" -f $altoPrivilegio.Count) `
            -Detail 'Estas tareas se ejecutan como SYSTEM o con el nivel de privilegio mas alto. Si el script o binario invocado reside en una ubicacion escribible, cualquier usuario con acceso a esa ruta logra ejecucion privilegiada.' `
            -Evidence (($altoPrivilegio | Select-Object -First 12 | ForEach-Object { "$($_.Nombre) [$($_.Principal)]" }) -join ' | ') `
            -Criterios @('ACC-02','SW-03') `
            -Recommendation 'Reducir el nivel de privilegio al minimo necesario y proteger con ACL restrictivas los archivos que estas tareas invocan.'))
    }
}

# ---------------------------------------------------------------------------
# 2. Claves Run / RunOnce del registro
# ---------------------------------------------------------------------------
$clavesRun = @(
    @{ Ruta='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';                 Ctx='Maquina' }
    @{ Ruta='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce';             Ctx='Maquina (una vez)' }
    @{ Ruta='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run';     Ctx='Maquina x86' }
    @{ Ruta='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';                 Ctx='Usuario actual' }
    @{ Ruta='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce';             Ctx='Usuario actual (una vez)' }
    @{ Ruta='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon';         Ctx='Winlogon' }
)

$autorunsRegistro = New-Object System.Collections.ArrayList
foreach ($c in $clavesRun) {
    try {
        if (-not (Test-Path $c.Ruta)) { continue }
        $props = Get-ItemProperty -Path $c.Ruta -ErrorAction SilentlyContinue
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { continue }

            # En Winlogon solo interesan Userinit y Shell (vectores clasicos)
            if ($c.Ctx -eq 'Winlogon' -and $p.Name -notin @('Userinit','Shell','TaskMan')) { continue }

            Add-Autorun -Tipo 'RegistroRun' -Nombre $p.Name -Comando ([string]$p.Value) `
                -Contexto $c.Ctx -Estado 'Activo' -Origen $c.Ruta
            $null = $autorunsRegistro.Add("$($c.Ctx)\$($p.Name) => $($p.Value)")

            if ($c.Ctx -eq 'Winlogon' -and $p.Name -eq 'Userinit' -and [string]$p.Value -notmatch '(?i)^\s*C:\\Windows\\system32\\userinit\.exe,?\s*$') {
                $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                    -Severity 'Critical' -Category 'IndicadorDeCompromiso' `
                    -Title 'Clave Winlogon\Userinit modificada respecto al valor predeterminado' `
                    -Asset 'HKLM\...\Winlogon\Userinit' `
                    -Detail ("Valor actual: {0}. La modificacion de Userinit es una tecnica de persistencia bien documentada; el valor esperado es unicamente C:\Windows\system32\userinit.exe," -f $p.Value) `
                    -Criterios @('ARQ-01','VUL-02','REG-02') `
                    -Recommendation 'Verificar el origen de la entrada adicional. Si no corresponde a un producto autorizado, tratar como incidente de seguridad.'))
            }
        }
    } catch { }
}
$metrics['EntradasAutorun'] = $autorunsRegistro.Count

if ($autorunsRegistro.Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'Low' -Category 'Automatizacion' `
        -Title 'Entradas de autoarranque configuradas en el registro' `
        -Asset ("{0} entradas" -f $autorunsRegistro.Count) `
        -Detail 'Las claves Run ejecutan programas automaticamente al inicio de sesion. En un servidor deben ser minimas y estar justificadas.' `
        -Evidence (($autorunsRegistro | Select-Object -First 15) -join ' | ') `
        -Criterios @('SW-03','ARQ-01') `
        -Recommendation 'Validar cada entrada contra el inventario de software autorizado y eliminar las que no correspondan a un producto aprobado.'))
}

# ---------------------------------------------------------------------------
# 3. Carpetas de inicio
# ---------------------------------------------------------------------------
$carpetasInicio = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($carpeta in $carpetasInicio) {
    if (-not (Test-Path -LiteralPath $carpeta)) { continue }
    foreach ($f in (Get-ChildItem -LiteralPath $carpeta -File -Force -ErrorAction SilentlyContinue)) {
        if ($f.Name -eq 'desktop.ini') { continue }
        Add-Autorun -Tipo 'CarpetaInicio' -Nombre $f.Name -Comando $f.FullName `
            -Contexto $(if ($carpeta -like "$env:ProgramData*") {'Todos los usuarios'} else {'Usuario actual'}) `
            -Estado 'Activo' -Origen $carpeta `
            -Notas ("Modificado: {0}" -f $f.LastWriteTime.ToString('yyyy-MM-dd'))
    }
}

# ---------------------------------------------------------------------------
# 4. Proveedores WMI permanentes (persistencia avanzada)
# ---------------------------------------------------------------------------
try {
    $consumidores = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction Stop
    foreach ($c in $consumidores) {
        Add-Autorun -Tipo 'SuscripcionWMI' -Nombre ([string]$c.Name) `
            -Comando (ConvertTo-SafeString $c 400) -Contexto 'WMI' -Estado 'Registrado' -Origen 'root\subscription'
    }
    if (@($consumidores).Count -gt 0) {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'High' -Category 'Persistencia' `
            -Title 'Suscripciones de eventos WMI permanentes registradas' `
            -Asset ("{0} consumidores" -f @($consumidores).Count) `
            -Detail 'Las suscripciones WMI permanentes ejecutan codigo ante eventos del sistema y sobreviven a reinicios. Son poco frecuentes en configuraciones legitimas y constituyen una tecnica de persistencia sigilosa.' `
            -Evidence ((@($consumidores) | Select-Object -First 10 | ForEach-Object { $_.Name }) -join ', ') `
            -Criterios @('REG-02','VUL-02') `
            -Recommendation 'Identificar el producto que registro cada suscripcion. Si no se corresponde con software autorizado (agentes de monitoreo o gestion), tratar como incidente.'))
    }
} catch {
    $null = $gaps.Add('No se pudo consultar root\subscription (suele requerir privilegios elevados).')
}

$metrics['TotalPuntosPersistencia'] = $records.Count

New-CollectorResult -Meta $meta -Records $records.ToArray() -Findings $findings.ToArray() `
    -Metrics $metrics -Gaps $gaps.ToArray()
