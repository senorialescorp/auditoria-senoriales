<#
    L2-03_Security-Config.ps1
    Capa L2 - Hardening y controles de seguridad del sistema operativo.
    Criterios de auditoria -> VUL-02, ARQ-01, REG-01, RED-01, CRI-02, CRI-01, ARQ-01
#>
param([switch]$Manifest, [hashtable]$Config)

$meta = @{
    Id            = 'L2-03'
    Nombre        = 'Configuracion de seguridad del sistema operativo'
    Layer         = 'L2'
    Criterios     = @('VUL-02','ARQ-01','REG-01','RED-01','CRI-02','CRI-01')
    RequiereAdmin = $false   # degrada con elegancia; algunos datos requieren elevacion
    Descripcion   = 'Antimalware, firewall, cifrado de volumenes, UAC, protocolos heredados y registro de PowerShell.'
}
if ($Manifest) { return [pscustomobject]$meta }

$records  = New-Object System.Collections.ArrayList
$findings = New-Object System.Collections.ArrayList
$gaps     = New-Object System.Collections.ArrayList
$metrics  = @{}

function Add-Control {
    param([string]$Control, [string]$Elemento, $Valor, [string]$Esperado = '', [string]$Estado = 'Info')
    $null = $records.Add([pscustomobject]@{
        Control  = $Control
        Elemento = $Elemento
        Valor    = ConvertTo-SafeString $Valor 256
        Esperado = $Esperado
        Estado   = $Estado
    })
}

# --- VUL-02 Proteccion contra codigo malicioso ------------------------------
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    Add-Control 'VUL-02' 'Antimalware' 'Microsoft Defender' 'Presente y activo' 'OK'
    Add-Control 'VUL-02' 'ProteccionTiempoReal' $mp.RealTimeProtectionEnabled 'True' $(if ($mp.RealTimeProtectionEnabled) {'OK'} else {'FALLA'})
    Add-Control 'VUL-02' 'AntimalwareHabilitado' $mp.AMServiceEnabled 'True' $(if ($mp.AMServiceEnabled) {'OK'} else {'FALLA'})
    Add-Control 'VUL-02' 'VersionFirmas' $mp.AntivirusSignatureVersion '' 'Info'
    Add-Control 'VUL-02' 'EdadFirmasDias' $mp.AntivirusSignatureAge '<= 3' $(if ($mp.AntivirusSignatureAge -le 3) {'OK'} else {'FALLA'})
    Add-Control 'VUL-02' 'UltimoEscaneoCompleto' $mp.FullScanEndTime '' 'Info'
    Add-Control 'VUL-02' 'ProteccionManipulacion' $mp.IsTamperProtected 'True' $(if ($mp.IsTamperProtected) {'OK'} else {'ADVERTENCIA'})

    $metrics['Antimalware']      = 'Microsoft Defender'
    $metrics['TiempoRealActivo'] = [bool]$mp.RealTimeProtectionEnabled
    $metrics['EdadFirmasDias']   = [int]$mp.AntivirusSignatureAge

    if (-not $mp.RealTimeProtectionEnabled) {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'Critical' -Category 'Antimalware' `
            -Title 'Proteccion antimalware en tiempo real deshabilitada' `
            -Asset 'Microsoft Defender' `
            -Detail 'La proteccion en tiempo real esta desactivada, dejando al servidor sin deteccion activa de codigo malicioso.' `
            -Criterios @('VUL-02') `
            -Recommendation 'Reactivar la proteccion en tiempo real y verificar que ninguna directiva de grupo o exclusion la este desactivando.'))
    }
    if ($mp.AntivirusSignatureAge -gt 3) {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'High' -Category 'Antimalware' `
            -Title 'Firmas de antimalware desactualizadas' `
            -Asset 'Microsoft Defender' `
            -Detail ("Las definiciones tienen {0} dias de antiguedad (version {1})." -f $mp.AntivirusSignatureAge, $mp.AntivirusSignatureVersion) `
            -Criterios @('VUL-02') `
            -Recommendation 'Forzar la actualizacion de definiciones y verificar la conectividad del servidor con la fuente de firmas.'))
    }
    if ($mp.PSObject.Properties['IsTamperProtected'] -and -not $mp.IsTamperProtected) {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'Medium' -Category 'Antimalware' `
            -Title 'Proteccion contra manipulacion (Tamper Protection) deshabilitada' `
            -Asset 'Microsoft Defender' `
            -Detail 'Sin esta proteccion, un atacante con privilegios locales puede desactivar el antimalware sin restriccion.' `
            -Criterios @('VUL-02') `
            -Recommendation 'Habilitar Tamper Protection desde la consola de seguridad centralizada.'))
    }

    # Exclusiones: un vector clasico de evasion (VUL-02 + SW-03)
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $exclusiones = @($pref.ExclusionPath) + @($pref.ExclusionProcess) + @($pref.ExclusionExtension) | Where-Object { $_ }
        Add-Control 'VUL-02' 'ExclusionesDefinidas' $exclusiones.Count '<= 10 justificadas' 'Info'
        foreach ($ex in @($pref.ExclusionPath | Where-Object { $_ })) {
            Add-Control 'VUL-02' 'ExclusionRuta' $ex '' 'Info'
        }
        if ($exclusiones.Count -gt 10) {
            $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                -Severity 'Medium' -Category 'Antimalware' `
                -Title 'Numero elevado de exclusiones de antimalware' `
                -Asset 'Microsoft Defender' `
                -Detail ("Se detectaron {0} exclusiones (rutas, procesos y extensiones). Cada exclusion es un area ciega para la deteccion." -f $exclusiones.Count) `
                -Evidence (($pref.ExclusionPath | Select-Object -First 15) -join '; ') `
                -Criterios @('VUL-02','ARQ-01') `
                -Recommendation 'Revisar y justificar cada exclusion; eliminar las que no respondan a un requerimiento tecnico vigente y documentado.'))
        }
        $exAmplias = @($pref.ExclusionPath | Where-Object { $_ -match '^[A-Za-z]:\\?$' -or $_ -match '(?i)^[A-Za-z]:\\(windows|users|program files)\\?$' })
        if ($exAmplias.Count -gt 0) {
            $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                -Severity 'High' -Category 'Antimalware' `
                -Title 'Exclusiones de antimalware sobre rutas demasiado amplias' `
                -Asset 'Microsoft Defender' `
                -Detail ("Rutas excluidas de alcance excesivo: {0}" -f ($exAmplias -join '; ')) `
                -Criterios @('VUL-02') `
                -Recommendation 'Reducir el alcance de las exclusiones al directorio o proceso especifico requerido.'))
        }
    } catch { $null = $gaps.Add('Get-MpPreference requiere privilegios elevados; no se pudieron enumerar exclusiones.') }
}
catch {
    $null = $gaps.Add('Get-MpComputerStatus no disponible. Puede indicar ausencia de Defender, un antimalware de terceros o falta de privilegios.')

    # Buscar antimalware de terceros via SecurityCenter2 (no siempre presente en Server)
    try {
        $av = Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop
        foreach ($a in $av) {
            Add-Control 'VUL-02' 'AntimalwareTerceros' $a.displayName '' 'Info'
            $metrics['Antimalware'] = [string]$a.displayName
        }
    } catch {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'High' -Category 'Antimalware' `
            -Title 'No se pudo verificar la presencia de proteccion antimalware' `
            -Asset $env:COMPUTERNAME `
            -Detail 'Ni Microsoft Defender ni el Centro de seguridad reportaron un producto antimalware. Requiere verificacion manual con privilegios elevados.' `
            -Criterios @('VUL-02') `
            -Recommendation 'Reejecutar la auditoria con privilegios administrativos y confirmar la cobertura del agente antimalware corporativo sobre este activo.'))
    }
}

# --- RED-01 Firewall --------------------------------------------------------
try {
    $perfiles = Get-NetFirewallProfile -ErrorAction Stop
    $desactivados = @()
    foreach ($p in $perfiles) {
        Add-Control 'RED-01' "Firewall-$($p.Name)" $p.Enabled 'True' $(if ($p.Enabled) {'OK'} else {'FALLA'})
        Add-Control 'RED-01' "FirewallEntrante-$($p.Name)" $p.DefaultInboundAction 'Block' $(if ($p.DefaultInboundAction -eq 'Block') {'OK'} else {'ADVERTENCIA'})
        Add-Control 'REG-01' "FirewallLog-$($p.Name)" $p.LogBlocked 'True' $(if ($p.LogBlocked) {'OK'} else {'ADVERTENCIA'})
        if (-not $p.Enabled) { $desactivados += $p.Name }
    }
    $metrics['PerfilesFirewallActivos'] = @($perfiles | Where-Object { $_.Enabled }).Count

    if ($desactivados.Count -gt 0) {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'High' -Category 'Red' `
            -Title 'Perfiles de firewall de Windows deshabilitados' `
            -Asset ($desactivados -join ', ') `
            -Detail ("Los siguientes perfiles estan desactivados: {0}. El servidor queda sin filtrado de host en esos contextos de red." -f ($desactivados -join ', ')) `
            -Criterios @('RED-01','RED-02') `
            -Recommendation 'Habilitar todos los perfiles con accion entrante predeterminada Block y definir reglas explicitas solo para los servicios requeridos.'))
    }
} catch { $null = $gaps.Add("Get-NetFirewallProfile fallo: $($_.Exception.Message)") }

# --- CRI-02 Cifrado de volumenes -------------------------------------------
try {
    $bl = Get-BitLockerVolume -ErrorAction Stop
    $sinCifrar = @()
    foreach ($v in $bl) {
        Add-Control 'CRI-02' "BitLocker-$($v.MountPoint)" $v.ProtectionStatus 'On' $(if ($v.ProtectionStatus -eq 'On') {'OK'} else {'ADVERTENCIA'})
        if ($v.VolumeType -eq 'OperatingSystem' -and $v.ProtectionStatus -ne 'On') { $sinCifrar += $v.MountPoint }
    }
    $metrics['VolumenesCifrados'] = @($bl | Where-Object { $_.ProtectionStatus -eq 'On' }).Count

    if ($sinCifrar.Count -gt 0) {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'Medium' -Category 'Criptografia' `
            -Title 'Volumen de sistema sin cifrado en reposo' `
            -Asset ($sinCifrar -join ', ') `
            -Detail 'El volumen del sistema operativo no esta protegido con BitLocker. Relevante si el activo puede salir del centro de datos o si el almacenamiento subyacente no ofrece cifrado.' `
            -Criterios @('CRI-02','CRI-01','DAT-03') `
            -Recommendation 'Evaluar el cifrado del volumen segun la clasificacion de la informacion alojada. Si el cifrado lo provee la capa de almacenamiento o el hipervisor, documentarlo como control compensatorio.'))
    }
} catch { $null = $gaps.Add('Get-BitLockerVolume no disponible (caracteristica no instalada o falta de privilegios).') }

# --- ARQ-01 Hardening: UAC, LSA, SMB, protocolos heredados ------------------
$clavesHardening = @(
    @{ Ruta='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Nombre='EnableLUA'; Esperado=1; Control='ARQ-01'
       Titulo='Control de cuentas de usuario (UAC) deshabilitado'; Sev='High'
       Rec='Habilitar UAC (EnableLUA=1). Su ausencia permite elevacion silenciosa de privilegios.' }
    @{ Ruta='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Nombre='ConsentPromptBehaviorAdmin'; Esperado=2; Control='ARQ-01'
       Titulo='UAC configurado sin solicitud de consentimiento'; Sev='Medium'
       Rec='Establecer ConsentPromptBehaviorAdmin en 2 (solicitar consentimiento en escritorio seguro) o superior.' }
    @{ Ruta='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Nombre='RunAsPPL'; Esperado=1; Control='ARQ-01'
       Titulo='LSA Protection (RunAsPPL) no habilitada'; Sev='Medium'
       Rec='Habilitar RunAsPPL=1 para proteger LSASS frente a volcado de credenciales.' }
    @{ Ruta='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Nombre='LimitBlankPasswordUse'; Esperado=1; Control='ACC-03'
       Titulo='Se permite el uso remoto de cuentas con contrasena en blanco'; Sev='High'
       Rec='Establecer LimitBlankPasswordUse=1.' }
    @{ Ruta='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Nombre='NoLMHash'; Esperado=1; Control='CRI-02'
       Titulo='Almacenamiento de hashes LM habilitado'; Sev='High'
       Rec='Establecer NoLMHash=1. Los hashes LM son trivialmente reversibles.' }
    @{ Ruta='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Nombre='SMB1'; Esperado=0; Control='RED-02'
       Titulo='SMBv1 habilitado en el servidor'; Sev='Critical'
       Rec='Deshabilitar SMBv1 (protocolo obsoleto, vector de EternalBlue/WannaCry).' }
    @{ Ruta='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Nombre='RequireSecuritySignature'; Esperado=1; Control='RED-02'
       Titulo='Firma SMB no exigida en el servidor'; Sev='Medium'
       Rec='Exigir firma SMB para mitigar ataques de retransmision (relay).' }
    @{ Ruta='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Nombre='EnableScriptBlockLogging'; Esperado=1; Control='REG-01'
       Titulo='Registro de bloques de script de PowerShell deshabilitado'; Sev='Medium'
       Rec='Habilitar ScriptBlockLogging: es la principal fuente de evidencia forense sobre actividad en PowerShell.' }
    @{ Ruta='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; Nombre='EnableModuleLogging'; Esperado=1; Control='REG-01'
       Titulo='Registro de modulos de PowerShell deshabilitado'; Sev='Low'
       Rec='Habilitar ModuleLogging para trazabilidad de comandos ejecutados.' }
)

foreach ($c in $clavesHardening) {
    try {
        $item = Get-ItemProperty -Path $c.Ruta -Name $c.Nombre -ErrorAction SilentlyContinue
        $valor = if ($item -and $item.PSObject.Properties[$c.Nombre]) { [int]$item.($c.Nombre) } else { $null }

        # SMB1: ausencia de la clave equivale a habilitado en sistemas heredados,
        # pero en Server 2016+ la caracteristica opcional es la fuente autoritativa.
        $estado = if ($null -eq $valor) { 'NO DEFINIDO' }
                  elseif ($valor -eq $c.Esperado) { 'OK' }
                  else { 'FALLA' }

        Add-Control $c.Control $c.Nombre $(if ($null -eq $valor) {'(no definido)'} else {$valor}) $c.Esperado $estado

        if ($estado -eq 'FALLA') {
            $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                -Severity $c.Sev -Category 'Hardening' `
                -Title $c.Titulo `
                -Asset ("{0}\{1}" -f $c.Ruta, $c.Nombre) `
                -Detail ("Valor actual: {0}. Valor esperado segun linea base: {1}." -f $valor, $c.Esperado) `
                -Evidence ("{0}\{1}={2}" -f $c.Ruta, $c.Nombre, $valor) `
                -Criterios @($c.Control) `
                -Recommendation $c.Rec))
        }
    } catch { }
}

# --- SMBv1 como caracteristica opcional (fuente autoritativa en Server 2016+)
try {
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
    Add-Control 'RED-02' 'SMB1Protocol (caracteristica)' $smb1.State 'Disabled' $(if ($smb1.State -eq 'Disabled') {'OK'} else {'FALLA'})
    $metrics['SMB1'] = [string]$smb1.State
    if ($smb1.State -eq 'Enabled') {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'Critical' -Category 'Protocolos' `
            -Title 'Caracteristica SMBv1 instalada y habilitada' `
            -Asset 'SMB1Protocol' `
            -Detail 'SMBv1 es un protocolo obsoleto sin firma ni cifrado, explotado por familias de ransomware conocidas.' `
            -Criterios @('RED-02','RED-01','VUL-01') `
            -Recommendation 'Desinstalar la caracteristica SMB1Protocol tras confirmar que ningun sistema heredado dependa de ella.'))
    }
} catch { $null = $gaps.Add('Get-WindowsOptionalFeature requiere privilegios elevados; no se verifico SMBv1 como caracteristica.') }

# --- CRI-02 Protocolos TLS/SChannel ----------------------------------------
$protocolos = @('SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1','TLS 1.2','TLS 1.3')
$base = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
foreach ($p in $protocolos) {
    foreach ($rol in @('Server','Client')) {
        $ruta = Join-Path $base "$p\$rol"
        try {
            if (Test-Path $ruta) {
                $prop = Get-ItemProperty -Path $ruta -ErrorAction SilentlyContinue
                $enabled     = if ($prop -and $prop.PSObject.Properties['Enabled']) { [int]$prop.Enabled } else { $null }
                $disabledDef = if ($prop -and $prop.PSObject.Properties['DisabledByDefault']) { [int]$prop.DisabledByDefault } else { $null }
                Add-Control 'CRI-02' "SChannel $p ($rol)" ("Enabled=$enabled DisabledByDefault=$disabledDef") '' 'Info'

                $obsoleto = $p -in @('SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1')
                if ($obsoleto -and $enabled -eq 1) {
                    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                        -Severity 'High' -Category 'Criptografia' `
                        -Title ("Protocolo criptografico obsoleto habilitado: {0} ({1})" -f $p, $rol) `
                        -Asset $ruta `
                        -Detail ("{0} esta explicitamente habilitado en el rol {1}. Estos protocolos presentan debilidades criptograficas conocidas (POODLE, BEAST, downgrade)." -f $p, $rol) `
                        -Criterios @('CRI-02','RED-02') `
                        -Recommendation ("Deshabilitar {0} estableciendo Enabled=0 y DisabledByDefault=1, previa validacion de compatibilidad de las aplicaciones." -f $p)))
                }
            }
        } catch { }
    }
}

# --- Directiva de auditoria (REG-01) ---------------------------------------
try {
    $auditpol = Invoke-NativeCapture -FilePath 'auditpol.exe' -Arguments @('/get','/category:*','/r') -TimeoutSec 30
    if (-not $auditpol.Failed -and $auditpol.StdOut) {
        $lineas = $auditpol.StdOut -split "`r?`n" | Where-Object { $_ -match ',' } | Select-Object -Skip 1
        $sinAuditar = 0
        foreach ($l in $lineas) {
            $campos = $l -split ','
            if ($campos.Count -ge 5) {
                $sub = $campos[2].Trim(); $set = $campos[4].Trim()
                if ($sub) {
                    Add-Control 'REG-01' "Auditoria: $sub" $set '' 'Info'
                    if ($set -match '(?i)no auditing|sin auditar') { $sinAuditar++ }
                }
            }
        }
        $metrics['SubcategoriasSinAuditar'] = $sinAuditar
        if ($sinAuditar -gt 30) {
            $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                -Severity 'Medium' -Category 'Registro' `
                -Title 'Cobertura insuficiente de la directiva de auditoria' `
                -Asset 'auditpol' `
                -Detail ("{0} subcategorias de auditoria estan sin configurar. Eventos relevantes de seguridad no se estan registrando." -f $sinAuditar) `
                -Criterios @('REG-01','REG-02') `
                -Recommendation 'Aplicar una linea base de auditoria avanzada (referencia CIS o Microsoft Security Baseline) que cubra inicio de sesion, gestion de cuentas, cambios de directiva y acceso a objetos.'))
        }
    } else {
        $null = $gaps.Add('auditpol requiere privilegios elevados; no se evaluo la directiva de auditoria.')
    }
} catch { $null = $gaps.Add('No se pudo ejecutar auditpol.exe.') }

$metrics['ControlesEvaluados'] = $records.Count
$metrics['ControlesEnFalla']   = @($records | Where-Object { $_.Estado -eq 'FALLA' }).Count

New-CollectorResult -Meta $meta -Records $records.ToArray() -Findings $findings.ToArray() `
    -Metrics $metrics -Gaps $gaps.ToArray()
