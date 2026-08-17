<#
    L7-01_Network-Exposure.ps1
    Capa L7 - Red y exposicion.
    Criterios de auditoria -> RED-01, RED-02, RED-03, ACC-04, ACC-04
#>
param([switch]$Manifest, [hashtable]$Config)

$meta = @{
    Id            = 'L7-01'
    Nombre        = 'Exposicion de red y servicios accesibles'
    Layer         = 'L7'
    Criterios     = @('RED-01','RED-02','RED-03','ACC-04')
    RequiereAdmin = $false
    Descripcion   = 'Puertos en escucha correlacionados con el software propietario, recursos compartidos, interfaces y reglas de firewall permisivas.'
}
if ($Manifest) { return [pscustomobject]$meta }

$records  = New-Object System.Collections.ArrayList
$findings = New-Object System.Collections.ArrayList
$gaps     = New-Object System.Collections.ArrayList
$metrics  = @{}

# Puertos de alto riesgo si estan expuestos en todas las interfaces
$puertosSensibles = @{
    21   = 'FTP (credenciales en claro)'
    23   = 'Telnet (protocolo sin cifrado)'
    69   = 'TFTP (sin autenticacion)'
    135  = 'RPC Endpoint Mapper'
    139  = 'NetBIOS Session Service'
    445  = 'SMB'
    1433 = 'Microsoft SQL Server'
    1521 = 'Oracle DB'
    3306 = 'MySQL/MariaDB'
    3389 = 'RDP'
    5432 = 'PostgreSQL'
    5985 = 'WinRM HTTP'
    5986 = 'WinRM HTTPS'
    6379 = 'Redis (por defecto sin autenticacion)'
    27017= 'MongoDB'
    5900 = 'VNC'
}

# ---------------------------------------------------------------------------
# 1. Puertos TCP en escucha, correlacionados con su proceso propietario
# ---------------------------------------------------------------------------
$expuestos = New-Object System.Collections.ArrayList
try {
    $conexiones = Get-NetTCPConnection -State Listen -ErrorAction Stop
    $procesos = @{}
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) { $procesos[$p.Id] = $p }

    foreach ($c in $conexiones) {
        $proc = $procesos[[int]$c.OwningProcess]
        $rutaProc = ''
        if ($proc) { try { $rutaProc = $proc.Path } catch { } }

        $enTodasInterfaces = $c.LocalAddress -in @('0.0.0.0','::')
        $puerto = [int]$c.LocalPort
        $sensible = $puertosSensibles.ContainsKey($puerto)

        $registro = [pscustomobject]@{
            Categoria     = 'PuertoEscucha'
            Protocolo     = 'TCP'
            DireccionLocal= [string]$c.LocalAddress
            Puerto        = $puerto
            Proceso       = if ($proc) { $proc.ProcessName } else { "PID $($c.OwningProcess)" }
            PID           = $c.OwningProcess
            RutaProceso   = ConvertTo-SafeString $rutaProc 400
            Servicio      = if ($sensible) { $puertosSensibles[$puerto] } else { '' }
            TodasInterfaces = $enTodasInterfaces
            Detalle       = ''
        }
        $null = $records.Add($registro)
        if ($sensible -and $enTodasInterfaces) { $null = $expuestos.Add($registro) }
    }
    $metrics['PuertosTCPEscucha'] = @($conexiones).Count
} catch {
    $null = $gaps.Add("Get-NetTCPConnection fallo: $($_.Exception.Message)")
}

try {
    foreach ($u in (Get-NetUDPEndpoint -ErrorAction Stop)) {
        $null = $records.Add([pscustomobject]@{
            Categoria='PuertoEscucha'; Protocolo='UDP'; DireccionLocal=[string]$u.LocalAddress
            Puerto=[int]$u.LocalPort; Proceso="PID $($u.OwningProcess)"; PID=$u.OwningProcess
            RutaProceso=''; Servicio=''; TodasInterfaces=($u.LocalAddress -in @('0.0.0.0','::')); Detalle=''
        })
    }
} catch { }

if ($expuestos.Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'High' -Category 'ExposicionDeRed' `
        -Title 'Servicios sensibles escuchando en todas las interfaces de red' `
        -Asset ("{0} puertos" -f $expuestos.Count) `
        -Detail 'Estos servicios aceptan conexiones en cualquier interfaz (0.0.0.0 o ::). Si el firewall perimetral o de host no los restringe, quedan accesibles desde toda la red alcanzable.' `
        -Evidence (($expuestos | ForEach-Object { "$($_.Puerto)/$($_.Protocolo) [$($_.Servicio)] <= $($_.Proceso)" }) -join ' | ') `
        -Criterios @('RED-01','RED-02','RED-03') `
        -Recommendation 'Restringir la escucha a las interfaces necesarias, aplicar reglas de firewall con origen acotado y aplicar segmentacion de red para los servicios de administracion y de base de datos.'))
}

# Protocolos en claro
$enClaro = @($records | Where-Object { $_.Puerto -in @(21,23,69,80) -and $_.Categoria -eq 'PuertoEscucha' -and $_.Protocolo -eq 'TCP' })
$sinCifrar = @($enClaro | Where-Object { $_.Puerto -in @(21,23,69) })
if ($sinCifrar.Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'Critical' -Category 'Criptografia' `
        -Title 'Protocolos sin cifrado activos en el servidor' `
        -Asset (($sinCifrar | ForEach-Object { "$($_.Puerto) ($($_.Servicio))" }) -join ', ') `
        -Detail 'FTP, Telnet y TFTP transmiten credenciales y datos en texto claro, permitiendo su captura por cualquier sistema con acceso al segmento de red.' `
        -Evidence (($sinCifrar | ForEach-Object { "$($_.Puerto) <= $($_.Proceso) ($($_.RutaProceso))" }) -join ' | ') `
        -Criterios @('CRI-02','RED-02','RED-01') `
        -Recommendation 'Sustituir por equivalentes cifrados (SFTP/FTPS, SSH, HTTPS) y deshabilitar los servicios heredados.'))
}

# ---------------------------------------------------------------------------
# 2. Recursos compartidos
# ---------------------------------------------------------------------------
try {
    $shares = Get-CimInstance Win32_Share -ErrorAction Stop
    foreach ($s in $shares) {
        $esAdmin = $s.Name -match '^\w\$$|^(ADMIN|IPC)\$$'
        $null = $records.Add([pscustomobject]@{
            Categoria='RecursoCompartido'; Protocolo='SMB'; DireccionLocal=''
            Puerto=445; Proceso=$s.Name; PID=$null; RutaProceso=[string]$s.Path
            Servicio=$(if ($esAdmin) {'Comparticion administrativa'} else {'Comparticion de datos'})
            TodasInterfaces=$true; Detalle=(ConvertTo-SafeString $s.Description 200)
        })
    }
    $noAdmin = @($shares | Where-Object { $_.Name -notmatch '^\w\$$|^(ADMIN|IPC)\$$' })
    $metrics['RecursosCompartidos'] = $noAdmin.Count

    if ($noAdmin.Count -gt 0) {
        # Verificar permisos de los recursos no administrativos
        $abiertos = New-Object System.Collections.ArrayList
        foreach ($s in $noAdmin) {
            try {
                $acc = Get-SmbShareAccess -Name $s.Name -ErrorAction Stop
                foreach ($a in $acc) {
                    if ($a.AccountName -match '(?i)(Everyone|Todos|ANONYMOUS|Usuarios autenticados|Authenticated Users)' -and
                        $a.AccessRight -in @('Full','Change')) {
                        $null = $abiertos.Add("$($s.Name) => $($a.AccountName): $($a.AccessRight)")
                    }
                }
            } catch { }
        }
        if ($abiertos.Count -gt 0) {
            $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                -Severity 'High' -Category 'ControlDeAcceso' `
                -Title 'Recursos compartidos con permisos amplios de escritura' `
                -Asset ("{0} recursos" -f $abiertos.Count) `
                -Detail 'Existen comparticiones que otorgan permisos de cambio o control total a grupos amplios, permitiendo lectura y modificacion de datos por cualquier cuenta autenticada de la red.' `
                -Evidence (($abiertos | Select-Object -First 12) -join ' | ') `
                -Criterios @('ACC-04','DAT-02') `
                -Recommendation 'Aplicar permisos basados en grupos especificos siguiendo el principio de privilegio minimo, tanto en la comparticion como en las ACL NTFS subyacentes.'))
        } else {
            $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                -Severity 'Info' -Category 'ControlDeAcceso' `
                -Title 'Recursos compartidos de datos publicados en el servidor' `
                -Asset ("{0} recursos" -f $noAdmin.Count) `
                -Detail (($noAdmin | ForEach-Object { "$($_.Name) => $($_.Path)" }) -join ' | ') `
                -Criterios @('ACC-04') `
                -Recommendation 'Verificar que cada comparticion responda a una necesidad vigente y que sus permisos esten alineados con la clasificacion de la informacion alojada.'))
        }
    }
} catch { $null = $gaps.Add("Enumeracion de recursos compartidos fallida: $($_.Exception.Message)") }

# ---------------------------------------------------------------------------
# 3. Interfaces y configuracion IP
# ---------------------------------------------------------------------------
try {
    foreach ($ip in (Get-NetIPConfiguration -ErrorAction Stop)) {
        $direcciones = @($ip.IPv4Address.IPAddress) -join ', '
        $null = $records.Add([pscustomobject]@{
            Categoria='Interfaz'; Protocolo='IP'; DireccionLocal=$direcciones; Puerto=$null
            Proceso=$ip.InterfaceAlias; PID=$null
            RutaProceso=("Gateway: {0}" -f ($ip.IPv4DefaultGateway.NextHop -join ', '))
            Servicio=("DNS: {0}" -f ($ip.DNSServer.ServerAddresses -join ', '))
            TodasInterfaces=$false; Detalle=[string]$ip.NetProfile.NetworkCategory
        })

        if ($ip.NetProfile -and $ip.NetProfile.NetworkCategory -eq 'Public' ) {
            $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                -Severity 'Low' -Category 'Red' `
                -Title 'Interfaz de red clasificada con perfil Publico' `
                -Asset $ip.InterfaceAlias `
                -Detail 'El perfil de red determina que conjunto de reglas de firewall aplica. Una clasificacion incorrecta puede dejar activo un conjunto de reglas que no corresponde al entorno real.' `
                -Criterios @('RED-01','RED-03') `
                -Recommendation 'Confirmar que la categoria de red asignada corresponde al segmento real de la interfaz.'))
        }
    }
} catch { $null = $gaps.Add("Get-NetIPConfiguration fallo: $($_.Exception.Message)") }

# ---------------------------------------------------------------------------
# 4. Reglas de firewall permisivas
# ---------------------------------------------------------------------------
try {
    $reglas = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop
    $permisivas = New-Object System.Collections.ArrayList

    foreach ($r in $reglas) {
        try {
            $addr = $r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
            $port = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            $remoto = if ($addr) { ($addr.RemoteAddress -join ',') } else { '' }
            $puertoLocal = if ($port) { ($port.LocalPort -join ',') } else { '' }

            if ($remoto -match '(?i)any' -and $puertoLocal -match '(?i)any') {
                $null = $permisivas.Add("$($r.DisplayName) [$($r.Profile)]")
            }
        } catch { }
    }
    $metrics['ReglasFirewallEntrantes'] = @($reglas).Count
    $metrics['ReglasPermisivas']        = $permisivas.Count

    if ($permisivas.Count -gt 0) {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'Medium' -Category 'Red' `
            -Title 'Reglas de firewall entrantes sin restriccion de origen ni de puerto' `
            -Asset ("{0} reglas" -f $permisivas.Count) `
            -Detail 'Estas reglas permiten trafico entrante desde cualquier origen hacia cualquier puerto, anulando en la practica el filtrado de host para el programa o perfil que cubren.' `
            -Evidence (($permisivas | Select-Object -First 15) -join ' | ') `
            -Criterios @('RED-01','RED-02') `
            -Recommendation 'Acotar cada regla al puerto y al rango de direcciones de origen estrictamente requeridos, y eliminar las reglas sin dueno identificable.'))
    }
} catch { $null = $gaps.Add('No se pudieron enumerar reglas de firewall (puede requerir elevacion).') }

# ---------------------------------------------------------------------------
# 5. WinRM
# ---------------------------------------------------------------------------
try {
    $winrm = Get-Service WinRM -ErrorAction SilentlyContinue
    if ($winrm -and $winrm.Status -eq 'Running') {
        $allowUnencrypted = (Get-Item WSMan:\localhost\Service\AllowUnencrypted -ErrorAction SilentlyContinue).Value
        $basicAuth        = (Get-Item WSMan:\localhost\Service\Auth\Basic -ErrorAction SilentlyContinue).Value

        $null = $records.Add([pscustomobject]@{
            Categoria='AdministracionRemota'; Protocolo='WinRM'; DireccionLocal=''
            Puerto=5985; Proceso='WinRM'; PID=$null; RutaProceso=''
            Servicio=("AllowUnencrypted={0} Basic={1}" -f $allowUnencrypted, $basicAuth)
            TodasInterfaces=$true; Detalle=[string]$winrm.Status
        })

        if ($allowUnencrypted -eq 'true' -or $basicAuth -eq 'true') {
            $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                -Severity 'High' -Category 'AdministracionRemota' `
                -Title 'WinRM configurado con transporte sin cifrar o autenticacion basica' `
                -Asset 'WinRM' `
                -Detail ("AllowUnencrypted={0}, Basic={1}. Ambas opciones exponen credenciales administrativas al trafico de red." -f $allowUnencrypted, $basicAuth) `
                -Criterios @('ACC-03','CRI-02','RED-01') `
                -Recommendation 'Deshabilitar AllowUnencrypted y la autenticacion basica; usar HTTPS (5986) con certificado valido y autenticacion Kerberos o por certificado.'))
        }
    }
} catch { }

New-CollectorResult -Meta $meta -Records $records.ToArray() -Findings $findings.ToArray() `
    -Metrics $metrics -Gaps $gaps.ToArray()
