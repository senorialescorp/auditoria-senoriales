<#
    L6-01_Identity-Access.ps1
    Capa L6 - Identidad y control de acceso.
    Criterios de auditoria -> ACC-04, ACC-01, ACC-03, ACC-02, ACC-02, ACC-03
#>
param([switch]$Manifest, [hashtable]$Config)

$meta = @{
    Id            = 'L6-01'
    Nombre        = 'Identidades locales y control de acceso'
    Layer         = 'L6'
    Criterios     = @('ACC-04','ACC-01','ACC-03','ACC-02')
    RequiereAdmin = $false
    Descripcion   = 'Cuentas locales, membresias privilegiadas, politica de contrasenas y configuracion de acceso remoto.'
}
if ($Manifest) { return [pscustomobject]$meta }

$records  = New-Object System.Collections.ArrayList
$findings = New-Object System.Collections.ArrayList
$gaps     = New-Object System.Collections.ArrayList
$metrics  = @{}

$umbrales = @{ DiasCuentaInactiva = 90; MaxAdministradoresLocales = 5; EdadMaxContrasenaDias = 365 }
if ($Config -and $Config.Thresholds) {
    foreach ($k in @('DiasCuentaInactiva','MaxAdministradoresLocales','EdadMaxContrasenaDias')) {
        if ($Config.Thresholds.ContainsKey($k)) { $umbrales[$k] = [int]$Config.Thresholds[$k] }
    }
}

# ---------------------------------------------------------------------------
# 1. Cuentas locales
# ---------------------------------------------------------------------------
$cuentas = @()
try {
    $cuentas = @(Get-LocalUser -ErrorAction Stop)
    foreach ($u in $cuentas) {
        $diasSinUso = if ($u.LastLogon) { ((Get-Date) - $u.LastLogon).Days } else { $null }
        $edadPwd    = if ($u.PasswordLastSet) { ((Get-Date) - $u.PasswordLastSet).Days } else { $null }

        $null = $records.Add([pscustomobject]@{
            Categoria           = 'CuentaLocal'
            Nombre              = $u.Name
            Habilitada          = $u.Enabled
            Descripcion         = ConvertTo-SafeString $u.Description 200
            UltimoInicioSesion  = if ($u.LastLogon) { $u.LastLogon.ToString('yyyy-MM-dd') } else { 'Nunca' }
            DiasSinUso          = $diasSinUso
            ContrasenaEstablecida = if ($u.PasswordLastSet) { $u.PasswordLastSet.ToString('yyyy-MM-dd') } else { 'Nunca' }
            EdadContrasenaDias  = $edadPwd
            ContrasenaNoExpira  = $u.PasswordNeverExpires
            ContrasenaRequerida = $u.PasswordRequired
            SID                 = [string]$u.SID
            Detalle             = ''
        })
    }
    $metrics['CuentasLocales']            = $cuentas.Count
    $metrics['CuentasLocalesHabilitadas'] = @($cuentas | Where-Object { $_.Enabled }).Count
} catch {
    $null = $gaps.Add("Get-LocalUser no disponible: $($_.Exception.Message). Intentando via WMI.")
    try {
        foreach ($u in (Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction Stop)) {
            $null = $records.Add([pscustomobject]@{
                Categoria='CuentaLocal'; Nombre=$u.Name; Habilitada=(-not $u.Disabled)
                Descripcion=(ConvertTo-SafeString $u.Description 200); UltimoInicioSesion='N/D'
                DiasSinUso=$null; ContrasenaEstablecida='N/D'; EdadContrasenaDias=$null
                ContrasenaNoExpira=$u.PasswordExpires -eq $false; ContrasenaRequerida=$u.PasswordRequired
                SID=[string]$u.SID; Detalle='Origen: WMI'
            })
        }
    } catch { $null = $gaps.Add('Tampoco fue posible enumerar cuentas por WMI.') }
}

$habilitadas = @($records | Where-Object { $_.Categoria -eq 'CuentaLocal' -and $_.Habilitada })

# Cuenta Administrador integrada habilitada (SID termina en -500)
$adminIntegrado = @($habilitadas | Where-Object { $_.SID -like '*-500' })
foreach ($a in $adminIntegrado) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'Medium' -Category 'Identidad' `
        -Title 'Cuenta de administrador integrada habilitada' `
        -Asset $a.Nombre `
        -Detail ("La cuenta con SID terminado en -500 esta habilitada. Es un objetivo conocido de ataques de fuerza bruta y no permite atribuir acciones a una persona concreta. Nombre actual: {0}." -f $a.Nombre) `
        -Evidence ("SID={0} UltimoInicio={1}" -f $a.SID, $a.UltimoInicioSesion) `
        -Criterios @('ACC-02','ACC-01','ACC-03') `
        -Recommendation 'Deshabilitar la cuenta integrada y operar con cuentas administrativas nominales sujetas a trazabilidad. Si debe permanecer activa, renombrarla y asignarle una contrasena larga custodiada en boveda.'))
}

# Cuentas inactivas
$inactivas = @($habilitadas | Where-Object {
    $null -ne $_.DiasSinUso -and $_.DiasSinUso -gt $umbrales.DiasCuentaInactiva
})
if ($inactivas.Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'Medium' -Category 'Identidad' `
        -Title 'Cuentas locales habilitadas sin uso reciente' `
        -Asset ("{0} cuentas" -f $inactivas.Count) `
        -Detail ("Las siguientes cuentas siguen habilitadas pese a no registrar inicio de sesion en mas de {0} dias. Las cuentas latentes amplian la superficie de ataque sin aportar valor operativo." -f $umbrales.DiasCuentaInactiva) `
        -Evidence (($inactivas | ForEach-Object { "$($_.Nombre) ($($_.DiasSinUso) dias)" }) -join '; ') `
        -Criterios @('ACC-01','ACC-02') `
        -Recommendation 'Ejecutar la revision periodica de derechos de acceso y deshabilitar las cuentas sin dueno o sin uso justificado.'))
}

# Nunca han iniciado sesion
$nuncaUsadas = @($habilitadas | Where-Object { $_.UltimoInicioSesion -eq 'Nunca' })
if ($nuncaUsadas.Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'Low' -Category 'Identidad' `
        -Title 'Cuentas habilitadas que nunca han iniciado sesion' `
        -Asset (($nuncaUsadas | ForEach-Object { $_.Nombre }) -join ', ') `
        -Detail 'Cuentas creadas y habilitadas sin uso registrado. Pueden ser cuentas de servicio (aceptable) o cuentas residuales de aprovisionamiento (a eliminar).' `
        -Criterios @('ACC-01') `
        -Recommendation 'Clasificar cada cuenta como de servicio o nominal y eliminar las que no tengan proposito vigente.'))
}

# Contrasenas que no expiran
$pwdNoExpira = @($habilitadas | Where-Object { $_.ContrasenaNoExpira -and $_.SID -notlike '*-503' -and $_.SID -notlike '*-504' })
if ($pwdNoExpira.Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'Medium' -Category 'Autenticacion' `
        -Title 'Cuentas con contrasena que nunca expira' `
        -Asset (($pwdNoExpira | ForEach-Object { $_.Nombre }) -join ', ') `
        -Detail 'Estas cuentas tienen deshabilitada la expiracion de contrasena. Sin rotacion, una credencial comprometida permanece valida de forma indefinida.' `
        -Criterios @('ACC-03') `
        -Recommendation 'Aplicar caducidad conforme a la politica de contrasenas. Para cuentas de servicio, migrar a gMSA con rotacion automatica.'))
}

# Contrasenas antiguas
$pwdAntigua = @($habilitadas | Where-Object {
    $null -ne $_.EdadContrasenaDias -and $_.EdadContrasenaDias -gt $umbrales.EdadMaxContrasenaDias
})
if ($pwdAntigua.Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'Medium' -Category 'Autenticacion' `
        -Title 'Contrasenas sin rotacion por periodo prolongado' `
        -Asset ("{0} cuentas" -f $pwdAntigua.Count) `
        -Detail ("Cuentas cuya contrasena no cambia desde hace mas de {0} dias." -f $umbrales.EdadMaxContrasenaDias) `
        -Evidence (($pwdAntigua | ForEach-Object { "$($_.Nombre) ($($_.EdadContrasenaDias) dias)" }) -join '; ') `
        -Criterios @('ACC-03') `
        -Recommendation 'Forzar el cambio de contrasena y verificar el cumplimiento de la politica corporativa de credenciales.'))
}

# ---------------------------------------------------------------------------
# 2. Grupos privilegiados locales
# ---------------------------------------------------------------------------
$gruposCriticos = @('Administradores','Administrators','Remote Desktop Users','Escritorio remoto',
                    'Backup Operators','Operadores de copia de seguridad','Power Users')
foreach ($g in $gruposCriticos) {
    try {
        $miembros = @(Get-LocalGroupMember -Group $g -ErrorAction Stop)
        foreach ($m in $miembros) {
            $null = $records.Add([pscustomobject]@{
                Categoria='MiembroDeGrupo'; Nombre=$m.Name; Habilitada=$true
                Descripcion="Miembro de: $g"; UltimoInicioSesion=''; DiasSinUso=$null
                ContrasenaEstablecida=''; EdadContrasenaDias=$null; ContrasenaNoExpira=$null
                ContrasenaRequerida=$null; SID=[string]$m.SID; Detalle=[string]$m.ObjectClass
            })
        }

        if ($g -match '(?i)^administrador' -and $miembros.Count -gt $umbrales.MaxAdministradoresLocales) {
            $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                -Severity 'High' -Category 'Privilegios' `
                -Title 'Numero excesivo de miembros en el grupo de administradores locales' `
                -Asset $g `
                -Detail ("El grupo tiene {0} miembros; el umbral definido es {1}. Cada miembro representa una via de compromiso total del servidor." -f $miembros.Count, $umbrales.MaxAdministradoresLocales) `
                -Evidence (($miembros | ForEach-Object { $_.Name }) -join '; ') `
                -Criterios @('ACC-02','ACC-04') `
                -Recommendation 'Aplicar el principio de privilegio minimo: retirar del grupo a quienes no requieran administracion permanente y adoptar un modelo de acceso privilegiado just-in-time.'))
        }

        # Cuentas nominales con acceso RDP directo
        if ($g -match '(?i)remote desktop|escritorio remoto' -and $miembros.Count -gt 0) {
            $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                -Severity 'Low' -Category 'AccesoRemoto' `
                -Title 'Miembros con derecho de acceso por Escritorio remoto' `
                -Asset ("{0}: {1} miembros" -f $g, $miembros.Count) `
                -Detail 'El acceso por RDP debe restringirse al personal estrictamente necesario y realizarse preferentemente a traves de un host de salto (jump server).' `
                -Evidence (($miembros | ForEach-Object { $_.Name }) -join '; ') `
                -Criterios @('ACC-04','ACC-03','ACC-02') `
                -Recommendation 'Revisar la membresia contra la matriz de accesos autorizada y exigir autenticacion multifactor en el punto de entrada remoto.'))
        }
    } catch { }
}

# ---------------------------------------------------------------------------
# 3. Politica de contrasenas y bloqueo de cuentas
# ---------------------------------------------------------------------------
try {
    $na = Invoke-NativeCapture -FilePath 'net.exe' -Arguments @('accounts') -TimeoutSec 30
    if (-not $na.Failed -and $na.StdOut) {
        foreach ($l in ($na.StdOut -split "`r?`n" | Where-Object { $_ -match ':' })) {
            $p = $l -split ':', 2
            if ($p.Count -eq 2) {
                $null = $records.Add([pscustomobject]@{
                    Categoria='PoliticaContrasena'; Nombre=$p[0].Trim(); Habilitada=$null
                    Descripcion=$p[1].Trim(); UltimoInicioSesion=''; DiasSinUso=$null
                    ContrasenaEstablecida=''; EdadContrasenaDias=$null; ContrasenaNoExpira=$null
                    ContrasenaRequerida=$null; SID=''; Detalle='net accounts'
                })
            }
        }

        # Longitud minima de contrasena
        $mLong = [regex]::Match($na.StdOut, '(?im)^(Minimum password length|Longitud m.nima de la contrase.a)\s*:\s*(\d+)')
        if ($mLong.Success) {
            $longMin = [int]$mLong.Groups[2].Value
            $metrics['LongitudMinimaContrasena'] = $longMin
            if ($longMin -lt 14) {
                $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                    -Severity $(if ($longMin -lt 8) {'High'} else {'Medium'}) -Category 'Autenticacion' `
                    -Title 'Longitud minima de contrasena por debajo de la recomendacion' `
                    -Asset 'Politica local de contrasenas' `
                    -Detail ("La longitud minima configurada es de {0} caracteres. Las lineas base actuales recomiendan al menos 14 para cuentas locales de servidor." -f $longMin) `
                    -Criterios @('ACC-03') `
                    -Recommendation 'Elevar la longitud minima a 14 caracteres o mas mediante directiva de grupo, priorizando longitud sobre complejidad.'))
            }
        }

        # Umbral de bloqueo de cuenta
        $mBloq = [regex]::Match($na.StdOut, '(?im)^(Lockout threshold|Umbral de bloqueo)\s*:\s*(\S+)')
        if ($mBloq.Success) {
            $valor = $mBloq.Groups[2].Value
            $metrics['UmbralBloqueo'] = $valor
            if ($valor -match '(?i)never|nunca') {
                $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                    -Severity 'High' -Category 'Autenticacion' `
                    -Title 'Bloqueo de cuenta por intentos fallidos no configurado' `
                    -Asset 'Politica local de contrasenas' `
                    -Detail 'Sin umbral de bloqueo, el servidor no ofrece resistencia frente a ataques de fuerza bruta o de rociado de contrasenas.' `
                    -Criterios @('ACC-03') `
                    -Recommendation 'Configurar un umbral de bloqueo (referencia: 10 intentos fallidos, ventana de 15 minutos) equilibrando seguridad y disponibilidad.'))
            }
        }
    } else {
        $null = $gaps.Add('net accounts no devolvio resultados.')
    }
} catch { $null = $gaps.Add("Consulta de politica de contrasenas fallida: $($_.Exception.Message)") }

# ---------------------------------------------------------------------------
# 4. Configuracion de Escritorio remoto
# ---------------------------------------------------------------------------
try {
    $ts  = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
    $rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue

    $rdpHabilitado = ($ts -and $ts.PSObject.Properties['fDenyTSConnections'] -and [int]$ts.fDenyTSConnections -eq 0)
    $nla = if ($rdp -and $rdp.PSObject.Properties['UserAuthentication']) { [int]$rdp.UserAuthentication } else { $null }
    $nivelSeguridad = if ($rdp -and $rdp.PSObject.Properties['SecurityLayer']) { [int]$rdp.SecurityLayer } else { $null }

    $null = $records.Add([pscustomobject]@{
        Categoria='AccesoRemoto'; Nombre='RDP'; Habilitada=$rdpHabilitado
        Descripcion=("NLA={0} SecurityLayer={1}" -f $nla, $nivelSeguridad); UltimoInicioSesion=''
        DiasSinUso=$null; ContrasenaEstablecida=''; EdadContrasenaDias=$null
        ContrasenaNoExpira=$null; ContrasenaRequerida=$null; SID=''; Detalle='Registro Terminal Server'
    })
    $metrics['RDPHabilitado'] = $rdpHabilitado

    if ($rdpHabilitado -and $nla -ne 1) {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'High' -Category 'AccesoRemoto' `
            -Title 'RDP habilitado sin autenticacion a nivel de red (NLA)' `
            -Asset 'RDP-Tcp' `
            -Detail 'Sin NLA, el servidor establece una sesion completa antes de autenticar al usuario, lo que lo expone a agotamiento de recursos y a vulnerabilidades previas a la autenticacion.' `
            -Criterios @('ACC-03','ACC-04','RED-01') `
            -Recommendation 'Habilitar UserAuthentication=1 y SecurityLayer=2 (TLS) en la configuracion de Escritorio remoto.'))
    }
} catch { }

$metrics['RegistrosIdentidad'] = $records.Count

New-CollectorResult -Meta $meta -Records $records.ToArray() -Findings $findings.ToArray() `
    -Metrics $metrics -Gaps $gaps.ToArray()
