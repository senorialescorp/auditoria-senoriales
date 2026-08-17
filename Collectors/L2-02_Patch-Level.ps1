<#
    L2-02_Patch-Level.ps1
    Capa L2 - Nivel de parcheo y gestion de actualizaciones.
    Criterios de auditoria -> VUL-01, CAM-01
#>
param([switch]$Manifest, [hashtable]$Config)

$meta = @{
    Id            = 'L2-02'
    Nombre        = 'Nivel de parcheo y actualizaciones'
    Layer         = 'L2'
    Criterios     = @('VUL-01','CAM-01')
    RequiereAdmin = $false
    Descripcion   = 'Historial de actualizaciones instaladas, configuracion de Windows Update y latencia de parcheo.'
}
if ($Manifest) { return [pscustomobject]$meta }

$records  = New-Object System.Collections.ArrayList
$findings = New-Object System.Collections.ArrayList
$gaps     = New-Object System.Collections.ArrayList
$metrics  = @{}

$diasMax = 45
if ($Config -and $Config.Thresholds -and $Config.Thresholds.DiasMaxSinParche) {
    $diasMax = [int]$Config.Thresholds.DiasMaxSinParche
}

# --- Historial de hotfixes --------------------------------------------------
$ultimoParche = $null
try {
    $hotfixes = Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending
    foreach ($h in $hotfixes) {
        $null = $records.Add([pscustomobject]@{
            Categoria     = 'Actualizacion'
            HotFixID      = $h.HotFixID
            Tipo          = $h.Description
            InstaladoEl   = if ($h.InstalledOn) { $h.InstalledOn.ToString('yyyy-MM-dd') } else { '' }
            InstaladoPor  = $h.InstalledBy
            DiasDesde     = if ($h.InstalledOn) { ((Get-Date) - $h.InstalledOn).Days } else { $null }
            Enlace        = $h.Caption
        })
    }

    $conFecha = @($hotfixes | Where-Object { $_.InstalledOn })
    $metrics['TotalActualizaciones'] = @($hotfixes).Count

    if ($conFecha.Count -gt 0) {
        $ultimoParche = $conFecha[0].InstalledOn
        $dias = ((Get-Date) - $ultimoParche).Days
        $metrics['DiasDesdeUltimoParche'] = $dias
        $metrics['UltimoParche'] = $ultimoParche.ToString('yyyy-MM-dd')

        if ($dias -gt ($diasMax * 2)) {
            $sev = 'Critical'
        } elseif ($dias -gt $diasMax) {
            $sev = 'High'
        } else {
            $sev = $null
        }

        if ($sev) {
            $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                -Severity $sev -Category 'Parcheo' `
                -Title 'Latencia de parcheo fuera del umbral definido' `
                -Asset $env:COMPUTERNAME `
                -Detail ("La ultima actualizacion registrada es del {0} ({1} dias). El umbral establecido para este servidor es de {2} dias." -f $ultimoParche.ToString('yyyy-MM-dd'), $dias, $diasMax) `
                -Evidence ("UltimoHotFix={0}" -f $conFecha[0].HotFixID) `
                -Criterios @('VUL-01') `
                -Recommendation 'Ejecutar el ciclo de actualizacion pendiente y verificar la conectividad del servidor con WSUS o el servicio de actualizacion corporativo.'))
        }
    } else {
        $null = $gaps.Add('Ningun hotfix reporta fecha de instalacion; no es posible calcular la latencia de parcheo.')
    }

    if (@($hotfixes).Count -eq 0) {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'High' -Category 'Parcheo' `
            -Title 'Sin historial de actualizaciones instaladas' `
            -Asset $env:COMPUTERNAME `
            -Detail 'Get-HotFix no devolvio ninguna actualizacion. El sistema podria no haber recibido parches desde su instalacion o el historial fue purgado.' `
            -Criterios @('VUL-01') `
            -Recommendation 'Verificar manualmente el estado de Windows Update y la conectividad con la fuente de actualizaciones.'))
    }
}
catch { $null = $gaps.Add("Get-HotFix fallo: $($_.Exception.Message)") }

# --- Configuracion de Windows Update ---------------------------------------
try {
    $auKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    $wuKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $au = Get-ItemProperty $auKey -ErrorAction SilentlyContinue
    $wu = Get-ItemProperty $wuKey -ErrorAction SilentlyContinue

    $modoAU = if ($au -and $au.PSObject.Properties['AUOptions']) {
        switch ([int]$au.AUOptions) {
            1 {'Nunca buscar actualizaciones (deshabilitado)'}
            2 {'Notificar antes de descargar'}
            3 {'Descargar y notificar antes de instalar'}
            4 {'Descargar e instalar automaticamente'}
            5 {'Los administradores locales eligen'}
            default {"Valor $($au.AUOptions)"}
        }
    } else { 'No definido por directiva' }

    $wsus = if ($wu -and $wu.PSObject.Properties['WUServer']) { [string]$wu.WUServer } else { '' }

    $null = $records.Add([pscustomobject]@{
        Categoria = 'ConfiguracionWU'; HotFixID = 'AUOptions'
        Tipo = $modoAU; InstaladoEl = ''; InstaladoPor = ''; DiasDesde = $null
        Enlace = if ($wsus) { "WSUS: $wsus" } else { 'Microsoft Update' }
    })
    $metrics['ModoWindowsUpdate'] = $modoAU
    $metrics['ServidorWSUS'] = if ($wsus) { $wsus } else { 'No configurado' }

    if ($au -and $au.PSObject.Properties['NoAutoUpdate'] -and [int]$au.NoAutoUpdate -eq 1) {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'High' -Category 'Parcheo' `
            -Title 'Actualizaciones automaticas deshabilitadas por directiva' `
            -Asset 'HKLM\...\WindowsUpdate\AU\NoAutoUpdate' `
            -Detail 'La directiva NoAutoUpdate=1 impide la instalacion automatica de actualizaciones de seguridad.' `
            -Criterios @('VUL-01') `
            -Recommendation 'Si el parcheo se gestiona por una herramienta externa, documentarlo como control compensatorio y evidenciar su cobertura sobre este servidor. En caso contrario, revertir la directiva.'))
    }

    $wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
    if ($wuService) {
        $null = $records.Add([pscustomobject]@{
            Categoria = 'ConfiguracionWU'; HotFixID = 'wuauserv'
            Tipo = "$($wuService.Status) / $($wuService.StartType)"; InstaladoEl = ''
            InstaladoPor = ''; DiasDesde = $null; Enlace = 'Servicio Windows Update'
        })
        if ($wuService.StartType -eq 'Disabled') {
            $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                -Severity 'High' -Category 'Parcheo' `
                -Title 'Servicio Windows Update deshabilitado' `
                -Asset 'wuauserv' `
                -Detail 'El servicio de actualizacion esta deshabilitado, impidiendo la aplicacion de parches por los canales estandar.' `
                -Criterios @('VUL-01') `
                -Recommendation 'Restablecer el tipo de inicio a Manual o Automatico, salvo que exista un mecanismo alterno documentado y verificado.'))
        }
    }
} catch { $null = $gaps.Add("Lectura de configuracion de Windows Update fallida: $($_.Exception.Message)") }

# --- Actualizaciones pendientes (requiere el agente COM de WU) -------------
try {
    $session  = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
    $searcher = $session.CreateUpdateSearcher()
    $result   = $searcher.Search("IsInstalled=0 and IsHidden=0")

    $metrics['ActualizacionesPendientes'] = $result.Updates.Count
    $criticas = 0

    foreach ($u in $result.Updates) {
        $esCritica = ($u.MsrcSeverity -in @('Critical','Important'))
        if ($esCritica) { $criticas++ }
        $null = $records.Add([pscustomobject]@{
            Categoria    = 'Pendiente'
            HotFixID     = ($u.KBArticleIDs -join ',')
            Tipo         = $u.Title
            InstaladoEl  = ''
            InstaladoPor = ''
            DiasDesde    = $null
            Enlace       = "Severidad MSRC: $($u.MsrcSeverity)"
        })
    }

    if ($criticas -gt 0) {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'Critical' -Category 'Parcheo' `
            -Title 'Actualizaciones de seguridad criticas pendientes de instalacion' `
            -Asset $env:COMPUTERNAME `
            -Detail ("Hay {0} actualizaciones pendientes, de las cuales {1} estan clasificadas por MSRC como Critical o Important." -f $result.Updates.Count, $criticas) `
            -Criterios @('VUL-01') `
            -Recommendation 'Priorizar la instalacion de las actualizaciones criticas en la proxima ventana y registrar el cambio en el proceso formal de gestion de cambios.'))
    }
    elseif ($result.Updates.Count -gt 0) {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'Low' -Category 'Parcheo' `
            -Title 'Actualizaciones no criticas pendientes' `
            -Asset $env:COMPUTERNAME `
            -Detail ("{0} actualizaciones estan disponibles y no instaladas." -f $result.Updates.Count) `
            -Criterios @('VUL-01') `
            -Recommendation 'Incorporar al ciclo regular de mantenimiento.'))
    }
}
catch {
    $null = $gaps.Add('No fue posible consultar actualizaciones pendientes via Microsoft.Update.Session. Suele requerir privilegios elevados o conectividad con WSUS.')
}

New-CollectorResult -Meta $meta -Records $records.ToArray() -Findings $findings.ToArray() `
    -Metrics $metrics -Gaps $gaps.ToArray()
