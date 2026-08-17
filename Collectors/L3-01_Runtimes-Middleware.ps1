<#
    L3-01_Runtimes-Middleware.ps1
    Capa L3 - Plataforma: runtimes, motores y middleware.
    Criterios de auditoria -> INV-01, VUL-01, ARQ-01, ARQ-03
#>
param([switch]$Manifest, [hashtable]$Config)

$meta = @{
    Id            = 'L3-01'
    Nombre        = 'Runtimes, motores y middleware'
    Layer         = 'L3'
    Criterios     = @('INV-01','SW-02','VUL-01','ARQ-01','ARQ-03')
    RequiereAdmin = $false
    Descripcion   = 'Deteccion de .NET, Java, Python, Node.js, IIS, bases de datos y servidores de aplicacion, con evaluacion de soporte.'
}
if ($Manifest) { return [pscustomobject]$meta }

$records  = New-Object System.Collections.ArrayList
$findings = New-Object System.Collections.ArrayList
$gaps     = New-Object System.Collections.ArrayList
$metrics  = @{}

function Add-Runtime {
    param(
        [string]$Familia, [string]$Producto, [string]$Version,
        [string]$Ruta = '', [string]$Origen = '', [string]$Notas = ''
    )
    $null = $records.Add([pscustomobject]@{
        Familia  = $Familia
        Producto = ConvertTo-SafeString $Producto 200
        Version  = ConvertTo-SafeString $Version 64
        Ruta     = ConvertTo-SafeString $Ruta 400
        Origen   = $Origen
        Notas    = ConvertTo-SafeString $Notas 300
    })
}

# ---------------------------------------------------------------------------
# .NET Framework (registro NDP)
# ---------------------------------------------------------------------------
try {
    $ndp = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP'
    if (Test-Path $ndp) {
        Get-ChildItem $ndp -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match '^v\d' } |
            ForEach-Object {
                $ver = (Get-ItemProperty $_.PSPath -Name Version -ErrorAction SilentlyContinue).Version
                if ($ver) {
                    Add-Runtime '.NET Framework' ".NET Framework $($_.PSChildName)" $ver $_.PSPath 'Registry:NDP'
                }
                foreach ($sub in (Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue)) {
                    $sv = (Get-ItemProperty $sub.PSPath -Name Version -ErrorAction SilentlyContinue).Version
                    $rel = (Get-ItemProperty $sub.PSPath -Name Release -ErrorAction SilentlyContinue).Release
                    if ($sv) {
                        $etiqueta = "$($_.PSChildName) $($sub.PSChildName)"
                        $nota = if ($rel) { "Release=$rel" } else { '' }
                        Add-Runtime '.NET Framework' ".NET Framework $etiqueta" $sv $sub.PSPath 'Registry:NDP' $nota
                    }
                }
            }
    }
} catch { $null = $gaps.Add("Lectura del registro NDP fallida: $($_.Exception.Message)") }

# ---------------------------------------------------------------------------
# .NET (Core) - SDK y runtimes
# ---------------------------------------------------------------------------
if (Test-CommandExists 'dotnet') {
    foreach ($modo in @(@{a='--list-runtimes'; f='Runtime'}, @{a='--list-sdks'; f='SDK'})) {
        $r = Invoke-NativeCapture -FilePath 'dotnet' -Arguments @($modo.a) -TimeoutSec 45
        if (-not $r.Failed -and $r.StdOut) {
            foreach ($l in ($r.StdOut -split "`r?`n" | Where-Object { $_.Trim() })) {
                $m = [regex]::Match($l, '^(?<name>[\w\.]+)\s+(?<ver>[\d\.\w\-]+)\s+\[(?<path>.+)\]')
                if ($m.Success) {
                    Add-Runtime '.NET' ("{0} ({1})" -f $m.Groups['name'].Value, $modo.f) `
                        $m.Groups['ver'].Value $m.Groups['path'].Value "dotnet $($modo.a)"
                } else {
                    $m2 = [regex]::Match($l, '^(?<ver>[\d\.\w\-]+)\s+\[(?<path>.+)\]')
                    if ($m2.Success) {
                        Add-Runtime '.NET' ".NET SDK" $m2.Groups['ver'].Value $m2.Groups['path'].Value "dotnet $($modo.a)"
                    }
                }
            }
        }
    }
    $sdks = @($records | Where-Object { $_.Producto -match 'SDK' })
    if ($sdks.Count -gt 0) {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'Low' -Category 'Segregacion' `
            -Title 'SDK de desarrollo instalado en servidor' `
            -Asset '.NET SDK' `
            -Detail ("Se detectaron {0} SDK de .NET. Un servidor productivo deberia contener unicamente runtimes, no herramientas de compilacion." -f $sdks.Count) `
            -Evidence (($sdks | Select-Object -First 5 | ForEach-Object { "$($_.Producto) $($_.Version)" }) -join '; ') `
            -Criterios @('ARQ-03','SW-03') `
            -Recommendation 'Confirmar si el servidor cumple funciones de compilacion. Si no, desinstalar los SDK para reducir la superficie de ataque y el riesgo de segregacion de entornos.'))
    }
}

# ---------------------------------------------------------------------------
# Java
# ---------------------------------------------------------------------------
$javaEncontrado = $false
try {
    foreach ($base in @('HKLM:\SOFTWARE\JavaSoft','HKLM:\SOFTWARE\WOW6432Node\JavaSoft','HKLM:\SOFTWARE\Eclipse Adoptium','HKLM:\SOFTWARE\Azul Systems')) {
        if (-not (Test-Path $base)) { continue }
        Get-ChildItem $base -Recurse -Depth 2 -ErrorAction SilentlyContinue | ForEach-Object {
            $home = (Get-ItemProperty $_.PSPath -Name JavaHome -ErrorAction SilentlyContinue).JavaHome
            if ($home) {
                $javaEncontrado = $true
                Add-Runtime 'Java' $_.PSParentPath.Split('\')[-1] $_.PSChildName $home 'Registry'
            }
        }
    }
} catch { }

if (Test-CommandExists 'java') {
    $jv = Invoke-NativeCapture -FilePath 'java' -Arguments @('-version') -TimeoutSec 30
    # java -version escribe en stderr por diseno
    $salida = if ($jv.StdErr) { $jv.StdErr } else { $jv.StdOut }
    if ($salida) {
        $m = [regex]::Match($salida, 'version "?([\d\._]+)')
        $ver = if ($m.Success) { $m.Groups[1].Value } else { 'desconocida' }
        $javaEncontrado = $true
        Add-Runtime 'Java' 'Java (en PATH)' $ver ((Get-Command java).Source) 'java -version' (ConvertTo-SafeString $salida 200)
    }
}
$metrics['JavaPresente'] = $javaEncontrado

# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------
foreach ($exe in @('python','python3','py')) {
    if (Test-CommandExists $exe) {
        $pv = Invoke-NativeCapture -FilePath $exe -Arguments @('--version') -TimeoutSec 25
        $salida = if ($pv.StdOut.Trim()) { $pv.StdOut } else { $pv.StdErr }
        if ($salida -match 'Python\s+([\d\.]+)') {
            Add-Runtime 'Python' "Python ($exe)" $Matches[1] ((Get-Command $exe -ErrorAction SilentlyContinue).Source) "$exe --version"
        }
    }
}

# ---------------------------------------------------------------------------
# Node.js
# ---------------------------------------------------------------------------
if (Test-CommandExists 'node') {
    $nv = Invoke-NativeCapture -FilePath 'node' -Arguments @('--version') -TimeoutSec 25
    if ($nv.StdOut -match 'v?([\d\.]+)') {
        $nodeVer = $Matches[1]
        Add-Runtime 'Node.js' 'Node.js' $nodeVer ((Get-Command node).Source) 'node --version'
        $mayor = [int]($nodeVer -split '\.')[0]
        if ($mayor -lt 20) {
            $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                -Severity $(if ($mayor -lt 18) {'High'} else {'Medium'}) -Category 'CicloDeVida' `
                -Title ("Node.js en rama sin soporte activo (v{0})" -f $nodeVer) `
                -Asset 'Node.js' `
                -Detail ("La version instalada es {0}. Las ramas por debajo de la LTS vigente dejan de recibir correcciones de seguridad." -f $nodeVer) `
                -Criterios @('SW-02','VUL-01') `
                -Recommendation 'Actualizar a la rama LTS vigente y verificar compatibilidad de las aplicaciones dependientes.'))
        }
    }
}

# ---------------------------------------------------------------------------
# IIS / servidores web
# ---------------------------------------------------------------------------
try {
    $iis = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\InetStp' -ErrorAction SilentlyContinue
    if ($iis -and $iis.PSObject.Properties['VersionString']) {
        Add-Runtime 'ServidorWeb' 'Internet Information Services' ([string]$iis.VersionString) ([string]$iis.PathWWWRoot) 'Registry:InetStp'
        $metrics['IIS'] = [string]$iis.VersionString

        $w3svc = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
        if ($w3svc -and $w3svc.Status -eq 'Running') {
            $null = $records.Add([pscustomobject]@{
                Familia='ServidorWeb'; Producto='W3SVC'; Version=''; Ruta=''
                Origen='Get-Service'; Notas="Estado: $($w3svc.Status)"
            })
        }

        # Grupos de aplicacion con runtime .NET obsoleto
        try {
            Import-Module WebAdministration -ErrorAction Stop
            foreach ($pool in Get-ChildItem IIS:\AppPools -ErrorAction Stop) {
                Add-Runtime 'IIS-AppPool' $pool.Name ([string]$pool.managedRuntimeVersion) '' 'WebAdministration' `
                    ("Identidad=$($pool.processModel.identityType) Estado=$($pool.state)")
                if ($pool.processModel.identityType -eq 'LocalSystem') {
                    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                        -Severity 'High' -Category 'Privilegios' `
                        -Title 'Grupo de aplicaciones de IIS ejecutandose como LocalSystem' `
                        -Asset ("AppPool: {0}" -f $pool.Name) `
                        -Detail 'LocalSystem otorga privilegios maximos. Una vulnerabilidad en la aplicacion web se convierte en compromiso total del servidor.' `
                        -Criterios @('ACC-02','ARQ-01') `
                        -Recommendation 'Cambiar la identidad del grupo de aplicaciones a ApplicationPoolIdentity o a una cuenta de servicio con privilegios minimos.'))
                }
            }
        } catch { $null = $gaps.Add('Modulo WebAdministration no disponible; no se enumeraron los grupos de aplicaciones de IIS.') }
    }
} catch { }

foreach ($svc in @('Apache2.4','httpd','nginx','Tomcat')) {
    $s = Get-Service -Name "*$svc*" -ErrorAction SilentlyContinue
    foreach ($item in @($s)) {
        if ($item) { Add-Runtime 'ServidorWeb' $item.DisplayName '' '' 'Get-Service' "Estado: $($item.Status)" }
    }
}

# ---------------------------------------------------------------------------
# Motores de base de datos
# ---------------------------------------------------------------------------
try {
    $sqlBase = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'
    if (Test-Path $sqlBase) {
        $inst = Get-ItemProperty $sqlBase -ErrorAction SilentlyContinue
        foreach ($p in $inst.PSObject.Properties) {
            if ($p.Name -notmatch '^PS') {
                $setup = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$($p.Value)\Setup"
                $ver   = (Get-ItemProperty $setup -Name Version -ErrorAction SilentlyContinue).Version
                $ed    = (Get-ItemProperty $setup -Name Edition -ErrorAction SilentlyContinue).Edition
                Add-Runtime 'BaseDeDatos' ("Microsoft SQL Server - instancia {0}" -f $p.Name) ([string]$ver) '' 'Registry' ([string]$ed)
                $metrics['SQLServer'] = "$ver ($ed)"
            }
        }
    }
} catch { }

foreach ($dbSvc in @('MySQL','MariaDB','postgresql','MongoDB','Redis','OracleService')) {
    foreach ($item in @(Get-Service -Name "*$dbSvc*" -ErrorAction SilentlyContinue)) {
        if ($item) { Add-Runtime 'BaseDeDatos' $item.DisplayName '' '' 'Get-Service' "Estado: $($item.Status)" }
    }
}

# ---------------------------------------------------------------------------
# Roles y caracteristicas de Windows Server
# ---------------------------------------------------------------------------
try {
    Import-Module ServerManager -ErrorAction Stop
    foreach ($f in (Get-WindowsFeature -ErrorAction Stop | Where-Object { $_.Installed })) {
        Add-Runtime 'RolWindows' $f.DisplayName '' $f.Name 'Get-WindowsFeature' ("Tipo: {0}" -f $f.FeatureType)
    }
    $metrics['RolesInstalados'] = @($records | Where-Object { $_.Familia -eq 'RolWindows' }).Count
} catch {
    $null = $gaps.Add('Modulo ServerManager no disponible o requiere elevacion; no se enumeraron roles y caracteristicas.')
}

# ---------------------------------------------------------------------------
# Evaluacion contra el catalogo de fin de soporte (EOL)
# ---------------------------------------------------------------------------
if ($Config -and $Config.EndOfLife) {
    foreach ($r in $records) {
        $etiqueta = "$($r.Producto) $($r.Version)"
        foreach ($eol in $Config.EndOfLife) {
            if ($etiqueta -match $eol.Patron) {
                $fechaEol = [datetime]$eol.EOL
                if ($fechaEol -lt (Get-Date)) {
                    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                        -Severity $eol.Severidad -Category 'CicloDeVida' `
                        -Title ("Componente de plataforma fuera de soporte: {0}" -f $r.Producto) `
                        -Asset $etiqueta `
                        -Detail ("{0}. Fin de soporte: {1}. Un componente sin soporte no recibe correcciones de seguridad." -f $eol.Nota, $fechaEol.ToString('yyyy-MM-dd')) `
                        -Evidence ("Ruta: {0} | Origen: {1}" -f $r.Ruta, $r.Origen) `
                        -Criterios @('SW-02','VUL-01','INV-01') `
                        -Recommendation 'Planificar la migracion a una version soportada o formalizar un plan de tratamiento del riesgo con controles compensatorios y fecha limite.'))
                }
                break
            }
        }
    }
}

$metrics['ComponentesPlataforma'] = $records.Count

New-CollectorResult -Meta $meta -Records $records.ToArray() -Findings $findings.ToArray() `
    -Metrics $metrics -Gaps $gaps.ToArray()
