<#
    L4-02_Package-Managers.ps1
    Capa L4 - ARTEFACTOS DE SOFTWARE.

    Inventario de software instalado FUERA del registro de desinstalacion:
    gestores de paquetes de desarrollador y de sistema. Es el punto ciego
    clasico de las auditorias de inventario: paquetes con capacidad de
    ejecucion arbitraria que ningun agente de inventario tradicional reporta.

    Criterios de auditoria -> INV-01, SW-03, SW-04, ARQ-03
#>
param([switch]$Manifest, [hashtable]$Config)

$meta = @{
    Id            = 'L4-02'
    Nombre        = 'Software gestionado por gestores de paquetes'
    Layer         = 'L4'
    Criterios     = @('INV-01','SW-03','SW-04','ARQ-03')
    RequiereAdmin = $false
    Descripcion   = 'winget, Chocolatey, Scoop, npm global, pip, dotnet tool, modulos de PowerShell y NuGet.'
}
if ($Manifest) { return [pscustomobject]$meta }

$records  = New-Object System.Collections.ArrayList
$findings = New-Object System.Collections.ArrayList
$gaps     = New-Object System.Collections.ArrayList
$metrics  = @{}

function Add-Paquete {
    param(
        [string]$Gestor, [string]$Nombre, [string]$Version,
        [string]$Ambito = 'Maquina', [string]$Ruta = '', [string]$Notas = ''
    )
    $null = $records.Add([pscustomobject]@{
        Gestor  = $Gestor
        Nombre  = ConvertTo-SafeString $Nombre 200
        Version = ConvertTo-SafeString $Version 64
        Ambito  = $Ambito
        Ruta    = ConvertTo-SafeString $Ruta 400
        Notas   = ConvertTo-SafeString $Notas 300
    })
}

$gestoresDetectados = New-Object System.Collections.ArrayList

# ---------------------------------------------------------------------------
# winget (Windows Package Manager)
# ---------------------------------------------------------------------------
if (Test-CommandExists 'winget') {
    $null = $gestoresDetectados.Add('winget')
    $r = Invoke-NativeCapture -FilePath 'winget' -Arguments @('list','--disable-interactivity','--accept-source-agreements') -TimeoutSec 120
    if (-not $r.Failed -and $r.StdOut) {
        $lineas = $r.StdOut -split "`r?`n"
        # Localizar la fila de separadores para delimitar el encabezado
        $inicio = 0
        for ($i = 0; $i -lt $lineas.Count; $i++) {
            if ($lineas[$i] -match '^-{5,}') { $inicio = $i + 1; break }
        }
        for ($i = $inicio; $i -lt $lineas.Count; $i++) {
            $l = $lineas[$i]
            if ([string]::IsNullOrWhiteSpace($l)) { continue }
            # Columnas separadas por 2+ espacios
            $cols = [regex]::Split($l.Trim(), '\s{2,}')
            if ($cols.Count -ge 2) {
                Add-Paquete 'winget' $cols[0] $(if ($cols.Count -ge 3) { $cols[2] } else { $cols[1] }) `
                    'Maquina' '' $(if ($cols.Count -ge 4) { "Disponible: $($cols[3])" } else { '' })
            }
        }
    } else {
        $null = $gaps.Add('winget esta presente pero no devolvio inventario (posible falta de origenes configurados o contexto sin sesion interactiva).')
    }
}

# ---------------------------------------------------------------------------
# Chocolatey
# ---------------------------------------------------------------------------
if (Test-CommandExists 'choco') {
    $null = $gestoresDetectados.Add('Chocolatey')
    $r = Invoke-NativeCapture -FilePath 'choco' -Arguments @('list','--local-only','--limit-output','--no-color') -TimeoutSec 90
    if (-not $r.Failed -and $r.StdOut) {
        foreach ($l in ($r.StdOut -split "`r?`n" | Where-Object { $_ -match '\|' })) {
            $p = $l -split '\|'
            if ($p.Count -ge 2) { Add-Paquete 'Chocolatey' $p[0] $p[1] 'Maquina' 'C:\ProgramData\chocolatey\lib' }
        }
    }
}

# ---------------------------------------------------------------------------
# Scoop (instala en perfil de usuario: elude por completo el inventario clasico)
# ---------------------------------------------------------------------------
$scoopDirs = @("$env:USERPROFILE\scoop\apps", "$env:ProgramData\scoop\apps")
foreach ($sd in $scoopDirs) {
    if (Test-Path $sd) {
        $null = $gestoresDetectados.Add('Scoop')
        foreach ($app in (Get-ChildItem $sd -Directory -ErrorAction SilentlyContinue)) {
            $ver = (Get-ChildItem $app.FullName -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -ne 'current' } |
                    Sort-Object Name -Descending | Select-Object -First 1).Name
            Add-Paquete 'Scoop' $app.Name ([string]$ver) $(if ($sd -like "$env:USERPROFILE*") {'Usuario'} else {'Maquina'}) $app.FullName
        }
    }
}

# ---------------------------------------------------------------------------
# npm global
# ---------------------------------------------------------------------------
if (Test-CommandExists 'npm') {
    $null = $gestoresDetectados.Add('npm')
    $r = Invoke-NativeCapture -FilePath 'npm.cmd' -Arguments @('ls','-g','--depth=0','--json') -TimeoutSec 120
    if ($r.Failed -or -not $r.StdOut) {
        $r = Invoke-NativeCapture -FilePath 'npm' -Arguments @('ls','-g','--depth=0','--json') -TimeoutSec 120
    }
    if ($r.StdOut) {
        try {
            $json = $r.StdOut | ConvertFrom-Json
            if ($json.PSObject.Properties['dependencies']) {
                foreach ($d in $json.dependencies.PSObject.Properties) {
                    Add-Paquete 'npm (global)' $d.Name ([string]$d.Value.version) 'Maquina' ([string]$json.path)
                }
            }
        } catch { $null = $gaps.Add('No se pudo interpretar la salida JSON de npm ls -g.') }
    }
}

# ---------------------------------------------------------------------------
# pip
# ---------------------------------------------------------------------------
foreach ($pipExe in @('pip','pip3')) {
    if (Test-CommandExists $pipExe) {
        if ($gestoresDetectados -notcontains 'pip') { $null = $gestoresDetectados.Add('pip') }
        $r = Invoke-NativeCapture -FilePath $pipExe -Arguments @('list','--format=json','--disable-pip-version-check') -TimeoutSec 120
        if ($r.StdOut) {
            try {
                foreach ($p in ($r.StdOut | ConvertFrom-Json)) {
                    Add-Paquete "pip ($pipExe)" $p.name $p.version 'Maquina'
                }
            } catch { }
        }
        break
    }
}

# ---------------------------------------------------------------------------
# dotnet tool
# ---------------------------------------------------------------------------
if (Test-CommandExists 'dotnet') {
    $r = Invoke-NativeCapture -FilePath 'dotnet' -Arguments @('tool','list','--global') -TimeoutSec 60
    if (-not $r.Failed -and $r.StdOut) {
        $lineas = $r.StdOut -split "`r?`n"
        $inicio = 0
        for ($i = 0; $i -lt $lineas.Count; $i++) { if ($lineas[$i] -match '^-{3,}') { $inicio = $i + 1; break } }
        for ($i = $inicio; $i -lt $lineas.Count; $i++) {
            if ([string]::IsNullOrWhiteSpace($lineas[$i])) { continue }
            $cols = [regex]::Split($lineas[$i].Trim(), '\s{2,}')
            if ($cols.Count -ge 2) {
                if ($gestoresDetectados -notcontains 'dotnet tool') { $null = $gestoresDetectados.Add('dotnet tool') }
                Add-Paquete 'dotnet tool' $cols[0] $cols[1] 'Maquina' '' $(if ($cols.Count -ge 3) { "Comando: $($cols[2])" } else { '' })
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Modulos de PowerShell (codigo ejecutable con alcance de sistema)
# ---------------------------------------------------------------------------
try {
    $rutasSistema = @($env:PSModulePath -split ';' | Where-Object { $_ })
    $modulos = Get-Module -ListAvailable -ErrorAction SilentlyContinue |
               Group-Object Name | ForEach-Object { $_.Group | Sort-Object Version -Descending | Select-Object -First 1 }

    foreach ($m in $modulos) {
        $esSistema = $m.ModuleBase -like "$env:SystemRoot\System32\WindowsPowerShell*"
        $ambito = if ($esSistema) { 'Sistema' }
                  elseif ($m.ModuleBase -like "$env:USERPROFILE*") { 'Usuario' }
                  else { 'Maquina' }
        # Solo se inventarian los modulos no provistos con el SO: son los que
        # representan superficie de software introducida.
        if (-not $esSistema) {
            Add-Paquete 'PowerShell Module' $m.Name ([string]$m.Version) $ambito $m.ModuleBase ([string]$m.Author)
        }
    }
    $metrics['ModulosPSNoSistema'] = @($records | Where-Object { $_.Gestor -eq 'PowerShell Module' }).Count
} catch { $null = $gaps.Add("Enumeracion de modulos de PowerShell fallida: $($_.Exception.Message)") }

# Repositorios de PowerShell no confiables (vector de cadena de suministro)
try {
    foreach ($repo in (Get-PSRepository -ErrorAction SilentlyContinue)) {
        Add-Paquete 'PSRepository' $repo.Name '' 'Maquina' $repo.SourceLocation ("Politica: {0}" -f $repo.InstallationPolicy)
        if ($repo.InstallationPolicy -eq 'Trusted' -and $repo.Name -ne 'PSGallery') {
            $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                -Severity 'Medium' -Category 'CadenaDeSuministro' `
                -Title ("Repositorio de paquetes de terceros marcado como confiable: {0}" -f $repo.Name) `
                -Asset $repo.Name `
                -Detail ("Origen: {0}. Un repositorio marcado como Trusted instala modulos sin solicitar confirmacion, ampliando el riesgo de cadena de suministro." -f $repo.SourceLocation) `
                -Criterios @('SW-03','SW-04') `
                -Recommendation 'Validar la titularidad del repositorio y restringir su politica a Untrusted salvo que sea un feed interno controlado por la organizacion.'))
        }
    }
} catch { }

# ---------------------------------------------------------------------------
# Evaluacion transversal
# ---------------------------------------------------------------------------
$metrics['GestoresDetectados'] = ($gestoresDetectados | Select-Object -Unique) -join ', '
$metrics['TotalPaquetes']      = $records.Count

# Gestores de desarrollador en un servidor de produccion (ARQ-03 / SW-04)
$gestoresDev = @($gestoresDetectados | Where-Object { $_ -in @('npm','pip','dotnet tool','Scoop') } | Select-Object -Unique)
if ($gestoresDev.Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'Medium' -Category 'Segregacion' `
        -Title 'Gestores de paquetes de desarrollo presentes en el servidor' `
        -Asset ($gestoresDev -join ', ') `
        -Detail ("Se detectaron los siguientes gestores: {0}. Permiten instalar codigo ejecutable de repositorios publicos sin pasar por el control de instalacion de software de la organizacion, y sus paquetes no aparecen en el inventario de Agregar o quitar programas." -f ($gestoresDev -join ', ')) `
        -Criterios @('SW-03','ARQ-03','SW-04') `
        -Recommendation 'Restringir el uso de estos gestores en produccion, o bien configurarlos contra un feed interno espejado y sumar sus paquetes al inventario formal de activos de software.'))
}

# Paquetes instalados en el perfil de usuario: eluden el control centralizado
$enUsuario = @($records | Where-Object { $_.Ambito -eq 'Usuario' })
if ($enUsuario.Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'Medium' -Category 'ControlDeInstalacion' `
        -Title 'Software instalado en el perfil de usuario' `
        -Asset ("{0} paquetes" -f $enUsuario.Count) `
        -Detail ("{0} paquetes residen en el perfil de usuario. Este tipo de instalacion no requiere privilegios administrativos y suele quedar fuera del inventario y del alcance del antimalware corporativo." -f $enUsuario.Count) `
        -Evidence (($enUsuario | Select-Object -First 12 | ForEach-Object { "$($_.Gestor): $($_.Nombre) $($_.Version)" }) -join '; ') `
        -Criterios @('SW-03','INV-01') `
        -Recommendation 'Aplicar control de aplicaciones (AppLocker o WDAC) que impida la ejecucion desde directorios escribibles por el usuario, e incorporar estos artefactos al inventario.'))
}

if ($records.Count -eq 0 -and $gestoresDetectados.Count -eq 0) {
    $null = $records.Add([pscustomobject]@{
        Gestor='(ninguno)'; Nombre='Sin gestores de paquetes detectados'; Version=''
        Ambito=''; Ruta=''; Notas='Resultado favorable: reduce la superficie de instalacion no controlada.'
    })
}

New-CollectorResult -Meta $meta -Records $records.ToArray() -Findings $findings.ToArray() `
    -Metrics $metrics -Gaps $gaps.ToArray()
