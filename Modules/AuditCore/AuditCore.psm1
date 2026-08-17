<#
    AuditCore.psm1
    Nucleo comun de la suite de auditoria de sistemas.

    Provee: contexto de ejecucion, logging, contrato de colectores,
    generacion de hallazgos, inventario base de software, verificacion
    de firmas Authenticode y exportacion de evidencia con integridad.

    NOTA DE CODIFICACION: este archivo se mantiene deliberadamente en ASCII
    (sin tildes ni caracteres especiales) porque Windows PowerShell 5.1
    interpreta los .ps1 sin BOM como ANSI y corromperia los acentos.
    Los textos de salida (HTML/CSV) se escriben siempre como UTF-8 con BOM.
#>

$script:AuditContext   = $null
$script:SignatureCache = @{}

# ---------------------------------------------------------------------------
# Contexto de ejecucion
# ---------------------------------------------------------------------------

function Initialize-AuditContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RootPath,
        [string]$OutputRoot,
        [string]$LogRoot,
        [string]$RunId,
        [hashtable]$Config
    )

    if (-not $RunId)      { $RunId      = (Get-Date -Format 'yyyyMMdd-HHmmss') }
    if (-not $OutputRoot) { $OutputRoot = Join-Path $RootPath 'Output' }
    if (-not $LogRoot)    { $LogRoot    = Join-Path $RootPath 'Logs' }

    $runPath = Join-Path $OutputRoot $RunId
    foreach ($d in @($runPath,
                     (Join-Path $runPath 'raw'),
                     (Join-Path $runPath 'csv'),
                     (Join-Path $runPath 'evidence'),
                     $LogRoot)) {
        if (-not (Test-Path -LiteralPath $d)) {
            New-Item -ItemType Directory -Path $d -Force | Out-Null
        }
    }

    $script:AuditContext = [pscustomobject]@{
        RunId        = $RunId
        RootPath     = $RootPath
        RunPath      = $runPath
        RawPath      = Join-Path $runPath 'raw'
        CsvPath      = Join-Path $runPath 'csv'
        EvidencePath = Join-Path $runPath 'evidence'
        LogFile      = Join-Path $LogRoot ("audit-{0}.log" -f $RunId)
        StartTime    = Get-Date
        Hostname     = $env:COMPUTERNAME
        Domain       = $env:USERDNSDOMAIN
        RunAs        = "$env:USERDOMAIN\$env:USERNAME"
        IsAdmin      = (Test-IsAdministrator)
        Config       = $Config
        Findings     = New-Object System.Collections.ArrayList
        Metrics      = @{}
        Artifacts    = New-Object System.Collections.ArrayList
    }

    Write-AuditLog -Level INFO -Message ("Contexto inicializado. RunId={0} Host={1} Admin={2}" -f `
        $RunId, $script:AuditContext.Hostname, $script:AuditContext.IsAdmin)

    return $script:AuditContext
}

function Get-AuditContext {
    if (-not $script:AuditContext) {
        throw "El contexto de auditoria no ha sido inicializado. Ejecute Initialize-AuditContext primero."
    }
    return $script:AuditContext
}

function Test-IsAdministrator {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return ([Security.Principal.WindowsPrincipal]$id).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

function Write-AuditLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('DEBUG','INFO','WARN','ERROR','OK')][string]$Level = 'INFO',
        [string]$Source = 'CORE',
        [switch]$Quiet
    )

    $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line  = "{0} [{1,-5}] [{2}] {3}" -f $stamp, $Level, $Source, $Message

    if ($script:AuditContext -and $script:AuditContext.LogFile) {
        try {
            Add-Content -LiteralPath $script:AuditContext.LogFile -Value $line -Encoding UTF8
        } catch { }
    }

    if ($Quiet) { return }

    $color = switch ($Level) {
        'DEBUG' { 'DarkGray' }
        'INFO'  { 'Gray' }
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
        'OK'    { 'Green' }
    }
    Write-Host $line -ForegroundColor $color
}

# ---------------------------------------------------------------------------
# Contrato de colectores
# ---------------------------------------------------------------------------

function New-CollectorResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Meta,
        [object[]]$Records  = @(),
        [object[]]$Findings = @(),
        [hashtable]$Metrics = @{},
        [string]$Status     = 'Completed',
        [string[]]$Gaps     = @()
    )

    return [pscustomobject]@{
        Meta        = [pscustomobject]$Meta
        Status      = $Status
        Records     = @($Records)
        RecordCount = @($Records).Count
        Findings    = @($Findings)
        Metrics     = $Metrics
        Gaps        = @($Gaps)   # brechas de evidencia (p.ej. requiere admin)
        CollectedAt = Get-Date
    }
}

function New-AuditFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CollectorId,
        [Parameter(Mandatory)][string]$Layer,
        [Parameter(Mandatory)]
        [ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity,
        [Parameter(Mandatory)][string]$Title,
        [string]$Asset          = '',
        [string]$Detail         = '',
        [string]$Evidence       = '',
        [string[]]$Criterios    = @(),
        [string]$Recommendation = '',
        [string]$Category       = 'Configuracion'
    )

    $hashSeed = "$CollectorId|$Title|$Asset"
    $fid = '{0}-{1}' -f $CollectorId, (Get-ShortHash -Text $hashSeed)

    return [pscustomobject]@{
        FindingId      = $fid
        CollectorId    = $CollectorId
        Layer          = $Layer
        Severity       = $Severity
        SeverityRank   = (Get-SeverityRank -Severity $Severity)
        Category       = $Category
        Title          = $Title
        Asset          = $Asset
        Detail         = $Detail
        Evidence       = $Evidence
        Criterios      = @($Criterios | Select-Object -Unique)
        CriteriosTexto = (@($Criterios | Select-Object -Unique) -join '; ')
        Recommendation = $Recommendation
        Host           = $env:COMPUTERNAME
        DetectedAt     = (Get-Date).ToString('s')
    }
}

function Get-SeverityRank {
    param([string]$Severity)
    switch ($Severity) {
        'Critical' { 5 } 'High' { 4 } 'Medium' { 3 } 'Low' { 2 } default { 1 }
    }
}

function Get-ShortHash {
    param([Parameter(Mandatory)][string]$Text)
    $sha = [System.Security.Cryptography.SHA1]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))
        return ([System.BitConverter]::ToString($bytes) -replace '-','').Substring(0,8)
    } finally { $sha.Dispose() }
}

# ---------------------------------------------------------------------------
# Utilidades de sistema
# ---------------------------------------------------------------------------

function Test-CommandExists {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

<#
    Ejecuta un binario nativo capturando stdout/stderr con timeout duro.
    Evita el patron "2>&1" que en PS 5.1 marca $? como falso aun con exit 0.
#>
function Invoke-NativeCapture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments = @(),
        [int]$TimeoutSec = 60
    )

    $result = [pscustomobject]@{
        FilePath = $FilePath
        ExitCode = $null
        StdOut   = ''
        StdErr   = ''
        TimedOut = $false
        Failed   = $false
        Error    = ''
    }

    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName               = $FilePath
        $psi.Arguments              = ($Arguments -join ' ')
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.UseShellExecute        = $false
        $psi.CreateNoWindow         = $true

        $proc = [System.Diagnostics.Process]::Start($psi)
        $outTask = $proc.StandardOutput.ReadToEndAsync()
        $errTask = $proc.StandardError.ReadToEndAsync()

        if (-not $proc.WaitForExit($TimeoutSec * 1000)) {
            try { $proc.Kill() } catch { }
            $result.TimedOut = $true
            $result.Failed   = $true
            $result.Error    = "Timeout tras $TimeoutSec s"
            return $result
        }

        $result.StdOut   = $outTask.Result
        $result.StdErr   = $errTask.Result
        $result.ExitCode = $proc.ExitCode
        if ($proc.ExitCode -ne 0) { $result.Failed = $true }
    }
    catch {
        $result.Failed = $true
        $result.Error  = $_.Exception.Message
    }

    return $result
}

<#
    Firma Authenticode con cache. Es la operacion mas cara del inventario de
    software, por eso se memoiza por ruta.
#>
function Get-SignatureInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$IncludeHash
    )

    $key = $Path.ToLowerInvariant()
    if ($script:SignatureCache.ContainsKey($key)) { return $script:SignatureCache[$key] }

    $info = [pscustomobject]@{
        Path          = $Path
        Exists        = $false
        SignatureStatus = 'NotChecked'
        Signer        = ''
        SignerIsMS    = $false
        TimeStamped   = $false
        SHA256        = ''
        SizeKB        = 0
        FileVersion   = ''
        ProductName   = ''
        Company       = ''
        LastWriteTime = $null
    }

    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            $script:SignatureCache[$key] = $info
            return $info
        }
        $info.Exists = $true

        $fi = Get-Item -LiteralPath $Path -ErrorAction Stop
        $info.SizeKB        = [math]::Round($fi.Length / 1KB, 1)
        $info.LastWriteTime = $fi.LastWriteTime

        $vi = $fi.VersionInfo
        if ($vi) {
            $info.FileVersion = [string]$vi.FileVersion
            $info.ProductName = [string]$vi.ProductName
            $info.Company     = [string]$vi.CompanyName
        }

        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $info.SignatureStatus = [string]$sig.Status
        if ($sig.SignerCertificate) {
            $info.Signer      = [string]$sig.SignerCertificate.Subject
            $info.SignerIsMS  = ($info.Signer -match 'O=Microsoft Corporation')
        }
        $info.TimeStamped = [bool]$sig.TimeStamperCertificate

        if ($IncludeHash) {
            $info.SHA256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
        }
    }
    catch {
        $info.SignatureStatus = 'Error'
    }

    $script:SignatureCache[$key] = $info
    return $info
}

function Get-NormalizedVersion {
    param([string]$Version)
    if ([string]::IsNullOrWhiteSpace($Version)) { return $null }
    $m = [regex]::Match($Version, '^\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?')
    if (-not $m.Success) { return $null }
    $parts = @(1,2,3,4) | ForEach-Object {
        if ($m.Groups[$_].Success -and $m.Groups[$_].Value -ne '') { [int]$m.Groups[$_].Value } else { 0 }
    }
    try { return New-Object System.Version($parts[0], $parts[1], $parts[2], $parts[3]) }
    catch { return $null }
}

function ConvertTo-SafeString {
    param($Value, [int]$MaxLength = 4000)
    if ($null -eq $Value) { return '' }
    $s = [string]$Value
    $s = $s -replace '[\r\n\t]+', ' '
    if ($s.Length -gt $MaxLength) { $s = $s.Substring(0, $MaxLength) + '...' }
    return $s.Trim()
}

# ---------------------------------------------------------------------------
# Inventario base de software (fuente compartida por varios colectores)
# ---------------------------------------------------------------------------

<#
    Lee las claves Uninstall del registro en las vistas de 64 y 32 bits,
    ademas de los perfiles de usuario cargados en HKU.

    Se evita deliberadamente Win32_Product / Get-CimInstance Win32_Product:
    esa clase dispara una reconfiguracion de consistencia MSI en cada paquete,
    es lenta y puede alterar el estado del servidor auditado.
#>
function Get-InstalledSoftwareRaw {
    [CmdletBinding()]
    param()

    $paths = @(
        @{ Scope = 'Machine-x64'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' },
        @{ Scope = 'Machine-x86'; Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' },
        @{ Scope = 'User-Current'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' }
    )

    # Perfiles de usuario cargados en HKEY_USERS (excluye clases y cuentas de servicio)
    try {
        if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
            New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Script -ErrorAction Stop | Out-Null
        }
        Get-ChildItem 'HKU:\' -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } |
            ForEach-Object {
                $paths += @{ Scope = "User-$($_.PSChildName)"
                             Path  = "HKU:\$($_.PSChildName)\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" }
            }
    } catch { }

    $items = New-Object System.Collections.ArrayList

    foreach ($p in $paths) {
        try {
            $entries = Get-ItemProperty -Path $p.Path -ErrorAction SilentlyContinue
        } catch { continue }

        foreach ($e in $entries) {
            if (-not $e) { continue }
            $name = $e.DisplayName
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            # Excluir parches/actualizaciones marcados como componentes del sistema
            if ($e.PSObject.Properties['SystemComponent'] -and $e.SystemComponent -eq 1) { continue }

            $installDate = $null
            if ($e.PSObject.Properties['InstallDate'] -and $e.InstallDate) {
                try { $installDate = [datetime]::ParseExact([string]$e.InstallDate, 'yyyyMMdd', $null) } catch { }
            }

            $sizeMB = 0
            if ($e.PSObject.Properties['EstimatedSize'] -and $e.EstimatedSize) {
                $sizeMB = [math]::Round(([double]$e.EstimatedSize) / 1024, 1)
            }

            $keyName = $e.PSChildName
            $isMsi   = ($keyName -match '^\{[0-9A-Fa-f-]{36}\}$')

            $null = $items.Add([pscustomobject]@{
                DisplayName     = ConvertTo-SafeString $name 256
                DisplayVersion  = ConvertTo-SafeString $e.DisplayVersion 64
                Publisher       = ConvertTo-SafeString $e.Publisher 128
                InstallDate     = $installDate
                InstallLocation = ConvertTo-SafeString $e.InstallLocation 512
                UninstallString = ConvertTo-SafeString $e.UninstallString 512
                DisplayIcon     = ConvertTo-SafeString $e.DisplayIcon 512
                Comments        = ConvertTo-SafeString $e.Comments 512
                Contact         = ConvertTo-SafeString $e.Contact 128
                URLInfoAbout    = ConvertTo-SafeString $e.URLInfoAbout 256
                EstimatedSizeMB = $sizeMB
                Scope           = $p.Scope
                Architecture    = $(if ($p.Scope -eq 'Machine-x86') { 'x86' } elseif ($p.Scope -like 'Machine*') { 'x64' } else { 'user' })
                RegistryKey     = $keyName
                PackageType     = $(if ($isMsi) { 'MSI' } else { 'EXE/Otro' })
                HelpLink        = ConvertTo-SafeString $e.HelpLink 256
                Source          = 'Registry:Uninstall'
            })
        }
    }

    return $items.ToArray()
}

# ---------------------------------------------------------------------------
# Arquitectura empresarial: resolucion de rutas, descripcion y rol
# ---------------------------------------------------------------------------

<#
    Determina la ruta real de instalacion de un artefacto aplicando una cascada
    de fuentes, porque InstallLocation esta vacio en buena parte de los paquetes:
      1. InstallLocation declarado en el registro
      2. Directorio extraido de UninstallString
      3. Directorio extraido de DisplayIcon
      4. Directorio del ejecutable principal si se conoce

    Devuelve la ruta y el origen del que se obtuvo, para que el auditor sepa
    que tan confiable es el dato.
#>
function Resolve-InstallPath {
    [CmdletBinding()]
    param(
        [string]$InstallLocation,
        [string]$UninstallString,
        [string]$DisplayIcon,
        [string]$ExecutablePath
    )

    $resultado = [pscustomobject]@{
        Ruta       = ''
        Origen     = 'No determinada'
        Verificada = $false
    }

    function Get-DirectorioDe {
        param([string]$Cadena)
        if ([string]::IsNullOrWhiteSpace($Cadena)) { return '' }

        $s = $Cadena.Trim()
        # MSI: no hay ruta util en la cadena de desinstalacion
        if ($s -match '(?i)^msiexec') { return '' }

        # Ruta entrecomillada
        if ($s -match '^"([^"]+)"') { $exe = $Matches[1] }
        else {
            # Recorta argumentos y el indice de icono (ruta,0)
            $m = [regex]::Match($s, '^([A-Za-z]:\\[^,]*?\.(exe|dll|ico))', 'IgnoreCase')
            if ($m.Success) { $exe = $m.Groups[1].Value }
            else { $exe = ($s -split ',')[0].Trim() }
        }

        $exe = [Environment]::ExpandEnvironmentVariables($exe)
        if ([string]::IsNullOrWhiteSpace($exe)) { return '' }

        try {
            if (Test-Path -LiteralPath $exe -PathType Container) { return $exe }
            $dir = Split-Path -Path $exe -Parent -ErrorAction Stop
            if ($dir) { return $dir }
        } catch { }
        return ''
    }

    $candidatos = @(
        @{ Valor = $InstallLocation; Origen = 'Registro: InstallLocation'; Directo = $true }
        @{ Valor = $ExecutablePath;  Origen = 'Binario en ejecucion';      Directo = $false }
        @{ Valor = $DisplayIcon;     Origen = 'Registro: DisplayIcon';     Directo = $false }
        @{ Valor = $UninstallString; Origen = 'Registro: UninstallString'; Directo = $false }
    )

    foreach ($c in $candidatos) {
        if ([string]::IsNullOrWhiteSpace($c.Valor)) { continue }

        $ruta = if ($c.Directo) {
            [Environment]::ExpandEnvironmentVariables($c.Valor.Trim().TrimEnd('\'))
        } else {
            Get-DirectorioDe -Cadena $c.Valor
        }

        if ([string]::IsNullOrWhiteSpace($ruta)) { continue }

        $existe = $false
        try { $existe = Test-Path -LiteralPath $ruta -PathType Container } catch { }

        # Una ruta que existe se acepta de inmediato; una que no, se guarda como
        # mejor esfuerzo y se sigue buscando una verificable.
        if ($existe) {
            $resultado.Ruta = $ruta; $resultado.Origen = $c.Origen; $resultado.Verificada = $true
            return $resultado
        }
        elseif (-not $resultado.Ruta) {
            $resultado.Ruta = $ruta
            $resultado.Origen = "$($c.Origen) (no verificada)"
        }
    }

    return $resultado
}

<#
    Obtiene la descripcion funcional de un artefacto aplicando una cascada:
      1. Catalogo de aplicaciones declarado por el arquitecto (autoridad maxima)
      2. Campo Comments del registro de desinstalacion
      3. FileDescription / ProductName del binario principal
      4. Descripcion generica del rol arquitectonico asignado
#>
function Get-SoftwareDescription {
    [CmdletBinding()]
    param(
        [string]$Comments,
        [string]$InstallPath,
        [string]$ExecutablePath,
        [string]$RoleDescription,
        [string]$CatalogDescription
    )

    # El catalogo describe la APLICACION; para el artefacto individual una
    # descripcion propia (registro o binario) es siempre mas informativa, por lo
    # que el catalogo actua como respaldo y no como primera opcion.
    if (-not [string]::IsNullOrWhiteSpace($Comments)) {
        return [pscustomobject]@{ Texto = (ConvertTo-SafeString $Comments 400); Origen = 'Registro: Comments' }
    }

    # Metadatos del binario principal
    $exe = $ExecutablePath
    if ([string]::IsNullOrWhiteSpace($exe) -and -not [string]::IsNullOrWhiteSpace($InstallPath)) {
        try {
            if (Test-Path -LiteralPath $InstallPath -PathType Container) {
                $cand = Get-ChildItem -LiteralPath $InstallPath -Filter '*.exe' -File -ErrorAction SilentlyContinue |
                        Sort-Object Length -Descending | Select-Object -First 1
                if ($cand) { $exe = $cand.FullName }
            }
        } catch { }
    }

    if (-not [string]::IsNullOrWhiteSpace($exe)) {
        try {
            if (Test-Path -LiteralPath $exe -PathType Leaf) {
                $vi = (Get-Item -LiteralPath $exe -ErrorAction Stop).VersionInfo
                $txt = ''
                if ($vi.FileDescription) { $txt = [string]$vi.FileDescription }
                elseif ($vi.ProductName)  { $txt = [string]$vi.ProductName }
                if (-not [string]::IsNullOrWhiteSpace($txt)) {
                    return [pscustomobject]@{ Texto = (ConvertTo-SafeString $txt 400); Origen = 'Metadatos del binario' }
                }
            }
        } catch { }
    }

    if (-not [string]::IsNullOrWhiteSpace($CatalogDescription)) {
        return [pscustomobject]@{ Texto = $CatalogDescription; Origen = 'Catalogo de arquitectura' }
    }
    if (-not [string]::IsNullOrWhiteSpace($RoleDescription)) {
        return [pscustomobject]@{ Texto = $RoleDescription; Origen = 'Rol arquitectonico (generico)' }
    }

    return [pscustomobject]@{ Texto = ''; Origen = 'Sin descripcion' }
}

<#
    Clasifica un artefacto dentro de la taxonomia de roles arquitectonicos.
    Evalua el catalogo de aplicaciones primero (autoridad maxima) y luego los
    patrones de la taxonomia en el orden declarado.
#>
function Get-ArchitectureRole {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Nombre,
        [string]$Publicador = '',
        [string]$Ruta = '',
        [Parameter(Mandatory)][hashtable]$Arquitectura
    )

    $sujeto = "$Nombre $Publicador $Ruta"

    # 1. Catalogo de aplicaciones de negocio
    foreach ($app in @($Arquitectura.Aplicaciones)) {
        if ([string]::IsNullOrWhiteSpace($app.Patron)) { continue }
        if ($sujeto -match $app.Patron) {
            return [pscustomobject]@{
                RolId            = [string]$app.Rol
                RolNombre        = 'Aplicacion de negocio'
                CapaEA           = [string]$app.CapaEA
                RolDescripcion   = [string]$app.Descripcion
                EnCatalogo       = $true
                AplicacionId     = [string]$app.Id
                AplicacionNombre = [string]$app.Nombre
                Propietario      = [string]$app.Propietario
                Criticidad       = [string]$app.Criticidad
                Autorizado       = [bool]$app.Autorizado
                Origen           = 'Catalogo de aplicaciones'
            }
        }
    }

    # 2. Taxonomia de roles
    foreach ($rol in @($Arquitectura.Roles)) {
        if ([string]::IsNullOrWhiteSpace($rol.Patron)) { continue }
        if ($sujeto -match $rol.Patron) {
            return [pscustomobject]@{
                RolId            = [string]$rol.Id
                RolNombre        = [string]$rol.Nombre
                CapaEA           = [string]$rol.CapaEA
                RolDescripcion   = [string]$rol.Descripcion
                EnCatalogo       = $false
                AplicacionId     = ''
                AplicacionNombre = ''
                Propietario      = ''
                Criticidad       = ''
                Autorizado       = $null
                Origen           = 'Taxonomia de roles'
            }
        }
    }

    # 3. Sin clasificar
    $def = $Arquitectura.RolPorDefecto
    return [pscustomobject]@{
        RolId            = [string]$def.Id
        RolNombre        = [string]$def.Nombre
        CapaEA           = [string]$def.CapaEA
        RolDescripcion   = [string]$def.Descripcion
        EnCatalogo       = $false
        AplicacionId     = ''
        AplicacionNombre = ''
        Propietario      = ''
        Criticidad       = ''
        Autorizado       = $null
        Origen           = 'Sin coincidencia'
    }
}

# ---------------------------------------------------------------------------
# Exportacion de evidencia
# ---------------------------------------------------------------------------

function Write-Utf8File {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content
    )
    $enc = New-Object System.Text.UTF8Encoding($true)
    [System.IO.File]::WriteAllText($Path, $Content, $enc)
}

function Export-AuditArtifact {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Data,
        [Parameter(Mandatory)][string]$Name,
        [ValidateSet('Json','Csv','Both')][string]$Format = 'Both',
        [int]$JsonDepth = 6
    )

    $ctx     = Get-AuditContext
    $written = @()

    if (@($Data).Count -eq 0) { $Data = @() }

    if ($Format -in @('Json','Both')) {
        $jsonPath = Join-Path $ctx.RawPath "$Name.json"
        try {
            $json = $Data | ConvertTo-Json -Depth $JsonDepth
            if ($null -eq $json) { $json = '[]' }
            Write-Utf8File -Path $jsonPath -Content $json
            $written += $jsonPath
        } catch {
            Write-AuditLog -Level WARN -Source 'EXPORT' -Message "No se pudo escribir JSON '$Name': $($_.Exception.Message)"
        }
    }

    if ($Format -in @('Csv','Both')) {
        $csvPath = Join-Path $ctx.CsvPath "$Name.csv"
        try {
            if (@($Data).Count -gt 0) {
                # Aplanar arrays para que el CSV sea legible
                $flat = $Data | ForEach-Object {
                    $o = $_ | Select-Object *
                    foreach ($prop in @($o.PSObject.Properties)) {
                        if ($prop.Value -is [System.Array]) {
                            $prop.Value = ($prop.Value -join '; ')
                        }
                    }
                    $o
                }
                $flat | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
            } else {
                Write-Utf8File -Path $csvPath -Content ''
            }
            $written += $csvPath
        } catch {
            Write-AuditLog -Level WARN -Source 'EXPORT' -Message "No se pudo escribir CSV '$Name': $($_.Exception.Message)"
        }
    }

    foreach ($f in $written) {
        # PS 5.1 no admite try/catch como expresion: se calcula antes de construir el objeto.
        $sha = ''
        $len = 0
        try { $sha = (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash } catch { }
        try { $len = (Get-Item -LiteralPath $f).Length } catch { }

        $null = $ctx.Artifacts.Add([pscustomobject]@{
            File   = Split-Path $f -Leaf
            Path   = $f
            SHA256 = $sha
            Bytes  = $len
        })
    }

    return $written
}

Export-ModuleMember -Function @(
    'Initialize-AuditContext','Get-AuditContext','Test-IsAdministrator',
    'Write-AuditLog','New-CollectorResult','New-AuditFinding','Get-SeverityRank',
    'Get-ShortHash','Test-CommandExists','Invoke-NativeCapture','Get-SignatureInfo',
    'Get-NormalizedVersion','ConvertTo-SafeString','Get-InstalledSoftwareRaw',
    'Export-AuditArtifact','Write-Utf8File',
    'Resolve-InstallPath','Get-SoftwareDescription','Get-ArchitectureRole'
)
