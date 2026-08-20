<#
    L4-01_Installed-Software.ps1
    Capa L4 - ARTEFACTOS DE SOFTWARE (capa prioritaria de esta auditoria).

    Inventario consolidado, normalizado y ENRIQUECIDO de todo el software
    instalado mediante mecanismos gestionados. Cada artefacto se acompana de:
      - Descripcion funcional (cascada catalogo -> registro -> binario -> rol)
      - Ruta de instalacion resuelta y verificada
      - Rol arquitectonico y capa de arquitectura empresarial
      - Propietario y criticidad cuando el catalogo los declara

    Criterios de auditoria -> INV-01, SW-03, INV-03, DAT-02, DAT-02, CAM-01
    Auditoria de sistemas -> linea base de arquitectura empresarial
#>
param([switch]$Manifest, [hashtable]$Config, [hashtable]$Arquitectura)

$meta = @{
    Id            = 'L4-01'
    Nombre        = 'Inventario consolidado de software instalado'
    Layer         = 'L4'
    Criterios     = @('INV-01','SW-03','INV-03','DAT-02','CAM-01')
    RequiereAdmin = $false
    Descripcion   = 'Inventario normalizado con descripcion funcional, ruta de instalacion, rol arquitectonico y deteccion de software no permitido.'
}
if ($Manifest) { return [pscustomobject]$meta }

$records  = New-Object System.Collections.ArrayList
$findings = New-Object System.Collections.ArrayList
$gaps     = New-Object System.Collections.ArrayList
$metrics  = @{}

# ---------------------------------------------------------------------------
# 0. Indice de binarios en ejecucion, para resolver rutas que el registro omite
# ---------------------------------------------------------------------------
$rutasProceso = @{}
try {
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
        $ruta = $null
        try { $ruta = $p.Path } catch { }
        if ($ruta) {
            $clave = $p.ProcessName.ToLowerInvariant()
            if (-not $rutasProceso.ContainsKey($clave)) { $rutasProceso[$clave] = $ruta }
        }
    }
} catch { }

function Find-ExecutablePath {
    param([string]$Nombre)
    if ([string]::IsNullOrWhiteSpace($Nombre)) { return '' }
    # Primer token significativo del nombre del producto
    $token = ($Nombre -split '[\s\-_]+' | Where-Object { $_.Length -ge 4 } | Select-Object -First 1)
    if (-not $token) { return '' }
    $t = $token.ToLowerInvariant()
    foreach ($k in $rutasProceso.Keys) {
        if ($k -eq $t -or $k -like "$t*") { return $rutasProceso[$k] }
    }
    return ''
}

# ---------------------------------------------------------------------------
# 1. Registro de desinstalacion (fuente principal, todas las vistas)
# ---------------------------------------------------------------------------
$crudo = @()
try {
    $crudo = @(Get-InstalledSoftwareRaw)
} catch {
    $null = $gaps.Add("Lectura del registro de desinstalacion fallida: $($_.Exception.Message)")
}

$vistos = @{}
foreach ($s in $crudo) {
    $clave = ("{0}|{1}" -f $s.DisplayName.ToLowerInvariant(), $s.DisplayVersion)
    if ($vistos.ContainsKey($clave)) {
        $vistos[$clave].Ambitos += ";$($s.Scope)"
        continue
    }

    # --- Resolucion de ruta de instalacion ---
    $exeProceso = Find-ExecutablePath -Nombre $s.DisplayName
    $ruta = Resolve-InstallPath -InstallLocation $s.InstallLocation `
                                -UninstallString $s.UninstallString `
                                -DisplayIcon $s.DisplayIcon `
                                -ExecutablePath $exeProceso

    # --- Clasificacion arquitectonica ---
    $rol = Get-ArchitectureRole -Nombre $s.DisplayName -Publicador $s.Publisher `
                                -Ruta $ruta.Ruta -Arquitectura $Arquitectura

    # --- Descripcion funcional ---
    $desc = Get-SoftwareDescription -Comments $s.Comments -InstallPath $ruta.Ruta `
                                    -ExecutablePath $exeProceso `
                                    -RoleDescription $rol.RolDescripcion `
                                    -CatalogDescription $(if ($rol.EnCatalogo) { $rol.RolDescripcion } else { '' })

    $vistos[$clave] = [pscustomobject]@{
        Nombre           = $s.DisplayName
        Version          = $s.DisplayVersion
        Descripcion      = $desc.Texto
        OrigenDescripcion= $desc.Origen
        RutaInstalacion  = $ruta.Ruta
        RutaVerificada   = $ruta.Verificada
        OrigenRuta       = $ruta.Origen
        RolArquitectonico= $rol.RolNombre
        RolId            = $rol.RolId
        CapaEA           = $rol.CapaEA
        AplicacionNegocio= $rol.AplicacionNombre
        Propietario      = $rol.Propietario
        Criticidad       = $rol.Criticidad
        EnCatalogoEA     = $rol.EnCatalogo
        Publicador       = $s.Publisher
        FechaInstalacion = if ($s.InstallDate) { $s.InstallDate.ToString('yyyy-MM-dd') } else { '' }
        DiasDesdeInstalacion = if ($s.InstallDate) { ((Get-Date) - $s.InstallDate).Days } else { $null }
        Arquitectura     = $s.Architecture
        TipoPaquete      = $s.PackageType
        TamanoMB         = $s.EstimatedSizeMB
        Ambitos          = $s.Scope
        Origen           = 'Registry:Uninstall'
        ClaveRegistro    = $s.RegistryKey
        Soporte          = $s.URLInfoAbout
        Riesgo           = ''
        CategoriaRiesgo  = ''
    }
}

# ---------------------------------------------------------------------------
# 2. Paquetes Appx / MSIX
# ---------------------------------------------------------------------------
try {
    $appx = Get-AppxPackage -ErrorAction Stop | Where-Object { -not $_.IsFramework }
    foreach ($a in $appx) {
        $clave = ("{0}|{1}" -f $a.Name.ToLowerInvariant(), $a.Version)
        if ($vistos.ContainsKey($clave)) { continue }

        $rol = Get-ArchitectureRole -Nombre $a.Name -Publicador ([string]$a.Publisher) `
                                    -Ruta ([string]$a.InstallLocation) -Arquitectura $Arquitectura

        $vistos[$clave] = [pscustomobject]@{
            Nombre           = $a.Name
            Version          = [string]$a.Version
            Descripcion      = $rol.RolDescripcion
            OrigenDescripcion= 'Rol arquitectonico (generico)'
            RutaInstalacion  = [string]$a.InstallLocation
            RutaVerificada   = $true
            OrigenRuta       = 'Appx: InstallLocation'
            RolArquitectonico= $rol.RolNombre
            RolId            = $rol.RolId
            CapaEA           = $rol.CapaEA
            AplicacionNegocio= $rol.AplicacionNombre
            Propietario      = $rol.Propietario
            Criticidad       = $rol.Criticidad
            EnCatalogoEA     = $rol.EnCatalogo
            Publicador       = [string]$a.Publisher
            FechaInstalacion = ''
            DiasDesdeInstalacion = $null
            Arquitectura     = [string]$a.Architecture
            TipoPaquete      = 'Appx/MSIX'
            TamanoMB         = 0
            Ambitos          = 'Appx'
            Origen           = 'Get-AppxPackage'
            ClaveRegistro    = [string]$a.PackageFullName
            Soporte          = ''
            Riesgo           = ''
            CategoriaRiesgo  = ''
        }
    }
} catch {
    $null = $gaps.Add('Get-AppxPackage no disponible o sin resultados (habitual en Windows Server Core).')
}

# ---------------------------------------------------------------------------
# 3. Software no permitido en produccion (SW-03 / INV-03)
# ---------------------------------------------------------------------------
$reglas = if ($Config -and $Config.SoftwareNoPermitido) { $Config.SoftwareNoPermitido } else { @() }

foreach ($app in $vistos.Values) {
    foreach ($regla in $reglas) {
        if ($app.Nombre -match $regla.Patron -or $app.Publicador -match $regla.Patron) {
            $app.Riesgo          = $regla.Severidad
            $app.CategoriaRiesgo = $regla.Categoria

            $criterios = switch -Regex ($regla.Categoria) {
                'nube'     { @('DAT-02','SW-03') ; break }
                'P2P'      { @('SW-03','DAT-02','INV-03') ; break }
                'remoto'   { @('SW-03','ACC-04','RED-01') ; break }
                'ofensiva' { @('SW-05','SW-03')          ; break }
                default    { @('SW-03','INV-03') }
            }

            $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                -Severity $regla.Severidad -Category 'SoftwareNoPermitido' `
                -Title ("Software fuera de politica instalado: {0}" -f $app.Nombre) `
                -Asset ("{0} {1}" -f $app.Nombre, $app.Version) `
                -Detail ("Categoria de riesgo: {0}. Publicador declarado: {1}. Rol arquitectonico: {2}. Este tipo de software no corresponde al perfil de un servidor de produccion y amplia la superficie de ataque o habilita canales de datos no controlados." -f $regla.Categoria, $app.Publicador, $app.RolArquitectonico) `
                -Evidence ("Ruta: {0} | Clave: {1}" -f $app.RutaInstalacion, $app.ClaveRegistro) `
                -Criterios $criterios `
                -Recommendation 'Validar la justificacion de negocio con el responsable del activo. De no existir autorizacion formal, desinstalar y registrar la desviacion como no conformidad frente a SW-03.'))
            break
        }
    }
}

# ---------------------------------------------------------------------------
# 4. Software sin publicador identificable
# ---------------------------------------------------------------------------
$sinPublicador = @($vistos.Values | Where-Object { [string]::IsNullOrWhiteSpace($_.Publicador) })
if ($sinPublicador.Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'Medium' -Category 'Procedencia' `
        -Title 'Software instalado sin publicador declarado' `
        -Asset ("{0} paquetes" -f $sinPublicador.Count) `
        -Detail ("Se identificaron {0} entradas sin campo Publisher. La ausencia de publicador impide verificar la procedencia del artefacto y su inclusion en el inventario autorizado." -f $sinPublicador.Count) `
        -Evidence (($sinPublicador | Select-Object -First 12 | ForEach-Object { "$($_.Nombre) [$($_.RutaInstalacion)]" }) -join '; ') `
        -Criterios @('INV-01','SW-03') `
        -Recommendation 'Documentar el origen de cada paquete y contrastarlo con la lista de software autorizado. Los artefactos sin origen verificable deben ser retirados o reinstalados desde una fuente confiable.'))
}

# ---------------------------------------------------------------------------
# 5. Artefactos sin ruta de instalacion determinable (brecha de linea base)
# ---------------------------------------------------------------------------
$sinRuta = @($vistos.Values | Where-Object { [string]::IsNullOrWhiteSpace($_.RutaInstalacion) })
$metrics['SinRutaDeterminada'] = $sinRuta.Count
if ($sinRuta.Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'Low' -Category 'LineaBaseEA' `
        -Title 'Artefactos sin ruta de instalacion determinable' `
        -Asset ("{0} paquetes" -f $sinRuta.Count) `
        -Detail ("No fue posible resolver la ubicacion fisica de {0} artefactos a partir de InstallLocation, UninstallString ni DisplayIcon. Sin ruta conocida no se puede verificar integridad, aplicar control de aplicaciones ni delimitar el respaldo." -f $sinRuta.Count) `
        -Evidence (($sinRuta | Select-Object -First 15 | ForEach-Object { $_.Nombre }) -join '; ') `
        -Criterios @('INV-01','SW-03') `
        -Recommendation 'Completar la ruta manualmente en el inventario de arquitectura para estos artefactos, o retirarlos si ya no estan efectivamente instalados.'))
}

# ---------------------------------------------------------------------------
# 6. Cambios recientes (trazabilidad de gestion de cambios, CAM-01)
# ---------------------------------------------------------------------------
$recientes = @($vistos.Values | Where-Object {
    $null -ne $_.DiasDesdeInstalacion -and $_.DiasDesdeInstalacion -le 30
} | Sort-Object DiasDesdeInstalacion)

$metrics['InstalacionesUltimos30Dias'] = $recientes.Count
if ($recientes.Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'Info' -Category 'GestionDeCambios' `
        -Title 'Instalaciones de software en los ultimos 30 dias' `
        -Asset ("{0} paquetes" -f $recientes.Count) `
        -Detail ("Se registraron {0} instalaciones o actualizaciones recientes. Cada una debe corresponder a un cambio aprobado y trazable." -f $recientes.Count) `
        -Evidence (($recientes | Select-Object -First 15 | ForEach-Object { "$($_.Nombre) $($_.Version) [$($_.FechaInstalacion)]" }) -join '; ') `
        -Criterios @('CAM-01','SW-03') `
        -Recommendation 'Contrastar esta lista contra los registros de cambio aprobados (RFC/tickets). Toda instalacion sin cambio asociado constituye una desviacion de SW-03.'))
}

# ---------------------------------------------------------------------------
# 7. Software potencialmente abandonado
# ---------------------------------------------------------------------------
$diasAbandono = 730
if ($Config -and $Config.Thresholds -and $Config.Thresholds.DiasSoftwareSinActualizar) {
    $diasAbandono = [int]$Config.Thresholds.DiasSoftwareSinActualizar
}
$antiguos = @($vistos.Values | Where-Object {
    $null -ne $_.DiasDesdeInstalacion -and $_.DiasDesdeInstalacion -gt $diasAbandono
})
if ($antiguos.Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'Low' -Category 'CicloDeVida' `
        -Title 'Software sin actualizacion desde hace mas de dos anios' `
        -Asset ("{0} paquetes" -f $antiguos.Count) `
        -Detail ("{0} paquetes no registran instalacion ni actualizacion en mas de {1} dias. Puede tratarse de software estable o de software abandonado sin mantenimiento de seguridad." -f $antiguos.Count, $diasAbandono) `
        -Evidence (($antiguos | Sort-Object DiasDesdeInstalacion -Descending | Select-Object -First 15 | ForEach-Object { "$($_.Nombre) $($_.Version) [$($_.FechaInstalacion)]" }) -join '; ') `
        -Criterios @('VUL-01','INV-01') `
        -Recommendation 'Verificar para cada paquete si existe una version soportada mas reciente y si el proveedor mantiene el producto. Ver tambien el colector L4-05 de ciclo de vida.'))
}

# ---------------------------------------------------------------------------
# Metricas
# ---------------------------------------------------------------------------
$inventario = @($vistos.Values | Sort-Object CapaEA, RolArquitectonico, Nombre)
$records    = $inventario

$metrics['TotalPaquetes']         = $inventario.Count
$metrics['PaquetesMSI']           = @($inventario | Where-Object { $_.TipoPaquete -eq 'MSI' }).Count
$metrics['PaquetesUsuario']       = @($inventario | Where-Object { $_.Ambitos -like 'User*' }).Count
$metrics['PaquetesSinPublicador'] = $sinPublicador.Count
$metrics['PaquetesEnRiesgo']      = @($inventario | Where-Object { $_.Riesgo }).Count
$metrics['PublicadoresDistintos'] = @($inventario | Where-Object { $_.Publicador } | Select-Object -ExpandProperty Publicador -Unique).Count
$metrics['ConRutaVerificada']     = @($inventario | Where-Object { $_.RutaVerificada }).Count
$metrics['ConDescripcion']        = @($inventario | Where-Object { $_.Descripcion }).Count
$metrics['SinClasificar']         = @($inventario | Where-Object { $_.RolId -eq 'SinClasificar' }).Count
$metrics['AplicacionesNegocio']   = @($inventario | Where-Object { $_.RolId -eq 'AplicacionNegocio' }).Count

New-CollectorResult -Meta $meta -Records $records -Findings $findings.ToArray() `
    -Metrics $metrics -Gaps $gaps.ToArray()
