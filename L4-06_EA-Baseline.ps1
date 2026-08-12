<#
    L4-06_EA-Baseline.ps1
    Capa L4 - ARTEFACTOS DE SOFTWARE.

    LINEA BASE DE ARQUITECTURA EMPRESARIAL Y CONFORMIDAD DE ROLES

    Este colector no busca vulnerabilidades: audita la ARQUITECTURA. Contrasta
    lo que el servidor ES contra lo que la organizacion DECLARO que deberia ser
    en Config\Arquitectura.psd1, y responde tres preguntas de auditoria de
    sistemas:

      1. Cada artefacto instalado, que rol cumple?
      2. Ese rol corresponde al proposito declarado de este servidor?
      3. Cada aplicacion de negocio tiene dueno, descripcion y ubicacion conocida?

    Correlaciona ademas cada artefacto con los servicios que ejecuta y los
    puertos que expone, para construir el mapa de la capa de aplicacion.

    Criterios de auditoria -> INV-01, SW-03, ARQ-01, INV-03, ARQ-03
    Auditoria de sistemas -> conformidad con la linea base de arquitectura
#>
param([switch]$Manifest, [hashtable]$Config, [hashtable]$Arquitectura)

$meta = @{
    Id            = 'L4-06'
    Nombre        = 'Linea base de arquitectura empresarial y conformidad de roles'
    Layer         = 'L4'
    Criterios     = @('INV-01','SW-03','ARQ-01','INV-03','ARQ-03')
    RequiereAdmin = $false
    Descripcion   = 'Clasifica cada artefacto por rol y capa de arquitectura, y evalua su alineacion con el rol declarado del servidor.'
}
if ($Manifest) { return [pscustomobject]$meta }

$records  = New-Object System.Collections.ArrayList
$findings = New-Object System.Collections.ArrayList
$gaps     = New-Object System.Collections.ArrayList
$metrics  = @{}

if (-not $Arquitectura -or -not $Arquitectura.RolServidor) {
    $null = $gaps.Add('No se cargo Config\Arquitectura.psd1; no es posible evaluar la linea base de arquitectura.')
    return New-CollectorResult -Meta $meta -Records @() -Findings @() -Metrics @{} `
        -Gaps $gaps.ToArray() -Status 'NoData'
}

$rolSrv  = $Arquitectura.RolServidor
$conf    = $Arquitectura.Conformidad
$sev     = $conf.Severidades

# ---------------------------------------------------------------------------
# 1. Indices de correlacion: servicios y puertos por ruta de binario
# ---------------------------------------------------------------------------
$serviciosPorRuta = @{}
try {
    foreach ($s in (Get-CimInstance Win32_Service -ErrorAction Stop)) {
        $pathName = [string]$s.PathName
        if (-not $pathName) { continue }
        $exe = ''
        if ($pathName -match '^\s*"([^"]+)"') { $exe = $Matches[1] }
        else {
            $m = [regex]::Match($pathName, '^\s*(\S+\.exe)', 'IgnoreCase')
            $exe = if ($m.Success) { $m.Groups[1].Value } else { ($pathName -split '\s+')[0] }
        }
        if (-not $exe) { continue }
        $exe = [Environment]::ExpandEnvironmentVariables($exe)
        $dir = ''
        try { $dir = (Split-Path -Path $exe -Parent).ToLowerInvariant() } catch { }
        if (-not $dir) { continue }

        if (-not $serviciosPorRuta.ContainsKey($dir)) {
            $serviciosPorRuta[$dir] = New-Object System.Collections.ArrayList
        }
        $null = $serviciosPorRuta[$dir].Add([pscustomobject]@{
            Nombre = $s.Name; Estado = $s.State; Inicio = $s.StartMode; Cuenta = $s.StartName
        })
    }
} catch { $null = $gaps.Add("No se pudieron enumerar servicios para correlacion: $($_.Exception.Message)") }

$puertosPorRuta = @{}
try {
    $procs = @{}
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
        $ruta = $null
        try { $ruta = $p.Path } catch { }
        if ($ruta) { $procs[$p.Id] = $ruta }
    }
    foreach ($c in (Get-NetTCPConnection -State Listen -ErrorAction Stop)) {
        $ruta = $procs[[int]$c.OwningProcess]
        if (-not $ruta) { continue }
        $dir = ''
        try { $dir = (Split-Path -Path $ruta -Parent).ToLowerInvariant() } catch { }
        if (-not $dir) { continue }
        if (-not $puertosPorRuta.ContainsKey($dir)) {
            $puertosPorRuta[$dir] = New-Object System.Collections.ArrayList
        }
        if ($puertosPorRuta[$dir] -notcontains $c.LocalPort) {
            $null = $puertosPorRuta[$dir].Add([int]$c.LocalPort)
        }
    }
} catch { $null = $gaps.Add('No se pudieron correlacionar puertos en escucha con rutas de binarios.') }

# ---------------------------------------------------------------------------
# 2. Construccion de la linea base: un registro por artefacto
# ---------------------------------------------------------------------------
$crudo = @()
try { $crudo = @(Get-InstalledSoftwareRaw) }
catch { $null = $gaps.Add("Inventario base no disponible: $($_.Exception.Message)") }

$appsDetectadas = @{}

foreach ($s in $crudo) {
    $ruta = Resolve-InstallPath -InstallLocation $s.InstallLocation `
                                -UninstallString $s.UninstallString `
                                -DisplayIcon $s.DisplayIcon

    $rol = Get-ArchitectureRole -Nombre $s.DisplayName -Publicador $s.Publisher `
                                -Ruta $ruta.Ruta -Arquitectura $Arquitectura

    $desc = Get-SoftwareDescription -Comments $s.Comments -InstallPath $ruta.Ruta `
                                    -RoleDescription $rol.RolDescripcion `
                                    -CatalogDescription $(if ($rol.EnCatalogo) { $rol.RolDescripcion } else { '' })

    # Correlacion con servicios y puertos
    $dirClave = if ($ruta.Ruta) { $ruta.Ruta.ToLowerInvariant().TrimEnd('\') } else { '' }
    $servicios = @()
    $puertos   = @()
    if ($dirClave) {
        foreach ($k in $serviciosPorRuta.Keys) {
            if ($k -eq $dirClave -or $k.StartsWith("$dirClave\")) {
                $servicios += @($serviciosPorRuta[$k] | ForEach-Object { "$($_.Nombre) [$($_.Estado)]" })
            }
        }
        foreach ($k in $puertosPorRuta.Keys) {
            if ($k -eq $dirClave -or $k.StartsWith("$dirClave\")) { $puertos += @($puertosPorRuta[$k]) }
        }
    }

    # Alineacion con el rol declarado del servidor
    $alineacion =
        if ($rol.RolId -eq 'SinClasificar')                  { 'Sin clasificar' }
        elseif ($rolSrv.RolesNoEsperados -contains $rol.RolId) { 'NO ALINEADO' }
        elseif ($rolSrv.RolesEsperados   -contains $rol.RolId) { 'Alineado' }
        else                                                 { 'Rol no declarado en la linea base' }

    $registro = [pscustomobject]@{
        Artefacto        = $s.DisplayName
        Version          = $s.DisplayVersion
        Descripcion      = $desc.Texto
        OrigenDescripcion= $desc.Origen
        RutaInstalacion  = $ruta.Ruta
        RutaVerificada   = $ruta.Verificada
        OrigenRuta       = $ruta.Origen
        CapaEA           = $rol.CapaEA
        RolArquitectonico= $rol.RolNombre
        RolId            = $rol.RolId
        Alineacion       = $alineacion
        AplicacionNegocio= $rol.AplicacionNombre
        EnCatalogoEA     = $rol.EnCatalogo
        Propietario      = $rol.Propietario
        Criticidad       = $rol.Criticidad
        Publicador       = $s.Publisher
        ServiciosAsociados = ($servicios -join '; ')
        PuertosExpuestos = (($puertos | Sort-Object -Unique) -join ', ')
        FechaInstalacion = if ($s.InstallDate) { $s.InstallDate.ToString('yyyy-MM-dd') } else { '' }
    }
    $null = $records.Add($registro)

    if ($rol.EnCatalogo -and $rol.AplicacionId) {
        if (-not $appsDetectadas.ContainsKey($rol.AplicacionId)) {
            $appsDetectadas[$rol.AplicacionId] = New-Object System.Collections.ArrayList
        }
        $null = $appsDetectadas[$rol.AplicacionId].Add($registro)
    }
}

# ---------------------------------------------------------------------------
# 3. Verificacion del catalogo: aplicaciones declaradas vs encontradas
# ---------------------------------------------------------------------------
$noEncontradas = New-Object System.Collections.ArrayList
foreach ($app in @($Arquitectura.Aplicaciones)) {
    $encontrada = $appsDetectadas.ContainsKey([string]$app.Id)

    # Segunda pasada: buscar el patron tambien en rutas de servicios y directorios
    if (-not $encontrada -and $app.Patron) {
        foreach ($k in $serviciosPorRuta.Keys) {
            if ($k -match $app.Patron) { $encontrada = $true; break }
        }
    }

    $null = $records.Add([pscustomobject]@{
        Artefacto        = "[CATALOGO] $($app.Nombre)"
        Version          = ''
        Descripcion      = [string]$app.Descripcion
        OrigenDescripcion= 'Catalogo de arquitectura'
        RutaInstalacion  = ''
        RutaVerificada   = $false
        OrigenRuta       = ''
        CapaEA           = [string]$app.CapaEA
        RolArquitectonico= 'Aplicacion de negocio (declarada)'
        RolId            = 'AplicacionNegocio'
        Alineacion       = $(if ($encontrada) { 'Declarada y detectada' } else { 'Declarada, NO detectada' })
        AplicacionNegocio= [string]$app.Nombre
        EnCatalogoEA     = $true
        Propietario      = [string]$app.Propietario
        Criticidad       = [string]$app.Criticidad
        Publicador       = ''
        ServiciosAsociados = ''
        PuertosExpuestos = ''
        FechaInstalacion = ''
    })

    if (-not $encontrada) { $null = $noEncontradas.Add($app) }
}

if ($noEncontradas.Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'Medium' -Category 'LineaBaseEA' `
        -Title 'Aplicaciones declaradas en el catalogo que no se detectaron en el servidor' `
        -Asset (($noEncontradas | ForEach-Object { $_.Id }) -join ', ') `
        -Detail ("El catalogo de arquitectura declara {0} aplicacion(es) que no fueron encontradas mediante el registro de desinstalacion ni las rutas de servicios. O la aplicacion no reside en este servidor, o su patron de deteccion esta mal definido, o se despliega por un mecanismo que el inventario gestionado no cubre (copia manual, contenedor, recurso de red)." -f $noEncontradas.Count) `
        -Evidence (($noEncontradas | ForEach-Object { "$($_.Id): patron '$($_.Patron)'" }) -join ' | ') `
        -Criterios @('INV-01','SW-03') `
        -Recommendation 'Confirmar con el responsable si la aplicacion reside efectivamente en este activo. Si reside, ajustar el patron de deteccion en Arquitectura.psd1 o ejecutar el colector L4-03 con la ruta de despliegue incluida en UnmanagedScan.Rutas.'))
}

# ---------------------------------------------------------------------------
# 4. Conformidad de roles con el proposito declarado del servidor
# ---------------------------------------------------------------------------
$artefactos = @($records | Where-Object { $_.Artefacto -notlike '`[CATALOGO`]*' })

$noAlineados = @($artefactos | Where-Object { $_.Alineacion -eq 'NO ALINEADO' })
if ($noAlineados.Count -gt 0) {
    $porRol = $noAlineados | Group-Object RolArquitectonico
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity $sev.RolNoEsperado -Category 'ConformidadArquitectonica' `
        -Title 'Artefactos con rol no alineado al proposito declarado del servidor' `
        -Asset ("{0} artefactos" -f $noAlineados.Count) `
        -Detail ("El servidor esta declarado como '{0}' en entorno de {1}. Se detectaron {2} artefactos cuyo rol arquitectonico figura entre los NO esperados para este proposito: {3}. Cada uno amplia la superficie de ataque sin aportar a la funcion del activo." -f `
            $rolSrv.RolDeclarado, $rolSrv.Entorno, $noAlineados.Count, (($porRol | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ', ')) `
        -Evidence (($noAlineados | Select-Object -First 15 | ForEach-Object { "$($_.Artefacto) [$($_.RolArquitectonico)] => $($_.RutaInstalacion)" }) -join ' | ') `
        -Criterios @('SW-03','ARQ-01','ARQ-03') `
        -Recommendation 'Para cada artefacto: documentar la justificacion funcional o retirarlo. Si el rol es legitimo para este servidor, incorporarlo a RolesEsperados en Arquitectura.psd1 y dejar constancia de la decision arquitectonica.'))
}

$rolNoDeclarado = @($artefactos | Where-Object { $_.Alineacion -eq 'Rol no declarado en la linea base' })
if ($rolNoDeclarado.Count -gt 0) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'Low' -Category 'LineaBaseEA' `
        -Title 'Roles presentes que la linea base no clasifica como esperados ni prohibidos' `
        -Asset ("{0} artefactos" -f $rolNoDeclarado.Count) `
        -Detail 'Estos artefactos fueron clasificados por la taxonomia, pero su rol no figura ni en RolesEsperados ni en RolesNoEsperados del rol declarado del servidor. La linea base esta incompleta para ellos.' `
        -Evidence ((@($rolNoDeclarado | Group-Object RolArquitectonico) | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ' | ') `
        -Criterios @('INV-01','ARQ-01') `
        -Recommendation 'Completar RolesEsperados / RolesNoEsperados en Arquitectura.psd1 para que la linea base cubra el 100% de los roles presentes.'))
}

# ---------------------------------------------------------------------------
# 5. Aplicaciones de negocio no catalogadas
# ---------------------------------------------------------------------------
if ($conf.ExigirCatalogoCompleto) {
    $negocioSinCatalogo = @($artefactos | Where-Object {
        $_.RolId -eq 'AplicacionNegocio' -and -not $_.EnCatalogoEA
    })
    if ($negocioSinCatalogo.Count -gt 0) {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity $sev.AplicacionNoCatalogada -Category 'LineaBaseEA' `
            -Title 'Aplicaciones de negocio detectadas que no figuran en el catalogo de arquitectura' `
            -Asset ("{0} aplicaciones" -f $negocioSinCatalogo.Count) `
            -Detail 'Estas aplicaciones cumplen un rol de negocio pero no estan declaradas en el catalogo, por lo que carecen de propietario, criticidad y clasificacion de datos formalmente asignados.' `
            -Evidence (($negocioSinCatalogo | Select-Object -First 15 | ForEach-Object { "$($_.Artefacto) => $($_.RutaInstalacion)" }) -join ' | ') `
            -Criterios @('INV-01','INV-03') `
            -Recommendation 'Incorporar cada aplicacion al bloque Aplicaciones de Arquitectura.psd1 con propietario, proposito, criticidad y clasificacion de datos.'))
    }
}

# ---------------------------------------------------------------------------
# 6. Artefactos sin clasificar (calidad de la linea base)
# ---------------------------------------------------------------------------
$sinClasificar = @($artefactos | Where-Object { $_.RolId -eq 'SinClasificar' })
$pctSinClasificar = if ($artefactos.Count -gt 0) {
    [math]::Round(($sinClasificar.Count / $artefactos.Count) * 100, 1)
} else { 0 }

$metrics['PorcentajeSinClasificar'] = $pctSinClasificar

if ($pctSinClasificar -gt [double]$conf.MaxPorcentajeSinClasificar) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity $sev.SinClasificar -Category 'LineaBaseEA' `
        -Title 'Cobertura insuficiente de la taxonomia de roles arquitectonicos' `
        -Asset ("{0} de {1} artefactos ({2}%)" -f $sinClasificar.Count, $artefactos.Count, $pctSinClasificar) `
        -Detail ("El {0}% de los artefactos no pudo clasificarse en ningun rol de la taxonomia; el maximo tolerado es {1}%. Una linea base con este nivel de indefinicion no permite afirmar que el servidor cumple su proposito arquitectonico." -f $pctSinClasificar, $conf.MaxPorcentajeSinClasificar) `
        -Evidence (($sinClasificar | Select-Object -First 20 | ForEach-Object { $_.Artefacto }) -join '; ') `
        -Criterios @('INV-01','ARQ-01') `
        -Recommendation 'Ampliar la taxonomia Roles en Arquitectura.psd1 con patrones que cubran estos artefactos, o clasificarlos manualmente incorporandolos al catalogo de aplicaciones.'))
}

# ---------------------------------------------------------------------------
# 7. Aplicaciones criticas sin propietario declarado
# ---------------------------------------------------------------------------
if ($conf.ExigirPropietario) {
    $sinDueno = @($Arquitectura.Aplicaciones | Where-Object {
        [string]::IsNullOrWhiteSpace($_.Propietario) -or $_.Propietario -eq 'DEFINIR'
    })
    if ($sinDueno.Count -gt 0) {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity $sev.SinPropietario -Category 'GobiernoDeActivos' `
            -Title 'Aplicaciones de negocio sin propietario asignado' `
            -Asset (($sinDueno | ForEach-Object { $_.Id }) -join ', ') `
            -Detail 'Sin propietario declarado no hay responsable de autorizar cambios, aprobar accesos, definir la clasificacion de la informacion ni asumir el riesgo residual del activo.' `
            -Criterios @('INV-01','INV-03','ACC-02') `
            -Recommendation 'Asignar propietario y responsable tecnico a cada aplicacion en Arquitectura.psd1, y formalizarlo en el inventario de activos del SGSI.'))
    }
}

if ($rolSrv.Propietario -eq 'DEFINIR' -or [string]::IsNullOrWhiteSpace($rolSrv.Propietario)) {
    $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
        -Severity 'Medium' -Category 'GobiernoDeActivos' `
        -Title 'El servidor no tiene propietario declarado en la linea base' `
        -Asset $rolSrv.Nombre `
        -Detail 'El bloque RolServidor de Arquitectura.psd1 mantiene el propietario sin definir. El activo no tiene responsable formal identificado.' `
        -Criterios @('INV-01','INV-03') `
        -Recommendation 'Completar Propietario, ResponsableTecnico y UnidadNegocio en Config\Arquitectura.psd1.'))
}

# ---------------------------------------------------------------------------
# 8. Distribucion por capa de arquitectura (mapa de la linea base)
# ---------------------------------------------------------------------------
foreach ($g in ($artefactos | Group-Object CapaEA | Sort-Object Count -Descending)) {
    $metrics["Capa_$($g.Name)"] = $g.Count
}
foreach ($g in ($artefactos | Group-Object RolArquitectonico | Sort-Object Count -Descending)) {
    $metrics["Rol_$($g.Name -replace '\W','_')"] = $g.Count
}

$metrics['TotalArtefactos']      = $artefactos.Count
$metrics['Alineados']            = @($artefactos | Where-Object { $_.Alineacion -eq 'Alineado' }).Count
$metrics['NoAlineados']          = $noAlineados.Count
$metrics['SinClasificar']        = $sinClasificar.Count
$metrics['ConRutaVerificada']    = @($artefactos | Where-Object { $_.RutaVerificada }).Count
$metrics['AplicacionesCatalogo'] = @($Arquitectura.Aplicaciones).Count
$metrics['AplicacionesDetectadas'] = $appsDetectadas.Keys.Count
$metrics['RolServidorDeclarado'] = [string]$rolSrv.RolDeclarado
$metrics['EntornoDeclarado']     = [string]$rolSrv.Entorno

New-CollectorResult -Meta $meta -Records $records.ToArray() -Findings $findings.ToArray() `
    -Metrics $metrics -Gaps $gaps.ToArray()
