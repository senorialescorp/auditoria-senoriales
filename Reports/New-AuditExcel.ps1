<#
.SYNOPSIS
    Genera el libro de Excel con todo el detalle de la auditoria.

.DESCRIPTION
    Produce un archivo .xlsx con una hoja por bloque de informacion.
    No requiere Excel instalado: usa el escritor OOXML nativo de la suite.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]$Resumen,
    [object[]]$Hallazgos  = @(),
    [object[]]$Capas      = @(),
    [object[]]$Cobertura  = @(),
    [object[]]$Brechas    = @(),
    [object[]]$Resultados = @(),
    [object[]]$Glosario   = @(),
    [hashtable]$Config,
    [hashtable]$Arquitectura,
    [Parameter(Mandatory)][string]$OutputPath
)

$ErrorActionPreference = 'Stop'

$raizSuite = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $raizSuite 'Modules\AuditCore\ExcelWriter.psm1') -Force -DisableNameChecking

$hojas = New-Object System.Collections.ArrayList

# ---------------------------------------------------------------------------
# 1. Resumen ejecutivo (formato vertical clave/valor)
# ---------------------------------------------------------------------------
$rs = $Arquitectura.RolServidor
$resumenFilas = @(
    [pscustomobject]@{ Seccion='Identificacion'; Campo='Servidor';              Valor=$Resumen.Servidor }
    [pscustomobject]@{ Seccion='Identificacion'; Campo='Dominio';               Valor=$(if ($Resumen.Dominio) { $Resumen.Dominio } else { 'Workgroup' }) }
    [pscustomobject]@{ Seccion='Identificacion'; Campo='Rol declarado';         Valor=$rs.RolDeclarado }
    [pscustomobject]@{ Seccion='Identificacion'; Campo='Entorno';               Valor=$rs.Entorno }
    [pscustomobject]@{ Seccion='Identificacion'; Campo='Criticidad';            Valor=$rs.Criticidad }
    [pscustomobject]@{ Seccion='Identificacion'; Campo='Clasificacion de datos';Valor=$rs.ClasificacionDatos }
    [pscustomobject]@{ Seccion='Identificacion'; Campo='Propietario';           Valor=$rs.Propietario }
    [pscustomobject]@{ Seccion='Identificacion'; Campo='Responsable tecnico';   Valor=$rs.ResponsableTecnico }
    [pscustomobject]@{ Seccion='Identificacion'; Campo='Unidad de negocio';     Valor=$rs.UnidadNegocio }

    [pscustomobject]@{ Seccion='Ejecucion'; Campo='Identificador de corrida'; Valor=$Resumen.RunId }
    [pscustomobject]@{ Seccion='Ejecucion'; Campo='Inicio';                   Valor=$Resumen.Inicio }
    [pscustomobject]@{ Seccion='Ejecucion'; Campo='Fin';                      Valor=$Resumen.Fin }
    [pscustomobject]@{ Seccion='Ejecucion'; Campo='Duracion (segundos)';      Valor=$Resumen.DuracionSegundos }
    [pscustomobject]@{ Seccion='Ejecucion'; Campo='Ejecutado por';            Valor=$Resumen.EjecutadoPor }
    [pscustomobject]@{ Seccion='Ejecucion'; Campo='Privilegios';              Valor=$(if ($Resumen.Elevado) { 'Administrativos' } else { 'Estandar (cobertura parcial)' }) }
    [pscustomobject]@{ Seccion='Ejecucion'; Campo='Colectores ejecutados';    Valor=("{0} de {1}" -f $Resumen.ColectoresOK, $Resumen.ColectoresTotal) }
    [pscustomobject]@{ Seccion='Ejecucion'; Campo='Registros levantados';     Valor=$Resumen.RegistrosTotal }

    [pscustomobject]@{ Seccion='Resultado'; Campo='Puntaje de riesgo';        Valor=$Resumen.PuntajeRiesgo }
    [pscustomobject]@{ Seccion='Resultado'; Campo='Nivel de riesgo';          Valor=$Resumen.NivelRiesgo }
    [pscustomobject]@{ Seccion='Resultado'; Campo='Hallazgos totales';        Valor=$Resumen.HallazgosTotal }
    [pscustomobject]@{ Seccion='Resultado'; Campo='Criticos';                 Valor=$Resumen.Criticos }
    [pscustomobject]@{ Seccion='Resultado'; Campo='Altos';                    Valor=$Resumen.Altos }
    [pscustomobject]@{ Seccion='Resultado'; Campo='Medios';                   Valor=$Resumen.Medios }
    [pscustomobject]@{ Seccion='Resultado'; Campo='Bajos';                    Valor=$Resumen.Bajos }
    [pscustomobject]@{ Seccion='Resultado'; Campo='Informativos';             Valor=$Resumen.Informativos }
    [pscustomobject]@{ Seccion='Resultado'; Campo='Criterios evaluados';      Valor=("{0} de {1}" -f $Resumen.CriteriosEvaluados, $Resumen.CriteriosTotal) }
    [pscustomobject]@{ Seccion='Resultado'; Campo='Criterios no conformes';   Valor=$Resumen.CriteriosNoConformes }
    [pscustomobject]@{ Seccion='Resultado'; Campo='Brechas de evidencia';     Valor=$Resumen.BrechasEvidencia }
)
$null = $hojas.Add(@{
    Nombre='Resumen'; Datos=$resumenFilas
    Columnas=@('Seccion','Campo','Valor'); Anchos=@(18,32,60)
})

# ---------------------------------------------------------------------------
# 2. Hallazgos
# ---------------------------------------------------------------------------
$hall = @($Hallazgos | ForEach-Object {
    [pscustomobject]@{
        Id             = $_.FindingId
        Severidad      = switch ($_.Severity) {
                            'Critical' {'CRITICO'} 'High' {'ALTO'} 'Medium' {'MEDIO'}
                            'Low' {'BAJO'} default {'INFO'} }
        Capa           = $_.Layer
        Colector       = $_.CollectorId
        Categoria      = $_.Category
        Hallazgo       = $_.Title
        Activo         = $_.Asset
        Detalle        = $_.Detail
        Criterios      = $_.CriteriosTexto
        Recomendacion  = $_.Recommendation
        Evidencia      = $_.Evidence
        Detectado      = $_.DetectedAt
    }
})
$null = $hojas.Add(@{
    Nombre='Hallazgos'; Datos=$hall
    Columnas=@('Id','Severidad','Capa','Colector','Categoria','Hallazgo','Activo','Detalle','Criterios','Recomendacion','Evidencia','Detectado')
    Anchos=@(16,11,7,10,20,45,30,60,18,60,50,18)
})

# ---------------------------------------------------------------------------
# 3. Inventario de software (capa prioritaria)
# ---------------------------------------------------------------------------
$invRes = @($Resultados | Where-Object { $_.Meta.Id -eq 'L4-01' })
if ($invRes.Count -gt 0) {
    $inv = @($invRes[0].Records | ForEach-Object {
        [pscustomobject]@{
            Producto         = $_.Nombre
            Version          = $_.Version
            Descripcion      = $_.Descripcion
            RutaInstalacion  = $_.RutaInstalacion
            RutaVerificada   = $(if ($_.RutaVerificada) { 'Si' } else { 'No' })
            OrigenRuta       = $_.OrigenRuta
            Rol              = $_.RolArquitectonico
            CapaArquitectura = $_.CapaEA
            AplicacionNegocio= $_.AplicacionNegocio
            Propietario      = $_.Propietario
            Criticidad       = $_.Criticidad
            Publicador       = $_.Publicador
            Instalado        = $_.FechaInstalacion
            Arquitectura     = $_.Arquitectura
            TipoPaquete      = $_.TipoPaquete
            TamanoMB         = $_.TamanoMB
            Ambito           = $_.Ambitos
            Riesgo           = $_.Riesgo
            CategoriaRiesgo  = $_.CategoriaRiesgo
            OrigenDescripcion= $_.OrigenDescripcion
        }
    })
    $null = $hojas.Add(@{
        Nombre='Inventario Software'; Datos=$inv
        Columnas=@('Producto','Version','Descripcion','RutaInstalacion','RutaVerificada','OrigenRuta','Rol','CapaArquitectura','AplicacionNegocio','Propietario','Criticidad','Publicador','Instalado','Arquitectura','TipoPaquete','TamanoMB','Ambito','Riesgo','CategoriaRiesgo','OrigenDescripcion')
        Anchos=@(48,16,55,55,10,26,26,16,28,16,12,32,12,10,12,10,14,10,26,24)
    })
}

# ---------------------------------------------------------------------------
# 4. Linea base de arquitectura
# ---------------------------------------------------------------------------
$eaRes = @($Resultados | Where-Object { $_.Meta.Id -eq 'L4-06' })
if ($eaRes.Count -gt 0) {
    $ea = @($eaRes[0].Records | ForEach-Object {
        [pscustomobject]@{
            Artefacto        = $_.Artefacto
            Version          = $_.Version
            Descripcion      = $_.Descripcion
            RutaInstalacion  = $_.RutaInstalacion
            CapaArquitectura = $_.CapaEA
            Rol              = $_.RolArquitectonico
            Alineacion       = $_.Alineacion
            AplicacionNegocio= $_.AplicacionNegocio
            EnCatalogo       = $(if ($_.EnCatalogoEA) { 'Si' } else { 'No' })
            Propietario      = $_.Propietario
            Criticidad       = $_.Criticidad
            Publicador       = $_.Publicador
            Servicios        = $_.ServiciosAsociados
            Puertos          = $_.PuertosExpuestos
        }
    })
    $null = $hojas.Add(@{
        Nombre='Arquitectura'; Datos=$ea
        Columnas=@('Artefacto','Version','Descripcion','RutaInstalacion','CapaArquitectura','Rol','Alineacion','AplicacionNegocio','EnCatalogo','Propietario','Criticidad','Publicador','Servicios','Puertos')
        Anchos=@(48,16,55,55,16,26,26,28,11,16,12,32,40,16)
    })
}

# ---------------------------------------------------------------------------
# 5. Resumen por capas
# ---------------------------------------------------------------------------
$null = $hojas.Add(@{
    Nombre='Capas'
    Datos=@($Capas | Sort-Object Orden | ForEach-Object {
        [pscustomobject]@{
            Capa=$_.Capa; Nombre=$_.Nombre; Descripcion=$_.Descripcion; Peso=$_.Peso
            Colectores=$_.Colectores; ColectoresOK=$_.ColectoresOK; Registros=$_.Registros
            Hallazgos=$_.Hallazgos; Criticos=$_.Criticos; Altos=$_.Altos
            Medios=$_.Medios; Bajos=$_.Bajos; PuntajeRiesgo=$_.PuntajeRiesgo
        }
    })
    Columnas=@('Capa','Nombre','Descripcion','Peso','Colectores','ColectoresOK','Registros','Hallazgos','Criticos','Altos','Medios','Bajos','PuntajeRiesgo')
    Anchos=@(7,40,70,7,11,13,11,11,10,8,8,8,14)
})

# ---------------------------------------------------------------------------
# 6. Cobertura de criterios
# ---------------------------------------------------------------------------
$null = $hojas.Add(@{
    Nombre='Cobertura Criterios'
    Datos=@($Cobertura | ForEach-Object {
        [pscustomobject]@{
            Criterio=$_.Criterio; Dominio=$_.Dominio; Titulo=$_.Titulo
            Capas=$_.Capas; Cobertura=$_.NivelCobertura; Estado=$_.Estado
            Conformidad=$_.Conformidad; Hallazgos=$_.TotalHallazgos
            Criticos=$_.Criticos; Altos=$_.Altos
            Colectores=$_.Colectores; Ejecutados=$_.ColectoresEjecutados
        }
    })
    Columnas=@('Criterio','Dominio','Titulo','Capas','Cobertura','Estado','Conformidad','Hallazgos','Criticos','Altos','Colectores','Ejecutados')
    Anchos=@(10,34,50,16,11,20,28,11,10,8,42,42)
})

# ---------------------------------------------------------------------------
# 7. Glosario de criterios
# ---------------------------------------------------------------------------
if ($Glosario.Count -gt 0) {
    $null = $hojas.Add(@{
        Nombre='Glosario Criterios'; Datos=$Glosario
        Columnas=@('Criterio','Dominio','Titulo','Descripcion','Objetivo','Cobertura','Capas','Colectores')
        Anchos=@(10,34,45,80,70,11,16,42)
    })
}

# ---------------------------------------------------------------------------
# 8. Brechas de evidencia
# ---------------------------------------------------------------------------
$null = $hojas.Add(@{
    Nombre='Brechas Evidencia'
    Datos=@($Brechas | ForEach-Object {
        [pscustomobject]@{ Colector=$_.Colector; Capa=$_.Capa; Limitacion=$_.Brecha }
    })
    Columnas=@('Colector','Capa','Limitacion'); Anchos=@(12,8,110)
})

# ---------------------------------------------------------------------------
# 9. Trazabilidad de la ejecucion
# ---------------------------------------------------------------------------
$null = $hojas.Add(@{
    Nombre='Trazabilidad'
    Datos=@($Resultados | Sort-Object { $_.Meta.Id } | ForEach-Object {
        $dur = if ($_.PSObject.Properties['DuracionSeg']) { $_.DuracionSeg } else { 0 }
        [pscustomobject]@{
            Colector=$_.Meta.Id; Capa=$_.Meta.Layer; Nombre=$_.Meta.Nombre
            Descripcion=$_.Meta.Descripcion
            Criterios=(@($_.Meta.Criterios) -join '; ')
            Estado=$_.Status; Registros=$_.RecordCount
            Hallazgos=@($_.Findings).Count; DuracionSeg=$dur
        }
    })
    Columnas=@('Colector','Capa','Nombre','Descripcion','Criterios','Estado','Registros','Hallazgos','DuracionSeg')
    Anchos=@(10,7,45,75,32,18,11,11,12)
})

# ---------------------------------------------------------------------------
# 10. Estadisticas del servidor
# ---------------------------------------------------------------------------
$statsRes = @($Resultados | Where-Object { $_.Meta.Id -eq 'L9-01' })
if ($statsRes.Count -gt 0 -and @($statsRes[0].Records).Count -gt 0) {
    $null = $hojas.Add(@{
        Nombre='Estadisticas Servidor'; Datos=@($statsRes[0].Records)
        Columnas=@('Grupo','Metrica','Valor','Unidad','Detalle','Estado')
        Anchos=@(16,32,14,22,80,14)
    })
}

# ---------------------------------------------------------------------------
# Generar
# ---------------------------------------------------------------------------
$destino = Join-Path $OutputPath ("Auditoria-{0}-{1}.xlsx" -f $Resumen.Servidor, $Resumen.RunId)

Export-ToExcel -Path $destino -Hojas @($hojas) `
    -Titulo ("Auditoria de sistemas - {0}" -f $Resumen.Servidor) `
    -Autor 'Suite de Auditoria de Artefactos' | Out-Null

return $destino
