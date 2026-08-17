<#
.SYNOPSIS
    Genera la ficha imprimible de auditoria del servidor.

.DESCRIPTION
    Documento de una a dos paginas en formato A4, disenado para imprimirse o
    exportarse a PDF desde el navegador (Ctrl+P). Contiene la identificacion
    del activo, el veredicto, el perfil arquitectonico y los hallazgos que
    exigen accion. El detalle completo vive en el libro de Excel.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]$Resumen,
    [object[]]$Hallazgos  = @(),
    [object[]]$Capas      = @(),
    [object[]]$Cobertura  = @(),
    [object[]]$Brechas    = @(),
    [object[]]$Resultados = @(),
    [hashtable]$Config,
    [hashtable]$Arquitectura,
    [string]$ArchivoExcel = '',
    [Parameter(Mandatory)][string]$OutputPath
)

$ErrorActionPreference = 'Stop'

function Esc {
    param([AllowNull()]$Texto)
    if ($null -eq $Texto) { return '' }
    return ([string]$Texto).Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;')
}

$rs = $Arquitectura.RolServidor
$sb = New-Object System.Text.StringBuilder
function W { param([string]$s) $null = $sb.AppendLine($s) }

$claseRiesgo = switch ($Resumen.NivelRiesgo) {
    'CRITICO' { 'r-crit' } 'ALTO' { 'r-crit' } 'MEDIO' { 'r-med' }
    'BAJO' { 'r-ok' } default { 'r-ok' }
}

# Hallazgos que exigen accion inmediata
$accionables = @($Hallazgos | Where-Object { $_.Severity -in @('Critical','High') })

# Datos de arquitectura
$eaRes = @($Resultados | Where-Object { $_.Meta.Id -eq 'L4-06' -and $_.Status -eq 'Completed' })
$artef = @()
if ($eaRes.Count -gt 0) {
    $artef = @($eaRes[0].Records | Where-Object { $_.Artefacto -notlike '`[CATALOGO`]*' })
}
$noAlineados = @($artef | Where-Object { $_.Alineacion -eq 'NO ALINEADO' })
$sinClasificar = @($artef | Where-Object { $_.RolId -eq 'SinClasificar' })

# Metricas de inventario
$invRes = @($Resultados | Where-Object { $_.Meta.Id -eq 'L4-01' })
$totalSw = if ($invRes.Count -gt 0) { @($invRes[0].Records).Count } else { 0 }

W '<!DOCTYPE html>'
W '<html lang="es"><head><meta charset="UTF-8">'
W ("<title>Ficha de auditoria - {0}</title>" -f (Esc $Resumen.Servidor))
W @'
<style>
@page { size: A4; margin: 12mm 10mm; }
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:"Segoe UI",Arial,sans-serif;font-size:9.5pt;line-height:1.4;color:#1a1f26;background:#e9ecef}
.hoja{width:210mm;min-height:297mm;margin:0 auto;background:#fff;padding:10mm 9mm}

h1{font-size:15pt;font-weight:700;letter-spacing:-.2px}
h2{font-size:10pt;font-weight:700;color:#1f4e79;text-transform:uppercase;letter-spacing:.7px;
   border-bottom:1.5pt solid #1f4e79;padding-bottom:2pt;margin:9pt 0 5pt}
h3{font-size:9pt;font-weight:700;margin:6pt 0 3pt;color:#374151}

.cab{display:flex;justify-content:space-between;align-items:flex-start;
     border-bottom:2.5pt solid #1f4e79;padding-bottom:6pt;margin-bottom:3pt}
.cab .sub{font-size:8.5pt;color:#5b6673;margin-top:2pt}
.cab .der{text-align:right;font-size:8pt;color:#5b6673;line-height:1.5}
.cab .der b{color:#1a1f26}

.veredicto{display:flex;gap:5pt;margin:7pt 0}
.vbox{flex:1;border:1pt solid #d5dae0;border-radius:3pt;padding:5pt 6pt;text-align:center}
.vbox .n{font-size:17pt;font-weight:700;line-height:1.1}
.vbox .l{font-size:6.8pt;color:#5b6673;text-transform:uppercase;letter-spacing:.4px;margin-top:1pt}
.vbox.r-crit{background:#fdecec;border-color:#c0272d} .vbox.r-crit .n{color:#c0272d}
.vbox.r-med{background:#fdf6e3;border-color:#c9a000}  .vbox.r-med .n{color:#8a6d00}
.vbox.r-ok{background:#eaf6ef;border-color:#1a7f4b}   .vbox.r-ok .n{color:#1a7f4b}
.vbox.crit .n{color:#c0272d} .vbox.alto .n{color:#e06c00}
.vbox.medio .n{color:#8a6d00} .vbox.bajo .n{color:#2c7bb6}

table{width:100%;border-collapse:collapse;font-size:8.3pt}
th{background:#eef2f6;text-align:left;padding:3pt 4pt;border:.5pt solid #d5dae0;
   font-weight:700;color:#1f4e79;font-size:7.8pt;text-transform:uppercase;letter-spacing:.3px}
td{padding:3pt 4pt;border:.5pt solid #d5dae0;vertical-align:top}
.ident td:first-child{width:33%;background:#f7f9fb;font-weight:600}
.pend{color:#c0272d;font-weight:700}

.sev{display:inline-block;padding:.5pt 4pt;border-radius:2pt;font-size:7pt;
     font-weight:700;color:#fff;white-space:nowrap}
.s-crit{background:#c0272d} .s-alto{background:#e06c00}
.s-med{background:#c9a000}  .s-bajo{background:#2c7bb6}

.dosc{display:flex;gap:7pt}
.dosc>div{flex:1}

.barras td{border:none;padding:1.5pt 0;font-size:8pt}
.barras .bn{width:32%} .barras .bv{width:12%;text-align:right;font-weight:700;padding-right:4pt}
.barra{height:7pt;background:#eef2f6;border-radius:2pt;overflow:hidden}
.barra i{display:block;height:100%;background:#1f4e79}
.barra i.prio{background:#c0272d}

.nota{background:#fdf6e3;border-left:2.5pt solid #c9a000;padding:4pt 6pt;font-size:8pt;margin:5pt 0}
.pie{margin-top:8pt;padding-top:4pt;border-top:.5pt solid #d5dae0;
     font-size:7.2pt;color:#5b6673;display:flex;justify-content:space-between}
.firma{margin-top:10pt;display:flex;gap:14pt}
.firma div{flex:1;border-top:.5pt solid #4b5563;padding-top:2pt;font-size:7.5pt;color:#5b6673;text-align:center}

.salto{page-break-before:always}
tr,td,th{page-break-inside:avoid}
@media print{body{background:#fff}.hoja{margin:0;padding:0;width:auto;min-height:0}.noimp{display:none}}
.noimp{position:fixed;top:8px;right:8px;background:#1f4e79;color:#fff;border:none;
       padding:7px 13px;border-radius:4px;font-size:12px;cursor:pointer;font-family:inherit}
</style>
'@
W '</head><body>'
W '<button class="noimp" onclick="window.print()">Imprimir / Guardar PDF</button>'
W '<div class="hoja">'

# ---------------------------------------------------------------------------
# Cabecera
# ---------------------------------------------------------------------------
W '<div class="cab">'
W '<div>'
W ("<h1>Ficha de auditoria de sistemas</h1>")
W ("<div class=""sub"">Servidor <b>{0}</b> &middot; {1}</div>" -f (Esc $Resumen.Servidor), (Esc $rs.RolDeclarado))
W '</div>'
W '<div class="der">'
W ("Corrida <b>{0}</b><br>" -f (Esc $Resumen.RunId))
W ("Fecha <b>{0}</b><br>" -f (Get-Date -Format 'yyyy-MM-dd HH:mm'))
W ("Privilegios <b>{0}</b>" -f $(if ($Resumen.Elevado) { 'Administrativos' } else { 'Estandar' }))
W '</div></div>'

# ---------------------------------------------------------------------------
# Veredicto
# ---------------------------------------------------------------------------
W '<div class="veredicto">'
W ("<div class=""vbox {0}""><div class=""n"">{1}</div><div class=""l"">Riesgo &middot; {2}</div></div>" -f `
    $claseRiesgo, $Resumen.PuntajeRiesgo, (Esc $Resumen.NivelRiesgo))
W ("<div class=""vbox crit""><div class=""n"">{0}</div><div class=""l"">Criticos</div></div>" -f $Resumen.Criticos)
W ("<div class=""vbox alto""><div class=""n"">{0}</div><div class=""l"">Altos</div></div>" -f $Resumen.Altos)
W ("<div class=""vbox medio""><div class=""n"">{0}</div><div class=""l"">Medios</div></div>" -f $Resumen.Medios)
W ("<div class=""vbox bajo""><div class=""n"">{0}</div><div class=""l"">Bajos</div></div>" -f $Resumen.Bajos)
W ("<div class=""vbox""><div class=""n"">{0}</div><div class=""l"">Artefactos</div></div>" -f $totalSw)
W '</div>'

if (-not $Resumen.Elevado) {
    W ("<div class=""nota""><b>Alcance limitado:</b> ejecutada sin privilegios administrativos. {0} verificaciones no pudieron completarse; ver hoja <i>Brechas Evidencia</i> del libro adjunto. Para expediente formal, reejecutar con cuenta administrativa.</div>" -f $Resumen.BrechasEvidencia)
}

# ---------------------------------------------------------------------------
# Identificacion + perfil arquitectonico
# ---------------------------------------------------------------------------
W '<div class="dosc">'

W '<div>'
W '<h2>Identificacion del activo</h2>'
W '<table class="ident">'
W ("<tr><td>Servidor</td><td>{0}</td></tr>" -f (Esc $Resumen.Servidor))
W ("<tr><td>Dominio</td><td>{0}</td></tr>" -f (Esc $(if ($Resumen.Dominio) { $Resumen.Dominio } else { 'Workgroup' })))
W ("<tr><td>Rol declarado</td><td>{0}</td></tr>" -f (Esc $rs.RolDeclarado))
W ("<tr><td>Entorno</td><td>{0}</td></tr>" -f (Esc $rs.Entorno))
W ("<tr><td>Criticidad</td><td>{0}</td></tr>" -f (Esc $rs.Criticidad))
W ("<tr><td>Clasificacion datos</td><td>{0}</td></tr>" -f (Esc $rs.ClasificacionDatos))

$prop = if ($rs.Propietario -eq 'DEFINIR' -or -not $rs.Propietario) { '<span class="pend">SIN ASIGNAR</span>' } else { Esc $rs.Propietario }
$resp = if ($rs.ResponsableTecnico -eq 'DEFINIR' -or -not $rs.ResponsableTecnico) { '<span class="pend">SIN ASIGNAR</span>' } else { Esc $rs.ResponsableTecnico }
$unid = if ($rs.UnidadNegocio -eq 'DEFINIR' -or -not $rs.UnidadNegocio) { '<span class="pend">SIN ASIGNAR</span>' } else { Esc $rs.UnidadNegocio }
W ("<tr><td>Propietario</td><td>{0}</td></tr>" -f $prop)
W ("<tr><td>Responsable tecnico</td><td>{0}</td></tr>" -f $resp)
W ("<tr><td>Unidad de negocio</td><td>{0}</td></tr>" -f $unid)
W '</table>'
W '</div>'

W '<div>'
W '<h2>Perfil arquitectonico</h2>'
if ($artef.Count -gt 0) {
    $alin = @($artef | Where-Object { $_.Alineacion -eq 'Alineado' }).Count
    $pct  = [math]::Round(($alin / $artef.Count) * 100, 0)
    W '<table class="ident">'
    W ("<tr><td>Artefactos clasificados</td><td>{0} de {1}</td></tr>" -f ($artef.Count - $sinClasificar.Count), $artef.Count)
    W ("<tr><td>Alineados al rol</td><td>{0} ({1}%)</td></tr>" -f $alin, $pct)
    $celdaNoAlin = if ($noAlineados.Count -gt 0) { "<span class=""pend"">$($noAlineados.Count)</span>" } else { '0' }
    W ("<tr><td>No alineados</td><td>{0}</td></tr>" -f $celdaNoAlin)
    W ("<tr><td>Sin clasificar</td><td>{0}</td></tr>" -f $sinClasificar.Count)
    W '</table>'

    W '<h3>Distribucion por capa de arquitectura</h3>'
    W '<table class="barras">'
    $maxCapa = 1
    foreach ($g in ($artef | Group-Object CapaEA)) { if ($g.Count -gt $maxCapa) { $maxCapa = $g.Count } }
    foreach ($g in ($artef | Group-Object CapaEA | Sort-Object Count -Descending)) {
        $w = [math]::Round(($g.Count / $maxCapa) * 100, 0)
        W ("<tr><td class=""bn"">{0}</td><td class=""bv"">{1}</td><td><div class=""barra""><i style=""width:{2}%""></i></div></td></tr>" -f `
            (Esc $g.Name), $g.Count, $w)
    }
    W '</table>'
} else {
    W '<p style="font-size:8pt;color:#5b6673">Linea base de arquitectura no disponible en esta corrida.</p>'
}
W '</div></div>'

# ---------------------------------------------------------------------------
# Riesgo por capa
# ---------------------------------------------------------------------------
W '<h2>Riesgo por capa</h2>'
W '<table class="barras">'
$maxR = 1
foreach ($c in $Capas) { if ($c.PuntajeRiesgo -gt $maxR) { $maxR = $c.PuntajeRiesgo } }
foreach ($c in ($Capas | Sort-Object Orden)) {
    if ($c.Colectores -eq 0) { continue }
    $w = [math]::Round(($c.PuntajeRiesgo / $maxR) * 100, 0)
    $cls = if ($c.Capa -eq 'L4') { ' prio' } else { '' }
    $etq = if ($c.Capa -eq 'L4') { '<b>' + (Esc $c.Nombre) + '</b>' } else { Esc $c.Nombre }
    W ("<tr><td class=""bn"">{0} {1}</td><td class=""bv"">{2}</td><td><div class=""barra""><i class=""{3}"" style=""width:{4}%""></i></div></td><td style=""width:22%;font-size:7.5pt;color:#5b6673"">{5} hallazgos</td></tr>" -f `
        (Esc $c.Capa), $etq, $c.PuntajeRiesgo, $cls.Trim(), $w, $c.Hallazgos)
}
W '</table>'

# ---------------------------------------------------------------------------
# Hallazgos que exigen accion
# ---------------------------------------------------------------------------
W ("<h2>Hallazgos que exigen accion ({0})</h2>" -f $accionables.Count)
if ($accionables.Count -eq 0) {
    W '<p style="font-size:8.5pt;color:#1a7f4b;font-weight:600">No se identificaron hallazgos criticos ni altos en el alcance evaluado.</p>'
} else {
    W '<table>'
    W '<thead><tr><th style="width:8%">Sev.</th><th style="width:6%">Capa</th><th style="width:34%">Hallazgo</th><th style="width:22%">Activo</th><th style="width:11%">Criterios</th><th style="width:19%">Accion requerida</th></tr></thead><tbody>'
    foreach ($h in $accionables) {
        $cls = if ($h.Severity -eq 'Critical') { 's-crit' } else { 's-alto' }
        $et  = if ($h.Severity -eq 'Critical') { 'CRIT' } else { 'ALTO' }
        # La recomendacion se recorta: el texto completo esta en el Excel
        $rec = [string]$h.Recommendation
        if ($rec.Length -gt 155) { $rec = $rec.Substring(0,152) + '...' }
        $act = [string]$h.Asset
        if ($act.Length -gt 70) { $act = $act.Substring(0,67) + '...' }
        W ("<tr><td><span class=""sev {0}"">{1}</span></td><td>{2}</td><td><b>{3}</b></td><td>{4}</td><td>{5}</td><td>{6}</td></tr>" -f `
            $cls, $et, (Esc $h.Layer), (Esc $h.Title), (Esc $act), (Esc $h.CriteriosTexto), (Esc $rec))
    }
    W '</tbody></table>'
}

# ---------------------------------------------------------------------------
# Desviaciones arquitectonicas
# ---------------------------------------------------------------------------
if ($noAlineados.Count -gt 0) {
    W ("<h2>Desviaciones arquitectonicas ({0})</h2>" -f $noAlineados.Count)
    W ("<p style=""font-size:8pt;color:#5b6673;margin-bottom:3pt"">Artefactos cuyo rol no corresponde al proposito declarado del servidor ({0}, entorno de {1}).</p>" -f (Esc $rs.RolDeclarado), (Esc $rs.Entorno))
    W '<table>'
    W '<thead><tr><th style="width:32%">Artefacto</th><th style="width:22%">Rol detectado</th><th style="width:46%">Ubicacion</th></tr></thead><tbody>'
    foreach ($n in ($noAlineados | Select-Object -First 18)) {
        $r = if ($n.RutaInstalacion) { Esc $n.RutaInstalacion } else { '<i style="color:#8894a3">ruta no determinada</i>' }
        W ("<tr><td><b>{0}</b></td><td>{1}</td><td style=""font-family:Consolas,monospace;font-size:7.5pt"">{2}</td></tr>" -f `
            (Esc $n.Artefacto), (Esc $n.RolArquitectonico), $r)
    }
    W '</tbody></table>'
    if ($noAlineados.Count -gt 18) {
        W ("<p style=""font-size:7.5pt;color:#5b6673;margin-top:2pt"">Se muestran 18 de {0}. Listado completo en la hoja <i>Arquitectura</i> del libro adjunto.</p>" -f $noAlineados.Count)
    }
}

# ---------------------------------------------------------------------------
# Conformidad por dominio de criterios
# ---------------------------------------------------------------------------
W '<h2>Conformidad por dominio de criterios</h2>'
W '<table>'
W '<thead><tr><th style="width:34%">Dominio</th><th style="width:11%">Criterios</th><th style="width:13%">Conformes</th><th style="width:20%">Con observaciones</th><th style="width:12%">No conformes</th><th style="width:10%">Sin evaluar</th></tr></thead><tbody>'
foreach ($g in ($Cobertura | Group-Object Dominio | Sort-Object Name)) {
    $cf = @($g.Group | Where-Object { $_.Conformidad -eq 'Conforme' }).Count
    $ob = @($g.Group | Where-Object { $_.Conformidad -eq 'Conforme con observaciones' }).Count
    $nc = @($g.Group | Where-Object { $_.Conformidad -eq 'No conforme' }).Count
    $ne = @($g.Group | Where-Object { $_.Conformidad -eq 'No evaluado' }).Count
    $ncCell = if ($nc -gt 0) { "<span class=""pend"">$nc</span>" } else { '0' }
    W ("<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>" -f `
        (Esc $g.Name), $g.Count, $cf, $ob, $ncCell, $ne)
}
W '</tbody></table>'

# ---------------------------------------------------------------------------
# Cierre
# ---------------------------------------------------------------------------
W '<div class="firma">'
W '<div>Elaborado por</div><div>Revisado por</div><div>Responsable del activo</div>'
W '</div>'

W '<div class="pie">'
$nombreExcel = if ($ArchivoExcel) { Split-Path $ArchivoExcel -Leaf } else { 'libro de Excel adjunto' }
W ("<span>Detalle completo: <b>{0}</b></span>" -f (Esc $nombreExcel))
W ("<span>Auditoria de solo lectura &middot; {0} registros &middot; {1} colectores</span>" -f $Resumen.RegistrosTotal, $Resumen.ColectoresOK)
W '</div>'

W '</div></body></html>'

$destino = Join-Path $OutputPath ("Ficha-{0}-{1}.html" -f $Resumen.Servidor, $Resumen.RunId)
$enc = New-Object System.Text.UTF8Encoding($true)
[System.IO.File]::WriteAllText($destino, $sb.ToString(), $enc)

return $destino
