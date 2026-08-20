#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# new_audit_excel.sh
# Genera el libro de Excel con todo el detalle de la auditoria (equivalente de
# Reports/New-AuditExcel.ps1).
#
# Produce un archivo .xlsx con una hoja por bloque de informacion. No requiere
# Excel ni LibreOffice: usa el escritor OOXML nativo de la suite.
#
# Recibe las rutas de los datos consolidados por variables de entorno y emite
# por stdout la ruta del archivo generado.
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/audit_core.sh"
. "$SCRIPT_DIR/../lib/xlsx_writer.sh"

: "${AUDIT_RESUMEN:?falta AUDIT_RESUMEN}"
: "${AUDIT_RUN_PATH:?falta AUDIT_RUN_PATH}"
HALLAZGOS=${AUDIT_HALLAZGOS:-}
CAPAS=${AUDIT_CAPAS:-}
COBERTURA=${AUDIT_COBERTURA:-}
BRECHAS=${AUDIT_BRECHAS:-}
GLOSARIO=${AUDIT_GLOSARIO:-}
TRAZA=${AUDIT_TRAZA:-}
TODOS=${AUDIT_TODOS:-}

if ! zip_available; then
    echo "No hay forma de crear el contenedor ZIP del .xlsx: se requiere 'zip' o 'python3'." >&2
    exit 1
fi

R() { jq -r "$1 // empty" "$AUDIT_RESUMEN"; }
leer() { [ -n "$1" ] && [ -s "$1" ] && cat "$1" || printf '[]'; }

servidor=$(R .Servidor)
runid=$(R .RunId)

xlsx_init

# ---------------------------------------------------------------------------
# 1. Resumen ejecutivo (formato vertical clave/valor)
# ---------------------------------------------------------------------------
resumen_filas=$(jq -n \
    --slurpfile r "$AUDIT_RESUMEN" \
    --arg rol      "$(arq '.RolServidor.RolDeclarado' 'No declarado')" \
    --arg entorno  "$(arq '.RolServidor.Entorno' 'No declarado')" \
    --arg crit     "$(arq '.RolServidor.Criticidad' 'No declarada')" \
    --arg clasif   "$(arq '.RolServidor.ClasificacionDatos' 'No declarada')" \
    --arg prop     "$(arq '.RolServidor.Propietario' 'DEFINIR')" \
    --arg resp     "$(arq '.RolServidor.ResponsableTecnico' 'DEFINIR')" \
    --arg unidad   "$(arq '.RolServidor.UnidadNegocio' 'DEFINIR')" '
    ($r[0]) as $s | [
      {Seccion:"Identificacion", Campo:"Servidor",               Valor:$s.Servidor},
      {Seccion:"Identificacion", Campo:"Dominio",                Valor:(if ($s.Dominio // "") == "" then "Sin dominio" else $s.Dominio end)},
      {Seccion:"Identificacion", Campo:"Sistema operativo",      Valor:$s.SistemaOperativo},
      {Seccion:"Identificacion", Campo:"Kernel",                 Valor:$s.Kernel},
      {Seccion:"Identificacion", Campo:"Rol declarado",          Valor:$rol},
      {Seccion:"Identificacion", Campo:"Entorno",                Valor:$entorno},
      {Seccion:"Identificacion", Campo:"Criticidad",             Valor:$crit},
      {Seccion:"Identificacion", Campo:"Clasificacion de datos", Valor:$clasif},
      {Seccion:"Identificacion", Campo:"Propietario",            Valor:$prop},
      {Seccion:"Identificacion", Campo:"Responsable tecnico",    Valor:$resp},
      {Seccion:"Identificacion", Campo:"Unidad de negocio",      Valor:$unidad},

      {Seccion:"Ejecucion", Campo:"Identificador de corrida", Valor:$s.RunId},
      {Seccion:"Ejecucion", Campo:"Inicio",                   Valor:$s.Inicio},
      {Seccion:"Ejecucion", Campo:"Fin",                      Valor:$s.Fin},
      {Seccion:"Ejecucion", Campo:"Duracion (segundos)",      Valor:$s.DuracionSegundos},
      {Seccion:"Ejecucion", Campo:"Ejecutado por",            Valor:$s.EjecutadoPor},
      {Seccion:"Ejecucion", Campo:"Privilegios",              Valor:(if $s.Elevado then "Root" else "Estandar (cobertura parcial)" end)},
      {Seccion:"Ejecucion", Campo:"Colectores ejecutados",    Valor:(($s.ColectoresOK|tostring) + " de " + ($s.ColectoresTotal|tostring))},
      {Seccion:"Ejecucion", Campo:"Registros levantados",     Valor:$s.RegistrosTotal},

      {Seccion:"Resultado", Campo:"Puntaje de riesgo",      Valor:$s.PuntajeRiesgo},
      {Seccion:"Resultado", Campo:"Nivel de riesgo",        Valor:$s.NivelRiesgo},
      {Seccion:"Resultado", Campo:"Hallazgos totales",      Valor:$s.HallazgosTotal},
      {Seccion:"Resultado", Campo:"Criticos",               Valor:$s.Criticos},
      {Seccion:"Resultado", Campo:"Altos",                  Valor:$s.Altos},
      {Seccion:"Resultado", Campo:"Medios",                 Valor:$s.Medios},
      {Seccion:"Resultado", Campo:"Bajos",                  Valor:$s.Bajos},
      {Seccion:"Resultado", Campo:"Informativos",           Valor:$s.Informativos},
      {Seccion:"Resultado", Campo:"Criterios evaluados",    Valor:(($s.CriteriosEvaluados|tostring) + " de " + ($s.CriteriosTotal|tostring))},
      {Seccion:"Resultado", Campo:"Criterios no conformes", Valor:$s.CriteriosNoConformes},
      {Seccion:"Resultado", Campo:"Brechas de evidencia",   Valor:$s.BrechasEvidencia}
    ]')
xlsx_sheet 'Resumen' "$resumen_filas" 'Seccion,Campo,Valor' '18,32,60'

# ---------------------------------------------------------------------------
# 2. Hallazgos
# ---------------------------------------------------------------------------
hall=$(leer "$HALLAZGOS" | jq -c '[.[] | {
    Id: .FindingId,
    Severidad: (if .Severity == "Critical" then "CRITICO"
                elif .Severity == "High"   then "ALTO"
                elif .Severity == "Medium" then "MEDIO"
                elif .Severity == "Low"    then "BAJO" else "INFO" end),
    Capa: .Layer, Colector: .CollectorId, Categoria: .Category,
    Hallazgo: .Title, Activo: .Asset, Detalle: .Detail,
    Criterios: .CriteriosTexto, Recomendacion: .Recommendation,
    Evidencia: .Evidence, Detectado: .DetectedAt }]')
xlsx_sheet 'Hallazgos' "$hall" \
    'Id,Severidad,Capa,Colector,Categoria,Hallazgo,Activo,Detalle,Criterios,Recomendacion,Evidencia,Detectado' \
    '16,11,7,10,20,45,30,60,18,60,50,18'

# ---------------------------------------------------------------------------
# 3. Inventario de software (capa prioritaria)
# ---------------------------------------------------------------------------
if [ -n "$TODOS" ] && [ -s "$TODOS" ]; then
    inv=$(jq -c '[.[] | select(.Meta.Id == "L4-01") | .Records[]? | {
        Producto: .Nombre, Version: .Version, Descripcion: .Descripcion,
        RutaInstalacion: .RutaInstalacion,
        RutaVerificada: (if .RutaVerificada then "Si" else "No" end),
        OrigenRuta: .OrigenRuta, Rol: .RolArquitectonico,
        CapaArquitectura: .CapaEA, AplicacionNegocio: .AplicacionNegocio,
        Propietario: .Propietario, Criticidad: .Criticidad,
        Publicador: .Publicador, Instalado: .FechaInstalacion,
        Arquitectura: .Arquitectura, TipoPaquete: .TipoPaquete,
        TamanoMB: .TamanoMB, Ambito: .Ambitos, Riesgo: .Riesgo,
        CategoriaRiesgo: .CategoriaRiesgo, OrigenDescripcion: .OrigenDescripcion }]' "$TODOS")
    if [ "$(printf '%s' "$inv" | jq 'length')" -gt 0 ]; then
        xlsx_sheet 'Inventario Software' "$inv" \
            'Producto,Version,Descripcion,RutaInstalacion,RutaVerificada,OrigenRuta,Rol,CapaArquitectura,AplicacionNegocio,Propietario,Criticidad,Publicador,Instalado,Arquitectura,TipoPaquete,TamanoMB,Ambito,Riesgo,CategoriaRiesgo,OrigenDescripcion' \
            '48,16,55,55,10,26,26,16,28,16,12,32,12,10,12,10,14,10,26,24'
    fi

    # -----------------------------------------------------------------------
    # 4. Linea base de arquitectura
    # -----------------------------------------------------------------------
    ea=$(jq -c '[.[] | select(.Meta.Id == "L4-06") | .Records[]? | {
        Artefacto: .Artefacto, Version: .Version, Descripcion: .Descripcion,
        RutaInstalacion: .RutaInstalacion, CapaArquitectura: .CapaEA,
        Rol: .RolArquitectonico, Alineacion: .Alineacion,
        AplicacionNegocio: .AplicacionNegocio,
        EnCatalogo: (if .EnCatalogoEA then "Si" else "No" end),
        Propietario: .Propietario, Criticidad: .Criticidad,
        Publicador: .Publicador, Servicios: .ServiciosAsociados,
        Puertos: .PuertosExpuestos }]' "$TODOS")
    if [ "$(printf '%s' "$ea" | jq 'length')" -gt 0 ]; then
        xlsx_sheet 'Arquitectura' "$ea" \
            'Artefacto,Version,Descripcion,RutaInstalacion,CapaArquitectura,Rol,Alineacion,AplicacionNegocio,EnCatalogo,Propietario,Criticidad,Publicador,Servicios,Puertos' \
            '48,16,55,55,16,26,26,28,11,16,12,32,40,16'
    fi
fi

# ---------------------------------------------------------------------------
# 5. Resumen por capas
# ---------------------------------------------------------------------------
xlsx_sheet 'Capas' "$(leer "$CAPAS" | jq -c 'sort_by(.Orden)')" \
    'Capa,Nombre,Descripcion,Peso,Colectores,ColectoresOK,Registros,Hallazgos,Criticos,Altos,Medios,Bajos,PuntajeRiesgo' \
    '7,40,70,7,11,13,11,11,10,8,8,8,14'

# ---------------------------------------------------------------------------
# 6. Cobertura de criterios
# ---------------------------------------------------------------------------
cob=$(leer "$COBERTURA" | jq -c '[.[] | {
    Criterio, Dominio, Titulo, Capas, Cobertura: .NivelCobertura,
    Estado, Conformidad, Hallazgos: .TotalHallazgos, Criticos, Altos,
    Colectores, Ejecutados: .ColectoresEjecutados }]')
xlsx_sheet 'Cobertura Criterios' "$cob" \
    'Criterio,Dominio,Titulo,Capas,Cobertura,Estado,Conformidad,Hallazgos,Criticos,Altos,Colectores,Ejecutados' \
    '10,34,50,16,11,20,28,11,10,8,42,42'

# ---------------------------------------------------------------------------
# 7. Glosario de criterios
# ---------------------------------------------------------------------------
glos=$(leer "$GLOSARIO")
if [ "$(printf '%s' "$glos" | jq 'length')" -gt 0 ]; then
    xlsx_sheet 'Glosario Criterios' "$glos" \
        'Criterio,Dominio,Titulo,Descripcion,Objetivo,Cobertura,Capas,Colectores' \
        '10,34,45,80,70,11,16,42'
fi

# ---------------------------------------------------------------------------
# 8. Brechas de evidencia
# ---------------------------------------------------------------------------
bre=$(leer "$BRECHAS" | jq -c '[.[] | {Colector, Capa, Limitacion: .Brecha}]')
xlsx_sheet 'Brechas Evidencia' "$bre" 'Colector,Capa,Limitacion' '12,8,110'

# ---------------------------------------------------------------------------
# 9. Trazabilidad de la ejecucion
# ---------------------------------------------------------------------------
xlsx_sheet 'Trazabilidad' "$(leer "$TRAZA")" \
    'Colector,Capa,Nombre,Descripcion,Criterios,Estado,Registros,Hallazgos,DuracionSeg' \
    '10,7,45,75,32,18,11,11,12'

# ---------------------------------------------------------------------------
# 10. Estadisticas del servidor
# ---------------------------------------------------------------------------
if [ -n "$TODOS" ] && [ -s "$TODOS" ]; then
    stats=$(jq -c '[.[] | select(.Meta.Id == "L9-01") | .Records[]?]' "$TODOS")
    if [ "$(printf '%s' "$stats" | jq 'length')" -gt 0 ]; then
        xlsx_sheet 'Estadisticas Servidor' "$stats" \
            'Grupo,Metrica,Valor,Unidad,Detalle,Estado' '16,32,14,22,80,14'
    fi

    # -----------------------------------------------------------------------
    # 11. Puertos en escucha: entregable de exposicion de red
    # -----------------------------------------------------------------------
    puertos=$(jq -c '[.[] | select(.Meta.Id == "L7-01") | .Records[]?
                      | select(.Categoria == "PuertoEscucha")]' "$TODOS")
    if [ "$(printf '%s' "$puertos" | jq 'length')" -gt 0 ]; then
        xlsx_sheet 'Exposicion Red' "$puertos" \
            'Categoria,Protocolo,DireccionLocal,Puerto,Proceso,PID,RutaProceso,Servicio,TodasInterfaces' \
            '16,10,18,9,22,8,50,32,16'
    fi
fi

# ---------------------------------------------------------------------------
# Generar
# ---------------------------------------------------------------------------
DESTINO="$AUDIT_RUN_PATH/Auditoria-${servidor}-${runid}.xlsx"
if xlsx_finish "$DESTINO" "Auditoria de sistemas - $servidor" 'Suite de Auditoria de Artefactos'; then
    printf '%s\n' "$DESTINO"
else
    echo "No se pudo empaquetar el archivo .xlsx." >&2
    exit 1
fi
