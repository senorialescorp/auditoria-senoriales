# Suite de Auditoría de Artefactos — ISO 27001 + Arquitectura Empresarial

Auditoría técnica de un servidor Windows organizada en **capas verticales**, con prioridad explícita en la **capa de artefactos de software (L4)**.

Opera en dos dimensiones simultáneas:

1. **Cumplimiento** — cada evidencia se mapea contra los controles del **Anexo A de ISO/IEC 27001:2022**.
2. **Auditoría de sistemas / Arquitectura Empresarial** — cada artefacto se clasifica por **rol arquitectónico** y **capa EA**, y se evalúa si ese rol corresponde al **propósito declarado del servidor**. La diferencia entre lo declarado y lo encontrado es el hallazgo.

La suite es **de solo lectura**: no modifica configuración, no instala nada, no reinicia servicios.

---

## Ejecución rápida

```powershell
cd C:\Scripts\Audit

# Auditoría completa (recomendado: consola elevada)
.\Invoke-Audit.ps1

# Solo la capa prioritaria: artefactos de software
.\Invoke-Audit.ps1 -SoftwareOnly

# Modo rápido: omite escaneo de binarios y muestreo de rendimiento
.\Invoke-Audit.ps1 -Quick

# Capas específicas
.\Invoke-Audit.ps1 -Layer L2,L4,L7

# Colectores específicos
.\Invoke-Audit.ps1 -Collector L4-01,L4-05
```

Al terminar se abre el expediente en `Output\<RunId>\Reporte-Auditoria.html`.

> **Privilegios.** Sin elevación la suite corre igual y degrada con elegancia, pero varios controles no pueden evidenciarse (BitLocker, `auditpol`, log de seguridad, SMBv1 como característica, WMI `root\subscription`). Cada limitación queda registrada en la sección **Brechas de evidencia** del reporte, para que el alcance real quede documentado en lugar de aparentar cobertura total. Para un expediente formal, ejecutar como administrador.

---

## Modelo de capas

| Capa | Nombre | Peso | Foco |
|------|--------|------|------|
| L1 | Infraestructura física y hardware | 0.8 | Chasis, CPU, memoria, discos, firmware, virtualización |
| L2 | Sistema operativo y hardening | 1.2 | Versión, parcheo, Defender, firewall, cifrado, TLS |
| L3 | Plataforma, runtimes y middleware | 1.5 | .NET, Java, Python, Node, IIS, bases de datos, roles |
| **L4** | **Artefactos de software** | **2.0** | **Inventario, gestores de paquetes, integridad, ciclo de vida** |
| L5 | Servicios, procesos y persistencia | 1.5 | Servicios, tareas programadas, autoarranque, WMI |
| L6 | Identidad y control de acceso | 1.4 | Cuentas, administradores, contraseñas, RDP |
| L7 | Red y exposición | 1.3 | Puertos, firewall, comparticiones, WinRM |
| L8 | Datos, registro y resiliencia | 1.1 | Event logs, respaldo, instantáneas, capacidad |
| L9 | Rendimiento y capacidad | 0.9 | CPU, memoria, disco, red, top de procesos |

El **peso** multiplica la severidad de cada hallazgo en el puntaje de riesgo agregado. L4 pondera el doble por ser el eje del alcance solicitado.

---

## Colectores

Cada colector es autónomo, declara su propio manifiesto y devuelve un contrato uniforme (`Records` / `Findings` / `Metrics` / `Gaps`).

| Id | Colector | Controles ISO |
|----|----------|---------------|
| L1-01 | Inventario de hardware y plataforma física | A.5.9, A.7.9, A.7.10, A.8.1 |
| L2-01 | Línea base del sistema operativo | A.5.9, A.8.9, A.8.17 |
| L2-02 | Nivel de parcheo y actualizaciones | A.8.8, A.8.32 |
| L2-03 | Configuración de seguridad del SO | A.8.7, A.8.9, A.8.15, A.8.20, A.8.24 |
| L3-01 | Runtimes, motores y middleware | A.5.9, A.8.8, A.8.9, A.8.31 |
| **L4-01** | **Inventario consolidado de software** | **A.5.9, A.8.19, A.5.10, A.5.23, A.8.12, A.8.32** |
| **L4-02** | **Software por gestores de paquetes** | **A.5.9, A.8.19, A.8.25, A.8.31** |
| **L4-03** | **Binarios y scripts no gestionados (shadow IT)** | **A.8.19, A.5.10, A.8.18, A.8.28** |
| **L4-04** | **Integridad y procedencia de binarios en ejecución** | **A.8.19, A.8.9, A.8.7, A.8.32** |
| **L4-05** | **Ciclo de vida y soporte del software** | **A.8.8, A.5.9, A.8.19, A.5.21** |
| **L4-06** | **Línea base de arquitectura empresarial y conformidad de roles** | **A.5.9, A.8.19, A.8.9, A.5.10, A.8.31** |
| L5-01 | Servicios Windows y configuración de ejecución | A.8.9, A.8.2, A.8.19, A.8.18 |
| L5-02 | Tareas programadas y puntos de autoarranque | A.8.19, A.8.16, A.5.37, A.8.9 |
| L6-01 | Identidades locales y control de acceso | A.5.15–A.5.18, A.8.2, A.8.5 |
| L7-01 | Exposición de red y servicios accesibles | A.8.20, A.8.21, A.8.22, A.8.3, A.5.15 |
| L8-01 | Registro de eventos, respaldo y resiliencia | A.8.15, A.8.16, A.8.13, A.5.30, A.8.10 |
| L9-01 | Estadísticas de rendimiento y capacidad | A.8.6, A.8.16, A.8.34 |

### Por qué la capa L4 tiene cinco colectores

El inventario de software de una auditoría típica se limita a *Agregar o quitar programas*. Esa fuente única deja tres puntos ciegos que aquí se cubren de forma explícita:

- **L4-02** — paquetes de `npm`, `pip`, `Scoop`, `dotnet tool` y módulos de PowerShell: código ejecutable que **nunca aparece** en el registro de desinstalación.
- **L4-03** — binarios y scripts copiados a mano, sin instalador: el *shadow IT* real, con verificación de firma Authenticode.
- **L4-04** — qué se está ejecutando *ahora mismo* (servicios y procesos), con hash SHA256 como línea base comparable entre auditorías. Detecta `HashMismatch`: binario alterado después de ser firmado.

`Win32_Product` **no se usa deliberadamente**: esa clase WMI dispara una reconfiguración de consistencia MSI por cada paquete, es lenta y altera el estado del servidor auditado.

---

## Línea base de Arquitectura Empresarial

`Config\Arquitectura.psd1` declara **cómo debería ser** el servidor. Los colectores levantan **cómo es**. `L4-06` contrasta ambos y responde tres preguntas de auditoría de sistemas:

1. ¿Qué rol cumple cada artefacto instalado?
2. ¿Ese rol corresponde al propósito declarado de este servidor?
3. ¿Cada aplicación de negocio tiene dueño, descripción y ubicación conocida?

### Los tres bloques del archivo

| Bloque | Qué declara |
|--------|-------------|
| `RolServidor` | Propósito, entorno, criticidad, propietario y **qué roles de software son admisibles** aquí |
| `Roles` | Taxonomía de clasificación automática (patrón regex → rol → capa EA) |
| `Aplicaciones` | Catálogo de aplicaciones de negocio: descripción, propósito, propietario, criticidad |

### Capas EA usadas

`Negocio` · `Aplicación` · `Datos` · `Tecnología` · `Infraestructura`

### Estados de alineación

| Estado | Significado |
|--------|-------------|
| **Alineado** | El rol figura en `RolesEsperados` del servidor |
| **NO ALINEADO** | El rol figura en `RolesNoEsperados` → desviación arquitectónica |
| **Sin clasificar** | Ningún patrón de la taxonomía coincidió → requiere decisión del arquitecto |
| **Rol no declarado** | El rol existe en la taxonomía pero la línea base no dice si se espera o no |

### Enriquecimiento del inventario

Cada artefacto de `L4-01` incluye ahora:

- **Descripción** — cascada: `Comments` del registro → `FileDescription` del binario → catálogo de arquitectura → descripción genérica del rol. La columna `OrigenDescripcion` dice de dónde salió cada una.
- **RutaInstalación** — cascada: `InstallLocation` → binario en ejecución → `DisplayIcon` → `UninstallString`. `RutaVerificada` indica si la ruta existe realmente en disco; el informe marca las no verificadas.
- **RolArquitectónico**, **CapaEA**, **AplicaciónNegocio**, **Propietario**, **Criticidad**.

`L4-06` además correlaciona cada artefacto con **los servicios Windows que ejecuta desde su ruta y los puertos TCP que mantiene en escucha** — el mapa operativo de la capa de aplicación.

### Mantenimiento

El ejercicio de arquitectura *es* mantener este archivo:

- Todo artefacto **sin clasificar** → ampliar `Roles` con un patrón nuevo, o declararlo en `Aplicaciones`.
- Toda aplicación de negocio detectada **fuera del catálogo** → agregarla con propietario y criticidad.
- Todo rol **no declarado** → decidir si va a `RolesEsperados` o `RolesNoEsperados`.

Cada una de esas tres brechas genera su propio hallazgo, de modo que la línea base converge a completitud con el uso.

---

## Salidas

```
Output\<RunId>\
├── Reporte-Auditoria.html        Expediente completo, autocontenido
├── MANIFIESTO-INTEGRIDAD.json    SHA256 de cada archivo (cadena de custodia)
├── csv\
│   ├── HALLAZGOS.csv                Todos los hallazgos con severidad y control ISO
│   ├── COBERTURA-ISO.csv            Matriz control → capa → conformidad
│   ├── GLOSARIO-CONTROLES-ISO.csv   Descripción de cada control citado
│   ├── INVENTARIO-SOFTWARE.csv      Entregable de la capa L4 (descripción + ruta + rol)
│   ├── LINEA-BASE-ARQUITECTURA.csv  Entregable del mapeo EA
│   ├── RESUMEN-CAPAS.csv            Riesgo ponderado por capa
│   ├── BRECHAS-EVIDENCIA.csv        Límites reales del alcance
│   └── L*-*.csv                     Datos crudos por colector
└── raw\                             Los mismos datos en JSON

Logs\audit-<RunId>.log            Traza de ejecución
```

El **manifiesto de integridad** registra el SHA256 de cada archivo de evidencia. Sustenta la reproducibilidad exigida por la cláusula 9.2 (auditoría interna) y permite demostrar que la evidencia no fue alterada después de la recolección.

---

## Puntaje de riesgo

```
riesgo = Σ ( puntos_severidad × peso_capa )

Critical 10 · High 6 · Medium 3 · Low 1 · Info 0
```

| Puntaje | Nivel |
|---------|-------|
| ≥ 200 | CRÍTICO |
| 100–199 | ALTO |
| 40–99 | MEDIO |
| 1–39 | BAJO |

Es una métrica **relativa y comparable entre ejecuciones del mismo servidor**, útil para evidenciar tendencia de remediación (cláusula 10.1). No es un puntaje absoluto ni comparable contra otras organizaciones.

---

## Conformidad reportada

| Estado | Criterio |
|--------|----------|
| **Conforme** | Control evidenciado, sin hallazgos |
| **Conforme con observaciones** | Solo hallazgos Medium/Low |
| **No conforme** | Al menos un hallazgo Critical o High |
| **No evaluado** | Ningún colector del control llegó a ejecutarse |

El campo **Nivel de cobertura** indica hasta dónde llega la evidencia automatizada:

- **Total** — el colector evidencia el control de forma suficiente.
- **Parcial** — aporta evidencia, requiere complemento documental o entrevista.
- **Indicio** — solo señala síntomas; no sustituye la revisión formal del auditor.

Los controles organizacionales y de personas (5.x, 6.x) se evidencian solo parcialmente por diseño: su cumplimiento pleno requiere documentación fuera del alcance de un script.

---

## Configuración

Todo lo ajustable vive en `Config\` — no hay que tocar el código de los colectores.

### `Audit.config.psd1`

| Sección | Qué ajustar |
|---------|-------------|
| `Scope` | **Completar `Organizacion` y `Responsable`** — aparecen en el reporte |
| `Layers` | Pesos de cada capa para el puntaje de riesgo |
| `Thresholds` | Días sin parche, % disco libre, cuentas inactivas, longitud de contraseña |
| `UnmanagedScan` | Rutas a escanear en busca de shadow IT, exclusiones, tope de archivos |
| `EndOfLife` | **Catálogo de fin de soporte** — mantenerlo actualizado es la base de A.8.8 |
| `SoftwareNoPermitido` | Patrones de software fuera de política y su severidad |
| `PublicadoresConfiables` | Editores aprobados; reduce el ruido en A.8.19 |

### `ISO27001.Mapping.psd1`

Mapeo control → capas → colectores → nivel de cobertura, más la **descripción normativa** de cada control (`Descripcion` = qué exige la norma; `Objetivo` = qué verifica esta auditoría). Esos dos campos alimentan el **glosario que aparece al final del informe**, que solo lista los controles efectivamente citados.

Agregar un control nuevo es añadir una entrada aquí; el reporte lo recoge automáticamente. Si un hallazgo cita un control ausente del mapeo, el glosario lo señala al pie para que se complete.

### `Arquitectura.psd1`

Línea base de Arquitectura Empresarial — ver la sección dedicada más arriba.

---

## Primeros pasos recomendados

1. Completar `Scope.Organizacion` y `Scope.Responsable` en `Audit.config.psd1`.
2. Ejecutar una vez como administrador y revisar **Brechas de evidencia** en el reporte.
3. Ajustar `UnmanagedScan.Rutas` a las rutas reales donde esta organización despliega software.
4. Revisar los hallazgos de *publicador no catalogado* (L4-04) y añadir los editores legítimos a `PublicadoresConfiables`. Baja mucho el ruido en la segunda corrida.
5. A partir de la tercera ejecución, comparar `PuntajeRiesgo` entre corridas como evidencia de mejora continua.

---

## Automatización

```powershell
# Tarea programada semanal con purga de ejecuciones antiguas
$acc = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Audit\Invoke-Audit.ps1" -Purge'
$trg = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 3am
Register-ScheduledTask -TaskName 'Auditoria-ISO27001' -Action $acc -Trigger $trg `
    -RunLevel Highest -Description 'Auditoria semanal de artefactos ISO/IEC 27001'
```

El orquestador devuelve un objeto con `Resumen`, `Hallazgos`, `Capas`, `Cobertura` y `Brechas`, apto para integrarse con monitoreo:

```powershell
$r = .\Invoke-Audit.ps1 -Quick
if ($r.Resumen.Criticos -gt 0) { <# alertar #> }
```

`-Purge` elimina ejecuciones anteriores a `Report.RetencionDias` (180 por defecto).

---

## Requisitos y notas técnicas

- **Windows PowerShell 5.1+** (validado en Windows Server 2022 / PS 5.1).
- Los `.ps1` se mantienen en **ASCII sin tildes** de forma deliberada: PS 5.1 interpreta archivos sin BOM como ANSI y corrompería los acentos. Las salidas (HTML/CSV/JSON) sí se escriben como **UTF-8 con BOM**.
- Un colector que falla no detiene la auditoría: se marca como `Failed` y el resto continúa.
- Duración típica: ~2 min en modo completo, ~1 min con `-Quick`.

### Agregar un colector

1. Crear `Collectors\L<capa>-<nn>_Nombre.ps1`.
2. Declarar `param([switch]$Manifest, [hashtable]$Config)` y devolver el manifiesto si `-Manifest`.
3. Devolver `New-CollectorResult -Meta $meta -Records ... -Findings ... -Metrics ... -Gaps ...`.
4. Registrar el Id en `ISO27001.Mapping.psd1` bajo los controles que evidencia.

El orquestador lo descubre solo — no hay registro central que actualizar.
