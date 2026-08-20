# Suite de Auditoría de Artefactos

Herramienta propia en PowerShell que levanta el inventario técnico del servidor y lo
evalúa contra un marco de criterios de auditoría de sistemas. Es el artefacto de
desarrollo interno más reciente y el único que **sí tiene documentación previa**
(`README.md`, 14 KB).

| | |
|---|---|
| **Ubicación** | `C:\Scripts\Audit` |
| **Lenguaje** | PowerShell 5.1 (Windows PowerShell) |
| **Punto de entrada** | `Invoke-Audit.ps1` (25 KB) |
| **Creado** | 11/08/2026 · última modificación 13/08/2026 |
| **Naturaleza** | **Solo lectura** — no modifica configuración, no instala, no reinicia servicios |
| **Dependencias externas** | **Ninguna** |
| **Control de versiones** | Ninguno en el servidor (existe `PortableGit` en `C:\Tools`, sin repositorio inicializado) |

---

## 1. Diseño

La auditoría se organiza en **nueve capas verticales**, cada una con un peso que
multiplica la severidad de sus hallazgos en el puntaje de riesgo agregado. La capa L4
(artefactos de software) pondera el doble por ser el eje del alcance:

| Capa | Nombre | Peso |
|---|---|---|
| L1 | Infraestructura física y hardware | 0.8 |
| L2 | Sistema operativo y hardening | 1.2 |
| L3 | Plataforma, runtimes y middleware | 1.5 |
| **L4** | **Artefactos de software** | **2.0** |
| L5 | Servicios, procesos y persistencia | 1.5 |
| L6 | Identidad y control de acceso | 1.4 |
| L7 | Red y exposición | 1.3 |
| L8 | Datos, registro y resiliencia | 1.1 |
| L9 | Rendimiento y capacidad | 0.9 |

Opera en dos dimensiones simultáneas: **cumplimiento** (cada evidencia se mapea contra
controles del Anexo A de ISO/IEC 27001:2022) y **arquitectura empresarial** (cada
artefacto se clasifica por rol arquitectónico y capa EA, y se evalúa si ese rol
corresponde al propósito declarado del servidor; la diferencia entre lo declarado y lo
encontrado *es* el hallazgo).

---

## 2. Estructura del proyecto

```
C:\Scripts\Audit\
├── Invoke-Audit.ps1              orquestador (25 KB)
├── bootstrap.ps1                 preparación del entorno (3 KB)
├── README.md                     documentación (14 KB)
├── Modules\AuditCore\
│   ├── AuditCore.psm1            núcleo: contexto, hallazgos, criterios (28 KB)
│   ├── ExcelWriter.psm1          generador nativo de .xlsx (15 KB)
│   └── WordWriter.psm1           generador nativo de .docx (agregado 17/08/2026)
├── Collectors\                   17 colectores, uno por archivo
│   ├── L1-01_Hardware-Inventory.ps1
│   ├── L2-01_OS-Baseline.ps1 · L2-02_Patch-Level.ps1 · L2-03_Security-Config.ps1
│   ├── L3-01_Runtimes-Middleware.ps1
│   ├── L4-01_Installed-Software.ps1 · L4-02_Package-Managers.ps1
│   ├── L4-03_Unmanaged-Binaries.ps1 · L4-04_Software-Integrity.ps1
│   ├── L4-05_Software-Lifecycle.ps1 · L4-06_EA-Baseline.ps1
│   ├── L5-01_Services.ps1 · L5-02_Autoruns-Tasks.ps1
│   ├── L6-01_Identity-Access.ps1
│   ├── L7-01_Network-Exposure.ps1
│   ├── L8-01_Logging-Backup.ps1
│   └── L9-01_Server-Stats.ps1
├── Config\
│   ├── Arquitectura.psd1         catálogo EA: rol del servidor, aplicaciones, roles (15 KB)
│   ├── Audit.config.psd1         parámetros de la corrida y umbrales (10 KB)
│   └── Criterios.Auditoria.psd1  37 criterios y su mapeo (22 KB)
├── Reports\
│   ├── New-AuditExcel.ps1        libro de trabajo por capas (13 KB)
│   ├── New-AuditFicha.ps1        ficha imprimible A4 en HTML (16 KB)
│   └── New-AuditFichaDocx.ps1    ficha A4 en Word (agregado 17/08/2026)
├── Output\<RunId>\               expediente por corrida
│   ├── raw\*.json                evidencia cruda por colector
│   ├── csv\*.csv                 evidencia tabulada
│   ├── evidence\                 anexos
│   ├── Auditoria-<host>-<run>.xlsx
│   ├── Ficha-<host>-<run>.html
│   ├── Ficha-<host>-<run>.docx
│   └── MANIFIESTO-INTEGRIDAD.json
└── Logs\audit-<RunId>.log
```

---

## 3. Uso

```powershell
cd C:\Scripts\Audit

.\Invoke-Audit.ps1                      # auditoría completa
.\Invoke-Audit.ps1 -SoftwareOnly        # sólo la capa prioritaria (L4)
.\Invoke-Audit.ps1 -Quick               # omite escaneo de binarios y muestreo de rendimiento
.\Invoke-Audit.ps1 -Layer L2,L4,L7      # capas específicas
.\Invoke-Audit.ps1 -Collector L4-01,L4-05
```

Al terminar abre `Output\<RunId>\Reporte-Auditoria.html`.

### Ficha en Word

Desde el 17/08/2026 cada corrida emite además la ficha en `.docx`, para entregarse como
reporte formal o firmarse. Se genera de forma independiente para cualquier corrida
pasada, porque se alimenta del expediente en `raw\*.json` y no de los objetos vivos:

```powershell
.\Reports\New-AuditFichaDocx.ps1                          # última corrida
.\Reports\New-AuditFichaDocx.ps1 -RunId LINEA-BASE-20260813
```

`WordWriter.psm1` construye el paquete OOXML (WordprocessingML sobre ZIP) directamente,
con el mismo criterio que `ExcelWriter.psm1`: **Word no está instalado en este servidor**
—sólo quedan restos de `Office14` y la clase COM `Word.Application` no está registrada—,
y la auditoría no debe instalar dependencias en el activo que audita.

### Comportamiento sin privilegios

La suite corre igual sin elevación y **degrada de forma explícita**: cada control que
no puede evidenciarse queda registrado en la sección *Brechas de evidencia* del reporte,
en lugar de aparentar cobertura total. Sin elevación no pueden verificarse:

- BitLocker (`Get-BitLockerVolume`)
- Directiva de auditoría (`auditpol`)
- Registro de eventos de seguridad
- SMBv1 como característica (`Get-WindowsOptionalFeature`)
- Suscripciones WMI en `root\subscription`
- Instantáneas de volumen (`Win32_ShadowCopy`)
- Enumeración completa de tareas programadas
- Módulo `WebAdministration` de IIS (grupos de aplicaciones y sitios)

Para un expediente formal debe ejecutarse en consola elevada.

---

## 4. Dependencias

**Ninguna externa.** Es una decisión de diseño documentada en el encabezado de
`ExcelWriter.psm1`:

> «Escribe el formato OOXML (SpreadsheetML) directamente sobre un contenedor ZIP usando
> `System.IO.Compression`. NO requiere Microsoft Excel instalado, ni el módulo
> ImportExcel, ni interoperabilidad COM: importante porque en un servidor de producción
> normalmente no existe ninguno de los tres, y porque instalar dependencias en el
> activo auditado contradice el principio de que la auditoría no debe alterar el
> sistema.»

Esa restricción es acertada y debe conservarse en cualquier extensión futura. Se
confirmó en la práctica: **Microsoft Word no está instalado** en este servidor (sólo
quedan restos de `Office14`), y el intento de instanciar `Word.Application` por COM
falla con `REGDB_E_CLASSNOTREG`.

### Superficie de plataforma utilizada

| Recurso | Uso |
|---|---|
| Windows PowerShell 5.1 | Intérprete |
| `System.IO.Compression` / `.FileSystem` | Empaquetado OOXML |
| `System.Text.StringBuilder`, `UTF8Encoding` | Generación de XML |
| CIM/WMI (`Get-CimInstance`) | Hardware, SO, servicios |
| `Get-ItemProperty` sobre `HKLM\...\Uninstall` | Inventario de software |
| `Get-AuthenticodeSignature` | Integridad de binarios (L4-03, L4-04) |
| `Get-NetTCPConnection`, `Get-NetFirewallProfile` | Exposición de red (L7) |
| `Get-WinEvent`, `Get-EventLog` | Registro y resiliencia (L8) |
| Contadores de rendimiento | Muestreo (L9) |

---

## 5. Estado de la última corrida

| | |
|---|---|
| **RunId** | `LINEA-BASE-20260813` |
| **Fecha** | 13/08/2026 09:26–09:29 (184 s) |
| **Ejecutado por** | `SRV-SAP\svalle` — **sin elevación** |
| **Colectores** | 17 de 17 correctos, 0 fallidos |
| **Registros** | 1 519 |
| **Hallazgos** | 48 (3 críticos, 16 altos, 19 medios, 9 bajos, 1 informativo) |
| **Puntaje de riesgo** | 288.4 — **CRÍTICO** |
| **Criterios** | 37 evaluados, 16 no conformes |
| **Brechas de evidencia** | 8 |

Corrida de verificación posterior, `20260817-110307` (17/08/2026, 198.7 s): mismos 48
hallazgos y mismo puntaje de 288.4, con dos variaciones por el paso del tiempo —la
latencia de parcheo subió de 105 a 109 días y las actualizaciones pendientes de 3 a 4—.
La estabilidad del resultado entre dos corridas separadas por cuatro días indica que
ningún hallazgo se ha remediado todavía.

Corridas anteriores en `Output\`: `20260811-184912`, `TEST-EA2`, `PRUEBA`, `PRUEBA2`.
Conviene depurar las de prueba para que el expediente conserve sólo líneas base
válidas.

---

## 6. Observaciones sobre el propio artefacto

| Severidad | Observación |
|---|---|
| **Medio** | Sin control de versiones. La suite misma es el tipo de artefacto que su colector `L4-03` marca como «scripts operativos sin control de versiones ni firma» — el hallazgo aplica a ella. `C:\Tools\PortableGit` ya está disponible para remediarlo. |
| **Medio** | Los campos `Organizacion`, `Propietario`, `ResponsableTecnico` y `UnidadNegocio` de `Arquitectura.psd1` están en `DEFINIR`. Mientras no se llenen, la ficha se emite con «SIN ASIGNAR» y el hallazgo «el servidor no tiene propietario declarado» se repite en cada corrida. |
| **Bajo** | Cuatro corridas de prueba conviven con la línea base en `Output\`. |
| **Bajo** | El catálogo EA declara REPOFEL como aplicación de negocio esperada, pero el colector `L4-06` la reporta «Declarada, NO detectada»: REPOFEL no se registra en el inventario de software de Windows porque es un sitio de IIS, no un paquete instalado. Conviene añadir al colector una regla que detecte aplicaciones publicadas por ruta (`G:\REPOFEL`), no sólo por registro. |

### Defecto encontrado: `-Collector` con un solo colector falla

Al ejecutar `.\Invoke-Audit.ps1 -Collector L1-01`, la corrida completa los colectores
pero **aborta en la fase de consolidación**:

```
Consolidando resultados...
Invoke-Audit.ps1 : Cannot bind argument to parameter 'Data' because it is an empty array.
```

Es un defecto preexistente, no relacionado con la ficha en Word: la excepción ocurre
antes de la sección de reportes. La causa es que `Export-AuditArtifact`
(`AuditCore.psm1:686`) declara `[Parameter(Mandatory)][object[]]$Data`, y PowerShell
rechaza un arreglo vacío en un parámetro obligatorio **antes** de que la propia función
pueda aplicar su tolerancia interna (`AuditCore.psm1:695`, que ya contempla el caso
`Count -eq 0`). Con un solo colector, alguna de las colecciones consolidadas
—`$cobertura`, `$brechas` o `$glosario`— llega vacía.

Corrección sugerida: añadir `[AllowEmptyCollection()]` al parámetro `$Data`. La
validación interna ya existe, así que el cambio es de una línea y no altera el
comportamiento de las corridas completas.

No lo corregí porque está fuera de lo solicitado; queda registrado aquí. Las corridas
completas y las de capa (`-Layer`) no se ven afectadas.

---

*Documento generado el 17/08/2026 a partir de la lectura de `C:\Scripts\Audit`, su
`README.md` y los resultados de la corrida `LINEA-BASE-20260813`.*
