# Conectores de facturación electrónica (CFDI)

Dos canales de integración basados en carpetas para el timbrado y envío de
comprobantes fiscales digitales de México. No son aplicaciones propias en sentido
estricto —el motor es un ejecutable de terceros— pero **la integración sí es propia**:
el flujo depende de una estructura de carpetas y de un archivo de parámetros
mantenidos internamente.

---

## 1. `C:\Conector` — Conector Advans

Canal principal de CFDI. Un ejecutable vigila carpetas, timbra los comprobantes contra
el proveedor autorizado de certificación y mueve los archivos según el resultado.

| | |
|---|---|
| **Motor** | `AdvUploaderT.exe` (07/06/2022) |
| **Configuración** | `AdvUploaderT.ini` (27/06/2023) |
| **Proveedor** | Advans (sección `[Advans]` del `.ini`) |
| **Dependencia de terceros** | `ChilkatAx-9.5.0-win32.dll` (25/02/2020) |

### Componente Chilkat

`ChilkatAx-9.5.0-win32.dll` es el control ActiveX de Chilkat 9.5.0, biblioteca
comercial de cifrado, firma digital y comunicaciones. La carpeta incluye los scripts de
registro COM del componente:

```
register_win32.bat     register_x64.bat
unregister_win32.bat   unregister_x64.bat
license.txt (09/07/2013)
```

La versión 9.5.0 de Chilkat con fecha de archivo 2020 está varias generaciones por
detrás de la rama actual. Al ser el componente que realiza la firma criptográfica de
los comprobantes, conviene verificar con Advans qué versión soportan hoy.

### Estructura de carpetas del flujo

| Carpeta | Rol |
|---|---|
| `Pendientes\` | Entrada — comprobantes por timbrar (última actividad: **29/12/2025**) |
| `Enviados\` | Timbrados correctamente; también configurada como carpeta de descarga |
| `Erroneos\` | Rechazados por el proveedor o por validación |
| `CFDIs\` | Repositorio de comprobantes (30/06/2022) |
| `Logs\` | Bitácora del ejecutable |

### Parámetros (`AdvUploaderT.ini`)

| Clave | Valor | Comentario |
|---|---|---|
| `RFC` | `CCN1705038N2` | RFC del emisor — corresponde a *Capillas y Cementerios del Norte* |
| `LUGAREXP` | `97000` | Lugar de expedición (código postal, Campeche) |
| `REGIMEN` | Régimen General de Ley Personas Morales | Régimen fiscal |
| `XML` / `PDF` | 1 / 1 | Genera ambos formatos |
| `IMPCFDI` | 0 | Sin impresión automática |
| `COPIAS` | 1 | |
| `CONV20` | 1 | Conversión a CFDI 4.0 / versión 2.0 del esquema |
| `EMAIL` | 1 | Envío de comprobante por correo activado |
| `EMAILREF` | 0 | Sin correo de referencia |
| `UTF8` / `BOM` | 0 / 0 | Salida sin marca de orden de bytes |
| `SERIES` | *(vacía)* | Sin series configuradas |
| `[Impresoras]` | *(vacía)* | |

**Credenciales.** Cuatro claves están cifradas u ofuscadas por la propia aplicación,
en Base64: `URL`, `USER`, `PASS` y `MAIL`. No están en texto plano —a diferencia de lo
que ocurre en REPOFEL— pero el esquema es reversible por quien conozca el algoritmo del
proveedor. Los valores no se reproducen en este documento.

### Observaciones

- La carpeta `Pendientes\` no registra actividad desde el **29 de diciembre de 2025**,
  mientras que `ConectorCapillas` sí operaba en 2025. Hay que confirmar si este canal
  sigue en uso o quedó reemplazado.
- `Conector txt2023.rar` (03/01/2023) es un respaldo comprimido dejado en la carpeta de
  producción.
- El `license.txt` de Chilkat es de 2013.

---

## 2. `C:\ConectorCapillas` — Conector de Capillas

Segundo canal, con una estructura de carpetas más elaborada y evidencia de operación
más reciente. No se identificó ejecutable propio en la raíz; el proceso que lo alimenta
está por determinar.

### Estructura

| Carpeta | Rol |
|---|---|
| `Archivos_Recibidos\` | Entrada de comprobantes |
| `Archivos Procesados\` | Procesados correctamente |
| `Archivos Erroneos\` | Con error |
| `PorCancelar\` | Cola de cancelación ante el SAT |
| `Cancelados\` | Cancelaciones completadas |
| `Bitacora\` | Bitácoras archivadas |
| `Parametros\` | Configuración |

### Bitácoras — hallazgo relevante

El proceso escribe **un archivo de bitácora por cada ejecución, y se ejecuta cada
minuto**:

```
Bitacora_01_03_2025_000013.txt
Bitacora_01_03_2025_000113.txt
Bitacora_01_03_2025_000213.txt
...
```

El patrón `Bitacora_DD_MM_AAAA_HHMMSS.txt` con incrementos de 60 segundos implica del
orden de **1 440 archivos por día**. Se acumulan en la raíz de `C:\ConectorCapillas`,
no en la carpeta `Bitacora\` prevista para ello. Esto contribuye directamente a la
ocupación del volumen `C:` —hoy al 88 %— y degrada el rendimiento del directorio.

**Recomendación:** consolidar la bitácora en un archivo diario con rotación, o al menos
mover los archivos existentes a `Bitacora\` y establecer una política de purga.

### Pendientes

- El contenido de `Parametros\` no pudo enumerarse en este levantamiento (la carpeta
  se listó vacía o sin permiso de lectura para la cuenta `svalle`). Es donde debería
  estar el RFC, el régimen y las credenciales de este canal.
- Identificar el proceso que ejecuta el ciclo de un minuto: puede ser una tarea
  programada (la enumeración completa requiere privilegios administrativos) o un
  servicio no evidente. Ninguno de los 141 servicios en ejecución tiene nombre
  relacionado.
- Confirmar la relación entre este canal y `C:\Conector`: si son proveedores distintos,
  empresas distintas o una migración a medio camino.

---

## 3. Software contable relacionado

`C:\Compac` contiene una instalación de **CONTPAQi / Compac**, sistema contable
mexicano, con tres carpetas: `Empresas\`, `Index\` e `Instal\` (todas del 12/12/2025).
Es software de terceros, pero conviene documentar la relación entre las empresas
definidas ahí y los canales de CFDI anteriores, ya que ambos operan sobre la misma
realidad fiscal mexicana.

---

## 4. Resumen de riesgos

| Severidad | Observación |
|---|---|
| **Alto** | El componente que firma criptográficamente los CFDI (Chilkat 9.5.0) tiene archivos de 2020 y licencia de 2013. Sin confirmación de soporte del proveedor. |
| **Medio** | Acumulación de ~1 440 bitácoras diarias en la raíz de `C:\ConectorCapillas`, en un volumen al 88 % de ocupación. |
| **Medio** | Credenciales de `C:\Conector` ofuscadas en Base64 dentro del `.ini`: mejor que texto plano, pero reversible. |
| **Medio** | Sin claridad sobre qué canal está vigente; `C:\Conector\Pendientes` sin actividad desde diciembre de 2025. |
| **Bajo** | Respaldo `.rar` de 2023 en carpeta de producción. |
| **Bajo** | Sin documentación previa del flujo ni responsable asignado. |

---

*Documento generado el 17/08/2026 a partir de la lectura de `AdvUploaderT.ini` y del
inventario de carpetas de `C:\Conector`, `C:\ConectorCapillas` y `C:\Compac`.
Ver [DEPENDENCIAS.md](DEPENDENCIAS.md).*
