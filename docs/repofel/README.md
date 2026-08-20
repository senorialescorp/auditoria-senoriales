# Documentación del software propio de SRV-SAP

Documentación técnica de los artefactos de software desarrollados internamente o a la
medida que operan en el servidor `SRV-SAP` (10.4.6.13), con su inventario de
dependencias.

**Alcance.** Se documenta el software *propio*. El software de terceros —SAP Business
One, SQL Server, IIS, Checkmk, Tableau Bridge— aparece sólo cuando el software propio
depende de él. Para el inventario general del servidor, ver la ficha de auditoría en
`C:\Scripts\Audit\Output\LINEA-BASE-20260813`.

**Levantado el** 17/08/2026, con la cuenta `SRV-SAP\svalle` (sin privilegios
administrativos). Cada documento cierra con una sección de pendientes de verificación
que enumera lo que esa limitación dejó abierto.

---

## Documentos

| Documento | Artefacto | Tipo | Estado |
|---|---|---|---|
| [REPOFEL.md](REPOFEL.md) | **REPOFEL** — repositorio de factura electrónica | Aplicación web PHP | Producción, activo |
| [SSO-Asientos-Contables.md](SSO-Asientos-Contables.md) | **SSO.TRF** — instalador de asientos contables | Escritorio .NET (proveedor REVCOM) | Producción |
| [Consultas-RENAP.md](Consultas-RENAP.md) | **Consultas RENAP** | Escritorio .NET / ClickOnce | Producción |
| [Conectores-CFDI.md](Conectores-CFDI.md) | **Conector** y **ConectorCapillas** | Integración por carpetas | Uno activo, uno por confirmar |
| [Suite-Auditoria.md](Suite-Auditoria.md) | **Suite de Auditoría** | PowerShell | Herramienta interna |
| [DEPENDENCIAS.md](DEPENDENCIAS.md) | *Todos* | Inventario consolidado | — |

## Auditorías

| Documento | Alcance | Fecha | Hallazgos críticos |
|---|---|---|---|
| [Auditoria-Permisos-Usuarios.md](Auditoria-Permisos-Usuarios.md) | Cuentas locales y permisos sobre los artefactos de software del servidor | 17/08/2026 | 2 |
| [Auditoria-Permisos-REPOFEL.md](Auditoria-Permisos-REPOFEL.md) | Usuarios, autenticación y autorización dentro de REPOFEL | 17/08/2026 | 3 |

## Vigilancia

| Herramienta | Qué hace | Estado |
|---|---|---|
| [Watch-WebLogs.ps1](../Watch/README.md) | Detecta indicadores de compromiso sobre los registros de acceso de IIS: 13 reglas derivadas de los hallazgos de la auditoría | Operativo a mano; pendiente instalarlo como chequeo local de Checkmk (requiere admin) |

---

## Panorama

Cinco artefactos propios, ninguno bajo control de versiones:

| Artefacto | Lenguaje | Dependencias externas | Repositorio | Documentación previa |
|---|---|---|---|---|
| REPOFEL | PHP 8.1 | 12 paquetes (Composer + manual) | No | No |
| SSO.TRF | .NET Framework | ~60 ensamblados | No (proveedor) | No |
| Consultas RENAP | .NET Framework | 2 (RestSharp, Newtonsoft.Json) | No | No |
| Conectores CFDI | Ejecutable de terceros + config propia | Chilkat 9.5.0 | No | No |
| Suite de Auditoría | PowerShell 5.1 | **Ninguna** | No | Sí (`README.md`) |

Dos observaciones transversales:

**Ningún artefacto está en un repositorio.** No existe un solo directorio `.git` en el
servidor, pese a que `C:\Tools\PortableGit` y `C:\Tools\gh` ya están instalados. En
REPOFEL esto es visible en el código: hay parches recientes insertados sobre lógica de
2022 sin ningún rastro de autoría ni motivo, y las dos instancias (Guatemala y México)
se mantienen sincronizadas a mano, con divergencias ya medibles.

**Los símbolos de depuración viajan a producción.** Ocho archivos `.pdb` entre SSO.TRF
y Consultas RENAP, más la documentación XML de cada ensamblado propio. Exponen la
estructura interna del código sin aportar nada en ejecución.

---

## Lo urgente

Todo lo urgente está en REPOFEL, y el orden lo determina un hecho que conviene fijar
primero: **la aplicación está publicada en internet y recibe sondeos de explotación
automatizados.** El 17/08/2026, entre las 09:43:42 y las 09:43:47, la dirección
`185.60.136.87` lanzó un barrido de 26 peticiones buscando el ejecutor remoto de PHPUnit
(CVE-2017-9841). Las 26 devolvieron 404 —PHPUnit no está instalado— pero el 42 % del
tráfico de la jornada fueron 404: es exploración, no usuarios. Y los tres perfiles del
firewall de Windows están deshabilitados. Detalle en [REPOFEL.md](REPOFEL.md) §10.

Sobre ese fondo:

1. **`z.php` publica la sesión completa.** Setenta y cinco bytes sin validación alguna
   que hacen `var_dump($_SESSION)`: identificador de usuario, perfil, permisos y el
   último POST recibido. Está en ambas instancias, alcanzable desde internet. Todavía
   no consta ninguna petición a esa ruta en los registros, así que aún no lo han
   encontrado. Borrarlo cuesta un minuto y es la corrección de mayor impacto de toda la
   lista. §8.2.

2. **Una sola contraseña de `sa` compartida entre servidores, en texto plano.** La que
   REPOFEL guarda en `php/cnbde.php` para `10.2.8.13` es **la misma** que los `.config`
   de SSO.TRF usan para `DB-SENO` y para el servidor `desarrollo`. Cinco destinos SQL
   distintos se alcanzan desde este equipo con la cuenta `sa`, todos con la credencial
   en claro: los archivos de REPOFEL son legibles por cualquiera con acceso a `G$`, y
   los de SSO.TRF están en `C:\Program Files (x86)`, legible por el grupo *Usuarios*.
   Como REPOFEL está expuesto a internet, comprometerlo entrega `sa` en varios motores
   a la vez. Detalle en [SSO-Asientos-Contables.md](SSO-Asientos-Contables.md) §4.1 y
   [REPOFEL.md](REPOFEL.md) §8.1.

3. **PHP 8.1 sin soporte de seguridad** desde el 31/12/2025, sirviendo esa aplicación
   expuesta. Con él, PhpSpreadsheet 1.24.1 y PHPMailer 6.6.0 atrasadas, ambas
   procesando entrada externa. Ver [DEPENDENCIAS.md](DEPENDENCIAS.md) §7.

4. **Escritura de archivo con ruta construida desde entrada del usuario** en
   `cardoc_a.php`, y validación del tipo de archivo por el MIME que declara el cliente.
   §8.3 y §8.4.

La lista completa y priorizada está en [DEPENDENCIAS.md](DEPENDENCIAS.md) §7.

---

## Qué falta

La documentación cubre el software propio **que tiene código en este servidor**. Quedan
tres huecos reales, en orden de importancia.

### 1. Once bases de datos sin código localizable — el hueco más grande

El servidor aloja bases de datos de aplicaciones cuyo código **no está aquí**. Se buscó
por nombre en las raíces de `C:`, `E:`, `F:` y `G:` y ninguna tiene carpeta asociada:

| Base de datos | Nombre interno / pista |
|---|---|
| `SSO_INT_SBO` | `SSO_INT_DOMISOL` — 86 GB, la segunda más grande del servidor |
| `SSO_WEB_SEG` | `SSO.Web.POS` — punto de venta web |
| `SSO_DOCUMENTOSBO` | y sus variantes `...SEN`, `...PAR`, `..._MAPER_Data` |
| `SENCOBRO` | Gestión de cobros |
| `IFSERV` | — |
| `RSP` | — |
| `INTRANET_SENORIALES` | Intranet corporativa |
| `Scout` | 9 GB |
| `Accesos_Aplicaciones` | Control de accesos a aplicaciones |
| `DBA_Tools` | Utilitarios de administración de base de datos |
| `SAPI_Mexico` | — |

El prefijo `SSO.` coincide con el del artefacto de REVCOM ya documentado
([SSO-Asientos-Contables.md](SSO-Asientos-Contables.md)), lo que apunta a una familia de
aplicaciones del mismo proveedor. Para documentarlas hace falta saber **en qué servidor
corre cada una**; este equipo sólo hospeda sus datos. Es una conversación con REVCOM y
con quien administre los servidores de aplicaciones, no un problema de acceso.

### 2. Configuración: leída, con dos puntos aún abiertos

Los archivos de configuración de SSO.TRF **ya se leyeron** (17/08/2026) y de ahí salió el
hallazgo de la contraseña de `sa` compartida, el mapa de seis servidores SQL y la
integración con Guatefacturas. Quedan dos cabos:

- **Consultas RENAP** — se leyó `BRL.dll.config` y **no contiene** el *endpoint* ni la
  llave de acceso, contra lo que se esperaba: sólo configuración de bitácora y un bloque
  `system.serviceModel` vacío. La dirección de la API está embebida en `BRL.dll` /
  `DAL.dll` o la escribe `Setting.exe` en un destino no identificado. Relevante porque
  la aplicación consulta datos personales de ciudadanos.
- **ConectorCapillas** — la carpeta `Parametros\` se listó vacía en dos intentos; o está
  realmente vacía, o la cuenta `svalle` no puede leerla.

Pendiente también: versiones exactas de `RestSharp`, `Newtonsoft.Json` y `log4net`, y la
identificación del proceso que ejecuta el ciclo de un minuto de `ConectorCapillas`.

### 3. Lo que exige privilegios administrativos

- **SQL Server** — el inicio de sesión con `svalle` fue rechazado. Los modelos de datos
  de estos documentos se derivaron de las consultas presentes en el código, no de
  `INFORMATION_SCHEMA`. Faltan tipos, llaves, índices, procedimientos, vistas y
  *triggers*, y los permisos efectivos de `usrRepo`.
- **IIS** — los tres sitios quedaron identificados por sus registros de acceso
  (ver [REPOFEL.md](REPOFEL.md) §9), pero no sus *bindings*: nombre de host,
  certificado TLS, y la identidad del grupo de aplicaciones con que corre PHP.
- **Tareas programadas** — la enumeración completa requiere elevación.

Una corrida de la suite en consola elevada (`C:\Scripts\Audit\Invoke-Audit.ps1`) cierra
las brechas de plataforma. El resto requiere lectura directa de los archivos citados o
información que sólo tiene el proveedor.
