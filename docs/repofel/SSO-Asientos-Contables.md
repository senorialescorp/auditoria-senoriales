# SSO.TRF — Instalador de Asientos Contables

Aplicación de escritorio en .NET Framework que inyecta asientos contables en SAP
Business One. Es software desarrollado a la medida por un proveedor externo, y es el
artefacto propio **mejor identificado** del servidor: conserva los símbolos de
depuración de su compilación.

| | |
|---|---|
| **Nombre del paquete** | `SSO.TRF.InstaladorAsientosContables` |
| **Versión** | 10.0.0 |
| **Editor** | **REVCOM** |
| **Instalado** | 04/01/2024 |
| **Ubicación** | `C:\Program Files (x86)\REVCOM\SSO.TRF.InstaladorAsientosContables` |
| **Plataforma** | .NET Framework, x86 |
| **Ejecutable** | `SSO.TRF.Controlador.exe` (4.0 MB, compilado 04/01/2024) |

El prefijo `SSO.` y el segmento `TRF` (probablemente *transferencia*) son la convención
de nombres del proveedor; el mismo prefijo aparece en varias bases de datos del
servidor (`SSO_INT_SBO`, `SSO_DOCUMENTOSBO`, `SSO_WEB_SEG`), lo que indica una familia
de aplicaciones del mismo origen.

---

## 1. Composición del artefacto

### Ensamblados propios

| Archivo | Tamaño | Compilado | Símbolos |
|---|---|---|---|
| `SSO.TRF.Controlador.exe` | 4 004 864 | 04/01/2024 | — |
| `SSO.TRF.Mediador.dll` | 1 525 760 | 04/01/2024 | **`.pdb` presente** |
| `SSO.GEN.ServicioCalendario_Pruebas.exe` | 30 208 | 04/01/2024 | — |
| `SSO.GENERALES.dll` | 139 264 | 27/09/2013 | **`.pdb` presente** |
| `SSO.DB.dll` | 26 112 | 27/09/2013 | **`.pdb` presente** |
| `SSO.UI.dll` | 252 416 | 27/09/2013 | **`.pdb` presente** |
| `SSO.VB.dll` | 14 336 | 27/09/2013 | — |

Se distinguen dos generaciones de código: la capa base (`SSO.DB`, `SSO.GENERALES`,
`SSO.UI`, `SSO.VB`) es de **septiembre de 2013** y no se ha recompilado en más de una
década; la capa de aplicación (`Controlador`, `Mediador`) es de enero de 2024.
`SSO.VB.dll` sugiere que parte del código base está escrito en Visual Basic .NET.

El nombre `SSO.GEN.ServicioCalendario_Pruebas.exe` indica un **binario de pruebas
desplegado en producción**.

### Presencia de archivos `.pdb`

Cuatro ensamblados incluyen sus símbolos de depuración. Un `.pdb` expone rutas de
compilación, nombres de variables locales y números de línea, lo que facilita la
ingeniería inversa del binario. En una instalación de producción no aportan nada y
deberían retirarse del paquete de despliegue.

---

## 2. Dependencias

### Integración con SAP Business One

| Componente | Versión / fecha | Función |
|---|---|---|
| `Interop.SAPbobsCOM.dll` | 27/09/2013 | **Interoperabilidad COM con la DI API de SAP B1** |

Esta es la dependencia central: la aplicación crea los asientos a través de la DI API
(objetos `SAPbobsCOM`), no por SQL directo. El interop es de 2013, generado contra una
versión de la DI API muy anterior a la instalada hoy (10.00.201.102, enero 2025). Que
funcione depende de la compatibilidad binaria hacia atrás de SAP; es un riesgo latente
en cada actualización del ERP.

### Interfaz de usuario y reportería

| Biblioteca | Versión | Notas |
|---|---|---|
| **DevExpress** (WinForms) | **v23.1** (30/11/2023) | ~45 ensamblados: `XtraGrid`, `XtraEditors`, `XtraBars`, `XtraReports`, `XtraCharts`, `XtraPivotGrid`, `XtraRichEdit`, `XtraTreeList`, `XtraLayout`, `Pdf.Core`, `Printing.Core`, `Xpo`, `DataAccess`, `Drawing`, `Diagram`, `Images` |
| **Crystal Decisions** | 04/01/2024 | `CrystalDecisions.CrystalReports.Engine`, `.Shared`, `.ReportAppServer.*` (11 ensamblados) |

Nota: el servidor tiene instalado por separado **DevExpress Components 24.2** (versión
24.2.7, mayo 2025), una generación más nueva que la que consume esta aplicación. Son
dos versiones mayores coexistiendo, y la 24.2 está clasificada en la auditoría como
artefacto **no alineado** al rol del servidor (es un SDK de desarrollo).

Convive además con la instalación de SAP Crystal Reports for SAP Business One
(14.3.2.4272), de modo que hay dos motores de Crystal en el equipo.

### Otras dependencias

| Biblioteca | Versión / fecha | Función |
|---|---|---|
| `log4net.dll` | 04/01/2024 | Registro de eventos de la aplicación |
| `Newtonsoft.Json` | — | *(no presente en esta carpeta; sí en Consultas RENAP)* |
| `System.Net.Http.dll` | 19/06/2015 | Cliente HTTP |
| `Microsoft.MSXML.dll` | 09/05/2021 | Procesamiento XML |
| `stdole.dll`, `EnvDTE`, `EnvDTE80`, `VSLangProj`, `dte80.olb`, `dte80a.olb` | 2010–2021 | **Automatización de Visual Studio** |
| `Microsoft.VisualStudio.Shell.*`, `.TextManager`, `.OLE.Interop`, `.Designer`, `.Settings`, `.TemplateWizard`, `.ProjectAggregator`, `.ComponentModel` | 2009–2024 | **SDK de extensibilidad de Visual Studio** |

La presencia del SDK de Visual Studio y de los ensamblados `EnvDTE` en una aplicación
de asientos contables es anómala: son bibliotecas para automatizar el IDE, no para
operar en producción. Lo más probable es que el proveedor haya empaquetado la carpeta
`bin` completa de su entorno de desarrollo, arrastrando referencias que la aplicación
no usa. Habría que confirmarlo con REVCOM antes de retirarlas, pero infla el paquete y
amplía la superficie de ataque.

---

## 3. Configuración

Cuatro archivos `.config` más un almacén propietario:

| Archivo | Fecha | Contenido |
|---|---|---|
| `SSO.TRF.Controlador.exe.config` | 10/12/2023 | 3 cadenas de conexión + parámetros de operación |
| `SSO.TRF.Mediador.dll.config` | 10/12/2023 | 6 cadenas de conexión + servicio web externo |
| `SSO.GENERALES.dll.config` | 30/11/2006 | 4 cadenas de conexión heredadas |
| `SSO.GEN.ServicioCalendario_Promociones.exe.config` | 10/12/2023 | Parámetros de correo del servicio de promociones |
| `SSO_Param_Conn.eif` | 10/12/2023 | 536 bytes en Base64 → 400 bytes binarios, **cifrados** |

`SSO_Param_Conn.eif` sí protege su contenido: el Base64 decodifica a binario sin
estructura legible, no a texto. Es el único almacén de credenciales del paquete que está
correctamente protegido — y resulta redundante, porque las mismas credenciales están en
texto plano en los `.config` (ver §5.1).

### 3.1 Infraestructura revelada por las cadenas de conexión

Los `.config` describen un mapa de servidores y bases que va mucho más allá de este
equipo:

| Servidor | Bases de datos | Origen |
|---|---|---|
| `C2N_PAAS` | `SBOIntegracion`, `Señoriales_Final` | `Controlador`, `Mediador` |
| `DB-SENO` | `SBOIntegracion`, `SBOIntegracion_RH`, `37_Senoriales_Final` | `Mediador` |
| `desarrollo` | `SBOIntegracion` | `Mediador` — **servidor de desarrollo** |
| `rublan` | `SSO_SEG_V2` | `SSO.GENERALES` (2006) |
| `(local)` / `.` | `SSO_SEG_V2`, `SSO_POS_V2`, `SSO_TRADOFILES` | `SSO.GENERALES` (2006) |

`rublan` es un nombre de equipo personal, no de servidor: coincide con el nombre del
contacto técnico que aparece en los correos de configuración (§3.3). Es una cadena de
conexión a la máquina de un desarrollador, embarcada en el paquete de producción desde
2006.

Las bases `SSO_SEG_V2` (seguridad) y `SSO_POS_V2` (punto de venta) emparentan este
paquete con las bases huérfanas `SSO_WEB_SEG` / `SSO.Web.POS` que este servidor hospeda
sin alojar su código.

### 3.2 Servicio web externo

```
https://dte.guatefacturas.com:444/webservices63/svc01M/Guatefac
```

Declarado en `SSO.TRF.Mediador.dll.config`. **Guatefacturas** es un certificador
autorizado de documentos tributarios electrónicos (DTE) de Guatemala. Es decir, el
paquete no sólo genera asientos contables: también participa en la emisión de factura
electrónica guatemalteca, en paralelo a los conectores de CFDI mexicanos documentados
aparte. Conviene reflejarlo en el catálogo de arquitectura, donde hoy figura sólo como
«instalador de asientos contables».

### 3.3 Parámetros de operación y contactos

| Parámetro | `Controlador` (asientos) | `ServicioCalendario_Promociones` |
|---|---|---|
| Servidor SMTP | `smtp.gmail.com` | `mail.inforumsol.com` |
| Usa credenciales | **True**, pero usuario y clave **vacíos** | False |
| Correo de salida | `rhernandez@ssodn.com` | `rhernandez@inforumsol.com` |
| Correo del administrador | `rhernandez@ssodn.com` | `rublan.hernandez@integrasap.com` |
| Tiempo de espera | 1 000 ms | 60 000 ms |
| Procedimiento almacenado | `_SSO_TRF_FINALIZATRANSFERENCIA` | `_SSO_TRF_FINALIZATRANSFERENCIA` |
| Registros / archivos máximos | 500 / 20 | 500 / 20 |
| `GrabarLog` | **False** | *(no declarado)* |

Dos observaciones operativas:

- El `Controlador` tiene `SMTPUsaCredenciales = True` con usuario y contraseña vacíos
  contra `smtp.gmail.com`. **Las alertas por correo no pueden estar funcionando**, y
  las cuatro categorías de alerta están activadas (error de conexión SQL, no pudo
  iniciar, servicio detenido, error de sentencia SQL). Es decir: los fallos del proceso
  contable se notifican a un canal roto.
- `GrabarLog = False` en el proceso de asientos: sin bitácora propia, no hay rastro de
  qué transfirió ni cuándo.

### 3.4 Identidad del proveedor

El vínculo con REVCOM no es tan simple como lo registrado en Windows. Aparecen **cuatro
identidades distintas** ligadas a la misma persona:

| Dato | Origen |
|---|---|
| Publisher `REVCOM`, ruta `C:\Program Files (x86)\REVCOM\` | Registro de instalación de Windows |
| `rhernandez@ssodn.com` | `SSO.TRF.Controlador.exe.config` |
| `rhernandez@inforumsol.com` | `ServicioCalendario_Promociones.exe.config` |
| `rublan.hernandez@integrasap.com` | `ServicioCalendario_Promociones.exe.config` |
| Equipo `rublan` | Cadena de conexión de `SSO.GENERALES` (2006) |

REVCOM es lo que declara el paquete instalado, y es el dato formal. Pero el soporte
técnico real parece recaer en una misma persona —R. Hernández— que ha operado bajo
`ssodn.com`, `inforumsol.com` e `integrasap.com` a lo largo del tiempo. Antes de abrir
un caso conviene confirmar **cuál de esas entidades tiene hoy el contrato vigente**, y
si existe alguno: es la diferencia entre un proveedor con obligaciones y una dependencia
personal no formalizada sobre un proceso contable y de facturación electrónica.

---

## 4. Riesgos y observaciones

### 4.1 Contraseñas de `sa` en texto plano, reutilizadas entre servidores — crítico

Las cadenas de conexión de los `.config` llevan la credencial completa, sin cifrar:

| Servidor | Usuario | Contraseña | Archivo |
|---|---|---|---|
| `C2N_PAAS` | `sa` | *(en claro en el archivo)* | `Controlador.exe.config`, `Mediador.dll.config` |
| `DB-SENO` | `sa` | *(en claro)* — **la misma que usa REPOFEL** | `Mediador.dll.config` |
| `desarrollo` | `sa` | *(en claro)* — **la misma que en producción** | `Mediador.dll.config` |
| `rublan`, `(local)` | `sa` | *(sin contraseña declarada)* | `SSO.GENERALES.dll.config` |

Los valores no se reproducen en este documento. Tres consecuencias, en orden de
gravedad:

1. **La contraseña de `sa` de `DB-SENO` es idéntica a la que REPOFEL guarda en
   `php/cnbde.php`** para el servidor `10.2.8.13` (ver [REPOFEL.md](REPOFEL.md) §8.1).
   Es la misma credencial de administración total reutilizada en al menos dos
   servidores y dos aplicaciones sin relación entre sí. Y REPOFEL **está publicado en
   internet**: quien obtenga ese archivo obtiene `sa` en varios motores a la vez.
2. **El servidor de desarrollo comparte la contraseña de `sa` con producción.** Un
   entorno con controles más laxos da acceso administrativo al entorno productivo.
3. `C:\Program Files (x86)` es legible por el grupo *Usuarios*. Cualquier cuenta con
   sesión en este servidor —incluidas las 9 cuentas locales habilitadas— puede leer
   estos archivos.

**Acciones:** rotar la contraseña de `sa` en `C2N_PAAS`, `DB-SENO`, `desarrollo` y
`10.2.8.13`, **con contraseñas distintas por servidor**; sustituir `sa` por cuentas de
servicio con permisos mínimos; pedir a REVCOM que la aplicación consuma
`SSO_Param_Conn.eif` —que sí está cifrado— en lugar de las cadenas en claro; y retirar
del paquete las cadenas heredadas de `SSO.GENERALES.dll.config`, que apuntan a un equipo
personal.

### 4.2 Resto de observaciones

| Severidad | Observación |
|---|---|
| **Alto** | Capa base sin recompilar desde 2013 y un `.config` de 2006: código sin mantenimiento evidente sobre el que corre un proceso contable y de facturación electrónica. |
| **Alto** | `Interop.SAPbobsCOM.dll` de 2013 contra una DI API de 2025. Cualquier actualización de SAP puede romper la integración sin aviso previo. |
| **Alto** | Cadena de conexión a un **servidor de desarrollo** (`desarrollo`) y a un **equipo personal** (`rublan`) embarcadas en el paquete de producción. |
| **Medio** | Las alertas por correo del proceso contable están rotas: `SMTPUsaCredenciales = True` con usuario y contraseña vacíos. Las cuatro categorías de alerta están activadas y ninguna puede entregarse. |
| **Medio** | `GrabarLog = False`: el proceso de asientos no deja bitácora propia. |
| **Medio** | Cuatro archivos `.pdb` en producción: facilitan la ingeniería inversa. |
| **Medio** | SDK de Visual Studio empaquetado con la aplicación; dependencias que casi con certeza no se usan en ejecución. |
| **Medio** | Coexistencia de DevExpress v23.1 (usada por esta app) y 24.2.7 (instalada aparte), más dos motores de Crystal Reports. |
| **Medio** | El paquete participa en la emisión de DTE guatemaltecos vía Guatefacturas, pero está catalogado sólo como «instalador de asientos contables». El catálogo de arquitectura subestima su criticidad. |
| **Bajo** | Sin contrato de soporte ni versión documentada frente al proveedor; el campo `Propietario` figura como `DEFINIR`, y la identidad misma del proveedor es ambigua (§3.4). |

> **Corrección respecto de la versión anterior de este documento.** Se documentó aquí un
> binario `SSO.GEN.ServicioCalendario_Pruebas.exe` como «binario de pruebas desplegado en
> producción». Era un error de lectura: el listado original venía truncado y el nombre
> real es **`SSO.GEN.ServicioCalendario_Promociones.exe`**, un servicio de promociones,
> no de pruebas. El hallazgo queda retirado.

---

## 5. Preguntas para el proveedor

Antes de nada: **confirmar con qué entidad existe contrato vigente** — REVCOM,
`ssodn.com`, `inforumsol.com` o `integrasap.com` (§3.4).

1. ¿Por qué las cadenas de conexión llevan `sa` en texto plano si el paquete ya incluye
   `SSO_Param_Conn.eif` cifrado? ¿Puede la aplicación consumir sólo el almacén cifrado?
2. ¿Con qué cuenta mínima puede operar la aplicación? ¿Requiere realmente `sa`?
3. ¿Por qué el paquete de producción incluye cadenas a `desarrollo` y al equipo
   `rublan`? ¿Pueden retirarse?
4. ¿Cuál es la versión soportada de `Interop.SAPbobsCOM` frente a SAP B1 10.0 FP2011?
5. ¿Qué ensamblados del paquete son realmente requeridos en ejecución? ¿Puede
   entregarse un paquete sin el SDK de Visual Studio ni los `.pdb`?
6. ¿Cuál es la configuración correcta de SMTP para que las alertas del proceso contable
   se entreguen? Hoy no pueden funcionar.
7. ¿Debe `GrabarLog` estar en `False` en producción?
8. ¿Qué alcance tiene la integración con Guatefacturas y quién la soporta?
9. ¿Existe repositorio y control de versiones del lado del proveedor, y cuál es el
   procedimiento para solicitar una compilación reproducible?
10. ¿Es REVCOM también el proveedor de las aplicaciones cuyas bases hospeda este
    servidor sin alojar su código (`SSO_WEB_SEG`/`SSO.Web.POS`, `SSO_INT_SBO`,
    `SSO_DOCUMENTOSBO`, `SENCOBRO`)? Las bases `SSO_SEG_V2` y `SSO_POS_V2` que aparecen
    en `SSO.GENERALES.dll.config` sugieren que sí.

---

*Documento generado el 17/08/2026 a partir del inventario de archivos de
`C:\Program Files (x86)\REVCOM` y del registro de instalación de Windows. Ver
[DEPENDENCIAS.md](DEPENDENCIAS.md).*
