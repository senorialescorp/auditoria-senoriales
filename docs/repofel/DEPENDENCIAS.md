# Inventario consolidado de dependencias

Todas las dependencias identificadas en el software propio de `SRV-SAP`, agrupadas por
tecnología. Es el insumo para revisar vulnerabilidades conocidas y para planificar
actualizaciones.

**Cómo leer la columna «Estado»:** *vigente* = con soporte del proveedor;
*atrasada* = existe versión más nueva pero la rama recibe correcciones;
*fuera de soporte* = la rama ya no recibe parches de seguridad.

---

## 1. Plataforma y runtimes

| Componente | Versión instalada | Estado | Consumido por |
|---|---|---|---|
| Windows Server | 2022 Standard, build 20348 | Vigente (último parche 30/04/2026) | Todo |
| PHP | **8.1.11** NTS x64 (28/09/2022) | **Fuera de soporte de seguridad** (rama 8.1 terminó el 31/12/2025) | REPOFEL, REPOFEL MX |
| PHP (segunda instalación) | 8.2.24 ZTS x64 (25/09/2024) | Vigente, pero **con extensiones que no cargan** | Ninguno identificado |
| IIS | 10.0 + FastCGI | Vigente | REPOFEL, B1 Web Access |
| SQL Server | 2019 Standard 15.0.2000.5 | Vigente; **parche KB5054833 descargado y no aplicado** (`C:\it`) | Todo |
| .NET Framework | — | — | SSO.TRF, Consultas RENAP |
| Windows PowerShell | 5.1 | Vigente | Suite de Auditoría |
| Windows PowerShell 2.0 Engine | característica habilitada | **Fuera de soporte desde 2017** | Nada — debe deshabilitarse |

---

## 2. Librerías PHP — REPOFEL

### Gestionadas con Composer (`G:\REPOFEL\PhpOffice`)

`composer.json` declara una sola dependencia directa: `phpoffice/phpspreadsheet: ^1.24`.
Las demás son transitivas, fijadas en `composer.lock`
(*content-hash* `bbda3ee01c5803f3a41570d94319d442`).

| Paquete | Versión | Estado |
|---|---|---|
| `phpoffice/phpspreadsheet` | 1.24.1 | Atrasada — rama 1.x con correcciones posteriores |
| `ezyang/htmlpurifier` | v4.14.0 | Atrasada |
| `maennchen/zipstream-php` | 2.2.1 | Atrasada |
| `markbaker/complex` | 3.0.1 | Atrasada |
| `markbaker/matrix` | 3.0.0 | Atrasada |
| `myclabs/php-enum` | 1.8.4 | Atrasada |
| `psr/http-client` | 1.0.1 | Estable |
| `psr/http-factory` | 1.0.1 | Estable |
| `psr/http-message` | 1.0.1 | Estable |
| `psr/simple-cache` | 1.0.1 | Estable |
| `symfony/polyfill-mbstring` | v1.26.0 | Atrasada |

> No hay `composer.phar` ni Composer instalado en el servidor. Cualquier actualización
> debe resolverse en otro equipo y copiarse. Las dos instancias (GT y MX) tienen árboles
> de `vendor` independientes: hay que actualizar ambas.

### Copiadas a mano, sin gestor

| Librería | Versión | Ubicación | Estado |
|---|---|---|---|
| PHPMailer | **6.6.0** | `G:\REPOFEL\PHPMailer\` | Atrasada — rama 6.x con correcciones posteriores |

Se carga con `require_once` explícito desde `correos.php`. Al no estar en Composer, no
aparece en ningún manifiesto y su actualización es manual.

### Extensiones de PHP declaradas

| Extensión | Estado |
|---|---|
| `php_sqlsrv_81_nts_x64.dll` | **La única que carga correctamente** |
| `odbc`, `pdo_odbc`, `openssl`, `opcache` | Cargan |
| `php_sqlsrv_81_ts.dll` | Declarada; **el archivo no existe** |
| `php_sqlsrv_8_nts_x64.dll` | Declarada; **el archivo no existe** |
| `php_sqlsrv_81_ts_x64.dll` | Build *thread-safe*; no aplica (PHP es NTS) |
| `php_pdo_sqlsrv_81_ts_x64.dll` | Build *thread-safe*; no aplica |

Cuatro de las seis líneas de SQL Server generan un `PHP Warning` en cada arranque.
Requiere limpieza del `php.ini`.

### Controladores de base de datos

| Componente | Versión | Estado |
|---|---|---|
| Microsoft Drivers for PHP for SQL Server | serie 5.10 | Atrasada |
| Microsoft ODBC Driver for SQL Server | 17 | Vigente |
| SQL Server 2012 Native Client | — | **Fuera de soporte desde el 09/07/2024** |
| Microsoft Access Database Engine 2010 | — | **Fuera de soporte desde el 13/10/2020** |

Los dos últimos siguen instalados y aparecen como hallazgo alto en la auditoría. El
motor de Access se usa con frecuencia como puente ODBC/OLEDB; hay que confirmar qué
proceso lo requiere antes de retirarlo.

---

## 3. Librerías .NET — SSO.TRF (REVCOM)

| Librería | Versión / fecha | Función | Observación |
|---|---|---|---|
| **`Interop.SAPbobsCOM.dll`** | 27/09/2013 | Interop COM con la DI API de SAP B1 | **Riesgo principal:** interop de 2013 contra DI API 10.00.201.102 (2025) |
| **DevExpress WinForms** | **v23.1** (30/11/2023) | ~45 ensamblados de UI y reportería | Coexiste con DevExpress 24.2.7 instalada aparte |
| **Crystal Decisions** | 04/01/2024 | 11 ensamblados (`CrystalReports.Engine`, `Shared`, `ReportAppServer.*`) | Coexiste con SAP Crystal Reports 14.3.2.4272 |
| `log4net.dll` | 04/01/2024 | Registro de eventos | Verificar versión: la rama 1.x tuvo CVE-2018-1285 |
| `System.Net.Http.dll` | 19/06/2015 | Cliente HTTP | Antigua |
| `Microsoft.MSXML.dll` | 09/05/2021 | XML | |
| SDK de Visual Studio (`EnvDTE`, `EnvDTE80`, `VSLangProj`, `Microsoft.VisualStudio.Shell.*`, `stdole`, `dte80.olb`) | 2009–2024 | Automatización del IDE | **No debería estar en producción** — probable empaquetado accidental del `bin` de desarrollo |

### Ensamblados propios (con símbolos de depuración)

| Ensamblado | Compilado | `.pdb` |
|---|---|---|
| `SSO.TRF.Controlador.exe` | 04/01/2024 | — |
| `SSO.TRF.Mediador.dll` | 04/01/2024 | Sí |
| `SSO.GENERALES.dll` | 27/09/2013 | Sí |
| `SSO.DB.dll` | 27/09/2013 | Sí |
| `SSO.UI.dll` | 27/09/2013 | Sí |
| `SSO.VB.dll` | 27/09/2013 | — |
| `SSO.GEN.ServicioCalendario_Pruebas.exe` | 04/01/2024 | — |

---

## 4. Librerías .NET — Consultas RENAP

| Librería | Función | Estado |
|---|---|---|
| **`RestSharp.dll`** | Cliente HTTP hacia la API de RENAP | **Versión por determinar** — CVE-2021-27293 (ReDoS) aplica a ramas antiguas |
| **`Newtonsoft.Json.dll`** | Serialización JSON | **Versión por determinar** — CVE-2024-21907 aplica a < 13.0.1 |

Ensamblados propios: `CONSULTAS RENAP.exe`, `BRL.dll`, `DAL.dll`, `Setting.exe` — los
cuatro con `.pdb` y documentación XML en producción.

Para obtener las versiones:

```powershell
'RestSharp.dll','Newtonsoft.Json.dll' | ForEach-Object {
    [Reflection.AssemblyName]::GetAssemblyName("C:\R\Consulta\$_") |
        Select-Object Name, Version
}
```

---

## 5. Componentes nativos — Conectores CFDI

| Componente | Versión / fecha | Función | Estado |
|---|---|---|---|
| **`ChilkatAx-9.5.0-win32.dll`** | 9.5.0 (25/02/2020) | Cifrado y **firma digital de los CFDI** | Atrasada varias generaciones; licencia de 2013 |
| `AdvUploaderT.exe` | 07/06/2022 | Motor de timbrado (Advans) | Verificar versión soportada con el proveedor |

Es la dependencia más sensible del inventario: firma criptográficamente comprobantes
fiscales y está registrada como control ActiveX de 32 bits.

---

## 6. Servicios externos

| Servicio | Endpoint | Autenticación | Consumido por |
|---|---|---|---|
| **Guatefacturas** (certificador de DTE, Guatemala) | `https://dte.guatefacturas.com:444/webservices63/svc01M/Guatefac` | No declarada en el `.config` | SSO.TRF |
| Proveedor de timbrado Advans (CFDI, México) | URL ofuscada en Base64 en `AdvUploaderT.ini` | Usuario y contraseña ofuscados | Conector |
| API RENAP (registro nacional, Guatemala) | **No está en ningún `.config`** — embebido en `BRL.dll`/`DAL.dll` o escrito por `Setting.exe` | Por determinar | Consultas RENAP |
| Correo SMTP | `secure.emailsrvr.com:587` (STARTTLS) | `informacion@senoriales.com` — **contraseña en texto plano en `correos.php`** | REPOFEL |
| Correo SMTP | `smtp.gmail.com` | `SMTPUsaCredenciales=True` con usuario y clave **vacíos** — las alertas no pueden entregarse | SSO.TRF |
| Correo SMTP | `mail.inforumsol.com` | Sin credenciales | SSO.GEN.ServicioCalendario_Promociones |
| Tableau Cloud | — | `Administrator@SRV-SAP` | Tableau Bridge |

### Servidores SQL alcanzados desde este equipo

| Servidor | Usuario | Estado de la credencial | Declarado en |
|---|---|---|---|
| `10.4.6.13` (local) | `usrRepo` | Texto plano | `cnbd.php` |
| `10.2.8.13` | **`sa`** | Texto plano | `cnbde.php` |
| `DB-SENO` | **`sa`** | Texto plano — **misma contraseña que `10.2.8.13`** | `SSO.TRF.Mediador.dll.config` |
| `C2N_PAAS` | **`sa`** | Texto plano | `Controlador.exe.config`, `Mediador.dll.config` |
| `desarrollo` | **`sa`** | Texto plano — **misma contraseña que producción** | `SSO.TRF.Mediador.dll.config` |
| `rublan` (equipo personal) | `sa` | Sin contraseña declarada | `SSO.GENERALES.dll.config` (2006) |

Seis destinos, cinco de ellos con la cuenta `sa`, y **una sola contraseña compartida
entre al menos tres servidores y dos aplicaciones sin relación entre sí**. Una de esas
aplicaciones —REPOFEL— está publicada en internet.

---

## 7. Prioridades de actualización

Ordenadas por relación entre riesgo y esfuerzo.

> **Contexto que cambia las prioridades:** REPOFEL está **publicado en internet** y
> recibe sondeos de explotación automatizados (barrido de CVE-2017-9841 registrado el
> 17/08/2026), con los tres perfiles del firewall de Windows deshabilitados. Toda
> dependencia atrasada que procese entrada externa deja de ser deuda técnica y pasa a
> ser exposición. Ver [REPOFEL.md](REPOFEL.md) §10.

| # | Acción | Motivo |
|---|---|---|
| 1 | **Eliminar `z.php`** de ambas instancias | Volcado público de la sesión en un sitio expuesto a internet. §8.2. Corrección de un minuto |
| 2 | **Rotar la contraseña de `sa` en los cinco servidores, con una distinta por servidor** | Una sola contraseña de `sa` compartida entre `10.2.8.13`, `DB-SENO` y `desarrollo`, en texto plano en archivos legibles por el grupo *Usuarios*, y presente en una aplicación expuesta a internet. Ver §6 y [SSO-Asientos-Contables.md](SSO-Asientos-Contables.md) §4.1 |
| 3 | **Sacar del código y de los `.config` todas las credenciales** (`cnbd.php`, `cnbde.php`, `correos.php`, los cuatro `.config` de SSO.TRF) | Texto plano. Pedir a REVCOM que use el `SSO_Param_Conn.eif` cifrado que el propio paquete ya incluye |
| 4 | **Separar las credenciales de desarrollo de las de producción** | El servidor `desarrollo` comparte la contraseña de `sa` con producción |
| 5 | **Restringir el acceso al sitio** (rangos de origen, proxy inverso o WAF) y **reactivar los perfiles del firewall** | Sondeos activos sin filtrado de host. §10 |
| 6 | **Actualizar PHP a 8.3 o 8.4** | La rama 8.1 no recibe parches de seguridad desde el 31/12/2025, en un servicio expuesto |
| 7 | **Sacar `PhpOffice\vendor` y `doc\` del directorio publicado** | Las dependencias son alcanzables por URL |
| 8 | **Aplicar el parche KB5054833 de SQL Server** ya descargado en `C:\it` | Pendiente desde abril de 2026 |
| 9 | Retirar del paquete de SSO.TRF las cadenas a `desarrollo` y al equipo `rublan` | Cadenas de un entorno de desarrollo y de una máquina personal, embarcadas en producción |
| 10 | Corregir la configuración SMTP de SSO.TRF | Las cuatro alertas del proceso contable están activadas y ninguna puede entregarse |
| 11 | Actualizar PhpSpreadsheet y PHPMailer | Ramas con correcciones posteriores; ambas procesan entrada externa. Requiere Composer fuera del servidor |
| 12 | Limpiar las cuatro líneas de extensión inválidas del `php.ini` | Ruido en cada arranque; enmascara fallos reales |
| 13 | Localizar el *endpoint* y la llave de RENAP | No están en ningún `.config`; sin eso no puede evaluarse cómo se protege el acceso a datos personales |
| 14 | Determinar versiones de RestSharp y Newtonsoft.Json | Sin el dato no puede evaluarse la exposición |
| 15 | Confirmar qué entidad tiene el contrato vigente de SSO.TRF | REVCOM, `ssodn.com`, `inforumsol.com` o `integrasap.com` |
| 16 | Consultar a REVCOM por `Interop.SAPbobsCOM` y el SDK de Visual Studio empaquetado | Riesgo en la próxima actualización de SAP |
| 17 | Consultar a Advans por la versión soportada de Chilkat | Firma criptográfica de comprobantes fiscales |
| 18 | Retirar SQL Server 2012 Native Client y Access Database Engine 2010 | Fuera de soporte; confirmar antes qué los consume |
| 19 | Deshabilitar la característica PowerShell 2.0 Engine | Fuera de soporte desde 2017, sin uso |
| 20 | Retirar los archivos `.pdb` de los despliegues de producción | Facilitan ingeniería inversa |
| 21 | Resolver la segunda instalación de PHP (`C:\php-8.2`) | O se usa y se arregla, o se retira |

---

*Documento generado el 17/08/2026. Fuentes: `composer.json` y `composer.lock` de ambas
instancias de REPOFEL, `php.ini`, inventario de archivos de
`C:\Program Files (x86)\REVCOM` y `C:\R`, `AdvUploaderT.ini`, y el colector L4-05
(ciclo de vida de software) de la corrida `LINEA-BASE-20260813`.*
