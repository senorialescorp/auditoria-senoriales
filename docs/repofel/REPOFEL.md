# REPOFEL — Repositorio de Factura Electrónica en Línea

Aplicación web de desarrollo propio para la recepción, revisión y archivo de facturas
electrónicas de proveedores. Es el segundo sistema de negocio del servidor `SRV-SAP`,
después de SAP Business One, y el único desarrollado internamente que está publicado
a la red.

| | |
|---|---|
| **Tipo** | Aplicación web monolítica en PHP, sin framework |
| **Ubicación** | `G:\REPOFEL` (Guatemala) · `G:\REPOFELMX` (México) |
| **Servidor web** | IIS 10 con módulo FastCGI |
| **Intérprete** | PHP 8.1.11 (NTS, VC++ 2019, x64) en `C:\php8.1\php-cgi.exe` |
| **Base de datos** | SQL Server 2019 — `BDREPOFEL` / `BDREPOFELMX` |
| **Autenticación** | Sesión de PHP, usuarios propios en tabla `Usuario` |
| **Control de versiones** | **Ninguno** — no existe repositorio Git |
| **Rango de fechas del código** | julio 2022 – julio 2026 |

---

## 1. Propósito funcional

Los proveedores y el personal administrativo cargan documentos en PDF asociados a una
factura (factura, recibo, retención, etc.), dentro de un **periodo de recepción** que
la administración abre y cierra. El personal de cuentas por pagar revisa, aprueba o
anula esos documentos, y genera comprobantes de pago y solicitudes de pago al banco.

El título que muestra la interfaz es *«Repositorio de Facturas — Corporación
Señoriales»*.

Flujo principal:

```
Proveedor / usuario                Administración               Tesorería
      │                                  │                          │
      │ 1. carga PDF (cardoc_*)          │                          │
      ├─────────────────────────────────►│                          │
      │                          2. revisa (revdoc_*)               │
      │                          3. anula si aplica (anufac_*)      │
      │                                  ├─────────────────────────►│
      │                                  │   4. comprobante de pago │
      │                                  │      (compago_*)         │
      │                                  │   5. solicitud al banco   │
      │                                  │      (tmpSolicitudPagoBanco)
```

---

## 2. Arquitectura

No hay framework, router ni autoload. **Cada acción es un archivo `.php` en la raíz**
del sitio, y el nombre del archivo codifica su función mediante un sufijo. Este es el
patrón más importante para entender el código:

| Sufijo | Significado | Ejemplo |
|---|---|---|
| `_f` | Formulario / vista principal del módulo | `cardoc_f.php` |
| `_l` | Listado (devuelve HTML de tabla, por AJAX) | `revdoc_l.php` |
| `_a` | Agregar — recibe POST e inserta | `cardoc_a.php` |
| `_m` | Modificar — precarga datos del registro | `usuario_m.php` |
| `_mf` | Modificar formulario — recibe POST y actualiza | `usuario_mf.php` |
| `_v` | Ver / validar un registro | `cardoc_v.php` |
| `_x` | Exportar a Excel (PhpSpreadsheet) | `revdoc_x.php` |
| `_e` | Eliminar | `permiso_e.php` |
| `_emp`, `_per` | Alimentan combos de filtro (empresa, periodo) | `revfac_emp.php` |

La interfaz es una sola página (`index.php`) que actúa de contenedor: `js/codigo.js`
carga por AJAX el HTML de cada módulo dentro de `#contenedor`, abre formularios en un
modal `#Modal` y muestra los PDF en un `<embed>` (`#contPDF`).

### Módulos

| Prefijo | Módulo | Archivos |
|---|---|---|
| `iniciar`, `cerrar` | Inicio y cierre de sesión | `iniciar.php`, `iniciar_f.php`, `cerrar.php` |
| `recuperapw`, `cambiopw` | Recuperación y cambio de contraseña | `recuperapw_{bus,val,cam,f}.php`, `cambiopw_{a,f}.php` |
| `usuario` | Usuarios | `usuario_{a,f,l,m,mf}.php` |
| `permiso` | Permisos por usuario y opción | `permiso_{a,c,e,f,l,m,mf}.php` |
| `modificarp` | Perfil propio | `modificarp_{a,f}.php` |
| `creaper`, `buscaperiodos` | Periodos de recepción | `creaper_{a,f,l,m,mf}.php`, `buscaperiodos.php` |
| `tipodep` | Tipos de documento | `tipodep_{a,f,l,m,mf}.php` |
| `cardoc` | **Carga de documentos** | `cardoc_{a,f,l,v,x}.php` |
| `revdoc` | **Revisión de documentos** | `revdoc_{a,f,fv,l,v,x,emp,per}.php` |
| `revfac` | Revisión de facturas | `revfac_{l,emp,per}.php` |
| `anufac` | Anulación de facturas | `anufac_{l,m,mf,emp,per}.php` |
| `compago` | **Comprobantes de pago** | `compago_{a,aa,ca,f,fc,l,m,mf,v,vd,vp}.php` |
| `buscaproveedor`, `guardarproveedor`, `buscamonto` | Búsquedas auxiliares contra SAP | 3 archivos |
| `correos` | Envío de correo (PHPMailer) | `correos.php` |
| `pie` | Pie de página | `pie.php` |

---

## 3. Modelo de datos

### Tablas propias (`BDREPOFEL`)

| Tabla | Rol | Campos observados en el código |
|---|---|---|
| `Usuario` | Usuarios de la aplicación | `idUsuario`, `nombre`, `apellido` |
| `PermisoReporte` | Permisos por usuario / opción | — |
| `Empresa` | Empresas receptoras del grupo | `idEmpresa` |
| `Proveedor` | Proveedores emisores | `idProveedor` (NIT/RFC) |
| `Periodo` | Ventana de recepción | `idPeriodo`, `fecha_inicial`, `fecha_final`, `estado_recepcion` (`A`=abierto) |
| `TipoDocumento` | Catálogo de tipos de PDF | `idTipoDocumento` |
| `DocRecibido` | **Cabecera del documento** | `idDocRecibido`, `idUsuario`, `idPeriodo`, `idEmpresa`, `idProveedor`, `contrasena`, `factura`, `monto` |
| `DetDocRecibido` | **Detalle: un PDF por fila** | `idDocRecibido`, `idTipoDocumento`, `nombre_documento`, `estado` (`P`=pendiente) |
| `ComprobantePago` | Comprobantes de pago | — |
| `tmpSolicitudPagoBanco` | Tabla temporal de solicitudes al banco | — |
| `Reporte` | Definición de reportes | — |

### Tablas de SAP Business One consultadas directamente

`buscamonto.php` y `buscaproveedor.php` **consultan la base de SAP sin pasar por la
DI API ni por la Service Layer**:

| Tabla SAP | Contenido |
|---|---|
| `OPCH` | Facturas de compra (*Purchase Invoices*) |
| `OCRD` | Socios de negocio (*Business Partners*) |

Esto crea un acoplamiento directo con el esquema interno de SAP: cualquier
actualización o migración del ERP puede romper REPOFEL sin aviso.

### Almacenamiento de archivos

Los PDF **no** se guardan en la base de datos, sino en el sistema de archivos:

- Carpeta: `G:\REPOFEL\doc\`
- Nombre: `{idDocRecibido}_{idTipoDocumento}.pdf`
- Volumen actual: **76 540 archivos · 14.3 GB** (GT) y 448 archivos · 57 MB (MX)

La base de datos guarda únicamente el nombre en `DetDocRecibido.nombre_documento`. No
hay verificación de integridad ni conciliación entre filas y archivos.

---

## 4. Autenticación y autorización

**Sesión.** `iniciar_f.php` valida contra la tabla `Usuario` y arma
`$_SESSION['usuario']['perfil']` con `idu` (id de usuario), `idt` (tipo de perfil;
`1` = administrador) y `nom`.

**Permisos.** `$_SESSION['usuario']['permiso']` es un arreglo cuyas claves tienen el
formato `opcion_acciones_sucursal`. La cadena de acciones es **posicional de cinco
caracteres**, interpretada por `accionP()` en `php/funciones.php`:

| Posición | Acción |
|---|---|
| 1 | `l` — listar |
| 2 | `a` — agregar |
| 3 | `m` — modificar |
| 4 | `e` — eliminar |
| 5 | `p` — permisos |

Un guion en la posición significa «denegado». Cada script deduce su propio permiso a
partir de su nombre de archivo:

```php
$arNomArchivo = explode('\\', $_SERVER['SCRIPT_FILENAME']);
$nArchivo     = array_pop($arNomArchivo);      // p. ej. "cardoc_a.php"
$permiso      = permisoScriptUSR($nArchivo);   // busca en la sesión
$perL         = accionP($permiso, 'a');        // ¿puede agregar?
```

**Protección de peticiones POST.** Todos los endpoints exigen que el POST incluya un
campo `SID` igual a `session_id()`:

```php
if (!isset($_POST['SID'])) { echo "<script> alert('Zona no autorizada') </script>"; exit(); }
if (session_id() == $_POST['SID']) { /* ... */ }
```

Es un control anti-CSRF improvisado. Funciona parcialmente, pero el identificador de
sesión no es un token de un solo uso y viaja en el cuerpo de cada formulario.

---

## 5. Configuración

### Conexiones a base de datos

Dos archivos, cada uno con una función que devuelve una conexión `sqlsrv`:

| Archivo | Función | Servidor | Usuario | Uso |
|---|---|---|---|---|
| `php/cnbd.php` | `BD($bd)` | `10.4.6.13` (este servidor) | `usrRepo` | Base propia de REPOFEL |
| `php/cnbde.php` | `BDE($bd)` | `10.2.8.13` (otro servidor) | **`sa`** | Bases de SAP Business One |

> **Las contraseñas de ambos usuarios están escritas en texto plano dentro de los
> archivos.** No se reproducen aquí a propósito. Ver la sección 8.

### PHP (`C:\php8.1\php.ini`)

| Parámetro | Valor | Observación |
|---|---|---|
| `upload_max_filesize` | 10M | Límite real de un PDF |
| `post_max_size` | 1000M | Cien veces mayor que el anterior; incoherente |
| `max_file_uploads` | 20 | Documentos por envío |
| `memory_limit` | 512M | |
| `max_execution_time` | 260 | Elevado, por los listados y exportaciones |
| `display_errors` | Off | Correcto para producción |
| `session.use_strict_mode` | 0 | Acepta identificadores de sesión no generados por el servidor |
| `session.cookie_httponly` | *(vacío)* | La cookie de sesión es legible por JavaScript |
| `session.cookie_samesite` | *(vacío)* | Sin protección SameSite |

### Extensiones declaradas en `php.ini`

```ini
extension=odbc
extension=openssl
extension=pdo_odbc
zend_extension=opcache
extension=php_sqlsrv_81_ts.dll          ; no existe en ext\ — falla al cargar
extension=php_sqlsrv_81_nts_x64.dll     ; ésta es la que efectivamente carga
extension=php_sqlsrv_81_ts_x64.dll      ; build TS, no aplica (PHP es NTS)
extension=php_pdo_sqlsrv_81_nts_x64.dll
extension=php_pdo_sqlsrv_81_ts_x64.dll  ; build TS, no aplica
extension=php_sqlsrv_8_nts_x64.dll      ; no existe en ext\ — falla al cargar
```

Seis líneas declaran controladores de SQL Server; **cuatro fallan en cada arranque**
porque corresponden a builds *thread-safe* o a nombres inexistentes. El intérprete
registra un `PHP Warning` por cada una. La única que aplica es
`php_sqlsrv_81_nts_x64.dll`. Conviene dejar solo las dos correctas (`sqlsrv` y
`pdo_sqlsrv` en variante `nts_x64`).

### IIS (`web.config`, idéntico en ambas instancias)

```xml
<handlers>
  <remove name="PHP fastCGI" />
  <add name="PHP fastCGI" path="*.php" verb="*" modules="FastCgiModule"
       scriptProcessor="C:\php8.1\php-cgi.exe" resourceType="File"
       requireAccess="Script" />
</handlers>
```

---

## 6. Dependencias

### Plataforma

| Componente | Versión | Notas |
|---|---|---|
| IIS | 10.0 | Módulo FastCGI |
| PHP | 8.1.11 NTS x64 | Compilado 28/09/2022. Rama 8.1 **fuera de soporte de seguridad desde el 31/12/2025** |
| Microsoft Drivers for PHP for SQL Server | serie 5.10 | `php_sqlsrv_81_nts_x64.dll` |
| Microsoft ODBC Driver for SQL Server | 17 | Requerido por el anterior |
| SQL Server | 2019 Standard (15.0.2000.5) | Instancia local `MSSQLSERVER` |

### Librerías PHP incluidas en el repositorio

**PHPMailer 6.6.0** — copiada a mano en `PHPMailer\`, sin Composer. Se carga con
`require_once` explícito desde `correos.php`:

```
PHPMailer/PHPMailer.php   PHPMailer/SMTP.php   PHPMailer/Exception.php
PHPMailer/OAuth.php       PHPMailer/OAuthTokenProvider.php   PHPMailer/POP3.php
```

**PhpSpreadsheet 1.24.1** — sí gestionada con Composer, en `PhpOffice\`. El
`composer.json` sólo declara `phpoffice/phpspreadsheet: ^1.24`; el resto son
dependencias transitivas resueltas en `composer.lock`
(*content-hash* `bbda3ee01c5803f3a41570d94319d442`):

| Paquete | Versión |
|---|---|
| `phpoffice/phpspreadsheet` | 1.24.1 |
| `ezyang/htmlpurifier` | v4.14.0 |
| `maennchen/zipstream-php` | 2.2.1 |
| `markbaker/complex` | 3.0.1 |
| `markbaker/matrix` | 3.0.0 |
| `myclabs/php-enum` | 1.8.4 |
| `psr/http-client` | 1.0.1 |
| `psr/http-factory` | 1.0.1 |
| `psr/http-message` | 1.0.1 |
| `psr/simple-cache` | 1.0.1 |
| `symfony/polyfill-mbstring` | v1.26.0 |

PhpSpreadsheet 1.24.1 es de 2022; la rama 1.x recibió varias correcciones de
seguridad posteriores. No hay `composer.phar` en el servidor, así que la
actualización debe prepararse fuera y copiarse.

**Front-end** — `css/`, `js/`, `fonts/`, `img/`. `js/codigo.js` es propio; no se
detectaron CDN externos en `index.php`.

### Servicio externo de correo

| Parámetro | Valor |
|---|---|
| Servidor SMTP | `secure.emailsrvr.com` |
| Puerto / cifrado | 587 / STARTTLS |
| Cuenta remitente | `informacion@senoriales.com` |
| Nombre visible | «REPOFEL Señoriales» |

La contraseña de la cuenta está escrita en texto plano en `correos.php`.

---

## 7. Código heredado: `php/funciones.php`

`index.php` y todos los endpoints incluyen `php/funciones.php`, pero **la mayor parte
de ese archivo pertenece a otra aplicación**, un sistema de ventas por sucursales
(«appVentas»). Evidencia:

- Usa una clase `BD` con métodos estáticos `BD::cnnBDG()` y `BD::cnnBDC()` que **no
  existen** en este proyecto — aquí `BD` es una *función*, no una clase.
- Consulta tablas que no están en `BDREPOFEL`: `tUsuario`, `tCorporacion`,
  `tSucursal`, `tAccesoSucursal`, `tPerSucMenu`, `tEstadoDepto`,
  `tCiudadMunicipio`, `tMenu`.
- `quitarhack()` llama a `$cnnBD->real_escape_string()`, método de **mysqli**, no de
  `sqlsrv`. Si algún script lo invocara, provocaría un error fatal.
- Escribe rutas `../img/appVentas/{codigo}/` con `mkdir(..., 0777)`.

Lo único de este archivo que REPOFEL usa realmente es `permisoScriptUSR()` y
`accionP()`. El resto —incluida una clase `PASS` con hash SHA-512 más *salt*, y una
clase `USUARIO` con toda una lógica de inicio de sesión multiempresa— es código muerto
que se interpreta en cada petición.

**Recomendación:** extraer `permisoScriptUSR()` y `accionP()` a un archivo nuevo
(`php/permisos.php`) y eliminar el resto, previa verificación con `grep` de que ninguna
función más se referencia.

---

## 8. Riesgos identificados

Ordenados por severidad. Los tres primeros son de atención inmediata.

### 8.1 Credenciales en texto plano en el código fuente — crítico

| Archivo | Credencial expuesta |
|---|---|
| `php/cnbde.php` | Usuario **`sa`** de SQL Server en `10.2.8.13` |
| `php/cnbd.php` | Usuario `usrRepo` de SQL Server en `10.4.6.13` |
| `correos.php` | Cuenta de correo `informacion@senoriales.com` |

El caso de `sa` es el más grave: es la cuenta de administración total del motor de
base de datos donde residen las empresas de SAP. Además, ambas contraseñas de base de
datos incluyen el año en su composición (`2023`), lo que sugiere que no han rotado.

Estas rutas son legibles por cualquier cuenta con acceso a la compartición `G$` y
quedan copiadas dentro de cualquier respaldo del volumen.

**Acciones:** rotar las tres credenciales; mover la configuración a un archivo fuera
del *webroot* con ACL restringida (o a variables de entorno del grupo de aplicaciones
de IIS); sustituir `sa` por un usuario con permisos mínimos de lectura sobre `OPCH` y
`OCRD`; revisar los respaldos existentes que ya contienen los valores.

### 8.2 `z.php` expone la sesión completa — crítico

```php
<?php session_start(); echo "<pre>"; var_dump($_SESSION); echo "</pre>"; ?>
```

Son 75 bytes, sin ninguna validación, accesibles desde el navegador. Vuelca la sesión
entera: identificador de usuario, perfil, arreglo de permisos y —por lo que guardan
otros scripts en `$_SESSION['PRI']`— el último POST recibido. Es un archivo de
depuración que quedó en producción.

**La aplicación está publicada en internet** (ver §10), lo que convierte este archivo
en un endpoint de divulgación accesible desde cualquier origen.

> **Corrección (17/08/2026).** Una versión anterior de este documento afirmaba que
> `z.php` «aún no ha sido descubierto por los escáneres». **Es falso.** El barrido del
> histórico completo de registros —1019 días en `W3SVC2`— encontró 15 peticiones a
> `z.php`, todas con estado 200. Catorce son depuración interna desde `10.2.8.28` en
> octubre de 2024, pero **la del 17/05/2026 a las 09:17:03 proviene de `110.238.87.156`
> y forma parte de un barrido de 53 nombres de webshell**: las otras 52 devolvieron 404
> y `z.php` devolvió 200, con una respuesta de 414 bytes. El agente de usuario iba vacío.
>
> Esto agrava el hallazgo en dos sentidos. Primero, el archivo es un recurso **conocido
> por terceros** desde esa fecha. Segundo, dado que otros scripts guardan el último POST
> recibido en `$_SESSION['PRI']`, un volcado de 414 bytes puede haber incluido
> credenciales enviadas por formulario.
>
> El análisis completo está en
> [Auditoria-Permisos-REPOFEL.md](Auditoria-Permisos-REPOFEL.md) §5.

**Acción:** eliminarlo de ambas instancias, **hoy**. Es la corrección más barata y de
mayor impacto de toda esta lista, y ya no es preventiva.

### 8.3 Nombre de archivo construido con entrada del usuario — alto

En `cardoc_a.php`:

```php
$nomsoloarchivo = $ultimoid . "_" . $_POST[$tipoDOC] . ".pdf";
$nomafinal      = $directorio . $nomsoloarchivo;
move_uploaded_file($archivo['tmp_name'], $nomafinal);
```

`$_POST[$tipoDOC]` (el id de tipo de documento) se concatena a la ruta sin validar que
sea numérico. Un valor como `../../algo` desplaza la escritura fuera de `doc\`.

**Acción:** forzar `(int)` sobre ese valor, o validarlo contra `TipoDocumento` antes
de usarlo.

### 8.4 Validación de tipo de archivo por MIME declarado — alto

```php
$archivospermitidos = array('application/pdf');
if (in_array($archivo['type'], $archivospermitidos)) { /* aceptado */ }
```

`$_FILES[...]['type']` lo envía el cliente y es trivial de falsificar. Un archivo
arbitrario puede declararse `application/pdf`. El riesgo se atenúa porque la extensión
se fuerza a `.pdf` y porque el `web.config` publica el handler PHP con
`requireAccess="Script"`, pero la carpeta `doc\` está bajo el *webroot*.

**Acción:** validar con `finfo_file()` sobre el archivo temporal y, mejor aún, mover
`doc\` fuera del directorio publicado y servirlo por un script intermedio.

### 8.5 Obtención del último id por `MAX()` — medio

```php
$sqlid = "SELECT MAX(idDocRecibido) FROM DocRecibido WHERE idUsuario=" . $_SESSION['usuario']['perfil']['idu'];
```

Con dos cargas simultáneas del mismo usuario, el detalle puede asociarse a la cabecera
equivocada. Debe usarse `SCOPE_IDENTITY()` u `OUTPUT INSERTED.idDocRecibido` en el
`INSERT`, dentro de una transacción que cubra cabecera y detalle.

### 8.6 Sin control de versiones ni entorno de pruebas — medio

No hay repositorio Git. Las fechas de modificación van de 2022 a julio de 2026 y no
existe forma de saber qué cambió, cuándo ni por qué. En `cardoc_a.php` se aprecia un
parche reciente —la revalidación *fail-closed* del periodo, con su propio comentario—
insertado sobre la lógica anterior sin dejar rastro de quién lo hizo.

### 6.7 Divergencia entre las dos instancias — medio

`REPOFELMX` es una copia manual de `REPOFEL`, no un despliegue parametrizado. Ya
divergen:

| Archivo | GT | MX |
|---|---|---|
| `index.php` | 3 575 bytes (01/12/2022) | 3 492 bytes (04/03/2026) |
| `iniciar_f.php` | 3 986 bytes (07/09/2023) | 4 002 bytes (04/03/2026) |
| `revdoc_a.php` | 3 861 bytes (30/08/2022) | 3 869 bytes (04/03/2026) |
| `pie.php` | 333 bytes | 341 bytes |
| `usuario_a.php` | 2 866 bytes | 2 874 bytes |
| `buscaperiodos.php`, `cardoc_a.php`, `creaper_m.php` | 02/07/2026 | 02/07/2026 |

Los tres últimos se tocaron el mismo día en ambas instancias: los cambios se están
aplicando dos veces a mano. Cada corrección futura tiene que replicarse manualmente, y
cada olvido es un defecto que aparece solo en un país.

### 8.8 Archivos residuales — bajo

- `composer_install.php` — 0 bytes, en ambas instancias.
- `SAP_old`, `Conector txt2023.rar` y similares en carpetas vecinas.

---

## 9. Sitios de IIS

`applicationHost.config` no es legible sin privilegios administrativos, pero el análisis
de los registros de acceso permite identificar los tres sitios sin ambigüedad, por las
rutas que sirve cada uno y por el campo `Referer`:

| Sitio | Instancia | Nombre de host | Directorio |
|---|---|---|---|
| `W3SVC1` | Sitio predeterminado de IIS, sin uso | — | `C:\inetpub\wwwroot` |
| `W3SVC2` | **REPOFEL (Guatemala)** | `repofel.senoriales.com` | `G:\REPOFEL` |
| `W3SVC3` | **REPOFEL MX** | `repofelmx.senoriales.com` | `G:\REPOFELMX` |

### Direcciones

| Dato | Valor |
|---|---|
| IP interna de escucha | `10.4.6.13` |
| Puerto | `443` (TLS); también se observan referers `http://` hacia `repofelmx` |
| **IP pública** | **`101.44.184.229`** |

Ambos sitios comparten IP y puerto, de modo que IIS los separa por cabecera de host
(SNI). **La aplicación responde también cuando se la invoca directamente por la IP
pública, sin nombre de host** — el registro del 17/08/2026 contiene 19 referers hacia
`https://101.44.184.229`. Eso significa que un filtro basado únicamente en el nombre de
dominio no acota el acceso.

El patrón de uso también distingue las instancias: en Guatemala predomina la revisión de
documentos (`revdoc_*`), en México la carga y la creación de periodos (`cardoc_*`,
`creaper_*`).

> Los nombres de host se derivaron del campo `Referer` de los registros de acceso, no de
> los *bindings* de IIS: el formato de log configurado no incluye el campo `cs-host`.
> Añadirlo (`Host` en las propiedades de registro del sitio) haría directa esta
> comprobación en el futuro.

---

## 10. Exposición a internet — crítico

**El sitio es accesible desde internet y está siendo sondeado activamente.** Los
registros de acceso del 17/08/2026 muestran 408 peticiones en la jornada, de las cuales
**171 (42 %) devolvieron 404**: es tráfico de exploración, no de usuarios.

### Direcciones de origen

| Origen | Naturaleza |
|---|---|
| `110.238.87.0/24` (múltiples direcciones) | Huawei Cloud. **Mezcla tráfico legítimo y hostil** — ver aviso abajo |
| `185.60.136.87` | **Barrido de explotación activo** — dos campañas distintas (ver abajo) |
| `169.58.57.214` | **Barrido de explotación activo** — repitió la campaña CVE-2024-4577 20 minutos después |
| `71.6.232.27` | Escáner de reconocimiento masivo de internet |
| `45.148.10.201`, `77.91.71.92`, `175.6.54.21`, `118.194.234.14` | Rangos ajenos, sin relación con la operación |
| `20.55.24.39`, `20.64.105.121`, `40.119.24.130`, `40.124.186.160` | Azure |
| `66.132.195.86` | SoftLayer / otros |

> **Corrección (17/08/2026).** Una versión anterior de este documento daba por legítimo
> todo el rango `110.238.87.0/24`, por coincidir con el entorno del grupo en Huawei Cloud.
> El barrido del histórico de registros desmiente esa lectura: **`110.238.87.156` ejecutó
> un escaneo de webshells contra el sitio el 17/05/2026** y localizó `z.php`. Huawei Cloud
> es un proveedor público y direcciones contiguas del mismo `/24` corresponden a inquilinos
> distintos. **El rango no sirve como criterio de confianza en una regla de firewall o
> WAF**; hay que enumerar las direcciones propias y tratar el resto como internet abierta.
> El detalle está en [Auditoria-Permisos-REPOFEL.md](Auditoria-Permisos-REPOFEL.md) §5.

### Intento de explotación 1 — CVE-2017-9841 (PHPUnit)

El 17/08/2026 entre las **09:43:42 y las 09:43:47**, la dirección `185.60.136.87`
ejecutó un barrido de **26 peticiones** buscando el ejecutor remoto de PHPUnit en 26
rutas distintas:

```
/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/laravel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/yii/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
...
```

Corresponde a **CVE-2017-9841**, que permite ejecución remota de código sin
autenticación cuando `phpunit` queda expuesto bajo el directorio publicado.

**Las 26 peticiones devolvieron 404**: PHPUnit no está instalado en este servidor, así
que el intento falló. Pero confirma que el sitio está en las listas de objetivos y que
recibe sondeos automatizados de forma rutinaria.

### Intento de explotación 2 — CVE-2024-4577 (inyección de argumentos en PHP-CGI)

El mismo día, **dos direcciones distintas** lanzaron una campaña diferente y más
pertinente que la anterior:

| Hora | Origen | Rutas probadas | Estado |
|---|---|---|---|
| 09:43:41 | `185.60.136.87` | `/`, `/index.php`, `/hello.world`, `/test.hello` | 302, 404 |
| 10:03:24 | `169.58.57.214` | las mismas cuatro | 302, 404 |

La cadena de consulta es la firma inequívoca de CVE-2024-4577:

```
%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input
```

El `%AD` es un **guion suave**. La vulnerabilidad explota la conversión *best-fit* de
código de página de Windows, que en ciertos idiomas convierte ese carácter en un guion
real, con lo que el resto de la cadena se convierte en argumentos de línea de comandos
para `php-cgi.exe`. `auto_prepend_file=php://input` hace que PHP ejecute el cuerpo de la
petición: es ejecución remota de código sin autenticación.

**Esta campaña apunta exactamente a la configuración de este servidor.** REPOFEL sirve
PHP mediante `scriptProcessor="C:\php8.1\php-cgi.exe"` sobre IIS FastCGI en Windows, que
es el escenario que el CVE describe. Y **la versión instalada es PHP 8.1.11 (compilada el
28/09/2022), muy anterior a PHP 8.1.29**, que es donde se corrigió el fallo en junio de
2024.

#### Por qué, pese a todo, el intento falló

Las ocho peticiones devolvieron 302 y 404, ninguna 200. La conversión *best-fit* que la
vulnerabilidad necesita solo se produce en códigos de página donde el guion suave (`0xAD`)
se transforma en guion (`0x2D`) — característicamente los asiáticos (936, 950, 932). Este
servidor está configurado así:

```
CodePage ANSI (ACP) : 1252
Locale del sistema  : es-GT
```

Con la página de códigos 1252, el vector del guion suave **no se aplica**. La protección
es, sin embargo, **accidental**: depende de la configuración regional del servidor, no de
un parche ni de un control deliberado. Cualquier cambio de configuración regional, o una
variante del ataque que no dependa del *best-fit*, encontraría un `php-cgi.exe` sin
parchear.

#### Lo que esto sí demuestra

El dato relevante no es este CVE concreto, sino que **`C:\php8.1\php-cgi.exe` está
expuesto a internet con una compilación de septiembre de 2022**. No son solo los cinco
meses transcurridos desde el fin de soporte de la rama 8.1 (31/12/2025): son **casi cuatro
años de correcciones de seguridad no aplicadas**, incluidas las 8.1.12 a 8.1.33. Dos
actores independientes probaron un fallo de ese intervalo el mismo día.

**Acción:** actualizar PHP es la prioridad. Si migrar a una rama con soporte (8.3/8.4)
exige pruebas de compatibilidad, `C:\php-8.2` ya está instalado en el servidor con la
versión 8.2.24, que sí incluye la corrección de CVE-2024-4577 — es un paso intermedio
disponible de inmediato.

### Por qué esto agrava el resto de los hallazgos

La exposición pública multiplica la severidad de todo lo demás en la sección 8:

- **Los tres perfiles del firewall de Windows están deshabilitados** (hallazgo de la
  auditoría, capa L2), de modo que no hay filtrado a nivel de host.
- **PHP 8.1.11, compilado el 28/09/2022.** La rama dejó de recibir parches el
  31/12/2025, pero el atraso real es mayor: esta compilación no incorpora ninguna de las
  correcciones de 8.1.12 en adelante. Una de ellas —CVE-2024-4577— fue probada contra
  este servidor el 17/08/2026 por dos direcciones distintas.
- **PhpSpreadsheet 1.24.1 y PHPMailer 6.6.0** están atrasadas, y ambas procesan entrada
  externa (archivos y correo).
- El `vendor\` de Composer **sí está bajo el directorio publicado**
  (`G:\REPOFEL\PhpOffice\vendor`). Aunque el barrido de hoy buscaba PHPUnit —que no
  está— la lección es que las dependencias son alcanzables por URL. Deben quedar fuera
  del *webroot*.

### Acciones

1. **Eliminar `z.php`** (§8.2) — inmediato.
2. **Restringir el acceso al sitio** a los rangos que realmente lo usan, o publicarlo
   detrás de un proxy inverso o WAF. Si los proveedores externos necesitan entrar, al
   menos denegar por geografía y aplicar limitación de tasa.
3. **Reactivar los perfiles del firewall de Windows.**
4. **Sacar `PhpOffice\vendor` y `doc\` del directorio publicado.**
5. **Actualizar PHP** a una rama con soporte.
6. Revisar los registros históricos de `C:\inetpub\logs\LogFiles\W3SVC2` y `W3SVC3`
   buscando peticiones con código 200 a rutas que no pertenezcan a la aplicación: eso
   distinguiría un sondeo fallido de un acceso logrado.

---

## 11. Pendientes de verificación

Estos puntos no pudieron confirmarse con la cuenta `svalle` (sin privilegios
administrativos) y quedan abiertos:

- **Bindings de IIS**: resuelto parcialmente. Los nombres de host quedaron confirmados
  vía el campo `Referer` (§9): `repofel.senoriales.com` y `repofelmx.senoriales.com`,
  sobre `10.4.6.13:443`, IP pública `101.44.184.229`. **Siguen abiertos** el certificado
  TLS (emisor, vigencia, alcance del SAN) y si el puerto 80 redirige al 443 o sirve la
  aplicación en claro — el registro muestra al menos un referer `http://` hacia
  `repofelmx`, lo que sugiere que el 80 está activo.
- **Identidad del grupo de aplicaciones** con que corre PHP y sus permisos NTFS sobre
  `G:\REPOFEL\doc`.
- **Esquema real de la base**: las tablas y columnas de este documento se derivaron de
  las consultas del código, no de `INFORMATION_SCHEMA`; el inicio de sesión a SQL
  Server fue rechazado. Faltan tipos de dato, llaves, índices y los objetos que el
  código no toca (procedimientos, vistas, *triggers*).
- **Permisos efectivos del usuario `usrRepo`** sobre `BDREPOFEL`.
- Si `ComprobantePago`, `Reporte` y `tmpSolicitudPagoBanco` tienen procesos externos
  que las alimenten.

---

*Documento generado el 17/08/2026 a partir de la lectura directa del código en
`G:\REPOFEL` y `G:\REPOFELMX`, la configuración de PHP e IIS, y los manifiestos de
Composer. Ver [DEPENDENCIAS.md](DEPENDENCIAS.md) para el inventario consolidado.*
