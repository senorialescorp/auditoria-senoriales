# Auditoría de usuarios y permisos — REPOFEL (aplicación)

**Fecha:** 2026-08-17 · **Artefacto:** REPOFEL — repositorio de factura electrónica
**Ubicación:** `G:\REPOFEL` (Guatemala) · `G:\REPOFELMX` (México) · PHP 8.1.11 sobre IIS FastCGI, SQL Server
**Publicado en:** `https://repofel.senoriales.com` y `https://repofelmx.senoriales.com` — `10.4.6.13:443`, IP pública **`101.44.184.229`**, alcanzable también por IP sin nombre de host
**Alcance:** modelo de usuarios, autenticación, autorización y aplicación efectiva de permisos en los 76 scripts publicados
**Complementa:** [Auditoria-Permisos-Usuarios.md](Auditoria-Permisos-Usuarios.md) (capa de sistema operativo) · [REPOFEL.md](REPOFEL.md) (documentación del artefacto)
**Naturaleza:** revisión estática de código. No se ejecutó ninguna prueba contra la aplicación ni se modificó nada.

---

## 1. Resumen ejecutivo

REPOFEL implementa un modelo de permisos propio, razonable en su diseño: cinco acciones (`l`,`a`,`m`,`e`,`p`) codificadas como una cadena posicional, asignadas por usuario y por opción en la tabla `PermisoReporte`. El modelo **falla cerrado** cuando un script no figura entre los permisos del usuario, que es la decisión correcta.

Ese modelo, sin embargo, **es irrelevante en la práctica**, porque existe una cadena de tres defectos que permite a un atacante **no autenticado tomar el control de cualquier cuenta —incluidas las administrativas— conociendo únicamente la dirección de correo del usuario**. La aplicación está publicada en internet y ya recibe tráfico de exploración.

Auditar quién tiene qué permiso en `PermisoReporte` es un ejercicio sin valor mientras esa cadena siga abierta: hoy cualquiera puede otorgarse a sí mismo el perfil de administrador.

| Severidad | Hallazgos |
|-----------|-----------|
| Crítico   | 3 |
| Alto      | 3 |
| Medio     | 4 |
| Bajo      | 2 |

---

## 2. El modelo de permisos tal como está diseñado

### 2.1 Estructura

| Elemento | Implementación |
|----------|----------------|
| Identidad | Tabla `Usuario` (`idUsuario`, `correo`, `clave`, `salt`, `idTipo`, `activo`) |
| Perfil | `Tipo.idTipo` — **`idTipo = 1` es superusuario** |
| Permisos | `PermisoReporte` (`idUsuario`, `idReporte`, `permiso`) × `Reporte` (`script`, `nombre_reporte`) |
| Sesión | `$_SESSION['usuario']['perfil']` y `$_SESSION['usuario']['permiso']` |
| Evaluación | `permisoScriptUSR($archivo)` + `accionP($permiso, $accion)` en `php/funciones.php` |

La cadena de permiso es posicional, cinco caracteres, `-` significa denegado:

```
posición  0    1    2    3    4
acción    l    a    m    e    p
          Listar Agregar Modificar Eliminar Imprimir
```

`permisoScriptUSR()` toma el prefijo del nombre del archivo antes del primer `_` (`usuario_mf.php` → `usuario`) y busca la cadena en la sesión. Si no la encuentra devuelve `""`, con lo que `accionP()` devuelve `""` y toda comparación `== "a"` falla. **El diseño es fail-closed.**

### 2.2 Aplicación efectiva por endpoint

De los 76 scripts PHP publicados:

| Categoría | Cantidad | Detalle |
|-----------|---------:|---------|
| Verifican permiso (`permisoScriptUSR`) | 27 | Módulos `usuario`, `permiso`, `revdoc`, `compago`, `creaper`, `tipodep`, `cardoc`, `anufac`, `revfac` |
| Solo verifican sesión | 27 | Formularios y vistas |
| **Sin sesión ni permiso** | **22** | Ver §2.3 |

### 2.3 Los 22 scripts sin ningún control

```
anufac_emp.php     anufac_per.php     buscamonto.php      buscaperiodos.php
buscaproveedor.php cerrar.php         composer_install.php correos.php
guardarproveedor.php idf.php          idr.php             permiso_c.php
pie.php            recuperapw_bus.php recuperapw_cam.php  recuperapw_f.php
recuperapw_val.php revdoc_emp.php     revdoc_per.php      revfac_emp.php
revfac_per.php     z.php
```

No todos son un problema: `pie.php` y `correos.php` son incluidos, no endpoints; `cerrar.php` y el flujo `recuperapw_*` deben ser accesibles sin sesión por definición. Los relevantes son:

- **`z.php`** — vuelca la sesión completa (H-01).
- **`recuperapw_bus.php` / `recuperapw_cam.php`** — el flujo de recuperación (H-01, H-02).
- **`buscaproveedor.php`, `buscamonto.php`, `buscaperiodos.php`, `idf.php`, `idr.php`, `*_emp.php`, `*_per.php`** — endpoints AJAX que consultan la base y devuelven datos **sin exigir sesión** (H-04).
- **`guardarproveedor.php`** — endpoint de escritura sin sesión ni permiso (H-05).
- **`composer_install.php`** — instalador de dependencias accesible desde el navegador (H-06).

---

## 3. Hallazgos

### CRÍTICO

#### H-01 · Toma de control de cualquier cuenta sin autenticación

Tres defectos encadenados en el flujo de recuperación de contraseña producen un compromiso total. **No requiere explotar ninguna vulnerabilidad de inyección**: usa funciones legítimas de la aplicación.

**Paso 1 — sembrar el token.** `recuperapw_bus.php` no exige sesión. Con solo el correo de la víctima:

```php
// recuperapw_bus.php:20-32
$_SESSION['SOL']['id']  = $fila['idUsuario'];   // <- id de la VÍCTIMA
$_SESSION['SOL']['cor'] = $fila['correo'];      //    en la sesión del ATACANTE
...
$_SESSION['SOL']['cod'] = CadenaAleatoria(10);  // <- el token de recuperación
$parametros = array($_SESSION['SOL']['cod'], 1, $_SESSION['SOL']['exp']);
$rsa = sqlsrv_query($cn, $sql, $parametros);    //    se guarda en la BD
```

El identificador de la víctima y **el token de recuperación quedan escritos en la sesión del atacante**. El correo se envía a la víctima, pero el atacante ya no lo necesita.

**Paso 2 — leer el token.** `z.php`, 75 bytes, sin ninguna validación:

```php
<?php session_start(); echo "<pre>"; var_dump($_SESSION); echo "</pre>"; ?>
```

Una petición del atacante a su propia sesión le devuelve `SOL.cod` en claro.

**Paso 3 — cambiar la contraseña.** `recuperapw_cam.php` acepta el token y reescribe la credencial de `$_SESSION['SOL']['id']`, es decir, la de la víctima.

**Resultado:** control de cualquier cuenta, incluida cualquiera con `idTipo = 1`, conociendo solo un correo electrónico. Todo el modelo de `PermisoReporte` queda anulado.

**Remediación (en este orden):**
1. **Eliminar `z.php` hoy.** Es una línea de trabajo olvidada, sin uso legítimo.
2. No almacenar el token en la sesión del solicitante. El token debe existir únicamente en la base de datos y viajar solo por correo.
3. Vincular el token a la víctima en la propia consulta de canje (`WHERE token = ? AND correo = ?`), no a un identificador guardado en la sesión del atacante.
4. Rotar las contraseñas de todos los usuarios y revisar los registros de IIS (`W3SVC2`, `W3SVC3`) buscando peticiones previas a `z.php` y `recuperapw_bus.php`.

#### H-02 · Inyección SQL en el inicio de sesión y en el canje de token

Ambas consultas concatenan entrada del usuario con `strip_tags()` como única defensa, que no filtra comillas:

```php
// iniciar.php:25-27
$us  = strip_tags($_POST['us']);
$sql = "select u.*, t.nombre_tipo from Usuario U INNER JOIN Tipo T on T.idTipo= u.idTipo
        where correo='$us' AND activo=1";
```

```php
// recuperapw_cam.php:12-16
$cod = strip_tags($_POST['COD']);
$sql = "select CONVERT(varchar,expira_token,20) as ftoken from Usuario
        where token='$cod' AND activo=1 AND idUsuario=". $_SESSION['SOL']['id'];
```

En `recuperapw_cam.php` la inyección es una segunda vía —independiente de `z.php`— para completar H-01: `COD` con `' OR '1'='1` satisface la condición sin conocer el token.

En `iniciar.php` la inyección permite además extraer el contenido de `Usuario` (correos, hashes, sales) y, dado el driver `sqlsrv` sobre SQL Server, encadenar consultas.

**Agravante:** según [REPOFEL.md](REPOFEL.md), `php/cnbde.php` se conecta con el usuario **`sa`**. Una inyección que alcance esa conexión no compromete solo la aplicación, sino la instancia de SQL Server completa.

**Remediación:** parametrizar ambas consultas con `sqlsrv_query($cn, $sql, $params)` — el patrón ya se usa correctamente en `usuario_a.php:31` y `recuperapw_bus.php:26`. El resto del código debe barrerse con el mismo criterio: `strip_tags()` no es un control de inyección SQL.

#### H-03 · La expiración del token de recuperación nunca se cumple

```php
// recuperapw_cam.php:29-30
$Diferencia = abs($fechaActual->getTimestamp() - $fechaExpira->getTimestamp());
if ($Diferencia > 0){   // <- siempre verdadero
```

El valor absoluto de la diferencia es positivo tanto si el token está vigente como si caducó hace un año. La ventana de 24 horas que `recuperapw_bus.php:28` se esfuerza en calcular **no se aplica jamás**: todo token emitido sigue siendo válido indefinidamente.

**Remediación:** `if ($fechaActual < $fechaExpira)`, e invalidar el token tras un uso exitoso (`recuperapw_cam.php` lo pone a `''`, lo cual es correcto, pero solo se alcanza si el resto del flujo funciona).

### ALTO

#### H-04 · Endpoints de datos accesibles sin sesión

`buscaproveedor.php`, `buscamonto.php`, `buscaperiodos.php`, `idf.php`, `idr.php`, `anufac_emp.php`, `anufac_per.php`, `revdoc_emp.php`, `revdoc_per.php`, `revfac_emp.php` y `revfac_per.php` consultan la base y devuelven datos sin comprobar `$_SESSION['usuario']`. Su única barrera es `session_id() == $_POST['SID']`, que un cliente cualquiera satisface enviando su propio identificador de sesión.

**Impacto:** enumeración de proveedores, empresas, períodos y montos de facturación sin credenciales.

**Remediación:** anteponer a todos la comprobación de sesión y, donde corresponda, la de permiso del módulo al que pertenecen.

#### H-05 · Escritura sin autorización en `guardarproveedor.php`

Endpoint de escritura sin comprobación de sesión ni de permiso. Cualquiera que alcance la URL puede dar de alta proveedores en el repositorio de facturas.

**Remediación:** exigir sesión y el permiso `a` del módulo correspondiente.

#### H-06 · La contraseña inicial de todo usuario es igual a su sal

```php
// usuario_a.php:29-33
$salnueva      = CadenaAleatoria(7);
$pw_encriptado = PASS::encriptar($salnueva, $salnueva);  // contraseña == sal
...
$var = array(..., $pw_encriptado, $salnueva, ...);       // la sal se guarda en claro
```

La contraseña asignada al crear un usuario **es la propia sal**, que se almacena sin cifrar en la columna `salt`. Cualquiera que lea la tabla `Usuario` —por H-02, por el usuario `usrRepo`, o desde una copia de seguridad— obtiene la contraseña inicial en texto claro, sin necesidad de romper el hash.

Agravantes:
- Son 7 caracteres, por debajo de cualquier política razonable.
- Se envía por correo en texto plano (`usuario_a.php:51`).
- **No hay obligación de cambiarla en el primer inicio de sesión**: el usuario que nunca la cambie conserva indefinidamente una credencial legible en la base de datos.

**Remediación:** generar contraseña y sal de forma independiente con `random_bytes()`; marcar la cuenta con cambio obligatorio en el primer acceso; sustituir el envío por un enlace de activación de un solo uso.

### MEDIO

#### H-07 · Hash de contraseñas sin coste computacional

```php
// php/funciones.php:124-131
class PASS {
    public static function encriptar($password, $sal) { return hash('sha512', $sal . $password); }
    public static function verificar($password, $pw_cifrado, $sal) { return ($pw_cifrado == self::encriptar($password, $sal)); }
}
```

SHA-512 de una pasada es una función rápida por diseño: una GPU actual evalúa miles de millones por segundo. Con las sales almacenadas en claro y contraseñas de 7 caracteres (H-06), el conjunto completo de credenciales es recuperable en un tiempo trivial si la tabla se filtra.

Además, `==` no es una comparación en tiempo constante.

**Remediación:** migrar a `password_hash()` / `password_verify()` (bcrypt o Argon2id), rehasheando de forma transparente en el siguiente inicio de sesión de cada usuario. Sustituir `==` por `hash_equals()`.

#### H-08 · Los permisos solo se releen al iniciar sesión

`iniciar.php:45-59` carga `$_SESSION['usuario']['permiso']` una única vez, en el momento del inicio de sesión.

**Impacto:** revocar un permiso o degradar un perfil en `PermisoReporte` **no tiene efecto** mientras la sesión del usuario siga viva. Un usuario al que se le retira acceso lo conserva hasta que cierre sesión voluntariamente. Es el problema clásico de autorización obsoleta, y es especialmente relevante durante una baja de personal.

**Remediación:** releer los permisos por petición, o mantener un contador de versión de permisos en `Usuario` que invalide la sesión cuando cambie.

#### H-09 · El perfil administrador es implícito y no auditable

```php
// iniciar.php:46-50
if ($idt==1){
    $sql="select idReporte,nombre_reporte,script,permiso from Reporte";   // TODO
}else{
    $sql="select ... from PermisoReporte P ... WHERE idUsuario=".$id;
}
```

`idTipo = 1` concede todos los reportes con la cadena de permiso por defecto de la tabla `Reporte`, sin pasar por `PermisoReporte`. Consecuencias:

- La tabla de permisos **no refleja lo que puede hacer un administrador**; una revisión de accesos que consulte `PermisoReporte` no verá a los superusuarios.
- Quien tenga permiso `m` sobre el módulo `usuario` puede cambiar el `idTipo` de cualquier cuenta a `1` y crear un administrador. Es escalada de privilegios dentro del modelo previsto.

**Remediación:** materializar los permisos del perfil administrador en `PermisoReporte` para que toda concesión sea consultable, y registrar en bitácora todo cambio de `idTipo`.

#### H-10 · El control anti-CSRF es el propio identificador de sesión

Todos los endpoints validan `session_id() == $_POST['SID']`. Es un token predecible por el propio cliente, reutilizable, sin un solo uso, y viaja en el cuerpo de cada formulario. Según [REPOFEL.md](REPOFEL.md), `session.cookie_httponly` está vacío, de modo que un XSS puede leer la cookie de sesión y, con ella, el valor de `SID`.

**Remediación:** token CSRF aleatorio por formulario, de un solo uso, y activar `session.cookie_httponly=1`, `session.use_strict_mode=1` y `session.cookie_secure=1`.

### BAJO

#### H-11 · `permiso_c.php` lee una variable de sesión inexistente

```php
// permiso_c.php:16
$permisop = str_split($_SESSION['permiso'][$opcion]);
```

La sesión real es `$_SESSION['usuario']['permiso']`. La clave `$_SESSION['permiso']` no se define en ninguna parte, por lo que el script devuelve siempre una cadena vacía y genera avisos de índice indefinido. La pantalla de asignación de permisos depende de él.

**Remediación:** corregir la referencia y verificar que el formulario de permisos muestra las casillas esperadas.

#### H-12 · Código muerto con lógica de autenticación paralela

`php/funciones.php` contiene la clase `USUARIO`, con un inicio de sesión multiempresa completo contra tablas (`tUsuario`, `tCorporacion`) que no existen en `BDREPOFEL`. Nunca se invoca.

**Impacto:** dos implementaciones de autenticación conviviendo en el mismo archivo confunden cualquier revisión y arriesgan que alguien la reactive por error.

**Remediación:** extraer `permisoScriptUSR()` y `accionP()` a `php/permisos.php` y eliminar el resto, tras verificar con `grep` que nadie lo referencia.

---

## 4. Lo que sí está bien resuelto

- **El modelo de autorización falla cerrado.** Un script ausente de la sesión devuelve `""` y toda comprobación de acción falla. Es la decisión correcta y no es habitual encontrarla en desarrollos de este tipo.
- **La parametrización se usa donde importa más.** `usuario_a.php:31`, `recuperapw_bus.php:26` y `recuperapw_cam.php:31` usan consultas parametrizadas. El patrón correcto ya está en el código; falta aplicarlo de forma sistemática.
- **Las contraseñas están hasheadas y saladas**, con sal distinta por usuario. El algoritmo es inadecuado (H-07), pero no hay contraseñas en texto plano en la tabla.
- **La sesión se invalida por inactividad del lado de PHP** y los formularios comprueban la existencia de sesión antes de renderizar.
- **`activo=1` se comprueba en el inicio de sesión**, de modo que desactivar un usuario impide autenticarse (aunque no cierra las sesiones vivas — ver H-08).

---

## 5. Revisión de registros de acceso

Se barrió el histórico completo de IIS: **1019 días** en `W3SVC2` (05/09/2023 – 17/08/2026)
y **159 días** en `W3SVC3` (05/03/2026 – 17/08/2026).

### 5.1 `z.php` fue encontrado por un escáner automatizado

`z.php` recibió **15 peticiones**, todas con estado 200:

| Fecha | Origen | Peticiones | Tamaño respuesta | Lectura |
|---|---|---|---:|---|
| 15–16/10/2024 | `10.2.8.28` (interna) | 14 | 70–176 bytes | Depuración durante el desarrollo |
| **17/05/2026 09:17:03** | **`110.238.87.156`** | **1** | **414 bytes** | **Escáner de webshells** |

La petición de 2026 no es tráfico de usuario. Forma parte de un barrido de **53 peticiones
en 5 segundos** probando nombres habituales de puerta trasera:

```
/x.php  /333.php  /png.php  /yas.php  /lib.php  /shell20211028.php
/wp-load.php  /wp-firewall.php  /wp-content/plugins/hellopress/wp_filemanager.php  ...
```

**52 devolvieron 404. `z.php` devolvió 200.** El agente de usuario iba vacío. La respuesta
de 414 bytes es notablemente mayor que las de la depuración interna, lo que indica una
sesión con más contenido volcado.

**Qué significa y qué no.** No hay evidencia de que ese escáner completara la cadena de
H-01: no hubo peticiones a `recuperapw_bus.php` desde esa dirección, ni más accesos a
`z.php` después. Pero un escáner que obtiene un 200 sobre un nombre de archivo de una sola
letra registra el hallazgo, y esos catálogos se revisitan. **`z.php` dejó de ser un
descuido interno el 17/05/2026: desde esa fecha es un recurso conocido por terceros.**

Como dato adyacente sin resolver, el **13/05/2026 a las 22:05** hubo una petición a
`recuperapw_bus.php` desde `110.238.87.152` —cuatro días antes y en el mismo /24—. Puede
ser un usuario legítimo recuperando su contraseña; con los datos disponibles no se puede
distinguir de la primera mitad de la cadena de H-01.

### 5.2 Corrección a la caracterización del rango `110.238.87.0/24`

[REPOFEL.md](REPOFEL.md) §10 describía ese rango como *«Huawei Cloud — coincide con el
entorno del propio grupo; es el tráfico legítimo»*. **Esa lectura no se sostiene para todo
el rango:** `110.238.87.156` ejecutó un barrido hostil de webshells. Huawei Cloud es un
proveedor público, y direcciones contiguas de un mismo `/24` pertenecen a inquilinos
distintos.

La consecuencia práctica es que **el rango no puede usarse como criterio de confianza** en
una regla de firewall o de WAF. Conviene identificar las direcciones concretas de la
infraestructura propia y tratar el resto del /24 como cualquier origen de internet.

### 5.3 Sin rastro de explotación de las inyecciones SQL

No se observaron en el histórico peticiones a `iniciar.php` con comillas o construcciones
de inyección en el cuerpo. La limitación es real: el registro de IIS **no guarda el cuerpo
de las peticiones POST**, y tanto `iniciar.php` como `recuperapw_cam.php` reciben sus
parámetros por POST. Una explotación de H-02 no dejaría rastro en estos registros.

---

## 6. Brechas de evidencia

| Brecha | Causa | Cómo cerrarla |
|--------|-------|---------------|
| **Padrón real de usuarios** (`Usuario`) y sus permisos efectivos (`PermisoReporte`) | Requiere conectar a `BDREPOFEL` con las credenciales de `php/cnbd.php` | Autorización explícita para ejecutar la consulta de solo lectura |
| Cuántos usuarios conservan la contraseña inicial (H-06) | Igual que la anterior | Comparar `clave` con `PASS::encriptar(salt, salt)` |
| Cuántas cuentas tienen `idTipo = 1` | Igual que la anterior | `SELECT correo, activo FROM Usuario WHERE idTipo = 1` |
| Si H-01 ya fue explotado | **Revisado** — ver §5.1. Un escáner de webshells localizó `z.php` el 17/05/2026 y obtuvo 200. Sin evidencia de que completara la cadena | Confirmar con el equipo si `110.238.87.152/.156` son infraestructura propia; revisar la tabla `Usuario` buscando cambios de `clave` no solicitados |
| Estado de `G:\REPOFELMX` | No revisado en esta pasada | Según [REPOFEL.md](REPOFEL.md) las dos instancias divergen; los hallazgos deben confirmarse por separado |

---

## 7. Plan de remediación priorizado

| # | Acción | Hallazgo | Plazo |
|---|--------|----------|-------|
| 1 | **Eliminar `z.php`** de ambas instancias — un escáner externo ya lo localizó (§5.1) | H-01 | Hoy |
| 2 | Corregir el flujo de recuperación: token solo en BD, vinculado al correo, expiración real | H-01, H-03 | 24 h |
| 3 | Parametrizar `iniciar.php` y `recuperapw_cam.php` | H-02 | 24 h |
| 4 | Revisar registros de IIS buscando explotación previa; rotar contraseñas si aparece | H-01 | 48 h |
| 5 | Sustituir el usuario `sa` de `php/cnbde.php` por uno de permisos mínimos | H-02 | 48 h |
| 6 | Exigir sesión en los 11 endpoints de datos y en `guardarproveedor.php` | H-04, H-05 | 1 semana |
| 7 | Contraseña inicial aleatoria e independiente de la sal + cambio obligatorio | H-06 | 1 semana |
| 8 | Migrar el hash a `password_hash()` con rehash transparente | H-07 | 2 semanas |
| 9 | Releer permisos por petición; materializar los del perfil administrador | H-08, H-09 | 2 semanas |
| 10 | Token CSRF de un solo uso + endurecer la configuración de sesión de PHP | H-10 | 2 semanas |
| 11 | Corregir `permiso_c.php` y eliminar la clase `USUARIO` muerta | H-11, H-12 | 1 mes |
| 12 | **Poner ambas instancias bajo Git** — sin esto ninguna corrección es verificable | — | 1 mes |

---

## 8. Relación con la auditoría de sistema operativo

Los dos informes describen el mismo problema en capas distintas: **no hay separación efectiva entre usuarios**.

- En el servidor, `Everyone: FullControl` sobre el directorio de SAP Business One y siete administradores locales sobre nueve cuentas.
- En la aplicación, un modelo de permisos correcto en su diseño pero anulado por una toma de control de cuentas sin autenticación.

Se refuerzan mutuamente: `G:\REPOFEL` es legible desde la compartición administrativa `G$` por cualquiera de las siete cuentas administrativas, y entre esas cuentas hay una sin uso desde hace más de dos años. Quien comprometa `edson.cuque` lee `php/cnbd.php` y `php/cnbde.php`, y con el usuario `sa` que ahí figura alcanza toda la instancia de SQL Server —incluidas las bases de SAP Business One.
