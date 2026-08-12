# Auditoría y documentación de los colectores de auditoría

**Repositorio:** auditoria-senoriales
**Alcance:** los 17 scripts `L*-*.ps1` del directorio raíz
**Fecha de revisión:** 2026-08-12
**Revisión sobre:** commit `4b5cd84` (rama `main`)

---

## 1. Alcance y método

Este documento cumple dos propósitos:

1. **Documentar** cada colector: qué recolecta, de qué fuente, qué hallazgos emite y de qué depende.
2. **Auditar el código de auditoría**: identificar defectos que afecten la exactitud, la cobertura o la trazabilidad de la evidencia que estos scripts producen.

El método fue lectura estática completa de los 17 archivos. No se ejecutó ningún colector: no existe en el repositorio el orquestador ni los archivos de configuración que requieren (ver hallazgo A-01), por lo que ninguno es ejecutable de forma aislada en su estado actual.

El criterio de severidad aplicado a los hallazgos de esta revisión es el impacto sobre la **evidencia de auditoría**: un defecto que hace que un control real no se evalúe y aun así el informe salga limpio es más grave que un error que produce ruido visible.

---

## 2. Arquitectura observada

Los 17 archivos comparten un contrato uniforme y bien definido. Ninguno se desvía de él, lo cual es una fortaleza notable del conjunto.

**Contrato de entrada.** Todos declaran `param([switch]$Manifest, [hashtable]$Config)`. Dos de ellos (`L4-01`, `L4-06`) reciben además `[hashtable]$Arquitectura`; `L9-01` acepta `$Muestras` e `$IntervaloSeg`.

**Modo manifiesto.** Invocado con `-Manifest`, cada script retorna únicamente su bloque `$meta` (Id, Nombre, Layer, Criterios, RequiereAdmin, Descripcion) y termina. Esto permite a un orquestador descubrir el catálogo de colectores sin ejecutarlos.

**Contrato de salida.** Todos terminan llamando a `New-CollectorResult` con cuatro colecciones:

| Colección | Contenido |
|---|---|
| `Records` | Evidencia cruda normalizada, un objeto por elemento inventariado |
| `Findings` | No conformidades u observaciones, construidas con `New-AuditFinding` |
| `Metrics` | Indicadores agregados clave-valor para el resumen ejecutivo |
| `Gaps` | Limitaciones de cobertura: lo que **no** se pudo verificar y por qué |

La colección `Gaps` es el elemento de diseño más valioso del conjunto: distingue explícitamente "verificado y conforme" de "no se pudo verificar", que es precisamente la distinción que una auditoría no puede permitirse perder.

**Estados de terminación.** Tres colectores devuelven un `-Status` explícito cuando no pueden operar: `Skipped` (L4-03, escaneo deshabilitado por configuración), `NoData` (L4-05 y L4-06, sin insumo base) y `Failed` (L5-01, WMI inaccesible).

**Capas.** La numeración L1–L9 modela un stack ascendente: hardware, sistema operativo, plataforma, artefactos de software, servicios, identidad, red, datos/registro y rendimiento. La capa L4 concentra 6 de los 17 colectores y está declarada en los propios comentarios como la capa prioritaria de la auditoría.

**Naturaleza de solo lectura.** Se verificó archivo por archivo: los 17 colectores usan exclusivamente operaciones de lectura (`Get-*`, `Test-Path`, lectura de registro, ejecución de utilidades nativas en modo consulta). Ninguno escribe en el registro, modifica servicios, altera archivos ni cambia configuración. Es apto para ejecución sobre servidores productivos desde el punto de vista de la integridad del activo auditado.

---

## 3. Documentación por colector

### L1-01 — Inventario de hardware y plataforma física
**Criterios declarados:** INV-01, CRI-01, DAT-03, ARQ-01
**Fuentes:** `Win32_ComputerSystem`, `Win32_BIOS`, `Win32_SystemEnclosure`, `Win32_Processor`, `Win32_PhysicalMemory`, `Win32_DiskDrive`, `Win32_LogicalDisk`, `Win32_NetworkAdapter`.

Levanta chasis, CPU, memoria física, discos, volúmenes y adaptadores. Incluye detección de virtualización por coincidencia de patrones sobre fabricante y modelo (VMware, Hyper-V, KVM/QEMU, Xen, VirtualBox, AWS EC2, Google Cloud), y un mapa de 20 tipos de chasis.

**Hallazgos que emite:** firmware BIOS con más de 4 años (solo si el equipo es físico), servidor fuera de dominio, medio extraíble conectado, volumen con sistema de archivos sin ACL.

### L2-01 — Línea base del sistema operativo
**Criterios declarados:** INV-01, ARQ-01, ARQ-04
**Fuentes:** `Win32_OperatingSystem`, `SoftwareLicensingProduct`, `Win32_TimeZone`, servicio W32Time, registro (W32Time, CBS, WindowsUpdate, Session Manager), `Get-ExecutionPolicy`.

Identidad y versión del SO, estado de activación, tiempo de actividad, zona horaria y sincronización NTP, política de ejecución de PowerShell y detección de reinicio pendiente por tres indicadores independientes.

**Hallazgos que emite:** uptime excesivo (parches no efectivos), SO sin licencia válida, W32Time detenido o ausente, fuente NTP no declarada, ExecutionPolicy permisiva, reinicio pendiente.

### L2-02 — Nivel de parcheo y actualizaciones
**Criterios declarados:** VUL-01, CAM-01
**Fuentes:** `Get-HotFix`, políticas de registro de Windows Update, servicio `wuauserv`, agente COM `Microsoft.Update.Session`.

Historial de hotfixes con antigüedad, configuración de actualización automática (mapeo de los 5 valores de `AUOptions`), servidor WSUS configurado y consulta de actualizaciones pendientes con severidad MSRC.

**Hallazgos que emite:** latencia de parcheo fuera de umbral (escala a Critical al doble del umbral), sin historial de actualizaciones, actualizaciones automáticas deshabilitadas por directiva, servicio Windows Update deshabilitado, actualizaciones críticas pendientes.

### L2-03 — Configuración de seguridad del sistema operativo
**Criterios declarados:** VUL-02, ARQ-01, REG-01, RED-01, CRI-02, CRI-01
**Fuentes:** `Get-MpComputerStatus`, `Get-MpPreference`, `root\SecurityCenter2`, `Get-NetFirewallProfile`, `Get-BitLockerVolume`, 9 claves de registro de hardening, `Get-WindowsOptionalFeature`, registro SCHANNEL, `auditpol.exe`.

Es el colector de hardening más extenso. Evalúa antimalware (incluyendo antigüedad de firmas, protección contra manipulación y análisis de exclusiones), perfiles de firewall, cifrado BitLocker, UAC, LSA Protection, hashes LM, SMBv1 y firma SMB, registro de PowerShell, los 6 protocolos SSL/TLS en rol cliente y servidor, y la cobertura de la directiva de auditoría avanzada.

**Hallazgos que emite:** 12 tipos distintos, desde protección en tiempo real deshabilitada (Critical) hasta cobertura insuficiente de auditoría (Medium).

### L3-01 — Runtimes, motores y middleware
**Criterios declarados:** INV-01, SW-02, VUL-01, ARQ-01, ARQ-03
**Fuentes:** registro NDP, `dotnet --list-runtimes/--list-sdks`, registro JavaSoft/Adoptium/Azul, `java -version`, `python --version`, `node --version`, registro InetStp, módulo WebAdministration, registro de instancias SQL Server, servicios de base de datos, `Get-WindowsFeature`.

Detecta la capa de plataforma sobre la que corren las aplicaciones. Incluye enumeración de grupos de aplicación de IIS con su identidad de proceso, y contraste del inventario resultante contra el catálogo de fin de soporte de la configuración.

**Hallazgos que emite:** SDK de desarrollo en servidor, Node.js en rama sin soporte, AppPool de IIS como LocalSystem, componente de plataforma fuera de soporte.

### L4-01 — Inventario consolidado de software instalado
**Criterios declarados:** INV-01, SW-03, INV-03, DAT-02, CAM-01
**Fuentes:** `Get-InstalledSoftwareRaw` (registro de desinstalación, todas las vistas), `Get-AppxPackage`, índice de procesos en ejecución.

Es el colector central de la capa prioritaria. Para cada artefacto resuelve: ruta de instalación (cascada InstallLocation → UninstallString → DisplayIcon → binario en ejecución), descripción funcional, rol arquitectónico, capa de arquitectura empresarial, propietario y criticidad. Deduplica entre ámbitos de máquina y usuario.

**Hallazgos que emite:** software fuera de política (con criterios diferenciados por categoría de riesgo: nube, P2P, acceso remoto, herramienta ofensiva), software sin publicador declarado, artefactos sin ruta determinable, instalaciones de los últimos 30 días (trazabilidad de cambios), software sin actualizar en más de dos años.

### L4-02 — Software gestionado por gestores de paquetes
**Criterios declarados:** INV-01, SW-03, SW-04, ARQ-03
**Fuentes:** `winget list`, `choco list`, directorios de Scoop, `npm ls -g`, `pip list`, `dotnet tool list`, `Get-Module -ListAvailable`, `Get-PSRepository`.

Cubre el punto ciego clásico del inventario: software con capacidad de ejecución arbitraria que no aparece en Agregar o quitar programas. Distingue explícitamente instalaciones de ámbito usuario, que no requieren privilegios administrativos.

**Hallazgos que emite:** repositorio de terceros marcado como confiable, gestores de desarrollo presentes en producción, software instalado en perfil de usuario. Emite un registro explícito de resultado favorable cuando no detecta ningún gestor.

### L4-03 — Binarios y scripts no gestionados (shadow IT)
**Criterios declarados:** SW-03, INV-03, SW-05
**Fuentes:** recorrido de las rutas definidas en `Config.UnmanagedScan`, con verificación de firma Authenticode.

Escaneo de sistema de archivos gobernado enteramente por configuración: rutas, exclusiones, extensiones, profundidad máxima, tope de archivos, cálculo opcional de hash y tamaño mínimo. Clasifica cada archivo en cinco categorías de procedencia. Está deshabilitado por defecto y devuelve `Skipped` si la configuración no lo habilita.

**Hallazgos que emite:** ejecutables sin firma digital, archivos con firma inválida o no confiable (Critical, tratado como indicador de compromiso), scripts operativos sin control de versiones, ejecutables en directorios temporales o de escritura general.

**Nota de calidad:** es el único colector que declara explícitamente su propia cobertura parcial cuando alcanza el tope de archivos, tanto en `Gaps` como en el log. Es el comportamiento correcto y debería replicarse en los demás.

### L4-04 — Integridad y procedencia de binarios en ejecución
**Criterios declarados:** SW-03, ARQ-01, VUL-02, CAM-01
**Fuentes:** `Win32_Service` (rutas de imagen), `Get-Process` (rutas de proceso), firma Authenticode y hash SHA256 de cada binario resuelto.

Verifica lo que efectivamente se ejecuta, no lo que está declarado como instalado. Genera la línea base de hashes destinada a la comparación entre ejecuciones sucesivas de la auditoría.

**Hallazgos que emite:** binarios sin firma, binario alterado tras su firma (Critical, indicador de compromiso), publicador fuera de la lista de confianza, firma sin sello de tiempo.

### L4-05 — Ciclo de vida y soporte del software instalado
**Criterios declarados:** SW-02, VUL-01, INV-01, SW-03, SW-04
**Fuentes:** `Get-InstalledSoftwareRaw` contrastado contra `Config.EndOfLife`.

Clasifica cada producto en cuatro estados (fuera de soporte, soporte próximo a vencer a menos de 180 días, soportado, no catalogado), detecta coexistencia de versiones múltiples y resume la concentración de proveedores como insumo del análisis de cadena de suministro.

**Hallazgos que emite:** un hallazgo individual por cada producto fuera de soporte (decisión correcta: son no conformidades independientes), fin de soporte próximo, versiones múltiples coexistentes.

### L4-06 — Línea base de arquitectura empresarial y conformidad de roles
**Criterios declarados:** INV-01, SW-03, ARQ-01, INV-03, ARQ-03
**Fuentes:** inventario base, `Win32_Service` y `Get-NetTCPConnection` para correlación, y el catálogo declarado en `Config\Arquitectura.psd1`.

El colector conceptualmente más ambicioso del conjunto. No busca vulnerabilidades: contrasta lo que el servidor **es** contra lo que la organización **declaró** que debería ser. Correlaciona cada artefacto con los servicios que ejecuta y los puertos que expone, y evalúa la alineación de su rol contra el propósito declarado del servidor.

**Hallazgos que emite:** aplicaciones declaradas no detectadas, artefactos con rol no alineado, roles no clasificados en la línea base, aplicaciones de negocio fuera del catálogo, cobertura insuficiente de la taxonomía, aplicaciones sin propietario, servidor sin propietario declarado.

### L5-01 — Servicios Windows y configuración de ejecución
**Criterios declarados:** ARQ-01, ACC-02, SW-03, SW-05
**Fuentes:** `Win32_Service`.

Inventario completo de servicios con tres análisis: rutas de imagen sin comillas que contienen espacios (secuestro de ruta no citada), binarios fuera de rutas de instalación estándar, y cuentas de ejecución privilegiadas o nominales.

**Hallazgos que emite:** rutas sin comillas, binarios fuera de ruta estándar, servicios de terceros como LocalSystem, servicios automáticos detenidos, cuentas de servicio nominales.

### L5-02 — Tareas programadas y puntos de autoarranque
**Criterios declarados:** SW-03, REG-02, CAM-02, ARQ-01
**Fuentes:** `Get-ScheduledTask`, 6 claves Run/RunOnce/Winlogon del registro, dos carpetas de inicio, `root\subscription` (consumidores de eventos WMI).

Cubre los cuatro mecanismos principales de persistencia y automatización, separando tareas del sistema (`\Microsoft\*`) de tareas de terceros.

**Hallazgos que emite:** tareas de terceros activas, tareas de terceros con privilegio máximo, `Winlogon\Userinit` modificado (Critical), entradas de autoarranque en registro, suscripciones WMI permanentes.

### L6-01 — Identidades locales y control de acceso
**Criterios declarados:** ACC-04, ACC-01, ACC-03, ACC-02
**Fuentes:** `Get-LocalUser` con respaldo a `Win32_UserAccount`, `Get-LocalGroupMember` sobre 7 grupos críticos, `net accounts`, registro de Terminal Server.

Cuentas locales con antigüedad de contraseña y último inicio de sesión, membresías privilegiadas, política de contraseñas y bloqueo, y configuración de RDP incluyendo NLA y nivel de seguridad.

**Hallazgos que emite:** cuenta Administrador integrada habilitada (detectada por SID `-500`, robusto frente a renombrado), cuentas inactivas, cuentas nunca usadas, contraseñas que no expiran, contraseñas sin rotación, exceso de administradores locales, miembros con acceso RDP, longitud mínima insuficiente, bloqueo no configurado, RDP sin NLA.

### L7-01 — Exposición de red y servicios accesibles
**Criterios declarados:** RED-01, RED-02, RED-03, ACC-04
**Fuentes:** `Get-NetTCPConnection`, `Get-NetUDPEndpoint`, `Win32_Share` con `Get-SmbShareAccess`, `Get-NetIPConfiguration`, `Get-NetFirewallRule` con sus filtros, WSMan.

Correlaciona cada puerto en escucha con el proceso propietario y su ruta en disco. Mantiene un catálogo de 16 puertos sensibles con su descripción de riesgo. Evalúa recursos compartidos, perfiles de red, reglas de firewall permisivas y configuración de WinRM.

**Hallazgos que emite:** servicios sensibles en todas las interfaces, protocolos sin cifrado (Critical), comparticiones con permisos amplios de escritura, interfaz con perfil público, reglas de firewall sin restricción, WinRM sin cifrado o con autenticación básica.

### L8-01 — Registro de eventos, respaldo y resiliencia
**Criterios declarados:** REG-01, REG-02, CAP-02, CAP-03, DAT-01, DAT-03
**Fuentes:** `Get-WinEvent -ListLog` sobre 7 canales críticos, política WEF, evento 1102, `Win32_ShadowCopy`, servicio `wbengine`, canal de respaldo, `Win32_LogicalDisk`, directorios temporales.

Evalúa la capacidad probatoria del servidor: si los canales están habilitados, si su tamaño permite retención útil, si el modo de retención puede detener el registro, si los eventos se remiten a una plataforma central, y si hay evidencia de borrado del registro de seguridad.

**Hallazgos que emite:** canal deshabilitado, tamaño insuficiente del registro Security, modo Retain, sin reenvío centralizado, borrados del registro de seguridad (indicador anti-forense), sin instantáneas de volumen, espacio libre insuficiente, acumulación de temporales.

### L9-01 — Estadísticas de rendimiento y capacidad
**Criterios declarados:** CAP-01, REG-02, AUD-01
**Fuentes:** `Get-Counter` sobre 7 contadores, `Win32_OperatingSystem`, `Get-Process`, `Win32_LogicalDisk`, `Get-NetAdapter`, `Get-NetAdapterStatistics`, evento 6008.

Toma múltiples muestras (5 por defecto, cada 2 segundos) en lugar de una lectura puntual, y reporta mínimo, máximo y promedio. Correlaciona el consumo con los procesos y sus rutas, enlazando con la capa L4.

**Hallazgos que emite:** memoria disponible bajo umbral, CPU sostenida sobre umbral, apagados inesperados en los últimos 30 días.

---

## 4. Hallazgos de la auditoría del código

### Críticos

**A-01 — El repositorio no contiene el marco de ejecución del que dependen los 17 colectores.**

Se contabilizaron **181 invocaciones a 11 funciones que no están definidas en ningún archivo del repositorio**:

`New-AuditFinding`, `New-CollectorResult`, `ConvertTo-SafeString`, `Invoke-NativeCapture`, `Test-CommandExists`, `Get-SignatureInfo`, `Get-InstalledSoftwareRaw`, `Resolve-InstallPath`, `Get-ArchitectureRole`, `Get-SoftwareDescription`, `Write-AuditLog`.

Las únicas 9 funciones definidas son auxiliares locales de un solo archivo (`Add-Runtime`, `Add-Control`, `Add-Paquete`, `Add-Autorun`, `Add-Stat`, `Add-Binario`, `Find-ExecutablePath`, `Test-PublicadorConfiable`, `Test-RutaExcluida`).

Faltan además los archivos de configuración que los colectores leen por nombre: `Audit.config.psd1` (referenciado en el texto de los hallazgos de L4-03 y L4-04) y `Config\Arquitectura.psd1` (requerido por L4-01 y L4-06), así como el orquestador que consume el modo `-Manifest` y agrega los resultados.

**Impacto:** ningún colector es ejecutable en el estado actual del repositorio. Las funciones más críticas son las dos del contrato de salida: `Get-InstalledSoftwareRaw` alimenta a tres colectores de la capa prioritaria, y `Get-SignatureInfo` sostiene por completo la verificación de integridad de L4-03 y L4-04. La lógica de negocio de la auditoría vive en esas funciones ausentes: la definición de "software instalado", la resolución de rutas y la clasificación arquitectónica no son auditables desde este repositorio.

**Recomendación:** incorporar el módulo común, los dos archivos de configuración y el orquestador al control de versiones. Mientras no estén, el repositorio no permite reproducir ni verificar los resultados de la auditoría, que es el requisito básico de la evidencia.

### Altos

**A-02 — Los 17 colectores declaran `RequiereAdmin = $false`, pero varios controles requieren elevación para evaluarse.**

La declaración es uniforme en los 17 archivos. Sin embargo, el propio código reconoce lo contrario en sus mensajes de `Gaps`: `Get-MpPreference` requiere elevación (L2-03:105), `Get-WindowsOptionalFeature` requiere elevación (L2-03:243), `auditpol` requiere elevación (L2-03:300), `root\subscription` requiere elevación (L5-02:190), el registro Security requiere privilegios administrativos (L8-01:127), `Win32_ShadowCopy` puede requerir elevación (L8-01:151), y las reglas de firewall pueden requerirla (L7-01:226).

**Impacto:** este es el defecto más relevante de la revisión desde la óptica de auditoría. Una ejecución sin elevación produce un informe que parece completo pero en el que SMBv1, la directiva de auditoría avanzada, las exclusiones de antimalware, los borrados del registro de seguridad y la persistencia por WMI simplemente no fueron evaluados. La degradación es elegante, pero el manifiesto miente sobre las condiciones necesarias para obtener cobertura completa.

**Recomendación:** declarar `RequiereAdmin = $true` en L2-03, L5-02, L7-01 y L8-01, o introducir un tercer estado (`CoberturaCompletaRequiereAdmin`) que el orquestador refleje en la portada del informe. Adicionalmente, el informe debería declarar en su encabezado si la ejecución fue elevada.

**A-03 — El control de exceso de administradores locales no se dispara en Windows en inglés.** (`L6-01:158`)

La condición es `$g -match '(?i)^administrador'`. El grupo en inglés se llama `Administrators`, que no coincide con el patrón `administrador` (difiere a partir del octavo carácter). El bucle recorre tanto `Administradores` como `Administrators`, pero solo el primero activa la verificación de umbral.

**Impacto:** sobre un servidor en inglés, el hallazgo "número excesivo de miembros en el grupo de administradores locales" —de severidad High y directamente ligado a ACC-02— nunca se emite, con independencia de cuántos administradores existan. Los miembros sí quedan registrados en `Records`, de modo que la evidencia está presente pero la no conformidad no se levanta.

**Recomendación:** cambiar el patrón a `'(?i)^administrador(es)?$|^administrators?$'` o, preferiblemente, resolver el grupo por SID conocido (`S-1-5-32-544`), que es independiente del idioma.

**A-04 — El control de bloqueo de cuenta no coincide con la salida real de `net accounts` en español.** (`L6-01:218`)

El patrón es `'(?im)^(Lockout threshold|Umbral de bloqueo)\s*:\s*(\S+)'`. La salida en español de `net accounts` rotula esa línea como *"Umbral de bloqueo de cuenta:"*, por lo que el `\s*:` exigido inmediatamente después de "bloqueo" no encuentra los dos puntos y la coincidencia falla.

**Impacto:** en sistemas en español, el hallazgo High "bloqueo de cuenta por intentos fallidos no configurado" no se emite nunca, y la métrica `UmbralBloqueo` queda ausente. El mismo riesgo, aunque menor, afecta al patrón de longitud mínima de la línea 202, que sí está redactado de forma más tolerante.

**Recomendación:** sustituir el análisis de texto localizado por `Get-CimInstance Win32_UserAccount` combinado con la exportación de `secedit /export`, o al menos relajar los patrones a `^(Lockout threshold|Umbral de bloqueo[^:]*)\s*:`.

**A-05 — Los contadores de rendimiento están escritos en inglés y su nombre es localizado en Windows.** (`L9-01:55-63`)

Los 7 contadores solicitados a `Get-Counter` usan los nombres en inglés (`\Processor(_Total)\% Processor Time`, etc.). En una instalación de Windows en español, los nombres de contador son distintos (`\Procesador(_Total)\% de tiempo de procesador`) y la llamada falla en bloque.

**Impacto:** en un servidor en español —el escenario esperable dado que toda la salida del proyecto está en español— el colector L9-01 pierde la totalidad de su muestreo multi-lectura y cae al respaldo por CIM de la línea 100, que solo recupera un valor puntual de CPU. Se pierden memoria, disco, cola de procesador y cambios de contexto, y con ellos la premisa declarada en la cabecera del archivo de "evitar conclusiones a partir de un único instante". Lo mismo aplica al contador de latencia de la línea 210.

**Recomendación:** resolver los nombres de contador por su identificador numérico mediante `PerfLib\009\Counter` del registro, o usar `Get-CimInstance Win32_PerfFormattedData_*`, que es independiente del idioma.

### Medios

**A-06 — Umbral no validado que produce un falso positivo permanente.** (`L2-01:23`)

La línea es `$umbrales = if ($Config -and $Config.Thresholds) { $Config.Thresholds } else { @{ DiasMaxSinReinicio = 60 } }`. Si la configuración define un bloque `Thresholds` que no incluye la clave `DiasMaxSinReinicio`, el valor por defecto nunca se aplica y `$umbrales.DiasMaxSinReinicio` es `$null`. La comparación posterior `$uptime.TotalDays -gt $null` evalúa a verdadero para cualquier uptime positivo.

**Impacto:** el hallazgo "tiempo de actividad excesivo sin reinicio" se emitiría en todos los servidores, con un umbral impreso como vacío en el texto del hallazgo. Es el tipo de falso positivo que erosiona la credibilidad del informe completo.

**Nota:** L6-01 (líneas 23-28), L8-01 (23-28) y L9-01 (33-38) resuelven correctamente el mismo problema iterando las claves esperadas con `ContainsKey`. El defecto está solo en L2-01, y la corrección consiste en replicar ese patrón.

**A-07 — Validación incompleta del archivo de arquitectura.** (`L4-06:39-47`)

El colector valida `$Arquitectura.RolServidor` antes de continuar, pero acto seguido asigna `$conf = $Arquitectura.Conformidad` y `$sev = $conf.Severidades` sin verificar que existan. Si el archivo declara `RolServidor` pero omite el bloque `Conformidad`, el acceso posterior a `$sev.RolNoEsperado` (línea 234), `$sev.AplicacionNoCatalogada` (265), `$conf.MaxPorcentajeSinClasificar` (285) y `$sev.SinClasificar` (287) falla en tiempo de ejecución.

**Impacto:** el colector aborta en medio de la construcción de la línea base, perdiendo también los registros ya acumulados. Dado que este colector es el que responde las tres preguntas de auditoría de arquitectura enunciadas en su propia cabecera, su fallo silencioso deja sin respaldo toda la sección de conformidad arquitectónica.

**Recomendación:** extender la validación de la línea 39 a `Conformidad` y `Conformidad.Severidades`, o aplicar valores por defecto.

**A-08 — La evaluación de protocolos TLS solo detecta el estado explícito.** (`L2-03:248-271`)

El bucle recorre las claves SCHANNEL y emite hallazgo únicamente cuando `Enabled -eq 1` de forma explícita. Está envuelto en `if (Test-Path $ruta)`, de modo que si la subclave del protocolo no existe, no se evalúa nada.

**Impacto:** falso negativo estructural. En Windows, la ausencia de la clave significa "valor por defecto del sistema operativo", y para TLS 1.0 y TLS 1.1 ese defecto es habilitado en las versiones de Windows Server aún en uso. Un servidor sin ninguna configuración SCHANNEL explícita —el caso más común— pasa la verificación sin observaciones aunque tenga TLS 1.0 activo. El registro `Add-Control` tampoco deja constancia de que el protocolo no fue evaluado.

**Recomendación:** registrar explícitamente el estado "no configurado, se aplica el valor por defecto del sistema" y emitir hallazgo de severidad Medium para los protocolos obsoletos en esa condición.

**A-09 — La verificación autoritativa de SMBv1 depende de una llamada que requiere elevación.** (`L2-03:229-243`)

El comentario del código reconoce correctamente que en Server 2016+ la característica opcional es la fuente autoritativa y que la clave de registro `SMB1` no lo es. Pero `Get-WindowsOptionalFeature -Online` requiere elevación, y su fallo se registra como un `Gap` textual.

**Impacto:** combinado con A-02, una ejecución sin elevación puede no reportar SMBv1 activo por ninguna de las dos vías: la clave de registro ausente se clasifica como "NO DEFINIDO" sin hallazgo, y la característica no se consulta. SMBv1 es el único hallazgo de severidad Critical del bloque de protocolos.

**Recomendación:** añadir una tercera vía no elevada (`Get-SmbServerConfiguration`, propiedad `EnableSMB1Protocol`) y elevar el `Gap` a hallazgo cuando ninguna de las tres fuentes pueda confirmarlo.

**A-10 — Heurística de resolución de rutas con riesgo de atribución incorrecta.** (`L4-01:47-58`)

`Find-ExecutablePath` toma el primer token de 4 o más caracteres del nombre del producto y lo compara por prefijo contra los nombres de todos los procesos en ejecución.

**Impacto:** para un producto llamado *"Microsoft Visual C++ 2015 Redistributable"*, el token extraído es `Microsoft`, que coincide por prefijo con cualquier proceso cuyo nombre empiece así. La ruta resultante se atribuye al producto equivocado, y esa ruta alimenta luego la descripción funcional, la clasificación arquitectónica y, en L4-06, la correlación con servicios y puertos. Un error de resolución se propaga a la línea base de arquitectura empresarial.

**Recomendación:** exigir coincidencia exacta del nombre de proceso, o registrar el origen de la ruta con un indicador de confianza que el informe pueda mostrar. El campo `OrigenRuta` ya existe y podría transportar esa distinción.

**A-11 — Extracción inconsistente del ejecutable de servicios sin comillas.** (`L4-04:86-91`, `L4-06:57-62`, `L5-01:40-44`)

Los tres colectores repiten la misma lógica: si `PathName` no empieza con comilla, intentan `^\s*(\S+\.exe)` y, si falla, toman `($pathName -split '\s+')[0]`.

**Impacto:** el caso de fallo es exactamente el que L5-01 identifica como vulnerable. Para `C:\Archivos de programa\App\srv.exe -flag`, el primer patrón no coincide (hay espacios antes de `.exe`) y el respaldo devuelve `C:\Archivos`, una ruta inexistente. En L4-04 eso significa que `Get-SignatureInfo` no encuentra el archivo y el binario se descarta silenciosamente por el `if (-not $sig.Exists) { return }` de la línea 52: **los servicios con ruta no citada, que son los de mayor riesgo, quedan fuera de la verificación de integridad**. En L4-06 se pierde su correlación con puertos y servicios.

**Recomendación:** extraer la lógica a una función común del módulo compartido que pruebe rutas candidatas acumulando tokens hasta encontrar un archivo existente, y registrar en `Gaps` los `PathName` que no pudieron resolverse.

**A-12 — Valor esperado de `Userinit` con ruta fija.** (`L5-02:127`)

El patrón de comparación es `'(?i)^\s*C:\\Windows\\system32\\userinit\.exe,?\s*$'`.

**Impacto:** falso positivo de severidad Critical y categoría "indicador de compromiso" en cualquier servidor cuyo Windows no esté instalado en `C:\Windows`. Un hallazgo Critical erróneo activa procedimientos de gestión de incidentes innecesarios.

**Recomendación:** construir el valor esperado con `$env:SystemRoot`.

**A-13 — Argumento de Chocolatey retirado en la versión 2.** (`L4-02:79`)

Se invoca `choco list --local-only`. Chocolatey v2 eliminó ese argumento; `choco list` ya opera sobre paquetes locales por defecto y la invocación con el argumento retirado devuelve error.

**Impacto:** en servidores con Chocolatey v2 o superior, el inventario de paquetes de Chocolatey queda vacío. El error no se registra: el bloque solo actúa si `-not $r.Failed`, y no hay rama `else` que añada un `Gap`. La ausencia de paquetes es indistinguible de un servidor sin paquetes instalados.

**Recomendación:** detectar la versión de Chocolatey y ajustar los argumentos; en todo caso, añadir el `Gap` en la rama de fallo, como sí se hace con winget en la línea 70.

**A-14 — Solo se inventaría el primer intérprete de Python encontrado.** (`L4-02:128-141`)

El bucle sobre `@('pip','pip3')` ejecuta `break` incondicionalmente al final de la primera iteración exitosa.

**Impacto:** en servidores con varias instalaciones de Python, los paquetes de las demás no se inventarían. Tampoco se cubren entornos virtuales, que es donde suele residir el código de aplicación. Dado que este colector existe precisamente para cerrar el punto ciego del inventario, la brecha residual debería quedar declarada.

**Recomendación:** enumerar los intérpretes disponibles (por ejemplo con `py --list-paths`) e inventariar cada uno, o declarar explícitamente en `Gaps` que la cobertura se limita al intérprete presente en el PATH.

**A-15 — No existe presupuesto de tiempo de ejecución y hay varias operaciones sin cota.**

Casos identificados: L4-04 calcula firma y hash SHA256 de **todos** los binarios de servicios y procesos, sin tope de archivos ni de tamaño, a diferencia de L4-03 que sí lo acota. L7-01 (líneas 201-212) invoca dos cmdlets de filtro por cada regla de firewall entrante habilitada, que en un servidor típico son varios cientos. L2-02 (línea 145) usa el agente COM de Windows Update, que puede realizar una búsqueda en línea de duración indeterminada sin timeout. L9-01 consume por diseño unos 13 segundos de muestreo. L8-01 (línea 215) recorre recursivamente los directorios temporales.

**Impacto:** una auditoría cuya duración no está acotada puede ser interrumpida en producción, y una interrupción parcial produce evidencia incompleta sin que quede constancia de ello.

**Recomendación:** aplicar el patrón de L4-03 (tope configurable, `LimiteAlcanzado` en métricas y `Gap` explícito) a L4-04 y L7-01, y añadir timeout a la consulta COM de L2-02.

**A-16 — Manejo de excepciones de grano grueso que atribuye mal la causa.** (`L1-01:24-105`, `L2-01:26-77`, `L2-02:30-85`)

Estos bloques `try` envuelven a la vez la recolección de datos y la construcción de los hallazgos. Un fallo en `New-AuditFinding` —o cualquier error en la lógica de evaluación— es capturado por el mismo `catch` que la consulta CIM y registrado como *"No se pudo consultar Win32_ComputerSystem"*.

**Impacto:** el diagnóstico registrado en `Gaps` puede señalar una causa que no ocurrió, lo que dificulta depurar por qué un control no se evaluó. En un `Gap` de auditoría, la exactitud de la causa es lo que determina si la limitación es aceptable o no.

**Recomendación:** separar el `try` de recolección del bloque de evaluación, y capturar la excepción con su tipo en el mensaje.

### Bajos

**A-17 — Variable muerta y control incompleto de protocolos en claro.** (`L7-01:103-104`) La colección `$enClaro` incluye el puerto 80 pero solo se usa `$sinCifrar`, que lo excluye. El puerto 80 se recolecta y nunca se evalúa. Si la intención era observar HTTP sin cifrar, el control falta; si no lo era, la línea 103 debe simplificarse.

**A-18 — Asignación sobre una variable automática de PowerShell.** (`L3-01:106`) Se asigna a `$home`, que es la variable automática del perfil de usuario. Aunque en PowerShell 5.1 la asignación es válida, altera el estado de la sesión y puede afectar la expansión de `~` en código posterior del mismo proceso, incluidos otros colectores si el orquestador comparte runspace. Renombrar a `$javaHome`.

**A-19 — Cobertura limitada al usuario que ejecuta.** (`L5-02:107-108`) Las claves `HKCU` cubren solo el perfil del usuario bajo el que corre la auditoría. En un servidor auditado con una cuenta de servicio, los autoarranques de los usuarios reales no se enumeran. Debe recorrerse `HKEY_USERS` o declararse la limitación en `Gaps`.

**A-20 — Agrupación de productos por expresión regular con riesgo de falsos positivos.** (`L4-05:110-112`) El patrón `'\s+\d[\d\.]*\s*$'` normaliza el nombre eliminando el sufijo numérico. Productos distintos que se diferencian solo por un número final quedan agrupados y se reportan como "versiones múltiples del mismo producto". El hallazgo es de severidad Low, por lo que el impacto es ruido, no error de fondo.

**A-21 — Espacios de claves distintos en la deduplicación de L4-01.** El inventario del registro se indexa por `DisplayName|DisplayVersion` (línea 72) y el de Appx por `Name|Version` (línea 131). Un paquete presente en ambas fuentes con rótulos distintos se contabiliza dos veces, inflando `TotalPaquetes`.

**A-22 — Unidad incorrecta en la velocidad de adaptador.** (`L1-01:200`) `$n.Speed` está expresado en bits por segundo y se divide entre `1MB` (1 048 576), lo que produce Mibit/s bajo la etiqueta `VelocidadMbps`. La desviación es del 4,9 %. Debe dividirse entre 1 000 000.

**A-23 — Umbrales fijos no parametrizables.** Varios umbrales relevantes están escritos en el código en lugar de leerse de la configuración: 30 subcategorías sin auditar (`L2-03:290`), 128 MB de tamaño del registro Security (`L8-01:63`), 3 días de antigüedad de firmas (`L2-03:41`), 10 exclusiones de antimalware (`L2-03:85`), 14 caracteres de longitud de contraseña (`L6-01:206`), 15 % de espacio libre en disco (`L9-01:205`), 500 archivos temporales antiguos (`L8-01:226`), 25 ms de latencia (`L9-01:213`). Contrastan con los umbrales que sí son configurables en los mismos archivos. Para una auditoría formal, todo umbral debe ser declarable y quedar impreso en el informe.

**A-24 — Trazabilidad de criterios inconsistente entre la cabecera y el manifiesto.**

| Archivo | Cabecera del comentario | Bloque `$meta.Criterios` |
|---|---|---|
| L2-03 | ARQ-01 aparece dos veces | 6 criterios, sin duplicados |
| L3-01 | INV-01, VUL-01, ARQ-01, ARQ-03 | añade SW-02 |
| L4-01 | DAT-02 aparece dos veces | 5 criterios, sin duplicados |
| L4-03 | SW-05 aparece dos veces | 3 criterios |
| L4-05 | VUL-01, INV-01, SW-03, SW-04 | añade SW-02 |
| L6-01 | ACC-02 y ACC-03 duplicados | 4 criterios |
| L7-01 | ACC-04 aparece dos veces | 4 criterios |

Adicionalmente, varios hallazgos citan criterios que su colector no declara en `$meta`: L1-01 emite hallazgos sobre VUL-01, ACC-04 y DAT-02 sin declararlos; L2-01 sobre VUL-01, INV-04, REG-01 y CAM-01; L2-03 sobre ACC-03, RED-02 y REG-02.

**Impacto:** si la matriz de trazabilidad del informe se construye a partir de `$meta.Criterios`, quedará incompleta y algunos criterios aparecerán como no cubiertos aunque sí se evalúen. Si se construye a partir de los hallazgos emitidos, un criterio verificado y conforme no aparecerá cubierto porque no generó hallazgo. La matriz debe construirse a partir de `$meta` y este debe ser exhaustivo.

**Recomendación:** hacer de `$meta.Criterios` la única fuente de verdad, completarlo con todos los criterios que el colector puede evaluar, eliminar las listas duplicadas de las cabeceras y añadir una verificación automática en el orquestador que rechace cualquier hallazgo cuyos criterios no estén declarados en el manifiesto de su colector.

---

## 5. Observaciones transversales

**Fortalezas del diseño.** Deben preservarse explícitamente en cualquier refactorización:

- El contrato uniforme de entrada y salida en los 17 archivos, sin excepciones.
- La colección `Gaps`, que separa "conforme" de "no verificado". Es el elemento que hace defendible el informe ante un tercero.
- La naturaleza estrictamente de solo lectura, verificada archivo por archivo.
- La degradación elegante: ningún colector aborta por completo ante la falta de un privilegio o de un componente opcional.
- La calidad de los textos de los hallazgos. Cada uno explica el riesgo en términos de negocio, no solo el síntoma técnico, y la recomendación es accionable. En varios casos se contempla explícitamente la posibilidad de un control compensatorio, que es el registro correcto para un informe de auditoría.
- El respaldo por vías alternativas cuando la principal falla: WMI si `Get-LocalUser` no está disponible (L6-01), `SecurityCenter2` si Defender no responde (L2-03), lectura puntual por CIM si `Get-Counter` falla (L9-01).
- La correlación entre capas: L4-06 enlaza artefactos con servicios y puertos, L9-01 enlaza consumo con software instalado, L5-01 remite explícitamente a L4-01 y L4-04 en sus recomendaciones.

**Ausencias en la disciplina de PowerShell.**

- Ningún archivo declara `#requires -Version`, pese a que se usan construcciones que no existen en PowerShell 2.0 y cmdlets propios de Windows 8/Server 2012 en adelante (`Get-NetTCPConnection`, `Get-ScheduledTask`, `Get-LocalUser`).
- Ninguno activa `Set-StrictMode`. Con la validación laxa de propiedades inexistentes, defectos como A-06 pasan desapercibidos.
- Ninguno está firmado digitalmente, lo cual es paradójico: L2-01 emite un hallazgo cuando `ExecutionPolicy` es permisiva y L4-03 recomienda establecerla en `AllSigned`. Bajo esa política, estos mismos colectores no podrían ejecutarse.
- No hay pruebas automatizadas ni datos de prueba en el repositorio, por lo que defectos como A-03, A-04 y A-05 —todos ellos condicionados al idioma del sistema— no serían detectados por ninguna verificación previa a la ejecución.

**Sensibilidad al idioma del sistema operativo.** Es el patrón de defecto más recurrente de la revisión y afecta a cuatro hallazgos independientes (A-03, A-04, A-05, y parcialmente A-24 por los nombres de grupo de L6-01:144-145). El proyecto está escrito en español y sus salidas también, lo que sugiere despliegue en entornos hispanohablantes, pero varias verificaciones asumen rótulos en inglés y otras asumen rótulos en español. **Recomendación general: no analizar texto localizado. Usar SID, identificadores numéricos de contador, propiedades CIM y valores de registro, que son invariantes al idioma.** Donde no haya alternativa, el fallo de coincidencia debe registrarse en `Gaps` y nunca interpretarse como conformidad.

**Ruido esperable en los hallazgos.** Algunos controles emiten hallazgo ante condiciones que en muchos entornos son legítimas: toda suscripción WMI permanente se reporta como High (L5-02:180) aunque los agentes de gestión y monitoreo las registran de forma habitual; toda tarea programada de terceros activa genera un hallazgo Medium (L5-02:77); todo publicador fuera de la lista de confianza genera un hallazgo (L4-04:151), lo cual es esperable en la primera ejecución cuando la lista aún está vacía. En los tres casos la recomendación del propio hallazgo orienta correctamente hacia la validación y el ajuste de la configuración, pero conviene anticipar que el primer informe tendrá un volumen de hallazgos poco representativo hasta que la línea base esté calibrada.

---

## 6. Resumen de hallazgos

| Id | Severidad | Ubicación | Resumen |
|---|---|---|---|
| A-01 | Crítico | Todo el repositorio | 11 funciones y 2 archivos de configuración ausentes; nada es ejecutable |
| A-02 | Alto | Los 17 archivos | `RequiereAdmin = $false` incorrecto; cobertura parcial silenciosa |
| A-03 | Alto | L6-01:158 | Exceso de administradores locales no se detecta en Windows en inglés |
| A-04 | Alto | L6-01:218 | Bloqueo de cuenta no se detecta en Windows en español |
| A-05 | Alto | L9-01:55-63 | Contadores de rendimiento fallan en Windows no inglés |
| A-06 | Medio | L2-01:23 | Umbral nulo produce falso positivo permanente de uptime |
| A-07 | Medio | L4-06:39-47 | Validación incompleta de `Arquitectura.psd1`; excepción no controlada |
| A-08 | Medio | L2-03:248-271 | TLS obsoleto no detectado cuando la clave no está definida |
| A-09 | Medio | L2-03:229-243 | SMBv1 puede no reportarse por ninguna de las dos vías sin elevación |
| A-10 | Medio | L4-01:47-58 | Resolución de ruta por heurística de prefijo; atribución incorrecta |
| A-11 | Medio | L4-04, L4-06, L5-01 | Servicios con ruta no citada excluidos del control de integridad |
| A-12 | Medio | L5-02:127 | Ruta fija `C:\Windows` produce falso positivo Critical |
| A-13 | Medio | L4-02:79 | `choco list --local-only` retirado en Chocolatey v2; fallo silencioso |
| A-14 | Medio | L4-02:128-141 | Solo se inventaría un intérprete de Python |
| A-15 | Medio | L4-04, L7-01, L2-02 | Operaciones sin cota de tiempo ni tope de elementos |
| A-16 | Medio | L1-01, L2-01, L2-02 | `try` de grano grueso atribuye mal la causa en `Gaps` |
| A-17 | Bajo | L7-01:103 | Variable muerta; puerto 80 recolectado y no evaluado |
| A-18 | Bajo | L3-01:106 | Asignación sobre la variable automática `$home` |
| A-19 | Bajo | L5-02:107-108 | Autoarranques limitados al usuario que ejecuta |
| A-20 | Bajo | L4-05:110-112 | Agrupación por regex une productos distintos |
| A-21 | Bajo | L4-01:72,131 | Claves de deduplicación distintas entre registro y Appx |
| A-22 | Bajo | L1-01:200 | Velocidad de red en Mibit/s rotulada como Mbps |
| A-23 | Bajo | 8 ubicaciones | Umbrales fijos no parametrizables |
| A-24 | Bajo | 7 archivos | Criterios inconsistentes entre cabecera, manifiesto y hallazgos |

**Distribución:** 1 crítico, 4 altos, 11 medios, 8 bajos.

---

## 7. Conclusión

El conjunto de colectores está bien concebido. La separación en capas es coherente, el contrato entre colector y orquestador es uniforme y disciplinado, y la distinción explícita entre lo verificado y lo no verificable —a través de la colección `Gaps`— demuestra un entendimiento correcto de lo que distingue una herramienta de diagnóstico de una herramienta de auditoría. La redacción de los hallazgos tiene calidad de informe profesional.

Los defectos encontrados se concentran en dos grupos con causas distintas:

**El primero es de completitud del repositorio.** El marco de ejecución, los dos archivos de configuración y el orquestador no están versionados. Esto no solo impide ejecutar los colectores: impide auditarlos, porque las decisiones más determinantes de la auditoría —qué se considera software instalado, cómo se resuelve una ruta, cómo se clasifica un artefacto en la taxonomía arquitectónica— viven en funciones que no están aquí. Es el hallazgo a resolver primero, porque condiciona la verificación de todos los demás.

**El segundo es de robustez frente al entorno real.** Cuatro controles no se disparan según el idioma del sistema operativo, y la declaración uniforme de que ningún colector requiere privilegios administrativos hace que una ejecución sin elevar entregue un informe que parece completo y no lo es. En una herramienta de auditoría, este tipo de defecto es más costoso que un falso positivo: un hallazgo erróneo se descarta en la revisión, mientras que un control que no se evaluó y no dejó rastro se lee como conformidad. La corrección de A-02 a A-05 debería preceder a cualquier uso del conjunto como respaldo de un dictamen formal.
