# Suite de auditoría de sistemas y arquitectura empresarial — Linux

Traducción a Linux de la suite PowerShell que vive en `../windows/`. Mantiene el
mismo modelo de auditoría (9 capas, 37 criterios, riesgo agregado ponderado con
prioridad en la capa L4 de artefactos de software) y los mismos entregables
(HTML imprimible, XLSX, DOCX, CSV, JSON y manifiesto de integridad).

**La suite es de solo lectura.** No instala paquetes, no refresca índices del
gestor, no reinicia servicios ni modifica configuración. Cuando algo no puede
verificarse, se documenta como *brecha de evidencia* en lugar de aparentar
cobertura total.

---

## Uso rápido

```bash
./preflight.sh                  # comprueba requisitos y cobertura esperada
sudo ./audit.sh                 # corrida completa con todos los entregables
```

Los resultados quedan en `Output/<RunId>/`:

```
Output/20260819-143012/
├── Ficha-<host>-<runid>.html      ficha imprimible A4 (Ctrl+P → PDF)
├── Ficha-<host>-<runid>.docx      ficha formal para firma
├── Auditoria-<host>-<runid>.xlsx  libro con 11 hojas de detalle
├── MANIFIESTO-INTEGRIDAD.json     hash SHA-256 de cada artefacto
├── raw/                           JSON por colector y consolidados
└── csv/                           el mismo expediente en CSV
```

### Opciones

| Opción | Efecto |
|---|---|
| `--software-only` | Solo la capa prioritaria L4 (artefactos de software) |
| `--layer L2,L4` | Limita a las capas indicadas |
| `--collector L4-01` | Limita a colectores concretos |
| `--quick` | Omite los colectores de mayor costo (`L4-03`, `L9-01`) |
| `--no-report` | Solo datos: sin HTML, XLSX ni DOCX |
| `--purge` | Elimina corridas anteriores al periodo de retención |
| `--run-id NOMBRE` | Fija el identificador de la corrida |
| `--output RUTA` | Cambia el directorio de salida |

**Códigos de salida** (para integrar con monitoreo): `0` sin hallazgos altos ni
críticos · `1` hay altos · `2` hay críticos · `1` error de invocación.

### Reemitir la ficha Word de una corrida pasada

```bash
./reports/new_audit_ficha_docx.sh 20260819-143012
```

Se alimenta del expediente ya escrito en `raw/`, sin volver a auditar el servidor.

---

## Requisitos

**Obligatorio:** `bash` 4.0+, `jq`, y las utilidades POSIX habituales
(`awk`, `sed`, `grep`, `sort`, `find`, `stat`, `date`) más una herramienta de
SHA-256 (`sha256sum`, `shasum` u `openssl`).

**Para los entregables .xlsx y .docx:** `zip` **o** `python3`. Sin ninguno de los
dos se generan HTML, CSV y JSON, y la ausencia se reporta.

```bash
apt-get install jq          # Debian / Ubuntu
dnf install jq              # RHEL / Rocky / Alma
zypper install jq           # SUSE
apk add jq                  # Alpine
```

**Distribuciones soportadas:** Debian/Ubuntu (dpkg/apt), RHEL/Rocky/Alma/CentOS
(rpm/dnf/yum), SUSE (zypper) y Alpine (apk). Init: systemd y OpenRC. La familia
se detecta en tiempo de ejecución; no hay que configurar nada.

**Privilegios:** conviene ejecutar con `sudo`. Sin elevación la suite funciona
igual, pero `/etc/shadow`, las reglas de auditd, los crontabs ajenos y la
correlación puerto↔proceso quedan fuera de alcance y se registran como brechas.

---

## Estructura

```
linux/
├── audit.sh                    orquestador          ← Invoke-Audit.ps1
├── preflight.sh                verificación previa  (sin equivalente Windows)
├── bootstrap.sh                instalador Claude Code ← bootstrap.ps1
├── lib/
│   ├── audit_core.sh           núcleo               ← AuditCore.psm1
│   ├── classify.awk            clasificador en lote (sin equivalente)
│   ├── xlsx_writer.sh          OOXML SpreadsheetML  ← ExcelWriter.psm1
│   └── docx_writer.sh          OOXML WordprocessingML ← WordWriter.psm1
├── config/
│   ├── audit.config.json       ← Audit.config.psd1
│   ├── criterios.auditoria.json ← Criterios.Auditoria.psd1
│   └── arquitectura.json       ← Arquitectura.psd1
├── collectors/                 17 colectores        ← Collectors/*.ps1
└── reports/
    ├── new_audit_ficha.sh      ← New-AuditFicha.ps1
    ├── new_audit_excel.sh      ← New-AuditExcel.ps1
    └── new_audit_ficha_docx.sh ← New-AuditFichaDocx.ps1
```

Los `.psd1` pasaron a JSON porque es el formato de datos que `jq` lee de forma
nativa; el contenido y la semántica son los mismos.

---

## Cómo se tradujo cada mecanismo

La equivalencia no es literal donde no puede serlo: se conserva el **control de
auditoría**, no la implementación. Cada colector documenta su tabla de
equivalencias en la cabecera. Las decisiones de fondo:

### Inventario de software

| Windows | Linux |
|---|---|
| Claves `Uninstall` del registro (x64, x86, HKU) | Base de dpkg / rpm / apk |
| `Get-AppxPackage` | `snap` y `flatpak` |
| `InstallDate` del registro | `/var/log/dpkg.log` · `%{INSTALLTIME}` de rpm |
| `Publisher` | `Maintainer` (deb) · `Vendor` (rpm) |

Se evita deliberadamente cualquier operación con efecto colateral, igual que el
original evita `Win32_Product` por disparar reconfiguraciones MSI.

### Procedencia e integridad — la traducción de fondo

En Windows la pregunta es *«¿quién firmó este binario y sigue intacto?»*
(Authenticode). En Linux la pregunta equivalente es *«¿qué paquete lo instaló y
coincide con el manifiesto del gestor?»*.

| Estado Authenticode | Estado equivalente | Cómo se determina |
|---|---|---|
| `Valid` | `Managed` | Pertenece a un paquete y su hash coincide |
| `HashMismatch` | `HashMismatch` | `dpkg -V` / `rpm -V` reportan digest distinto |
| `NotSigned` | `Unmanaged` | No pertenece a ningún paquete: **sin procedencia verificable** |

Un archivo `Unmanaged` es el análogo exacto de un ejecutable sin firma: no se
puede verificar su origen, ni comprobar su integridad, ni parchearlo por el canal
del gestor. La confianza en el publicador se traslada al *vendor/maintainer* del
paquete y a la firma GPG del repositorio de origen.

### Controles del sistema operativo

| Windows | Linux |
|---|---|
| `Get-CimInstance Win32_*` | `/proc`, `/sys`, `dmidecode`, `lsblk`, `lscpu`, `ip` |
| `Get-MpComputerStatus` (Defender) | ClamAV + agentes EDR + **SELinux/AppArmor** |
| `Get-NetFirewallProfile` (3 perfiles) | firewalld (zonas) · ufw · nftables · iptables |
| `Get-BitLockerVolume` | LUKS/dm-crypt (`lsblk TYPE=crypt`) |
| Claves de hardening (UAC, LSA, NoLMHash) | `sysctl` del kernel + `/etc/login.defs` |
| `SMB1Protocol` | `server min protocol` de Samba + módulos heredados |
| TLS/SChannel en el registro | `update-crypto-policies` + versión de OpenSSL |
| `auditpol /get` | `auditctl -l` / reglas de auditd |
| `ScriptBlockLogging` | Reglas `execve` de auditd |
| `Get-HotFix` | `/var/log/dpkg.log` · `rpm -qa --last` |
| `Microsoft.Update.Session` | `apt-get --just-print upgrade` · `dnf check-update` (solo caché local) |
| `Win32_Service` | `systemctl show` / OpenRC |
| `Get-ScheduledTask` | Temporizadores systemd + cron + `/etc/cron.*` |
| Claves `Run` / `RunOnce` | `/etc/profile.d`, `rc.local`, perfiles de shell, autostart |
| `Winlogon\Userinit` | **`/etc/ld.so.preload`** y `LD_PRELOAD` en unidades |
| Suscripciones WMI permanentes | Reglas udev con `RUN` + unidades `.path` |
| `Get-LocalUser` / `net accounts` | `/etc/passwd` + `/etc/shadow` + `login.defs` + PAM |
| Grupo *Administradores* | `sudo` / `wheel` / `admin` + `/etc/sudoers` |
| Cuenta integrada (SID `-500`) | `root` **y toda cuenta con UID 0** |
| RDP + NLA | `sshd_config` (`PermitRootLogin`, `PasswordAuthentication`) |
| `Get-NetTCPConnection -Listen` | `ss -tlnp` |
| `Win32_Share` + `Get-SmbShareAccess` | `/etc/exports` (NFS) + `smb.conf` (Samba) |
| Registro de eventos de Windows | journald + rsyslog + auditd |
| Evento 1102 (borrado de log) | `journalctl --verify` + sellado FSS |
| WEF (reenvío centralizado) | rsyslog/syslog-ng remoto, journal-upload, agentes SIEM |
| `Win32_ShadowCopy` | Instantáneas LVM / Btrfs / ZFS |
| `Get-Counter` (PDH) | Lectura **diferencial** de `/proc/stat`, `/proc/diskstats` |
| Evento 6008 (apagado inesperado) | `last -x` (marca `crash`) |

### Controles añadidos que no existen en la versión Windows

Son propios de Linux y de primer orden en una auditoría de servidor:

- **Binarios SUID/SGID sin paquete de origen** (`L4-03`) — vía directa de
  escalada de privilegios y mecanismo de persistencia habitual.
- **Procesos con el binario borrado del disco** (`L4-04`) — indicador de
  compromiso clásico; en Windows el sistema bloquea la imagen y no ocurre.
- **`/etc/ld.so.preload`** (`L5-02`) — carga una biblioteca en *todos* los
  procesos enlazados dinámicamente; es el indicador de rootkit de espacio de
  usuario.
- **Módulos del kernel fuera del árbol firmado** (`L5-02`).
- **Cuentas con UID 0 distintas de root** (`L6-01`) — puerta trasera que pasa
  desapercibida en revisiones que solo miran el grupo de administradores.
- **Reglas sudo `NOPASSWD`** (`L6-01`).
- **Agotamiento de inodos** (`L8-01`) — provoca «disco lleno» con espacio libre;
  NTFS no expone esta limitación.
- **Intervenciones del OOM killer** (`L9-01`).
- **API de Docker expuesta sin TLS** (`L7-01`) — equivale a root remoto sin
  credenciales.
- **Repositorios sin verificación GPG** (`L4-02`) — vector directo de cadena de
  suministro.
- **Fin de soporte de la propia distribución** (`L4-05`) — en Linux es el
  determinante principal de si el activo sigue recibiendo parches.

### Controles reinterpretados

- **Rutas de servicio sin comillas.** No aplica: systemd usa `argv`, no una
  cadena que el sistema deba dividir. Se sustituye por el riesgo equivalente:
  binario, unidad o directorio **escribibles por terceros**, que permiten el
  mismo secuestro.
- **`ExecutionPolicy` de PowerShell.** No hay análogo directo. Se sustituye por
  la integridad del `PATH` (directorios escribibles por terceros o entradas
  relativas) y por el registro de ejecución de comandos vía auditd.
- **Antimalware.** En Linux rara vez hay un antivirus residente y el control
  primario es el acceso obligatorio (SELinux/AppArmor). Se evalúan ambos y se
  exige que exista al menos uno; la ausencia de antivirus con MAC en *enforcing*
  se reporta como decisión que debe estar documentada, no como falla.
- **Pertenencia a dominio.** Se traduce a integración con un directorio central
  vía `realm`, SSSD o winbind.

---

## Decisiones de implementación

**`jq` como única dependencia dura.** Toda la suite intercambia JSON: los
colectores emiten un objeto por stdout y el orquestador consolida con `jq`. Es lo
que permite mantener el mismo contrato que la versión PowerShell, donde los
colectores devolvían objetos.

**Clasificación en lote (`lib/classify.awk`).** La versión PowerShell evalúa los
patrones de la taxonomía artefacto por artefacto porque el motor de regex vive
dentro del proceso. El equivalente literal en bash sería un `grep` por patrón y
por artefacto: con ~20 patrones y ~2000 paquetes son 40 000 subprocesos, del
orden de varios minutos. `classify.awk` carga la taxonomía una vez y resuelve
todo el inventario en un único proceso.

Por el mismo motivo, el índice *paquete → ruta de instalación* se construye de
una sola pasada sobre los manifiestos del gestor, en vez de consultarlo una vez
por paquete.

**Un patrón coincide contra el nombre o contra el sujeto completo.** Los patrones
anclados al final (`^git$`, `.*-dev$`) nunca coincidirían contra la cadena
`nombre + publicador + ruta`; se prueba también el nombre por separado.

**Escritores OOXML propios.** `.xlsx` y `.docx` se construyen escribiendo el XML
y empaquetándolo como ZIP, sin LibreOffice, pandoc, openpyxl ni python-docx —
mismo criterio que la versión Windows, que evita Excel, Word y el módulo
ImportExcel: en un servidor de producción no existe ninguno, y **instalar
dependencias en el activo auditado contradice el principio de que la auditoría no
debe alterarlo**.

**Sin `apt update` ni `dnf makecache`.** Refrescar los índices modificaría el
estado del activo (criterio AUD-01). Se consulta solo la caché local; si tiene
más de 7 días, el conteo de actualizaciones pendientes se reporta como **cota
inferior** y se registra la brecha.

---

## Configuración

Los tres archivos de `config/` son el punto de ajuste; no hay que tocar código.

- **`audit.config.json`** — umbrales, catálogo de fin de soporte, software no
  permitido, orígenes confiables, rutas del escaneo de binarios no gestionados y
  pesos de las capas para el riesgo agregado.
- **`criterios.auditoria.json`** — los 37 criterios y sus 12 dominios. Para
  añadir uno basta con una entrada aquí y referenciar su Id desde el colector.
- **`arquitectura.json`** — **la línea base**: qué debería ser el servidor.
  Declara el rol del activo, los roles de software admisibles y prohibidos, la
  taxonomía de clasificación y el catálogo de aplicaciones de negocio.

`arquitectura.json` es el archivo que hay que mantener al día: cada artefacto que
el colector no logre clasificar, o que no figure en el catálogo, aparece como
brecha de línea base en el reporte. Los patrones son regex extendidas (ERE)
evaluadas **sin distinguir mayúsculas**, en el orden declarado: la primera
coincidencia gana, así que van de lo más específico a lo más general.

Antes de la primera corrida formal conviene sustituir los `DEFINIR` de
`RolServidor` y de las aplicaciones del catálogo: mientras estén, la suite emite
hallazgos de gobierno de activos (y así debe ser).

---

## Estado de verificación

Comprobado en este entorno:

- Sintaxis de los 25 scripts (`bash -n`).
- Validez de los tres archivos de configuración JSON.
- Clasificación de la taxonomía contra 47 nombres de paquete reales, incluidos
  los patrones anclados y el catálogo de aplicaciones.
- Corrida completa extremo a extremo del orquestador con 17 colectores simulados:
  consolidación, riesgo ponderado por capa, cobertura de los 37 criterios,
  brechas de evidencia, y los tres reportes.
- `.xlsx` con 11 hojas: ZIP íntegro, todas las partes XML bien formadas, abierto
  correctamente con openpyxl (números como números, escapes correctos).
- `.docx`: ZIP íntegro, XML bien formado, 24 tablas, salto de página y escapes.
- HTML: todas las etiquetas balanceadas, recortes de texto y contenido esperado.
- Modos `--software-only`, `--layer`, `--collector`, `--quick`, `--no-report`.
- Códigos de salida y degradación: colector que falla, colector con salida
  inválida, ausencia de `arquitectura.json`, ejecución sin privilegios.
- Reemisión independiente del `.docx` desde una corrida pasada.

**Lo que no se pudo verificar aquí:** la recolección real de cada colector, que
requiere un servidor Linux (este entorno es Windows). La lógica de consolidación,
los reportes y el contrato entre colectores y orquestador sí están probados de
extremo a extremo. Ejecute `./preflight.sh` en el servidor destino antes de la
primera corrida.
