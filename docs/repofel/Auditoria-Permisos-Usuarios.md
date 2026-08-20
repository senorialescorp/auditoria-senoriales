# Auditoría de usuarios y permisos a nivel de software — SRV-SAP

**Fecha:** 2026-08-17 · **Alcance:** cuentas locales y permisos efectivos sobre los artefactos de software del servidor
**Criterios:** ACC-01 a ACC-05 (`Config\Criterios.Auditoria.psd1`) · ISO/IEC 27001:2022 A.5.15–A.5.18, A.8.2, A.8.3, A.8.5
**Ejecución:** sesión de `SRV-SAP\svalle`, **sin elevación** — ver *Brechas de evidencia*
**Naturaleza:** solo lectura. No se modificó ninguna cuenta, ACL ni configuración.

---

## 1. Resumen ejecutivo

El servidor tiene **9 cuentas locales habilitadas**, de las cuales **7 son administradores locales** (78 %). El umbral definido en la suite es 5. Más grave que el número es la composición: hay cuentas administrativas sin uso desde hace más de dos años, cuentas de servicio con privilegio total y una cuenta integrada `Administrator` usada como identidad de ejecución de un servicio.

En la capa de software el problema es más severo que en la capa de cuentas. El directorio de instalación de **SAP Business One tiene `Everyone: FullControl` a nivel NTFS** y está publicado como recurso compartido con `Everyone: Full`. Cualquier usuario de la red puede reemplazar los binarios que ejecutan las estaciones de trabajo del ERP.

| Severidad | Hallazgos |
|-----------|-----------|
| Crítico   | 2 |
| Alto      | 4 |
| Medio     | 5 |
| Bajo      | 2 |

**Conclusión:** el control de acceso a nivel de sistema operativo está degradado por acumulación (cuentas que nunca se dieron de baja), y el control de acceso a nivel de software está efectivamente ausente: los permisos sobre los artefactos no distinguen entre usuarios.

---

## 2. Inventario de usuarios y permisos efectivos

### 2.1 Cuentas habilitadas

| Cuenta | Días sin uso | Edad contraseña | ¿Expira? | Admin local | RDP | Rol observado |
|--------|-------------:|----------------:|----------|:-----------:|:---:|---------------|
| `Administrator` | 0 | **1112** | Sí | ✔ | — | Integrada + **ejecuta servicio Tableau Bridge** |
| `svalle` | 0 | 6 | Sí | ✔ | ✔ | Nominal — administración |
| `conta.seno` | 5 | **774** | **Nunca** | ✔ | — | Nominal — contabilidad |
| `db_replica` | 53 | 67 | Sí | ✔ | ✔ | Servicio Tableau Bridge (detenido) |
| `rublan` | 90 | **1011** | **Nunca** | ✔ | — | Nominal |
| `jefedesarrollo` | **327** | **1053** | **Nunca** | ✔ | — | Nominal — desarrollo |
| `edson.cuque` | **747** | **804** | **Nunca** | ✔ | — | Nominal — **sin uso ~2 años** |
| `b1scswworkingshare` | **564** | 564 | Sí | — | — | Servicio SAP B1 (SCSW share) |
| `B1_Tech_User` | **nunca** | 564 | **Nunca** | — | — | Servicio técnico SAP B1 |

Deshabilitadas (correcto): `Guest`, `DefaultAccount`, `WDAGUtilityAccount`.

### 2.2 Membresías privilegiadas

```
Administrators      → Administrator, conta.seno, db_replica, edson.cuque,
                      jefedesarrollo, rublan, svalle          (7 miembros)
Remote Desktop Users→ db_replica, svalle                      (2 miembros)
```

### 2.3 Permisos a nivel de software

| Artefacto | Mecanismo | Identidad | Permiso efectivo |
|-----------|-----------|-----------|------------------|
| `C:\Program Files\SAP\SAP Business One` | NTFS | **Everyone** | **FullControl** |
| Share `SAP Business One` | SMB | **Everyone** | **Full** |
| Share `Program Files` (`C:\Program Files`) | SMB | **Everyone** | **Full** |
| Share `B1_SHR` | SMB | **Everyone** | **Full** |
| Share `B1_SHR` | NTFS | `B1_Tech_User` | Write, ReadAndExecute |
| Share `Guacamole` (`E:\Guacamole`) | SMB | **Everyone** | **Full** |
| Share `SCSW_WORKING_SHARE` | SMB | `b1scswworkingshare` | Read ✔ |
| `C:\Scripts`, `C:\Tools`, `C:\Conector*`, `C:\Compac`, `C:\it`, `C:\B1WebAccess`, `C:\Backups`, `C:\certificados_2027` | NTFS | `BUILTIN\Users` | ReadAndExecute + **CreateFiles/AppendData** |
| Servicio `Tableau Bridge worker` | SCM | `.\Administrator` | Ejecución con privilegio total |
| Servicio `Tableau Bridge worker` | SCM | `.\db_replica` | Ejecución con privilegio total (detenido) |
| SQL Server `MSSQLSERVER` | Login | `SRV-SAP\svalle` | **Sin login** (login failed) |

### 2.4 Política de contraseñas vigente

```
Longitud mínima             : 7          ← recomendado ≥ 14
Vigencia máxima             : 30 días    ← eludida por 5 cuentas con "nunca expira"
Vigencia mínima             : 1 día
Historial                   : 24
Umbral de bloqueo           : Never      ← sin resistencia a fuerza bruta
Duración de bloqueo         : 30 min (inaplicable)
```

---

## 3. Hallazgos

### CRÍTICO

**H-01 · `Everyone: FullControl` sobre el directorio de SAP Business One** — ACC-04
`C:\Program Files\SAP\SAP Business One` concede control total a `Everyone` en NTFS, y el mismo árbol se publica como recurso compartido `SAP Business One` con `Everyone: Full` en SMB. Ambas capas coinciden, por lo que el permiso efectivo para cualquier usuario de la red es escritura completa sobre los binarios del ERP.
*Impacto:* sustitución de un ejecutable o DLL del cliente SAP B1 se propaga a toda estación que lo ejecute o lo despliegue desde el share. Es un vector de compromiso masivo, no local.
*Recomendación:* retirar el ACE de `Everyone` en NTFS; dejar `SYSTEM` y `Administrators` con control total, `Users` solo lectura y ejecución. En el share, sustituir `Everyone: Full` por `Authenticated Users: Read`. Verificar antes qué proceso de despliegue depende de la escritura y sustituirlo por una cuenta de servicio nominal.

**H-02 · Recursos compartidos con `Everyone: Full`** — ACC-04
`B1_SHR`, `Program Files`, `SAP Business One` y `Guacamole` exponen control total a `Everyone` en la capa SMB. En `B1_SHR` y `Program Files` el NTFS todavía contiene el alcance real; en los otros dos no.
*Impacto:* el permiso de share es el techo del permiso efectivo; dejarlo en `Full` significa que cualquier relajación futura de NTFS queda inmediatamente explotable desde la red, sin defensa en profundidad.
*Recomendación:* aplicar `Authenticated Users: Change` o `Read` según la función real de cada share y documentar el propósito de `Guacamole` y `Program Files`, que no corresponden a un patrón de publicación reconocible.

### ALTO

**H-03 · Servicio ejecutándose como la cuenta `Administrator` integrada** — ACC-02
`Tableau Bridge worker(Administrator@SRV-SAP)` está en ejecución bajo `.\Administrator`.
*Impacto:* la contraseña de la cuenta administrativa integrada queda almacenada como secreto LSA y es recuperable con privilegio local; además la cuenta no puede rotarse sin interrumpir el servicio, lo que explica los 1112 días sin cambio de contraseña. Ninguna acción del servicio es atribuible a una persona.
*Recomendación:* crear una cuenta de servicio dedicada y sin pertenencia a `Administrators`, otorgarle únicamente `Log on as a service` y los permisos concretos que Tableau Bridge requiera. Después rotar la contraseña de `Administrator` y deshabilitarla.

**H-04 · Siete administradores locales sobre nueve cuentas habilitadas** — ACC-02
El grupo `Administrators` supera el umbral de 5 definido en la suite, e incluye cuentas nominales sin función administrativa evidente (`conta.seno`, contabilidad) y una cuenta de servicio (`db_replica`).
*Impacto:* cada miembro es una vía de compromiso total del servidor y del ERP que aloja.
*Recomendación:* revisar la membresía contra una matriz de accesos autorizada. `db_replica` debe salir del grupo y conservar solo los permisos que su función de replicación requiera; las cuentas de negocio deben degradarse a `Users`.

**H-05 · Sin umbral de bloqueo de cuenta** — ACC-03
`Lockout threshold: Never`, con RDP habilitado y dos cuentas con derecho de acceso remoto.
*Impacto:* el servidor no ofrece resistencia a fuerza bruta ni a rociado de contraseñas contra el punto de entrada RDP. Combinado con la longitud mínima de 7 caracteres, el espacio de búsqueda es tratable.
*Recomendación:* configurar umbral de 10 intentos con ventana de 15 minutos, y elevar la longitud mínima a 14.

**H-06 · Cuenta administrativa sin uso desde hace más de dos años** — ACC-01
`edson.cuque` sigue habilitada y es administradora local, con último inicio de sesión el 2024-07-30 (747 días) y contraseña sin rotar desde hace 804 días, configurada para no expirar.
*Impacto:* perfil característico de baja de personal no procesada. Credencial de alto privilegio, antigua, sin vigilancia y sin dueño operativo.
*Recomendación:* confirmar con RR. HH. la situación laboral, deshabilitar de inmediato y eliminar tras el período de retención definido. Aplicar el mismo criterio a `jefedesarrollo` (327 días).

### MEDIO

**H-07 · Cinco cuentas eluden la política de caducidad** — ACC-03
`conta.seno`, `edson.cuque`, `jefedesarrollo`, `rublan` y `B1_Tech_User` tienen la expiración de contraseña deshabilitada, con edades de 564 a 1053 días, mientras la política local declara una vigencia máxima de 30 días. La política existe pero no se aplica a la mayoría de las cuentas humanas.
*Recomendación:* retirar el atributo en las cuentas nominales y forzar el cambio. Para las de servicio, documentar la excepción con dueño y fecha de revisión.

**H-08 · Credenciales de aplicación en archivos legibles por todos los usuarios** — ACC-03
`C:\Conector\AdvUploaderT.ini` contiene campos `USER`, `PASS`, `URL` y `MAIL` con valores ofuscados en base64, y es legible por `BUILTIN\Users`. Igual situación en `C:\SMS-Agent-Py3\config\auth.cfg` y en la clave privada `C:\SMS-Agent-Py3\config\prikey_v2.pem`.
*Impacto:* la ofuscación no es control de acceso. Cualquier cuenta local puede leer las credenciales del conector CFDI y la clave privada del agente SMS.
*Recomendación:* restringir el ACL de esos archivos a la identidad que ejecuta cada conector y a `Administrators`; retirar la herencia. Rotar las credenciales expuestas, ya que deben considerarse comprometidas.

**H-09 · `Users` puede crear archivos en los directorios de aplicación** — ACC-04
`C:\Scripts`, `C:\Tools`, `C:\Conector`, `C:\ConectorCapillas`, `C:\Compac`, `C:\it`, `C:\B1WebAccess`, `C:\Backups` y `C:\certificados_2027` heredan del raíz `C:\` los permisos `CreateFiles`/`AppendData` para `BUILTIN\Users`.
*Impacto:* cualquier usuario puede depositar archivos en rutas desde las que se ejecutan scripts y conectores. Es el vector clásico de secuestro por DLL o por script cuando un proceso privilegiado carga desde esas rutas. `C:\Backups` y `C:\certificados_2027` además contienen material que no debería ser escribible.
*Recomendación:* romper la herencia en los directorios de aplicación y datos, y dejar `Users` en solo lectura y ejecución.

**H-10 · Dos cuentas privilegiadas sin requisito de contraseña** — ACC-03
`db_replica` y `svalle` tienen `PasswordRequired = False`; ambas son administradoras locales y ambas tienen acceso RDP.
*Recomendación:* activar el requisito de contraseña en las dos cuentas.

**H-11 · Cuentas de servicio SAP B1 latentes** — ACC-01
`b1scswworkingshare` sin uso desde hace 564 días y `B1_Tech_User` sin ningún inicio de sesión registrado desde su creación.
*Recomendación:* verificar con el administrador de SAP B1 si siguen siendo necesarias para el despliegue centralizado; deshabilitar las que no lo sean.

### BAJO

**H-12 · Cuenta integrada `Administrator` habilitada** — ACC-02
SID terminado en `-500`, activa y con inicio de sesión el día de la auditoría. No permite atribuir acciones a una persona.
*Recomendación:* tras resolver H-03, deshabilitarla y operar con cuentas nominales.

**H-13 · Acceso RDP directo al servidor** — ACC-05
`db_replica` y `svalle` tienen acceso por Escritorio remoto directo, sin host de salto.
*Recomendación:* revisar la membresía contra la matriz autorizada y exigir MFA en el punto de entrada remoto. `db_replica`, al ser cuenta de servicio, no debería tener acceso interactivo.

---

## 4. Controles que sí operan correctamente

Conviene registrarlos porque acotan el riesgo real y no deben perderse en una remediación:

- **Separación entre administración del SO y administración de la base de datos.** `SRV-SAP\svalle`, administrador local, no tiene login en la instancia `MSSQLSERVER` (*Login failed*). El grupo `BUILTIN\Administrators` no está mapeado a `sysadmin`, que es la desviación por defecto más común en instalaciones de SAP B1.
- `Guest`, `DefaultAccount` y `WDAGUtilityAccount` están deshabilitadas.
- `SCSW_WORKING_SHARE` está correctamente acotado: solo `b1scswworkingshare` con permiso de lectura.
- El historial de contraseñas (24) y la vigencia mínima (1 día) impiden la rotación circular.
- Las tareas programadas fuera de `\Microsoft\` se limitan a OneDrive, sin automatizaciones ejecutándose con privilegio no justificado.

---

## 5. Brechas de evidencia

La auditoría se ejecutó **sin elevación**, y el alcance real quedó limitado en estos puntos:

| Brecha | Causa | Cómo cerrarla |
|--------|-------|---------------|
| **Usuarios y autorizaciones de SAP Business One** (`OUSR`, `USR1`, licencias, superusuarios) | `svalle` no tiene login en SQL Server | Ejecutar la consulta con una cuenta con permiso `VIEW SERVER STATE` o con un login SAP B1 de auditoría |
| **Logins y roles de SQL Server** (`sysadmin`, `db_owner` por base) | Igual que la anterior | Igual que la anterior |
| **Asignación de derechos de usuario** (`SeDebugPrivilege`, `SeServiceLogonRight`, etc.) | `secedit /export` requiere elevación | Reejecutar en consola elevada |
| **ACL de `E:\Guacamole`** | Acceso denegado a la lectura del descriptor | Reejecutar en consola elevada |
| **Identidades de grupos de aplicaciones de IIS** | `appcmd` no devolvió resultados; `wwwroot` solo contiene la página por defecto | Confirmar si IIS presta servicio real o puede retirarse |
| **Cuentas de dominio** | El servidor opera con cuentas locales (`Computer role: SERVER`) | Sin acción; el alcance local es el alcance completo |

---

## 6. Plan de remediación priorizado

| # | Acción | Hallazgo | Riesgo si se omite | Plazo |
|---|--------|----------|--------------------|-------|
| 1 | Retirar `Everyone` del NTFS de `C:\Program Files\SAP\SAP Business One` | H-01 | Compromiso del ERP y de las estaciones | Inmediato |
| 2 | Reducir a `Read`/`Change` los shares con `Everyone: Full` | H-02 | Exposición de toda la ruta desde la red | Inmediato |
| 3 | Deshabilitar `edson.cuque` y revisar `jefedesarrollo` | H-06 | Credencial administrativa huérfana | 24 h |
| 4 | Configurar umbral de bloqueo (10/15 min) y longitud mínima 14 | H-05 | Fuerza bruta contra RDP | 48 h |
| 5 | Migrar el servicio Tableau Bridge a cuenta de servicio dedicada y rotar `Administrator` | H-03, H-12 | Robo de credencial administrativa vía LSA | 1 semana |
| 6 | Restringir ACL y rotar las credenciales de conectores y clave privada | H-08 | Credenciales del conector CFDI comprometidas | 1 semana |
| 7 | Depurar `Administrators` hasta ≤ 3 miembros; sacar `db_replica` | H-04 | Superficie de compromiso total | 2 semanas |
| 8 | Romper herencia en directorios de aplicación y datos | H-09 | Secuestro de DLL/script | 2 semanas |
| 9 | Retirar "nunca expira" y forzar cambio en cuentas nominales | H-07, H-10 | Credenciales sin rotación desde 2023 | 2 semanas |
| 10 | Reejecutar la auditoría elevada y con acceso a SQL para cerrar las brechas | §5 | Alcance incompleto del expediente | 1 mes |

---

## 7. Nota sobre la suite de auditoría

El colector `L6-01_Identity-Access.ps1` cubre correctamente la capa de identidad del sistema operativo (cuentas, grupos privilegiados, política de contraseñas, RDP), pero **no evidencia la capa de permisos sobre el software**: no lee ACL de directorios de aplicación, no correlaciona cuentas con identidades de ejecución de servicios, no revisa permisos de recursos compartidos ni detecta credenciales almacenadas en archivos de configuración legibles.

Los hallazgos H-01, H-02, H-03, H-08 y H-09 —incluidos los dos críticos— **no aparecen en el reporte automatizado actual**. Se recolectaron manualmente para este informe.

Cerrar esa brecha equivale a añadir un colector `L6-02_Software-Permissions.ps1` que evidencie ACC-02 y ACC-04 sobre la capa L4. El orquestador lo descubriría solo.
