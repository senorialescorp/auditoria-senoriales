# Consultas RENAP

Aplicación de escritorio en .NET que consulta el registro nacional de personas de
Guatemala (RENAP) a través de una API REST. Desarrollo propio, con arquitectura en
capas y símbolos de depuración presentes.

| | |
|---|---|
| **Ubicación** | `C:\R\Consulta` |
| **Ejecutable** | `CONSULTAS RENAP.exe` (602 KB) |
| **Distribución** | **ClickOnce** — `CONSULTAS RENAP.application` + `app.publish\` |
| **Plataforma** | .NET Framework |
| **Fecha del despliegue** | 17/11/2023 (`Consulta`), 16/11/2023 (`Setting`) |
| **Control de versiones** | Ninguno en el servidor |

---

## 1. Composición

### Arquitectura en capas

El nombre de los ensamblados revela una separación clásica en tres capas:

| Ensamblado | Tamaño | Capa | Símbolos |
|---|---|---|---|
| `CONSULTAS RENAP.exe` | 602 112 | Presentación | **`.pdb` (77 KB)** |
| `BRL.dll` | 10 240 | *Business Rules Layer* — reglas de negocio | **`.pdb` (26 KB)** |
| `DAL.dll` | 18 944 | *Data Access Layer* — acceso a datos | **`.pdb` (46 KB)** |

Los tres ensamblados incluyen además su documentación XML generada por el compilador
(`.xml`), lo que permite reconstruir la firma pública de cada clase y método sin
descompilar.

### Aplicación acompañante

`C:\R\Setting\Setting.exe` (200 KB, con `Setting.pdb` y `Setting.xml`) es un utilitario
de configuración independiente, probablemente el editor de los parámetros de conexión
de la aplicación principal.

### Archivos de configuración

| Archivo | Tamaño | Contenido real |
|---|---|---|
| `CONSULTAS RENAP.exe.config` | 184 bytes | Sólo `<startup>`: .NET Framework 4.8 |
| `BRL.dll.config` | 1 458 bytes | Configuración de bitácora + `system.serviceModel` **vacío** |
| `Setting.exe.config` | 186 bytes | Sólo `<startup>`: .NET Framework 4.8 |
| `CONSULTAS RENAP.exe.manifest` | 7 935 bytes | Manifiesto ClickOnce |

> **Corrección respecto de la versión anterior de este documento.** Se anticipó aquí que
> `BRL.dll.config` contendría el *endpoint* de la API de RENAP y su llave de acceso. Se
> leyó el archivo y **no es así**: contiene únicamente la configuración de
> `My.Application.Log` (un `FileLogTraceListener` con nivel *Information*) y un bloque
> `<system.serviceModel>` con `<bindings/>` y `<client/>` **vacíos**.

Que el bloque `system.serviceModel` esté declarado pero vacío es significativo: indica
que el proyecto se creó para consumir un servicio WCF y esa vía se abandonó. El consumo
real ocurre por REST, vía `RestSharp` — y como no hay ningún `.config` con la dirección,
**el *endpoint* y las credenciales de RENAP están embebidos en el código de `BRL.dll` o
`DAL.dll`, o se configuran a través de `Setting.exe` hacia un destino aún no
identificado** (registro de Windows, archivo propio o base de datos).

`BRL.dll` pesa 10 KB y su `.pdb` está presente, de modo que la respuesta es alcanzable
por inspección del ensamblado. Es el siguiente paso para cerrar este punto.

---

## 2. Dependencias

| Biblioteca | Tamaño | Función |
|---|---|---|
| **`RestSharp.dll`** | 168 960 | Cliente HTTP para consumir la API REST de RENAP |
| **`Newtonsoft.Json.dll`** | 711 952 | Serialización JSON de las respuestas |

Ambas se distribuyen con su documentación XML completa (`RestSharp.xml` 151 KB,
`Newtonsoft.Json.xml` 713 KB), señal de que se agregaron vía NuGet con la opción de
documentación activada.

No se detectaron dependencias de base de datos local en la carpeta, pese al ensamblado
`DAL.dll`: el acceso a datos podría ir contra la API remota, o usar `System.Data.SqlClient`
del propio .NET Framework (que no requiere DLL adicional).

> **Pendiente:** determinar la versión exacta de RestSharp y Newtonsoft.Json. Ambas son
> bibliotecas con historial de vulnerabilidades relevantes —RestSharp tuvo
> CVE-2021-27293 (ReDoS) y Newtonsoft.Json CVE-2024-21907 (agotamiento de recursos al
> deserializar)— y la versión determina si aplican. Se obtiene con
> `[Reflection.AssemblyName]::GetAssemblyName("C:\R\Consulta\RestSharp.dll").Version`.

---

## 3. Observaciones

| Severidad | Observación |
|---|---|
| **Alto** | La aplicación maneja **datos personales de ciudadanos** (consulta al registro nacional). Su tratamiento, el resguardo de la llave de acceso a RENAP y la bitácora de consultas deberían estar formalmente documentados; no se encontró documentación previa. |
| **Medio** | Cuatro archivos `.pdb` más la documentación XML de cada ensamblado propio, en producción. Exponen la estructura interna del código. |
| **Medio** | Instalada en `C:\R`, fuera de `Program Files` y sin registro en el inventario de software de Windows: no aparece en «Programas instalados» y por eso el colector de inventario no la clasificó. Es un artefacto **no gestionado**. |
| **Medio** | Distribución ClickOnce en un servidor: el modelo está pensado para estaciones de trabajo con actualización automática desde una URL. Habría que confirmar si el servidor es el origen de publicación o simplemente un cliente más. |
| **Bajo** | Sin actualización desde noviembre de 2023. |
| **Bajo** | La carpeta `app.publish\` conserva una copia del ejecutable (603 KB), duplicando el binario. |

---

## 4. Pendientes de verificación

- **Dónde viven el *endpoint* y la llave de acceso a RENAP.** No están en ningún
  `.config` (ver §1). Hay que inspeccionar `BRL.dll` / `DAL.dll` o determinar dónde
  escribe `Setting.exe`. Es el pendiente principal: mientras no se sepa, no puede
  evaluarse cómo se protege el acceso a un registro nacional de personas.
- Versiones exactas de `RestSharp` y `Newtonsoft.Json`.
- Si la aplicación se ejecuta desatendida (tarea programada) o de forma interactiva.
  No se detectó servicio de Windows asociado; la enumeración completa de tareas
  programadas requiere privilegios administrativos.
- Qué base de datos usa `DAL.dll` y con qué usuario.
- Si existe registro de auditoría de las consultas realizadas al registro nacional.

---

*Documento generado el 17/08/2026 a partir del inventario de archivos de `C:\R`.
Ver [DEPENDENCIAS.md](DEPENDENCIAS.md).*
