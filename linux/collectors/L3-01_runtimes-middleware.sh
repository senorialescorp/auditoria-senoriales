#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# L3-01_runtimes-middleware.sh
# Capa L3 - Plataforma: runtimes, motores y middleware.
# Criterios de auditoria -> INV-01, SW-02, VUL-01, ARQ-01, ARQ-03
#
# EQUIVALENCIAS respecto de L3-01_Runtimes-Middleware.ps1:
#   Registro NDP (.NET Fx)   -> dotnet --list-runtimes / paquetes dotnet-runtime
#   Registro JavaSoft        -> update-alternatives, /usr/lib/jvm, java -version
#   Registro InetStp (IIS)   -> apache2 -v / httpd -v / nginx -v
#   IIS AppPools             -> unidades systemd de los servidores de aplicacion
#                               y usuario bajo el que se ejecutan
#   Instance Names\SQL       -> unidades y binarios de los motores de BD
#   Get-WindowsFeature       -> grupos de paquetes / patrones instalados
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/audit_core.sh"

collector_init 'L3-01' 'Runtimes, motores y middleware' 'L3' \
    'INV-01|SW-02|VUL-01|ARQ-01|ARQ-03' false \
    'Deteccion de JVM, Python, Node.js, PHP, .NET, servidores web, bases de datos y servidores de aplicacion, con evaluacion de soporte.'
maybe_emit_manifest "${1:-}"

# Acumulador en memoria para la evaluacion EOL del final: "producto|version|ruta|origen"
RUNTIMES_TMP=$(mktemp)
trap 'rm -f "$RUNTIMES_TMP" 2>/dev/null' EXIT

add_runtime() {
    local familia=$1 producto=$2 version=$3 ruta=${4:-} origen=${5:-} notas=${6:-}
    rec Familia "$familia" \
        Producto "$(safe_str "$producto" 200)" \
        Version "$(safe_str "$version" 64)" \
        Ruta "$(safe_str "$ruta" 400)" \
        Origen "$origen" \
        Notas "$(safe_str "$notas" 300)"
    printf '%s\t%s\t%s\t%s\n' "$producto" "$version" "$ruta" "$origen" >> "$RUNTIMES_TMP"
}

# ---------------------------------------------------------------------------
# Java
# ---------------------------------------------------------------------------
java_presente=false

# JVM instaladas bajo /usr/lib/jvm: el equivalente de las claves JavaSoft
for jvm in /usr/lib/jvm/*/ /opt/java/*/ /usr/java/*/; do
    [ -d "$jvm" ] || continue
    [ -x "${jvm}bin/java" ] || continue
    java_presente=true
    ver=$("${jvm}bin/java" -version 2>&1 | head -1 | sed -E 's/.*version "?([^"]+)"?.*/\1/')
    add_runtime 'Java' "JVM $(basename "${jvm%/}")" "$ver" "${jvm%/}" 'Directorio /usr/lib/jvm'
done

# java en PATH (puede ser un enlace a una de las anteriores o a otra instalacion)
if has_cmd java; then
    java_presente=true
    # java -version escribe en stderr por diseno, igual que en Windows
    native_capture 30 java -version
    salida=${NC_ERR:-$NC_OUT}
    ver=$(printf '%s' "$salida" | head -1 | sed -E 's/.*version "?([^" ]+)"?.*/\1/')
    add_runtime 'Java' 'Java (en PATH)' "${ver:-desconocida}" \
        "$(command -v java)" 'java -version' "$(safe_str "$(printf '%s' "$salida" | head -2 | tr '\n' ' ')" 200)"
fi
metric JavaPresente "$java_presente" b

# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------
python_visto=''
for exe in python3 python python2; do
    has_cmd "$exe" || continue
    ruta=$(command -v "$exe")
    real=$(readlink -f "$ruta" 2>/dev/null)
    case " $python_visto " in *" $real "*) continue ;; esac
    python_visto="$python_visto $real"

    native_capture 25 "$exe" --version
    salida=${NC_OUT:-$NC_ERR}
    ver=$(printf '%s' "$salida" | sed -E 's/^Python[ ]+//I' | head -1)
    add_runtime 'Python' "Python ($exe)" "$ver" "$ruta" "$exe --version" "Real: $real"

    # Python 2 es un caso critico propio: sin soporte desde 2020
    case $ver in
        2.*)
            finding Critical 'Interprete Python 2 presente en el servidor' \
                -c 'CicloDeVida' -a "$ruta" \
                -d "Python $ver esta instalado. La rama 2.x no recibe parches de seguridad desde enero de 2020, ni para el interprete ni para su biblioteca estandar." \
                -e "$ruta -> $real" \
                -k 'SW-02|VUL-01' \
                -r 'Migrar los scripts y aplicaciones dependientes a Python 3 y desinstalar el interprete 2.x. Si alguna aplicacion de negocio lo exige, documentar la aceptacion de riesgo con fecha limite de remediacion.' ;;
    esac
done

# ---------------------------------------------------------------------------
# Node.js
# ---------------------------------------------------------------------------
if has_cmd node; then
    native_capture 25 node --version
    nodever=$(printf '%s' "$NC_OUT" | tr -d 'v' | tr -d '[:space:]')
    add_runtime 'Node.js' 'Node.js' "$nodever" "$(command -v node)" 'node --version'
    mayor=${nodever%%.*}
    if [ -n "$mayor" ] && [ "$mayor" -lt 20 ] 2>/dev/null; then
        sev='Medium'; [ "$mayor" -lt 18 ] 2>/dev/null && sev='High'
        finding "$sev" "Node.js en rama sin soporte activo (v$nodever)" \
            -c 'CicloDeVida' -a 'Node.js' \
            -d "La version instalada es $nodever. Las ramas por debajo de la LTS vigente dejan de recibir correcciones de seguridad." \
            -e "node --version = v$nodever" \
            -k 'SW-02|VUL-01' \
            -r 'Actualizar a la rama LTS vigente y verificar compatibilidad de las aplicaciones dependientes.'
    fi
fi

# ---------------------------------------------------------------------------
# PHP
# ---------------------------------------------------------------------------
if has_cmd php; then
    native_capture 25 php --version
    phpver=$(printf '%s' "$NC_OUT" | head -1 | awk '{print $2}')
    add_runtime 'PHP' 'PHP' "$phpver" "$(command -v php)" 'php --version'
fi

# ---------------------------------------------------------------------------
# .NET
# ---------------------------------------------------------------------------
if has_cmd dotnet; then
    for modo in '--list-runtimes:Runtime' '--list-sdks:SDK'; do
        flag=${modo%%:*}; etiqueta=${modo##*:}
        native_capture 45 dotnet "$flag"
        [ -n "$NC_OUT" ] || continue
        while read -r linea; do
            [ -n "$linea" ] || continue
            nombre=$(printf '%s' "$linea" | awk '{print $1}')
            version=$(printf '%s' "$linea" | awk '{print $2}')
            ruta=$(printf '%s' "$linea" | sed -E 's/.*\[(.*)\]$/\1/')
            case $etiqueta in
                SDK) add_runtime '.NET' '.NET SDK' "$nombre" "$ruta" "dotnet $flag" ;;
                *)   add_runtime '.NET' "$nombre ($etiqueta)" "$version" "$ruta" "dotnet $flag" ;;
            esac
        done <<< "$NC_OUT"
    done

    # SDK de desarrollo en un servidor: desviacion de segregacion de entornos
    n_sdk=$(dotnet --list-sdks 2>/dev/null | grep -c . 2>/dev/null)
    if [ "${n_sdk:-0}" -gt 0 ]; then
        finding Low 'SDK de desarrollo .NET instalado en servidor' \
            -c 'Segregacion' -a '.NET SDK' \
            -d "Se detectaron $n_sdk SDK de .NET. Un servidor productivo deberia contener unicamente runtimes, no herramientas de compilacion." \
            -e "$(safe_str "$(dotnet --list-sdks 2>/dev/null | head -5 | tr '\n' ';')" 300)" \
            -k 'ARQ-03|SW-03' \
            -r 'Confirmar si el servidor cumple funciones de compilacion. Si no, desinstalar los SDK para reducir la superficie de ataque y el riesgo de segregacion de entornos.'
    fi
fi

# ---------------------------------------------------------------------------
# Compiladores y cadena de construccion (ARQ-03)
# ---------------------------------------------------------------------------
compiladores=''
for c in gcc g++ cc clang make cmake javac go rustc; do
    has_cmd "$c" || continue
    compiladores="$compiladores $c"
    native_capture 20 "$c" --version
    v=$(printf '%s' "${NC_OUT:-$NC_ERR}" | head -1)
    add_runtime 'Desarrollo' "$c" "$(safe_str "$v" 120)" "$(command -v "$c")" "$c --version"
done
if [ -n "$compiladores" ]; then
    finding Medium 'Cadena de compilacion presente en el servidor' \
        -c 'Segregacion' -a "$(safe_str "$compiladores" 200)" \
        -d "Se detectaron los siguientes compiladores o herramientas de construccion:$compiladores. En un servidor productivo permiten construir binarios en el propio activo, lo que facilita la evasion del control de instalacion de software y la compilacion de exploits locales." \
        -e "Rutas: $(for c in $compiladores; do printf '%s ' "$(command -v "$c")"; done)" \
        -k 'ARQ-03|SW-03|SW-05' \
        -r 'Retirar la cadena de compilacion de los servidores productivos y construir los artefactos en un entorno de integracion dedicado. Si algun producto exige compilar modulos en sitio (por ejemplo DKMS), documentarlo como excepcion aprobada.'
fi

# ---------------------------------------------------------------------------
# Servidores web y de aplicaciones
# ---------------------------------------------------------------------------
detectar_servicio() {
    local unidad=$1
    if systemctl is-active "$unidad" >/dev/null 2>&1; then printf 'activo'
    elif systemctl is-enabled "$unidad" >/dev/null 2>&1; then printf 'habilitado (detenido)'
    elif has_cmd rc-service && rc-service "$unidad" status >/dev/null 2>&1; then printf 'activo (OpenRC)'
    else printf ''
    fi
}

# Apache
for httpd_bin in apache2 httpd; do
    has_cmd "$httpd_bin" || continue
    native_capture 25 "$httpd_bin" -v
    ver=$(printf '%s' "$NC_OUT" | awk -F'/' '/Server version/{print $2}' | awk '{print $1}')
    estado=$(detectar_servicio "$httpd_bin")
    add_runtime 'ServidorWeb' "Apache HTTP Server ($httpd_bin)" "$ver" \
        "$(command -v "$httpd_bin")" "$httpd_bin -v" "Estado: ${estado:-no activo}"
    metric ServidorWeb "Apache $ver"
done

# nginx
if has_cmd nginx; then
    native_capture 25 nginx -v
    ver=$(printf '%s' "${NC_ERR:-$NC_OUT}" | sed -E 's|.*nginx/([0-9.]+).*|\1|')
    estado=$(detectar_servicio nginx)
    add_runtime 'ServidorWeb' 'nginx' "$ver" "$(command -v nginx)" 'nginx -v' "Estado: ${estado:-no activo}"
    metric ServidorWeb "nginx $ver"
fi

# Tomcat / servidores de aplicacion Java
for base in /opt/tomcat /usr/share/tomcat* /var/lib/tomcat* /opt/jboss /opt/wildfly /opt/weblogic; do
    [ -d "$base" ] || continue
    ver=''
    [ -r "$base/RELEASE-NOTES" ] && ver=$(grep -m1 -oE '[0-9]+\.[0-9]+\.[0-9]+' "$base/RELEASE-NOTES" 2>/dev/null)
    add_runtime 'ServidorAplicaciones' "$(basename "$base")" "$ver" "$base" 'Directorio de despliegue'
done

# Unidades systemd de servidores de aplicacion, con el usuario que las ejecuta.
# Es el analogo del inventario de grupos de aplicaciones de IIS y su identidad.
if [ "$(detect_init_system)" = 'systemd' ]; then
    systemctl list-units --type=service --all --no-legend --no-pager 2>/dev/null |
    awk '{print $1}' |
    grep -iE 'tomcat|jboss|wildfly|jetty|glassfish|payara|gunicorn|uwsgi|puma|unicorn|php.*fpm|nginx|apache|httpd' |
    while read -r unidad; do
        [ -n "$unidad" ] || continue
        usuario=$(systemctl show "$unidad" -p User --value 2>/dev/null)
        [ -n "$usuario" ] || usuario='root'
        estado=$(systemctl is-active "$unidad" 2>/dev/null)
        add_runtime 'ServidorAplicaciones' "$unidad" '' '' 'systemd' \
            "Usuario=$usuario Estado=$estado"

        # Servidor de aplicaciones expuesto ejecutandose como root: analogo del
        # AppPool de IIS con identidad LocalSystem.
        if [ "$usuario" = 'root' ] && [ "$estado" = 'active' ]; then
            finding High 'Servidor de aplicaciones ejecutandose como root' \
                -c 'Privilegios' -a "$unidad" \
                -d "La unidad $unidad se ejecuta con el usuario root. Una vulnerabilidad en la aplicacion web o en el propio servidor se convierte directamente en compromiso total del sistema, sin necesidad de escalar privilegios." \
                -e "systemctl show $unidad -p User => ${usuario}" \
                -k 'ACC-02|ARQ-01' \
                -r 'Ejecutar el servicio bajo una cuenta dedicada sin privilegios (User= en la unidad systemd) y otorgar acceso a puertos privilegiados mediante AmbientCapabilities=CAP_NET_BIND_SERVICE o un proxy inverso.'
        fi
    done
fi

# ---------------------------------------------------------------------------
# Motores de base de datos
# ---------------------------------------------------------------------------
for db in mysqld mariadbd postgres psql mongod redis-server; do
    has_cmd "$db" || continue
    native_capture 25 "$db" --version
    ver=$(printf '%s' "${NC_OUT:-$NC_ERR}" | head -1)
    add_runtime 'BaseDeDatos' "$db" "$(safe_str "$ver" 150)" "$(command -v "$db")" "$db --version"
done

if [ "$(detect_init_system)" = 'systemd' ]; then
    systemctl list-units --type=service --all --no-legend --no-pager 2>/dev/null |
    awk '{print $1}' |
    grep -iE 'mysql|mariadb|postgres|mongod|redis|memcached|oracle|db2|cassandra|elasticsearch|opensearch|influxdb|clickhouse' |
    while read -r unidad; do
        estado=$(systemctl is-active "$unidad" 2>/dev/null)
        usuario=$(systemctl show "$unidad" -p User --value 2>/dev/null)
        add_runtime 'BaseDeDatos' "$unidad" '' '' 'systemd' \
            "Estado=$estado Usuario=${usuario:-root}"
        metric MotorBaseDatos "$unidad"
    done
fi

# ---------------------------------------------------------------------------
# Plataforma de contenedores
# ---------------------------------------------------------------------------
for motor in docker podman containerd kubelet; do
    has_cmd "$motor" || continue
    native_capture 30 "$motor" --version
    ver=$(printf '%s' "${NC_OUT:-$NC_ERR}" | head -1)
    estado=$(detectar_servicio "$motor")
    add_runtime 'Contenedores' "$motor" "$(safe_str "$ver" 150)" \
        "$(command -v "$motor")" "$motor --version" "Estado: ${estado:-no activo}"
    metric Contenedores "$motor"
done

# ---------------------------------------------------------------------------
# Evaluacion contra el catalogo de fin de soporte (EOL)
# ---------------------------------------------------------------------------
#
# Se recorre el catalogo una sola vez y se contrasta contra cada runtime
# detectado, replicando la logica de la version Windows.
eol_json=$(cfg_json '.EndOfLife')
hoy_epoch=$(date +%s)

if [ "$eol_json" != '[]' ]; then
    # Volcado del catalogo a TSV: patron | fecha | severidad | nota
    eol_tsv=$(printf '%s' "$eol_json" | jq -r '.[] | [.Patron, .EOL, .Severidad, .Nota] | @tsv' 2>/dev/null)

    while IFS=$'\t' read -r producto version ruta origen; do
        [ -n "$producto" ] || continue
        etiqueta="$producto $version"
        while IFS=$'\t' read -r patron fecha_eol sev nota; do
            [ -n "$patron" ] || continue
            printf '%s' "$etiqueta" | grep -qiE "$patron" 2>/dev/null || continue

            eol_epoch=$(date -d "$fecha_eol" +%s 2>/dev/null) || break
            if [ "$eol_epoch" -lt "$hoy_epoch" ]; then
                finding "${sev:-High}" "Componente de plataforma fuera de soporte: $producto" \
                    -c 'CicloDeVida' -a "$(safe_str "$etiqueta" 200)" \
                    -d "$nota Fin de soporte: $fecha_eol. Un componente sin soporte no recibe correcciones de seguridad." \
                    -e "Ruta: $ruta | Origen: $origen" \
                    -k 'SW-02|VUL-01|INV-01' \
                    -r 'Planificar la migracion a una version soportada o formalizar un plan de tratamiento del riesgo con controles compensatorios y fecha limite.'
            fi
            break
        done <<< "$eol_tsv"
    done < "$RUNTIMES_TMP"
fi

metric ComponentesPlataforma "$(rec_count)" n

emit_result
