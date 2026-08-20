#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# L7-01_network-exposure.sh
# Capa L7 - Red y exposicion.
# Criterios de auditoria -> RED-01, RED-02, RED-03, ACC-04, ACC-05
#
# EQUIVALENCIAS respecto de L7-01_Network-Exposure.ps1:
#   Get-NetTCPConnection -Listen -> ss -tlnp
#   Get-NetUDPEndpoint           -> ss -ulnp
#   Win32_Share / Get-SmbShareAccess -> /etc/exports (NFS) y smb.conf (Samba)
#   Get-NetIPConfiguration       -> ip addr / ip route / resolv.conf
#   Get-NetFirewallRule          -> firewalld / ufw / nftables / iptables
#   WinRM                        -> sshd (ya evaluado en L6-01) y servicios de
#                                   administracion remota expuestos
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/audit_core.sh"

collector_init 'L7-01' 'Exposicion de red y servicios accesibles' 'L7' \
    'RED-01|RED-02|RED-03|ACC-04|ACC-05' false \
    'Puertos en escucha correlacionados con su proceso, exportaciones NFS y Samba, interfaces y reglas de firewall permisivas.'
maybe_emit_manifest "${1:-}"

# Puertos de alto riesgo si estan expuestos en todas las interfaces.
# Se conserva el mismo catalogo que la version Windows, ajustando los servicios
# propios de Windows por sus equivalentes Linux.
servicio_sensible() {
    case $1 in
        21)   printf 'FTP (credenciales en claro)' ;;
        23)   printf 'Telnet (protocolo sin cifrado)' ;;
        69)   printf 'TFTP (sin autenticacion)' ;;
        111)  printf 'rpcbind (mapeador de puertos RPC)' ;;
        139)  printf 'NetBIOS Session Service (Samba)' ;;
        445)  printf 'SMB (Samba)' ;;
        512|513|514) printf 'Servicios r* heredados (rsh/rlogin/rexec)' ;;
        1433) printf 'Microsoft SQL Server' ;;
        1521) printf 'Oracle DB' ;;
        2049) printf 'NFS' ;;
        2375) printf 'API de Docker SIN TLS' ;;
        2376) printf 'API de Docker con TLS' ;;
        3306) printf 'MySQL/MariaDB' ;;
        3389) printf 'RDP (xrdp)' ;;
        5432) printf 'PostgreSQL' ;;
        5900) printf 'VNC' ;;
        6379) printf 'Redis (por defecto sin autenticacion)' ;;
        9200|9300) printf 'Elasticsearch' ;;
        11211) printf 'Memcached (amplificacion UDP)' ;;
        27017) printf 'MongoDB' ;;
        *) printf '' ;;
    esac
}

# ---------------------------------------------------------------------------
# 1. Puertos en escucha, correlacionados con su proceso propietario
# ---------------------------------------------------------------------------
if ! has_cmd ss && ! has_cmd netstat; then
    gap 'Ni "ss" ni "netstat" estan disponibles; no fue posible enumerar los puertos en escucha.'
    collector_status 'Failed'
    emit_result
    exit 0
fi

if ! is_root; then
    gap 'Sin privilegios de root no es posible asociar los puertos en escucha con el proceso que los abre para los procesos de otros usuarios. La correlacion puerto-artefacto es PARCIAL.'
fi

tcp_escucha=0
expuestos=0;     lista_expuestos=''
en_claro=0;      lista_claro=''

procesar_socket() {
    local proto=$1 local_addr=$2 proceso=$3

    local puerto direccion
    puerto=${local_addr##*:}
    direccion=${local_addr%:*}
    # Normalizar la notacion IPv6 [::]:80 y el comodin *
    direccion=${direccion#[}
    direccion=${direccion%]}
    [ "$direccion" = '*' ] && direccion='0.0.0.0'

    local pid nombre ruta
    pid=$(printf '%s' "$proceso" | sed -nE 's/.*pid=([0-9]+).*/\1/p' | head -1)
    nombre=$(printf '%s' "$proceso" | sed -nE 's/.*users:\(\("([^"]+)".*/\1/p' | head -1)
    ruta=''
    if [ -n "$pid" ]; then
        ruta=$(readlink "/proc/$pid/exe" 2>/dev/null)
        ruta=${ruta% (deleted)}
        [ -n "$nombre" ] || nombre=$(tr -d '\000' < "/proc/$pid/comm" 2>/dev/null)
    fi

    local todas=false
    case $direccion in
        '0.0.0.0'|'::'|'*') todas=true ;;
    esac

    local servicio
    servicio=$(servicio_sensible "$puerto")

    rec Categoria 'PuertoEscucha' Protocolo "$proto" \
        DireccionLocal "$direccion" Puerto:n "$puerto" \
        Proceso "${nombre:-PID ${pid:-desconocido}}" PID "${pid:-}" \
        RutaProceso "$(safe_str "$ruta" 400)" \
        Servicio "$servicio" TodasInterfaces:b "$todas" Detalle ''

    if [ -n "$servicio" ] && [ "$todas" = 'true' ]; then
        expuestos=$((expuestos + 1))
        [ "$expuestos" -le 20 ] && lista_expuestos="$lista_expuestos | $puerto/$proto [$servicio] <= ${nombre:-?}"
    fi
    case $puerto in
        21|23|69|512|513|514)
            en_claro=$((en_claro + 1))
            lista_claro="$lista_claro | $puerto/$proto ($servicio) <= ${nombre:-?} ${ruta:+($ruta)}" ;;
    esac
}

if has_cmd ss; then
    # TCP en escucha
    while IFS= read -r linea; do
        [ -n "$linea" ] || continue
        set -- $linea
        # Formato ss -tlnpH: State Recv-Q Send-Q Local Peer [Process]
        local_addr=$4
        proceso=$(printf '%s' "$linea" | sed -nE 's/.*(users:\(\(.*)/\1/p')
        procesar_socket 'TCP' "$local_addr" "$proceso"
        tcp_escucha=$((tcp_escucha + 1))
    done < <(ss -tlnpH 2>/dev/null)

    # UDP
    while IFS= read -r linea; do
        [ -n "$linea" ] || continue
        set -- $linea
        local_addr=$4
        proceso=$(printf '%s' "$linea" | sed -nE 's/.*(users:\(\(.*)/\1/p')
        procesar_socket 'UDP' "$local_addr" "$proceso"
    done < <(ss -ulnpH 2>/dev/null)
else
    while read -r proto recvq sendq local_addr remoto estado proceso; do
        case $proto in tcp*|udp*) ;; *) continue ;; esac
        procesar_socket "$(printf '%s' "$proto" | tr 'a-z' 'A-Z')" "$local_addr" "pid=${proceso%%/*}"
        tcp_escucha=$((tcp_escucha + 1))
    done < <(netstat -tulnp 2>/dev/null | tail -n +3)
fi

metric PuertosTCPEscucha "$tcp_escucha" n
metric PuertosSensiblesExpuestos "$expuestos" n

if [ "$expuestos" -gt 0 ]; then
    finding High 'Servicios sensibles escuchando en todas las interfaces de red' \
        -c 'ExposicionDeRed' -a "$expuestos puertos" \
        -d 'Estos servicios aceptan conexiones en cualquier interfaz (0.0.0.0 o ::). Si el firewall perimetral o de host no los restringe, quedan accesibles desde toda la red alcanzable. Varios de ellos (bases de datos, Redis, Elasticsearch, la API de Docker) no exigen autenticacion en su configuracion por omision.' \
        -e "$(safe_str "${lista_expuestos# | }" 1500)" \
        -k 'RED-01|RED-02|RED-03' \
        -r 'Restringir la escucha a la interfaz o direccion de bucle necesaria (bind-address / listen_addresses), aplicar reglas de firewall con origen acotado y aplicar segmentacion de red para los servicios de administracion y de base de datos.'
fi

if [ "$en_claro" -gt 0 ]; then
    finding Critical 'Protocolos sin cifrado activos en el servidor' \
        -c 'Criptografia' -a "$en_claro servicios" \
        -d 'FTP, Telnet, TFTP y los servicios r* transmiten credenciales y datos en texto claro, permitiendo su captura por cualquier sistema con acceso al segmento de red.' \
        -e "$(safe_str "${lista_claro# | }" 1200)" \
        -k 'CRI-02|RED-02|RED-01' \
        -r 'Sustituir por equivalentes cifrados (SFTP/FTPS, SSH, HTTPS) y desinstalar los servicios heredados en lugar de solo detenerlos.'
fi

# La API de Docker sin TLS equivale a conceder root remoto sin autenticacion
if grep -q '"Puerto":2375' "$COL_RECORDS" 2>/dev/null; then
    finding Critical 'API de Docker expuesta sin TLS' \
        -c 'ExposicionDeRed' -a 'Puerto 2375' \
        -d 'El demonio de Docker escucha en el puerto 2375 sin TLS ni autenticacion. Cualquiera que alcance ese puerto puede lanzar un contenedor privilegiado que monte el sistema de archivos del anfitrion: equivale a conceder acceso root remoto sin credenciales.' \
        -k 'RED-01|ACC-05|ACC-02' \
        -r 'Deshabilitar el socket TCP del demonio de forma inmediata y usar unicamente el socket UNIX local. Si se requiere acceso remoto, habilitar TLS mutuo (2376) y restringirlo por firewall.'
fi

# ---------------------------------------------------------------------------
# 2. Recursos compartidos: NFS y Samba
# ---------------------------------------------------------------------------
comparticiones=0
abiertos=0
lista_abiertos=''

# --- NFS ---
if [ -r /etc/exports ] || [ -d /etc/exports.d ]; then
    while IFS= read -r linea; do
        case $linea in ''|\#*) continue ;; esac
        ruta=$(printf '%s' "$linea" | awk '{print $1}')
        clientes=$(printf '%s' "$linea" | cut -d' ' -f2-)
        [ -n "$ruta" ] || continue
        comparticiones=$((comparticiones + 1))

        rec Categoria 'RecursoCompartido' Protocolo 'NFS' DireccionLocal '' \
            Puerto:n 2049 Proceso "$ruta" PID '' RutaProceso "$ruta" \
            Servicio 'Exportacion NFS' TodasInterfaces:b true \
            Detalle "$(safe_str "$clientes" 300)"

        # Exportacion a cualquier host, con escritura o sin squash de root
        problema=''
        case $clientes in
            '*'*|*' *('*) problema="$problema exportada a cualquier host;" ;;
        esac
        case $clientes in
            *no_root_squash*) problema="$problema no_root_squash (root remoto = root local);" ;;
        esac
        case $clientes in
            *insecure*) problema="$problema insecure (permite puertos de origen no privilegiados);" ;;
        esac
        if [ -n "$problema" ]; then
            abiertos=$((abiertos + 1))
            lista_abiertos="$lista_abiertos | NFS $ruta =>$problema"
        fi
    done < <(cat /etc/exports /etc/exports.d/*.exports 2>/dev/null)
fi

# --- Samba ---
if [ -r /etc/samba/smb.conf ]; then
    seccion=''
    guest_ok=''; writable=''; ruta_share=''
    while IFS= read -r linea; do
        case $linea in
            \#*|\;*|'') continue ;;
            \[*\])
                # Cierre de la seccion anterior
                if [ -n "$seccion" ] && [ "$seccion" != 'global' ]; then
                    comparticiones=$((comparticiones + 1))
                    rec Categoria 'RecursoCompartido' Protocolo 'SMB' DireccionLocal '' \
                        Puerto:n 445 Proceso "$seccion" PID '' RutaProceso "$ruta_share" \
                        Servicio 'Comparticion Samba' TodasInterfaces:b true \
                        Detalle "guest ok=$guest_ok writable=$writable"
                    if [ "$guest_ok" = 'yes' ]; then
                        abiertos=$((abiertos + 1))
                        lista_abiertos="$lista_abiertos | SMB [$seccion] $ruta_share => acceso invitado permitido"
                    fi
                fi
                seccion=$(printf '%s' "$linea" | tr -d '[]' | tr 'A-Z' 'a-z' | tr -d ' ')
                guest_ok=''; writable=''; ruta_share='' ;;
            *)
                clave=$(printf '%s' "$linea" | cut -d= -f1 | tr -d ' ' | tr 'A-Z' 'a-z')
                valor=$(printf '%s' "$linea" | cut -d= -f2- | tr -d ' ' | tr 'A-Z' 'a-z')
                case $clave in
                    guestok|publico|public) guest_ok=$valor ;;
                    writable|writeable) writable=$valor ;;
                    path) ruta_share=$valor ;;
                esac ;;
        esac
    done < /etc/samba/smb.conf

    if [ -n "$seccion" ] && [ "$seccion" != 'global' ]; then
        comparticiones=$((comparticiones + 1))
        rec Categoria 'RecursoCompartido' Protocolo 'SMB' DireccionLocal '' \
            Puerto:n 445 Proceso "$seccion" PID '' RutaProceso "$ruta_share" \
            Servicio 'Comparticion Samba' TodasInterfaces:b true \
            Detalle "guest ok=$guest_ok writable=$writable"
        [ "$guest_ok" = 'yes' ] && {
            abiertos=$((abiertos + 1))
            lista_abiertos="$lista_abiertos | SMB [$seccion] $ruta_share => acceso invitado permitido"; }
    fi
fi

metric RecursosCompartidos "$comparticiones" n

if [ "$abiertos" -gt 0 ]; then
    finding High 'Recursos compartidos con permisos excesivamente amplios' \
        -c 'ControlDeAcceso' -a "$abiertos recursos" \
        -d 'Existen exportaciones o comparticiones accesibles desde cualquier host, con acceso de invitado, o con no_root_squash. En el caso de NFS, no_root_squash permite que el usuario root de un cliente remoto opere como root sobre los archivos exportados, lo que convierte la exportacion en una via de compromiso del servidor.' \
        -e "$(safe_str "${lista_abiertos# | }" 1500)" \
        -k 'ACC-04|DAT-02|RED-01' \
        -r 'Acotar cada exportacion a los hosts o subredes que la requieran, activar root_squash, y en Samba retirar "guest ok" aplicando permisos basados en grupos especificos. Verificar tambien las ACL del sistema de archivos subyacente.'
elif [ "$comparticiones" -gt 0 ]; then
    finding Info 'Recursos compartidos publicados en el servidor' \
        -c 'ControlDeAcceso' -a "$comparticiones recursos" \
        -d 'El servidor publica recursos compartidos por NFS o SMB. No se detectaron permisos abiertos, pero cada comparticion debe corresponder a una necesidad vigente.' \
        -k 'ACC-04' \
        -r 'Verificar que cada comparticion responda a una necesidad vigente y que sus permisos esten alineados con la clasificacion de la informacion alojada.'
fi

# ---------------------------------------------------------------------------
# 3. Interfaces y configuracion IP
# ---------------------------------------------------------------------------
if has_cmd ip; then
    gateway=$(ip route show default 2>/dev/null | awk '{print $3; exit}')
    dns=$(awk '/^nameserver/{printf "%s ", $2}' /etc/resolv.conf 2>/dev/null)

    while read -r idx iface resto; do
        iface=${iface%:}
        [ -n "$iface" ] || continue
        [ "$iface" = 'lo' ] && continue
        direcciones=$(ip -o addr show dev "$iface" 2>/dev/null | awk '{print $4}' | tr '\n' ',' | sed 's/,$//')
        estado=$(cat "/sys/class/net/$iface/operstate" 2>/dev/null)

        rec Categoria 'Interfaz' Protocolo 'IP' DireccionLocal "$direcciones" \
            Puerto:n 0 Proceso "$iface" PID '' \
            RutaProceso "Gateway: ${gateway:-ninguno}" \
            Servicio "DNS: $(safe_str "$dns" 200)" \
            TodasInterfaces:b false Detalle "$estado"
    done < <(ip -o link show 2>/dev/null | awk -F': ' '{print NR": "$2}')
fi

# ---------------------------------------------------------------------------
# 4. Reglas de firewall permisivas
# ---------------------------------------------------------------------------
reglas_total=0
permisivas=0
lista_permisivas=''

if has_cmd firewall-cmd && systemctl is-active firewalld >/dev/null 2>&1; then
    for z in $(firewall-cmd --get-active-zones 2>/dev/null | grep -v '^ '); do
        servicios=$(firewall-cmd --zone="$z" --list-services 2>/dev/null)
        puertos=$(firewall-cmd --zone="$z" --list-ports 2>/dev/null)
        fuentes=$(firewall-cmd --zone="$z" --list-sources 2>/dev/null)
        n=$(printf '%s %s' "$servicios" "$puertos" | wc -w)
        reglas_total=$((reglas_total + n))
        rec Categoria 'ReglaFirewall' Protocolo 'firewalld' DireccionLocal "$z" \
            Puerto:n 0 Proceso "zona $z" PID '' \
            RutaProceso "$(safe_str "$servicios" 300)" \
            Servicio "$(safe_str "$puertos" 200)" TodasInterfaces:b true \
            Detalle "Fuentes: ${fuentes:-cualquiera}"
        # Zona sin restriccion de origen y con servicios abiertos
        if [ -z "$fuentes" ] && [ "$n" -gt 0 ]; then
            permisivas=$((permisivas + 1))
            lista_permisivas="$lista_permisivas | zona $z: $servicios $puertos (sin restriccion de origen)"
        fi
    done
elif has_cmd ufw && ufw status numbered >/dev/null 2>&1; then
    while IFS= read -r linea; do
        case $linea in *ALLOW*) ;; *) continue ;; esac
        reglas_total=$((reglas_total + 1))
        rec Categoria 'ReglaFirewall' Protocolo 'ufw' DireccionLocal '' \
            Puerto:n 0 Proceso "$(safe_str "$linea" 200)" PID '' RutaProceso '' \
            Servicio '' TodasInterfaces:b true Detalle ''
        case $linea in
            *Anywhere*)
                permisivas=$((permisivas + 1))
                [ "$permisivas" -le 15 ] && lista_permisivas="$lista_permisivas | $(safe_str "$linea" 150)" ;;
        esac
    done < <(ufw status 2>/dev/null)
elif has_cmd nft; then
    reglas_total=$(nft list ruleset 2>/dev/null | grep -c 'accept' 2>/dev/null)
    permisivas=$(nft list ruleset 2>/dev/null | grep -cE 'accept' 2>/dev/null)
    rec Categoria 'ReglaFirewall' Protocolo 'nftables' DireccionLocal '' \
        Puerto:n 0 Proceso 'ruleset' PID '' RutaProceso '' Servicio '' \
        TodasInterfaces:b true Detalle "$reglas_total reglas accept"
elif has_cmd iptables; then
    reglas_total=$(iptables -S 2>/dev/null | grep -c '^-A INPUT' 2>/dev/null)
    while IFS= read -r linea; do
        case $linea in
            *'-j ACCEPT'*)
                # Regla sin restriccion de origen (-s) ni de puerto (--dport)
                case $linea in
                    *' -s '*|*'--dport'*) ;;
                    *) permisivas=$((permisivas + 1))
                       [ "$permisivas" -le 15 ] && lista_permisivas="$lista_permisivas | $(safe_str "$linea" 150)" ;;
                esac ;;
        esac
    done < <(iptables -S INPUT 2>/dev/null)
    rec Categoria 'ReglaFirewall' Protocolo 'iptables' DireccionLocal '' \
        Puerto:n 0 Proceso 'INPUT' PID '' RutaProceso '' Servicio '' \
        TodasInterfaces:b true Detalle "$reglas_total reglas"
else
    gap 'No se detecto ningun motor de firewall consultable; no se evaluaron las reglas de filtrado.'
fi

metric ReglasFirewallEntrantes "$reglas_total" n
metric ReglasPermisivas "$permisivas" n

if [ "$permisivas" -gt 0 ]; then
    finding Medium 'Reglas de firewall entrantes sin restriccion de origen' \
        -c 'Red' -a "$permisivas reglas" \
        -d 'Estas reglas permiten trafico entrante desde cualquier origen, anulando en la practica el filtrado de host para el servicio o la zona que cubren.' \
        -e "$(safe_str "${lista_permisivas# | }" 1500)" \
        -k 'RED-01|RED-02' \
        -r 'Acotar cada regla al puerto y al rango de direcciones de origen estrictamente requeridos, y eliminar las reglas sin dueno identificable.'
fi

# ---------------------------------------------------------------------------
# 5. Servicios de administracion remota expuestos
# ---------------------------------------------------------------------------
for svc in cockpit webmin; do
    if systemctl is-active "$svc" >/dev/null 2>&1 || systemctl is-active "$svc.socket" >/dev/null 2>&1; then
        rec Categoria 'AdministracionRemota' Protocolo 'HTTPS' DireccionLocal '' \
            Puerto:n 0 Proceso "$svc" PID '' RutaProceso '' \
            Servicio "Consola de administracion web" TodasInterfaces:b true Detalle 'activo'
        finding Medium "Consola de administracion web activa: $svc" \
            -c 'AdministracionRemota' -a "$svc" \
            -d "El servicio $svc expone una consola de administracion del servidor por HTTP(S). Concede acceso equivalente a una sesion privilegiada y amplia la superficie de ataque de administracion." \
            -k 'ACC-05|RED-01|ACC-02' \
            -r 'Restringir el acceso por firewall a la red de administracion, exigir autenticacion multifactor y deshabilitar el servicio si no forma parte del procedimiento operativo aprobado.'
    fi
done

emit_result
