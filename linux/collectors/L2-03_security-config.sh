#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# L2-03_security-config.sh
# Capa L2 - Hardening y controles de seguridad del sistema operativo.
# Criterios de auditoria -> VUL-02, ARQ-01, REG-01, RED-01, CRI-02, CRI-01
#
# EQUIVALENCIAS respecto de L2-03_Security-Config.ps1:
#   Get-MpComputerStatus     -> ClamAV (clamd/freshclam) + agentes EDR instalados
#   Exclusiones de Defender  -> exclusiones de ClamAV / rutas excluidas del EDR
#   Get-NetFirewallProfile   -> firewalld / ufw / nftables / iptables
#   Get-BitLockerVolume      -> LUKS / dm-crypt (lsblk TYPE=crypt, cryptsetup)
#   Claves de hardening      -> sysctl del kernel + /etc/login.defs + modulos
#   SMB1Protocol             -> Samba: 'server min protocol' / modulos legacy
#   SChannel TLS             -> politica criptografica del sistema + OpenSSL
#   auditpol                 -> auditctl -l / reglas de auditd
#   ScriptBlockLogging       -> auditd execve + SELinux/AppArmor (control
#                               equivalente de trazabilidad de ejecucion)
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/audit_core.sh"

collector_init 'L2-03' 'Configuracion de seguridad del sistema operativo' 'L2' \
    'VUL-02|ARQ-01|REG-01|RED-01|CRI-02|CRI-01' false \
    'Antimalware, MAC (SELinux/AppArmor), firewall, cifrado de volumenes, sysctl de hardening, protocolos heredados y auditoria del kernel.'
maybe_emit_manifest "${1:-}"

# Registra un control evaluado. Equivalente de la funcion Add-Control.
add_control() {
    rec Control "$1" Elemento "$2" Valor "$(safe_str "$3" 256)" \
        Esperado "${4:-}" Estado "${5:-Info}"
}

controles_falla=0
marcar_falla() { controles_falla=$((controles_falla + 1)); }

# ---------------------------------------------------------------------------
# VUL-02 Proteccion contra codigo malicioso
# ---------------------------------------------------------------------------
#
# En Linux el modelo de proteccion difiere de Windows: rara vez hay un
# antimalware residente, y el control primario es el control de acceso
# obligatorio (SELinux/AppArmor) mas la verificacion de integridad. Se evaluan
# ambos y se exige que exista al menos uno activo.

antimalware='Ninguno detectado'
antimalware_activo=0

if has_cmd clamscan || has_cmd clamdscan || systemctl list-unit-files 2>/dev/null | grep -q 'clamav'; then
    antimalware='ClamAV'
    if systemctl is-active clamav-daemon >/dev/null 2>&1 || systemctl is-active clamd >/dev/null 2>&1 || \
       systemctl is-active 'clamd@scan' >/dev/null 2>&1; then
        antimalware_activo=1
        add_control 'VUL-02' 'Antimalware' 'ClamAV (demonio activo)' 'Presente y activo' 'OK'
    else
        add_control 'VUL-02' 'Antimalware' 'ClamAV (demonio detenido)' 'Presente y activo' 'FALLA'
        marcar_falla
    fi

    # Antiguedad de las firmas: equivalente de AntivirusSignatureAge
    firmas_dias=''
    for d in /var/lib/clamav /var/lib/clamav/daily.cld /var/lib/clamav/daily.cvd; do
        [ -e "$d" ] || continue
        m=$(stat -c %Y "$d" 2>/dev/null) || continue
        firmas_dias=$(( ( $(date +%s) - m ) / 86400 ))
        break
    done
    if [ -n "$firmas_dias" ]; then
        add_control 'VUL-02' 'EdadFirmasDias' "$firmas_dias" '<= 3' \
            "$(if [ "$firmas_dias" -le 3 ]; then printf OK; else printf FALLA; fi)"
        metric EdadFirmasDias "$firmas_dias" n
        if [ "$firmas_dias" -gt 3 ]; then
            marcar_falla
            finding High 'Firmas de antimalware desactualizadas' \
                -c 'Antimalware' -a 'ClamAV' \
                -d "Las definiciones tienen $firmas_dias dias de antiguedad. Un antimalware con firmas obsoletas no detecta amenazas recientes." \
                -e "Directorio de firmas=/var/lib/clamav" \
                -k 'VUL-02' \
                -r 'Verificar que el servicio freshclam este activo y con conectividad hacia la fuente de firmas (o hacia el espejo interno de la organizacion).'
        fi
    else
        gap 'No fue posible determinar la antiguedad de las firmas de ClamAV.'
    fi
fi

# Agentes EDR / antimalware comercial
for agente in falcon-sensor sentinelone sentinelagent cbagent cbsensor \
              mfetpd mcafee trellix ds_agent wazuh-agent ossec-hids osqueryd; do
    if systemctl is-active "$agente" >/dev/null 2>&1 || pgrep -x "$agente" >/dev/null 2>&1; then
        antimalware="$antimalware + $agente"
        antimalware_activo=1
        add_control 'VUL-02' 'AgenteEDR' "$agente (activo)" 'Activo' 'OK'
    fi
done

metric Antimalware "$antimalware"

# Control de acceso obligatorio: SELinux / AppArmor
mac_estado='Ninguno'
mac_activo=0
if has_cmd getenforce; then
    mac_estado="SELinux: $(getenforce 2>/dev/null)"
    case $(getenforce 2>/dev/null) in
        Enforcing) mac_activo=1
                   add_control 'VUL-02' 'ControlAccesoObligatorio' "$mac_estado" 'Enforcing' 'OK' ;;
        Permissive) add_control 'VUL-02' 'ControlAccesoObligatorio' "$mac_estado" 'Enforcing' 'ADVERTENCIA'
                   finding Medium 'SELinux en modo permisivo' \
                       -c 'Hardening' -a 'SELinux' \
                       -d 'SELinux esta cargado pero en modo Permissive: registra las violaciones de politica sin bloquearlas. No provee contencion efectiva ante un compromiso.' \
                       -e "getenforce=Permissive" \
                       -k 'VUL-02|ARQ-01' \
                       -r 'Revisar las denegaciones registradas (ausearch -m avc), corregir la politica y pasar a Enforcing mediante /etc/selinux/config.' ;;
        *) add_control 'VUL-02' 'ControlAccesoObligatorio' "$mac_estado" 'Enforcing' 'FALLA'; marcar_falla ;;
    esac
elif has_cmd aa-status; then
    if aa-status --enabled 2>/dev/null; then
        perfiles=$(aa-status 2>/dev/null | awk '/profiles are in enforce mode/{print $1; exit}')
        mac_estado="AppArmor: $perfiles perfiles en modo enforce"
        mac_activo=1
        add_control 'VUL-02' 'ControlAccesoObligatorio' "$mac_estado" 'Habilitado' 'OK'
    else
        add_control 'VUL-02' 'ControlAccesoObligatorio' 'AppArmor deshabilitado' 'Habilitado' 'FALLA'
        marcar_falla
    fi
elif [ -d /sys/kernel/security/apparmor ]; then
    mac_estado='AppArmor cargado (aa-status no disponible)'
    mac_activo=1
    add_control 'VUL-02' 'ControlAccesoObligatorio' "$mac_estado" 'Habilitado' 'Info'
else
    add_control 'VUL-02' 'ControlAccesoObligatorio' 'Ninguno' 'SELinux o AppArmor' 'FALLA'
    marcar_falla
fi
metric ControlAccesoObligatorio "$mac_estado"

if [ "$antimalware_activo" -eq 0 ] && [ "$mac_activo" -eq 0 ]; then
    finding High 'Sin proteccion activa contra codigo malicioso ni control de acceso obligatorio' \
        -c 'Antimalware' -a "$AUDIT_HOSTNAME" \
        -d 'No se detecto antimalware residente (ClamAV o agente EDR) ni un mecanismo de control de acceso obligatorio activo (SELinux/AppArmor). El servidor carece de contencion frente a la ejecucion de codigo malicioso.' \
        -e "Antimalware=$antimalware | MAC=$mac_estado" \
        -k 'VUL-02' \
        -r 'Habilitar SELinux o AppArmor en modo enforcing como control base, y evaluar el despliegue del agente EDR corporativo sobre este activo. Complementar con verificacion periodica de integridad (AIDE/Tripwire).'
elif [ "$antimalware_activo" -eq 0 ]; then
    finding Medium 'Sin antimalware residente; la proteccion recae en el control de acceso obligatorio' \
        -c 'Antimalware' -a "$AUDIT_HOSTNAME" \
        -d "No hay antimalware residente activo. El control compensatorio presente es $mac_estado. Es una arquitectura defendible en Linux, pero debe estar declarada como decision formal y no ser el resultado de una omision." \
        -k 'VUL-02' \
        -r 'Documentar la decision de no usar antimalware residente como aceptacion de riesgo, y evidenciar el control compensatorio (MAC en enforcing + verificacion de integridad + parcheo dentro de plazo).'
fi

# Exclusiones de analisis: vector clasico de evasion (VUL-02 + SW-03)
exclusiones=0
excl_lista=''
if [ -r /etc/clamav/clamd.conf ]; then
    excl_lista=$(awk '/^ExcludePath/{print $2}' /etc/clamav/clamd.conf 2>/dev/null | tr '\n' ' ')
    exclusiones=$(printf '%s\n' "$excl_lista" | wc -w)
fi
if [ "$exclusiones" -gt 0 ]; then
    add_control 'VUL-02' 'ExclusionesDefinidas' "$exclusiones" '<= 10 justificadas' 'Info'
    for e in $excl_lista; do add_control 'VUL-02' 'ExclusionRuta' "$e" '' 'Info'; done
    if [ "$exclusiones" -gt 10 ]; then
        finding Medium 'Numero elevado de exclusiones de antimalware' \
            -c 'Antimalware' -a 'ClamAV' \
            -d "Se detectaron $exclusiones rutas excluidas del analisis. Cada exclusion es un area ciega para la deteccion." \
            -e "$(safe_str "$excl_lista" 500)" \
            -k 'VUL-02|ARQ-01' \
            -r 'Revisar y justificar cada exclusion; eliminar las que no respondan a un requerimiento tecnico vigente y documentado.'
    fi
    # Exclusiones de alcance excesivo
    for e in $excl_lista; do
        case $e in
            '/'|'^/$'|'/home'|'/usr'|'/opt'|'/var'|'/etc'|'/srv')
                finding High 'Exclusiones de antimalware sobre rutas demasiado amplias' \
                    -c 'Antimalware' -a 'ClamAV' \
                    -d "Ruta excluida de alcance excesivo: $e. Excluir un arbol completo del sistema de archivos anula la deteccion en toda esa rama." \
                    -e "ExcludePath=$e" \
                    -k 'VUL-02' \
                    -r 'Reducir el alcance de la exclusion al directorio o proceso especifico requerido.'
                break ;;
        esac
    done
fi

# ---------------------------------------------------------------------------
# RED-01 Firewall de host
# ---------------------------------------------------------------------------
#
# Windows tiene tres perfiles fijos (Domain/Private/Public). En Linux el
# equivalente son las zonas de firewalld, o el estado global de ufw/nftables.

fw_motor='Ninguno'
fw_activo=0
fw_politica=''

if has_cmd firewall-cmd && systemctl is-active firewalld >/dev/null 2>&1; then
    fw_motor='firewalld'
    fw_activo=1
    zona_def=$(firewall-cmd --get-default-zone 2>/dev/null)
    for z in $(firewall-cmd --get-active-zones 2>/dev/null | grep -v '^ '); do
        target=$(firewall-cmd --zone="$z" --get-target 2>/dev/null)
        servicios=$(firewall-cmd --zone="$z" --list-services 2>/dev/null)
        puertos=$(firewall-cmd --zone="$z" --list-ports 2>/dev/null)
        add_control 'RED-01' "Firewall-zona-$z" "target=$target" 'DROP o %%REJECT%%' \
            "$(case $target in DROP|'%%REJECT%%'|REJECT) printf OK ;; *) printf ADVERTENCIA ;; esac)"
        add_control 'RED-01' "FirewallServicios-$z" "$(safe_str "$servicios $puertos" 200)" '' 'Info'
        [ "$z" = "$zona_def" ] && fw_politica=$target
    done
elif has_cmd ufw && ufw status 2>/dev/null | grep -qi '^Status: active'; then
    fw_motor='ufw'
    fw_activo=1
    fw_politica=$(ufw status verbose 2>/dev/null | awk -F'[(,]' '/^Default:/{print $0; exit}')
    add_control 'RED-01' 'Firewall-ufw' 'activo' 'activo' 'OK'
    add_control 'RED-01' 'FirewallPoliticaDefecto' "$(safe_str "$fw_politica" 200)" 'deny (incoming)' \
        "$(if printf '%s' "$fw_politica" | grep -q 'deny (incoming)'; then printf OK; else printf ADVERTENCIA; fi)"
elif has_cmd nft && [ -n "$(nft list ruleset 2>/dev/null)" ]; then
    fw_motor='nftables'
    fw_activo=1
    fw_politica=$(nft list ruleset 2>/dev/null | awk '/type filter hook input/{print $0; exit}')
    add_control 'RED-01' 'Firewall-nftables' 'ruleset cargado' 'policy drop' \
        "$(if printf '%s' "$fw_politica" | grep -q 'policy drop'; then printf OK; else printf ADVERTENCIA; fi)"
elif has_cmd iptables; then
    reglas=$(iptables -S 2>/dev/null | grep -c '^-A' 2>/dev/null)
    pol_input=$(iptables -S 2>/dev/null | awk '/^-P INPUT/{print $3; exit}')
    if [ "${reglas:-0}" -gt 0 ] || [ "$pol_input" = 'DROP' ]; then
        fw_motor='iptables'
        fw_activo=1
    fi
    fw_politica="INPUT policy=$pol_input reglas=$reglas"
    add_control 'RED-01' 'Firewall-iptables' "$fw_politica" 'policy DROP' \
        "$(if [ "$pol_input" = 'DROP' ]; then printf OK; else printf ADVERTENCIA; fi)"
fi

metric FirewallMotor "$fw_motor"
metric FirewallActivo "$fw_activo" b

if [ "$fw_activo" -eq 0 ]; then
    finding High 'Firewall de host inactivo o ausente' \
        -c 'Red' -a "$AUDIT_HOSTNAME" \
        -d 'No se detecto un firewall de host activo (firewalld, ufw, nftables o iptables con reglas). El servidor queda sin filtrado local: todo puerto en escucha es alcanzable desde cualquier origen que tenga ruta de red hacia el activo.' \
        -e "Motor detectado=$fw_motor" \
        -k 'RED-01|RED-02' \
        -r 'Habilitar el firewall de host con politica entrante DROP por defecto y definir reglas explicitas unicamente para los servicios requeridos, acotadas por puerto y rango de origen.'
elif printf '%s' "$fw_politica" | grep -qiE 'accept|allow \(incoming\)'; then
    finding Medium 'Firewall activo con politica entrante permisiva' \
        -c 'Red' -a "$fw_motor" \
        -d "El firewall esta activo pero su politica entrante por defecto no es restrictiva: $fw_politica. Un firewall que acepta por omision solo protege frente a lo que se bloquee explicitamente, invirtiendo el modelo de seguridad." \
        -e "$(safe_str "$fw_politica" 300)" \
        -k 'RED-01|RED-02' \
        -r 'Cambiar la politica por defecto de la cadena/zona de entrada a DROP o REJECT y declarar explicitamente los servicios permitidos.'
fi

# ---------------------------------------------------------------------------
# CRI-01 / CRI-02 Cifrado de volumenes en reposo
# ---------------------------------------------------------------------------
cifrados=0
sin_cifrar=''
if has_cmd lsblk; then
    # TYPE=crypt identifica los mapeos dm-crypt/LUKS activos
    cifrados=$(lsblk -ln -o TYPE 2>/dev/null | grep -c '^crypt' 2>/dev/null)
    raiz_src=$(findmnt -no SOURCE / 2>/dev/null)
    raiz_tipo=$(lsblk -no TYPE "$raiz_src" 2>/dev/null | head -1)

    add_control 'CRI-02' 'VolumenesCifrados' "$cifrados" '>= 1 en activos con datos sensibles' \
        "$(if [ "${cifrados:-0}" -gt 0 ]; then printf OK; else printf ADVERTENCIA; fi)"

    if [ "${cifrados:-0}" -eq 0 ]; then
        sin_cifrar='/'
    elif [ "$raiz_tipo" != 'crypt' ]; then
        # Hay cifrado en el sistema, pero la raiz no esta cifrada
        padre=$(lsblk -nso TYPE "$raiz_src" 2>/dev/null | grep -c '^crypt' 2>/dev/null)
        [ "${padre:-0}" -eq 0 ] && sin_cifrar='/'
    fi
fi
metric VolumenesCifrados "${cifrados:-0}" n

if [ -n "$sin_cifrar" ]; then
    finding Medium 'Volumen de sistema sin cifrado en reposo' \
        -c 'Criptografia' -a "$sin_cifrar" \
        -d 'El volumen raiz no esta protegido con LUKS/dm-crypt. Es relevante si el activo puede salir del centro de datos, si los discos se dan de baja sin borrado seguro, o si el almacenamiento subyacente no ofrece cifrado.' \
        -e "Volumenes cifrados detectados=$cifrados" \
        -k 'CRI-02|CRI-01|DAT-03' \
        -r 'Evaluar el cifrado del volumen segun la clasificacion de la informacion alojada. Si el cifrado lo provee la capa de almacenamiento (SAN/hipervisor/nube), documentarlo como control compensatorio con evidencia del proveedor.'
fi

# ---------------------------------------------------------------------------
# ARQ-01 Hardening del kernel via sysctl
#
# Sustituye a las claves de registro (EnableLUA, RunAsPPL, NoLMHash, SMB1...).
# Cada entrada declara: parametro | valor esperado | criterio | severidad |
# titulo | recomendacion.
# ---------------------------------------------------------------------------
evaluar_sysctl() {
    local param=$1 esperado=$2 control=$3 sev=$4 titulo=$5 reco=$6
    local actual
    actual=$(sysctl -n "$param" 2>/dev/null)
    if [ -z "$actual" ]; then
        add_control "$control" "$param" '(no disponible)' "$esperado" 'NO DEFINIDO'
        return 0
    fi
    if [ "$actual" = "$esperado" ]; then
        add_control "$control" "$param" "$actual" "$esperado" 'OK'
    else
        add_control "$control" "$param" "$actual" "$esperado" 'FALLA'
        marcar_falla
        finding "$sev" "$titulo" \
            -c 'Hardening' -a "sysctl $param" \
            -d "Valor actual: $actual. Valor esperado segun linea base: $esperado." \
            -e "$param=$actual" \
            -k "$control" \
            -r "$reco"
    fi
}

evaluar_sysctl 'kernel.randomize_va_space' '2' 'ARQ-01' 'Medium' \
    'Aleatorizacion del espacio de direcciones (ASLR) no esta en su nivel maximo' \
    'Establecer kernel.randomize_va_space=2 en /etc/sysctl.d/. ASLR completo dificulta la explotacion de corrupciones de memoria.'

evaluar_sysctl 'kernel.kptr_restrict' '2' 'ARQ-01' 'Low' \
    'Punteros del kernel expuestos a usuarios sin privilegios' \
    'Establecer kernel.kptr_restrict=2 para impedir la fuga de direcciones del kernel que facilitan la escalada de privilegios.'

evaluar_sysctl 'kernel.dmesg_restrict' '1' 'ARQ-01' 'Low' \
    'El buffer de mensajes del kernel es legible por cualquier usuario' \
    'Establecer kernel.dmesg_restrict=1: dmesg filtra informacion util para un atacante local.'

evaluar_sysctl 'fs.suid_dumpable' '0' 'ARQ-01' 'Medium' \
    'Los procesos SUID pueden generar volcados de memoria' \
    'Establecer fs.suid_dumpable=0. Un volcado de un proceso privilegiado puede contener credenciales en claro.'

evaluar_sysctl 'kernel.yama.ptrace_scope' '1' 'ARQ-01' 'Low' \
    'ptrace sin restriccion entre procesos del mismo usuario' \
    'Establecer kernel.yama.ptrace_scope=1 para limitar la inspeccion de procesos ajenos y el robo de credenciales en memoria.'

evaluar_sysctl 'net.ipv4.conf.all.rp_filter' '1' 'RED-02' 'Medium' \
    'Filtrado de ruta inversa deshabilitado' \
    'Establecer net.ipv4.conf.all.rp_filter=1 para descartar paquetes con origen suplantado.'

evaluar_sysctl 'net.ipv4.conf.all.accept_redirects' '0' 'RED-02' 'Medium' \
    'El host acepta redirecciones ICMP' \
    'Establecer net.ipv4.conf.all.accept_redirects=0: las redirecciones ICMP permiten alterar la tabla de rutas del servidor.'

evaluar_sysctl 'net.ipv4.conf.all.accept_source_route' '0' 'RED-02' 'Medium' \
    'El host acepta paquetes con enrutamiento de origen' \
    'Establecer net.ipv4.conf.all.accept_source_route=0. El source routing permite evadir controles de segmentacion.'

evaluar_sysctl 'net.ipv4.tcp_syncookies' '1' 'RED-01' 'Low' \
    'SYN cookies deshabilitadas' \
    'Establecer net.ipv4.tcp_syncookies=1 para resistir el agotamiento de la cola de conexiones entrantes.'

# El reenvio IP en un servidor que no es router convierte al activo en un
# posible puente entre segmentos de red (RED-03).
ip_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
add_control 'RED-03' 'net.ipv4.ip_forward' "${ip_forward:-n/d}" '0 salvo router/contenedores' \
    "$(if [ "${ip_forward:-0}" = '0' ]; then printf OK; else printf ADVERTENCIA; fi)"
if [ "${ip_forward:-0}" = '1' ]; then
    # Docker y Kubernetes lo habilitan legitimamente: se reporta como observacion
    contenedores=''
    (systemctl is-active docker >/dev/null 2>&1 || systemctl is-active containerd >/dev/null 2>&1 || \
     systemctl is-active kubelet >/dev/null 2>&1) && contenedores=' No obstante, se detecto una plataforma de contenedores activa, que habilita el reenvio de forma legitima.'
    finding Low 'Reenvio de paquetes IP habilitado' \
        -c 'Red' -a 'net.ipv4.ip_forward' \
        -d "El servidor esta configurado para reenviar paquetes IP entre interfaces. En un activo que no cumple funciones de router o firewall, esto lo convierte en un puente potencial entre segmentos de red, debilitando la segmentacion.$contenedores" \
        -e "net.ipv4.ip_forward=$ip_forward" \
        -k 'RED-03|RED-02' \
        -r 'Deshabilitar el reenvio (net.ipv4.ip_forward=0) salvo que el rol del servidor lo requiera; en ese caso documentarlo en la linea base de arquitectura.'
fi

# ---------------------------------------------------------------------------
# RED-02 Protocolos heredados: modulos de sistemas de archivos y red en desuso
# ---------------------------------------------------------------------------
for modulo in cramfs freevxfs jffs2 hfs hfsplus squashfs udf usb-storage dccp sctp rds tipc; do
    if lsmod 2>/dev/null | grep -q "^$modulo "; then
        add_control 'RED-02' "Modulo-$modulo" 'cargado' 'no cargado' 'ADVERTENCIA'
    fi
done
modulos_riesgo=$(lsmod 2>/dev/null | awk '$1=="dccp"||$1=="sctp"||$1=="rds"||$1=="tipc"{printf "%s ", $1}')
if [ -n "$modulos_riesgo" ]; then
    finding Medium 'Modulos de protocolos de red poco usados cargados en el kernel' \
        -c 'Protocolos' -a "$(safe_str "$modulos_riesgo" 200)" \
        -d "Estan cargados los modulos: $modulos_riesgo. Son pilas de protocolo raramente utilizadas en servidores de produccion, con historial de vulnerabilidades y que amplian la superficie de ataque del kernel sin aportar funcionalidad." \
        -e "lsmod: $modulos_riesgo" \
        -k 'RED-02|VUL-01' \
        -r 'Deshabilitar los modulos no requeridos con "install <modulo> /bin/false" en /etc/modprobe.d/ y confirmar que ningun servicio dependa de ellos.'
fi

# SMBv1 en Samba: analogo directo del hallazgo SMB1Protocol de Windows
if [ -r /etc/samba/smb.conf ]; then
    min_proto=$(awk -F= '/^[ \t]*(server )?min protocol/{gsub(/ /,"",$2); print tolower($2); exit}' /etc/samba/smb.conf 2>/dev/null)
    add_control 'RED-02' 'Samba min protocol' "${min_proto:-no definido}" 'SMB2 o superior' \
        "$(case $min_proto in smb2*|smb3*) printf OK ;; *) printf FALLA ;; esac)"
    case $min_proto in
        smb2*|smb3*) : ;;
        *)
            marcar_falla
            finding Critical 'Samba admite SMBv1' \
                -c 'Protocolos' -a '/etc/samba/smb.conf' \
                -d "El parametro 'server min protocol' vale '${min_proto:-no definido}'. Sin un minimo de SMB2, el servicio acepta SMBv1: un protocolo obsoleto sin firma ni cifrado, explotado por familias de ransomware conocidas." \
                -e "server min protocol=${min_proto:-no definido}" \
                -k 'RED-02|RED-01|VUL-01' \
                -r 'Establecer "server min protocol = SMB2_10" (o SMB3) en smb.conf tras confirmar que ningun cliente heredado dependa de SMBv1.' ;;
    esac
fi

# ---------------------------------------------------------------------------
# CRI-02 Politica criptografica del sistema
# ---------------------------------------------------------------------------
if has_cmd update-crypto-policies; then
    politica=$(update-crypto-policies --show 2>/dev/null)
    add_control 'CRI-02' 'PoliticaCriptografica' "$politica" 'DEFAULT o FUTURE' \
        "$(case $politica in LEGACY*) printf FALLA ;; *) printf OK ;; esac)"
    metric PoliticaCriptografica "$politica"
    case $politica in
        LEGACY*)
            marcar_falla
            finding High 'Politica criptografica del sistema en modo LEGACY' \
                -c 'Criptografia' -a 'update-crypto-policies' \
                -d "La politica criptografica vale '$politica', lo que rehabilita algoritmos y protocolos con debilidades conocidas (TLS 1.0/1.1, SHA-1, claves RSA cortas) en todas las aplicaciones que respetan la politica del sistema." \
                -e "update-crypto-policies --show = $politica" \
                -k 'CRI-02|RED-02' \
                -r 'Volver a la politica DEFAULT (o FUTURE) y tratar las incompatibilidades de aplicaciones concretas con sub-politicas acotadas en lugar de degradar el sistema completo.' ;;
    esac
fi

if has_cmd openssl; then
    ver_ssl=$(openssl version 2>/dev/null)
    add_control 'CRI-02' 'OpenSSL' "$ver_ssl" '3.x' \
        "$(case $ver_ssl in *' 3.'*) printf OK ;; *) printf ADVERTENCIA ;; esac)"
    metric OpenSSL "$ver_ssl"
    case $ver_ssl in
        *' 1.0'*|*' 1.1'*)
            finding High 'Version de OpenSSL fuera de soporte' \
                -c 'Criptografia' -a 'openssl' \
                -d "La version instalada es '$ver_ssl'. Las ramas 1.0.x y 1.1.x ya no reciben correcciones de seguridad del proyecto upstream." \
                -e "openssl version = $ver_ssl" \
                -k 'CRI-02|SW-02|VUL-01' \
                -r 'Actualizar a OpenSSL 3.x. Si la distribucion mantiene parches retroportados sobre la rama 1.1 con soporte vigente, documentarlo como control compensatorio con evidencia del proveedor.' ;;
    esac
fi

# ---------------------------------------------------------------------------
# REG-01 Auditoria del kernel (analogo de auditpol)
# ---------------------------------------------------------------------------
auditd_activo=0
reglas_audit=0

if systemctl is-active auditd >/dev/null 2>&1 || pgrep -x auditd >/dev/null 2>&1; then
    auditd_activo=1
    if has_cmd auditctl; then
        if is_root; then
            native_capture 25 auditctl -l
            if printf '%s' "$NC_OUT" | grep -qi 'No rules'; then
                reglas_audit=0
            else
                reglas_audit=$(printf '%s\n' "$NC_OUT" | grep -c . 2>/dev/null)
            fi
        else
            gap 'auditctl -l requiere privilegios de root; no se pudo enumerar el conjunto de reglas de auditoria cargado.'
            reglas_audit=$(cat /etc/audit/rules.d/*.rules /etc/audit/audit.rules 2>/dev/null | grep -c '^-' 2>/dev/null)
        fi
    fi
    add_control 'REG-01' 'auditd' 'activo' 'activo' 'OK'
    add_control 'REG-01' 'ReglasAuditoria' "$reglas_audit" '> 20 (linea base CIS)' \
        "$(if [ "${reglas_audit:-0}" -gt 20 ]; then printf OK; else printf ADVERTENCIA; fi)"
else
    add_control 'REG-01' 'auditd' 'inactivo o ausente' 'activo' 'FALLA'
    marcar_falla
fi

metric AuditdActivo "$auditd_activo" b
metric ReglasAuditoria "${reglas_audit:-0}" n

if [ "$auditd_activo" -eq 0 ]; then
    finding High 'Subsistema de auditoria del kernel (auditd) inactivo' \
        -c 'Registro' -a 'auditd' \
        -d 'auditd no esta en ejecucion. Sin el no se registran los eventos de seguridad a nivel de llamada al sistema: accesos a archivos sensibles, ejecucion de binarios privilegiados, cambios de identidad ni modificaciones de configuracion. Es la fuente de evidencia equivalente al registro de seguridad de Windows.' \
        -k 'REG-01|REG-02' \
        -r 'Instalar y habilitar auditd con arranque automatico, y cargar un conjunto de reglas basado en una linea base reconocida (CIS Benchmark o las reglas de referencia de la distribucion).'
elif [ "${reglas_audit:-0}" -le 20 ]; then
    finding Medium 'Cobertura insuficiente de las reglas de auditoria' \
        -c 'Registro' -a 'auditd' \
        -d "auditd esta activo pero solo tiene $reglas_audit reglas cargadas. Un conjunto tan reducido no cubre los eventos minimos exigibles (identidad, permisos, montajes, ejecucion privilegiada, acceso a /etc/shadow), por lo que eventos relevantes de seguridad no se estan registrando." \
        -e "auditctl -l => $reglas_audit reglas" \
        -k 'REG-01|REG-02' \
        -r 'Aplicar una linea base de auditoria (referencia CIS) que cubra autenticacion, gestion de cuentas, cambios de configuracion, montaje de sistemas de archivos y ejecucion de binarios privilegiados.'
fi

# Trazabilidad de la ejecucion de comandos: analogo de ScriptBlockLogging.
ejecucion_auditada=0
if [ "$auditd_activo" -eq 1 ]; then
    if is_root && printf '%s' "$NC_OUT" | grep -q 'execve'; then
        ejecucion_auditada=1
    elif cat /etc/audit/rules.d/*.rules /etc/audit/audit.rules 2>/dev/null | grep -q 'execve'; then
        ejecucion_auditada=1
    fi
fi
add_control 'REG-01' 'RegistroDeEjecucion' \
    "$(if [ "$ejecucion_auditada" -eq 1 ]; then printf 'auditd registra execve'; else printf 'No se registra la ejecucion de comandos'; fi)" \
    'Reglas execve activas' \
    "$(if [ "$ejecucion_auditada" -eq 1 ]; then printf OK; else printf ADVERTENCIA; fi)"

if [ "$ejecucion_auditada" -eq 0 ]; then
    finding Medium 'Sin registro de la ejecucion de comandos' \
        -c 'Registro' -a 'auditd / execve' \
        -d 'No hay reglas de auditoria que registren las llamadas execve. Es la principal fuente de evidencia forense sobre que se ejecuto en el servidor, quien lo ejecuto y cuando: el equivalente del registro de bloques de script de PowerShell.' \
        -k 'REG-01|REG-02|SW-05' \
        -r 'Anadir reglas de auditoria sobre execve (por ejemplo, -a always,exit -F arch=b64 -S execve -k exec) y remitir el registro a la plataforma central. Como alternativa o complemento, desplegar un agente de telemetria de procesos.'
fi

metric ControlesEvaluados "$(rec_count)" n
metric ControlesEnFalla "$controles_falla" n

emit_result
