#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# L1-01_hardware-inventory.sh
# Capa L1 - Infraestructura fisica y hardware.
# Criterios de auditoria -> INV-01, CRI-01, DAT-03, ARQ-01
#
# EQUIVALENCIAS respecto de L1-01_Hardware-Inventory.ps1:
#   Win32_ComputerSystem   -> /sys/class/dmi/id/*, /proc/cpuinfo, /proc/meminfo
#   Win32_BIOS             -> /sys/class/dmi/id/bios_{vendor,version,date}
#   Win32_SystemEnclosure  -> /sys/class/dmi/id/chassis_type
#   Win32_Processor        -> lscpu / /proc/cpuinfo
#   Win32_PhysicalMemory   -> dmidecode -t memory (requiere root)
#   Win32_DiskDrive        -> lsblk -d / /sys/block/*
#   Win32_LogicalDisk      -> findmnt / df
#   Win32_NetworkAdapter   -> ip link / /sys/class/net/*
#   PartOfDomain           -> pertenencia a directorio central (realm/sssd/winbind)
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/audit_core.sh"

collector_init 'L1-01' 'Inventario de hardware y plataforma fisica' 'L1' \
    'INV-01|CRI-01|DAT-03|ARQ-01' false \
    'Chasis, CPU, memoria, discos, firmware y deteccion de virtualizacion.'
maybe_emit_manifest "${1:-}"

dmi() {
    local campo=$1 f="/sys/class/dmi/id/$campo"
    [ -r "$f" ] && tr -d '\000' < "$f" 2>/dev/null | head -1
}

# --- Sistema / chasis -------------------------------------------------------
#
# El mapa de tipos de chasis proviene de la especificacion SMBIOS, la misma
# tabla que Win32_SystemEnclosure.ChassisTypes expone en Windows.
chassis_nombre() {
    case "${1:-}" in
        1) printf 'Otro' ;;                2) printf 'Desconocido' ;;
        3) printf 'Escritorio' ;;          4) printf 'Escritorio bajo' ;;
        5) printf 'Pizza box' ;;           6) printf 'Mini torre' ;;
        7) printf 'Torre' ;;               8) printf 'Portatil' ;;
        9) printf 'Laptop' ;;              10) printf 'Notebook' ;;
        11) printf 'Handheld' ;;           12) printf 'Docking' ;;
        13) printf 'All in one' ;;         14) printf 'Sub notebook' ;;
        15) printf 'Space saving' ;;       16) printf 'Lunch box' ;;
        17) printf 'Chasis de servidor principal' ;;
        23) printf 'Rack Mount Chassis' ;; 24) printf 'Sealed-case PC' ;;
        28) printf 'Blade' ;;              29) printf 'Blade Enclosure' ;;
        *) printf 'Desconocido' ;;
    esac
}

fabricante=$(dmi sys_vendor)
modelo=$(dmi product_name)
serie=$(dmi product_serial)
bios_ver=$(dmi bios_version)
bios_fecha=$(dmi bios_date)
bios_vendor=$(dmi bios_vendor)
chasis=$(chassis_nombre "$(dmi chassis_type)")

# Deteccion de virtualizacion. systemd-detect-virt es la fuente autoritativa;
# si no existe se infiere del vendor DMI y del flag hypervisor de la CPU.
virt='Fisico'
if has_cmd systemd-detect-virt; then
    v=$(systemd-detect-virt 2>/dev/null)
    case $v in
        none|'') virt='Fisico' ;;
        vmware) virt='VMware' ;;
        microsoft) virt='Hyper-V' ;;
        kvm|qemu) virt='KVM/QEMU' ;;
        xen) virt='Xen' ;;
        oracle) virt='VirtualBox' ;;
        amazon) virt='AWS EC2' ;;
        docker|lxc|lxc-libvirt|podman|systemd-nspawn) virt="Contenedor ($v)" ;;
        *) virt=$v ;;
    esac
else
    sujeto="$fabricante $modelo"
    case ${sujeto,,} in
        *vmware*)     virt='VMware' ;;
        *microsoft*virtual*|*hyper-v*) virt='Hyper-V' ;;
        *kvm*|*qemu*) virt='KVM/QEMU' ;;
        *xen*)        virt='Xen' ;;
        *virtualbox*|*innotek*) virt='VirtualBox' ;;
        *amazon*ec2*) virt='AWS EC2' ;;
        *google*)     virt='Google Cloud' ;;
        *)  grep -qm1 '^flags.*\bhypervisor\b' /proc/cpuinfo 2>/dev/null && virt='Virtualizado (hipervisor no identificado)' ;;
    esac
fi

cpus_logicos=$(nproc --all 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null || printf 0)
sockets=$(lscpu 2>/dev/null | awk -F: '/^Socket\(s\)/{gsub(/ /,"",$2); print $2}')
[ -n "$sockets" ] || sockets=1
mem_kb=$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null)
mem_gb=$(awk -v k="${mem_kb:-0}" 'BEGIN{printf "%.2f", k/1048576}')

# Pertenencia a un directorio centralizado. Es el analogo de PartOfDomain:
# determina si el activo recibe politica y credenciales de forma central.
dominio=''
en_directorio=0
if has_cmd realm && realm list >/dev/null 2>&1 && [ -n "$(realm list 2>/dev/null)" ]; then
    dominio=$(realm list 2>/dev/null | awk '/^[a-zA-Z]/{print $1; exit}')
    en_directorio=1
elif [ -f /etc/sssd/sssd.conf ] && systemctl is-active sssd >/dev/null 2>&1; then
    dominio=$(awk -F= '/^\s*domains\s*=/{gsub(/ /,"",$2); print $2; exit}' /etc/sssd/sssd.conf 2>/dev/null)
    en_directorio=1
elif has_cmd wbinfo && wbinfo --own-domain >/dev/null 2>&1; then
    dominio=$(wbinfo --own-domain 2>/dev/null)
    en_directorio=1
fi
[ -n "$dominio" ] || dominio=$(hostname -d 2>/dev/null)

rec Tipo 'Sistema' \
    Nombre "$AUDIT_HOSTNAME" \
    Dominio "$dominio" \
    Fabricante "$fabricante" \
    Modelo "$modelo" \
    TipoChasis "$chasis" \
    Virtualizacion "$virt" \
    NumeroSerie "$serie" \
    BiosVersion "$(safe_str "$bios_vendor $bios_ver" 200)" \
    BiosFecha "$bios_fecha" \
    ProcesadoresFisicos:n "$sockets" \
    ProcesadoresLogicos:n "$cpus_logicos" \
    MemoriaTotalGB:n "$mem_gb" \
    Kernel "$(uname -r 2>/dev/null)" \
    Arquitectura "$(uname -m 2>/dev/null)" \
    EnDirectorioCentral:b "$en_directorio"

metric Virtualizacion "$virt"
metric MemoriaTotalGB "$mem_gb" n
metric CPULogicos "$cpus_logicos" n

# --- Firmware antiguo (VUL-01 / ARQ-01) ------------------------------------
# Solo aplica a hardware fisico: en una VM la fecha de BIOS es la del hipervisor
# y no representa un riesgo de firmware sin parchear del activo.
if [ -n "$bios_fecha" ] && [ "$virt" = 'Fisico' ]; then
    dias_bios=$(days_since "$bios_fecha")
    if [ -n "$dias_bios" ] && [ "$dias_bios" -gt 1460 ] 2>/dev/null; then
        finding Medium 'Firmware BIOS/UEFI con antiguedad superior a 4 anios' \
            -c 'Firmware' -a "$fabricante $modelo" \
            -d "Fecha de version del firmware: $bios_fecha ($dias_bios dias). El firmware desactualizado puede contener vulnerabilidades sin corregir." \
            -e "BIOSVersion=$bios_vendor $bios_ver" \
            -k 'VUL-01|ARQ-01' \
            -r 'Revisar el catalogo de firmware del fabricante e incorporar el firmware al ciclo formal de gestion de parches.'
    fi
else
    [ -n "$bios_fecha" ] || gap 'No se pudo leer la fecha de firmware desde /sys/class/dmi/id/bios_date (habitual en contenedores y en algunos hipervisores).'
fi

if [ "$en_directorio" -eq 0 ]; then
    finding Low 'Servidor fuera de un directorio centralizado' \
        -c 'Gobierno' -a "$AUDIT_HOSTNAME" \
        -d 'El equipo no esta integrado a un directorio central (Active Directory via realm/SSSD/winbind, o LDAP). No recibe politica de identidad ni de configuracion centralizada, y la gestion de cuentas queda enteramente local.' \
        -k 'ARQ-01|ACC-04' \
        -r 'Confirmar si el aislamiento es intencional. De no serlo, integrar al directorio o aplicar una linea base local equivalente y auditable (por ejemplo, gestion por Ansible/Puppet con estado versionado).'
fi

# --- Procesadores -----------------------------------------------------------
if has_cmd lscpu; then
    modelo_cpu=$(lscpu 2>/dev/null | awk -F: '/^Model name/{sub(/^[ \t]+/,"",$2); print $2; exit}')
    vendor_cpu=$(lscpu 2>/dev/null | awk -F: '/^Vendor ID/{gsub(/ /,"",$2); print $2; exit}')
    nucleos=$(lscpu 2>/dev/null | awk -F: '/^Core\(s\) per socket/{gsub(/ /,"",$2); print $2; exit}')
    mhz=$(lscpu 2>/dev/null | awk -F: '/^CPU max MHz/{gsub(/ /,"",$2); print $2; exit}')
    [ -n "$mhz" ] || mhz=$(lscpu 2>/dev/null | awk -F: '/^CPU MHz/{gsub(/ /,"",$2); print $2; exit}')
    [ -n "$mhz" ] || mhz=$(awk -F: '/^cpu MHz/{gsub(/ /,"",$2); print $2; exit}' /proc/cpuinfo 2>/dev/null)
    bits=$(lscpu 2>/dev/null | awk -F: '/^Architecture/{gsub(/ /,"",$2); print $2; exit}')
    virt_fw=$(lscpu 2>/dev/null | awk -F: '/^Virtualization:/{gsub(/ /,"",$2); print $2; exit}')

    rec Tipo 'CPU' \
        Nombre "$(safe_str "$modelo_cpu" 200)" \
        Fabricante "$vendor_cpu" \
        Nucleos:n "$(( ${nucleos:-1} * ${sockets:-1} ))" \
        HilosLogicos:n "$cpus_logicos" \
        VelocidadMaxMHz:n "$(round "${mhz:-0}" 0)" \
        Arquitectura "$bits" \
        SocketDesignation "$sockets socket(s)" \
        VirtualizacionFirmware "$virt_fw"
else
    gap 'lscpu no disponible: el detalle de procesador se limita a /proc/cpuinfo.'
fi

# --- Memoria fisica ---------------------------------------------------------
# dmidecode requiere privilegios: sin ellos no hay forma de enumerar los modulos
# fisicos. Se registra como brecha explicita, igual que Win32_PhysicalMemory
# degradaba en maquinas virtuales.
if has_cmd dmidecode && is_root; then
    dmidecode -t memory 2>/dev/null | awk '
        /^Memory Device/ { in_dev=1; loc=""; size=""; speed=""; manu=""; part=""; serial=""; next }
        in_dev && /^\t(Locator|Size|Speed|Manufacturer|Part Number|Serial Number):/ {
            split($0, kv, ": "); key=kv[1]; val=kv[2]
            gsub(/^\t/, "", key)
            if (key == "Locator")        loc = val
            else if (key == "Size")      size = val
            else if (key == "Speed")     speed = val
            else if (key == "Manufacturer") manu = val
            else if (key == "Part Number")  part = val
            else if (key == "Serial Number") serial = val
        }
        in_dev && /^$/ {
            if (size != "" && size !~ /No Module Installed/)
                printf "%s\t%s\t%s\t%s\t%s\t%s\n", loc, size, speed, manu, part, serial
            in_dev=0
        }
    ' | while IFS=$'\t' read -r loc size speed manu part serial; do
        gb=0
        case $size in
            *GB) gb=${size% GB} ;;
            *MB) gb=$(awk -v m="${size% MB}" 'BEGIN{printf "%.2f", m/1024}') ;;
        esac
        rec Tipo 'Memoria' Nombre "$loc" CapacidadGB:n "$gb" \
            VelocidadMHz "$speed" Fabricante "$(safe_str "$manu" 80)" \
            NumeroParte "$(safe_str "$part" 80)" NumeroSerie "$(safe_str "$serial" 80)"
    done
else
    if is_root; then
        gap 'dmidecode no esta instalado; no fue posible enumerar los modulos de memoria fisica.'
    else
        gap 'La enumeracion de modulos de memoria fisica (dmidecode) requiere privilegios de root.'
    fi
fi

# --- Discos fisicos y volumenes --------------------------------------------
if has_cmd lsblk; then
    # -d: solo dispositivos raiz; -b: bytes; -n: sin encabezado; -P: pares clave=valor
    lsblk -dnb -o NAME,MODEL,SIZE,ROTA,RM,TRAN,SERIAL,TYPE 2>/dev/null |
    while read -r nombre modelo_d tam rota rm tran serial tipo; do
        [ "$tipo" = 'disk' ] || [ -z "$tipo" ] || continue
        [ -n "$nombre" ] || continue
        gb=$(awk -v b="${tam:-0}" 'BEGIN{printf "%.2f", b/1073741824}')
        medio='Fijo'
        [ "${rm:-0}" = '1' ] && medio='Extraible'
        clase='HDD'; [ "${rota:-1}" = '0' ] && clase='SSD/NVMe'
        parts=$(lsblk -ln -o NAME "/dev/$nombre" 2>/dev/null | tail -n +2 | wc -l)

        rec Tipo 'DiscoFisico' Nombre "$(safe_str "$modelo_d" 120)" \
            Dispositivo "/dev/$nombre" Interfaz "${tran:-desconocida}" \
            TamanoGB:n "$gb" Particiones:n "${parts:-0}" \
            NumeroSerie "$(safe_str "$serial" 80)" MediaType "$medio / $clase"

        # Medio extraible conectado -> DAT-03
        if [ "$medio" = 'Extraible' ]; then
            finding Medium 'Medio de almacenamiento extraible conectado al servidor' \
                -c 'Medios' -a "/dev/$nombre $(safe_str "$modelo_d" 80)" \
                -d 'Se detecto una unidad extraible conectada al activo. En servidores de produccion representa un canal de fuga de informacion o de introduccion de codigo no autorizado.' \
                -e "Dispositivo=/dev/$nombre Tamano=${gb}GB Transporte=${tran:-n/d}" \
                -k 'DAT-03|DAT-02' \
                -r 'Retirar el medio si no responde a una necesidad operativa aprobada y evaluar el bloqueo de dispositivos de almacenamiento USB mediante reglas udev o el modulo USBGuard.'
        fi
    done
else
    gap 'lsblk no disponible: no fue posible inventariar los discos fisicos.'
fi

# --- Volumenes montados -----------------------------------------------------
# Se excluyen los pseudo-sistemas de archivos (proc, sys, tmpfs, overlay...):
# el equivalente del filtro DriveType=3 de Win32_LogicalDisk.
df -PT 2>/dev/null | tail -n +2 |
while read -r disp fstipo bloques usado libre pctusado punto; do
    case $fstipo in
        proc|sysfs|devtmpfs|devpts|tmpfs|squashfs|overlay|cgroup*|securityfs|pstore|debugfs|tracefs|configfs|fusectl|bpf|autofs|mqueue|hugetlbfs|binfmt_misc|nsfs|ramfs)
            continue ;;
    esac
    [ "${bloques:-0}" -gt 0 ] 2>/dev/null || continue

    total_gb=$(awk -v k="$bloques" 'BEGIN{printf "%.2f", k/1048576}')
    libre_gb=$(awk -v k="$libre"   'BEGIN{printf "%.2f", k/1048576}')
    pct_libre=$(pct "$libre" "$bloques")

    rec Tipo 'Volumen' Nombre "$punto" Dispositivo "$disp" \
        SistemaArchivos "$fstipo" TotalGB:n "$total_gb" LibreGB:n "$libre_gb" \
        PorcentajeLibre:n "$pct_libre"

    # Sistemas de archivos sin soporte de permisos POSIX ni ACL. Es el analogo
    # directo del hallazgo "volumen no NTFS" de la version Windows.
    case $fstipo in
        vfat|msdos|exfat|ntfs|ntfs3|iso9660|udf)
            finding Medium 'Volumen con sistema de archivos sin control de acceso' \
                -c 'Almacenamiento' -a "$punto ($disp)" \
                -d "El volumen usa $fstipo, que no soporta permisos POSIX ni listas de control de acceso (ACL), por lo que no es posible restringir el acceso a la informacion que aloja." \
                -e "Dispositivo=$disp Punto=$punto Tipo=$fstipo" \
                -k 'ACC-04' \
                -r 'Migrar el volumen a ext4/XFS/Btrfs o justificar formalmente su uso si almacena unicamente datos publicos.' ;;
    esac
done

# --- Adaptadores de red (inventario; la evaluacion va en L7) ---------------
if has_cmd ip; then
    for iface_path in /sys/class/net/*; do
        [ -d "$iface_path" ] || continue
        iface=$(basename "$iface_path")
        [ "$iface" = 'lo' ] && continue
        # Solo adaptadores fisicos: el enlace 'device' existe unicamente para
        # interfaces respaldadas por hardware (equivale a PhysicalAdapter=True).
        [ -e "$iface_path/device" ] || continue

        mac=$(cat "$iface_path/address" 2>/dev/null)
        estado=$(cat "$iface_path/operstate" 2>/dev/null)
        vel=$(cat "$iface_path/speed" 2>/dev/null)
        case $vel in ''|-1|*[!0-9-]*) vel=0 ;; esac

        rec Tipo 'AdaptadorRed' Nombre "$iface" MAC "$mac" \
            Estado "$estado" VelocidadMbps:n "$vel" \
            Driver "$(basename "$(readlink -f "$iface_path/device/driver" 2>/dev/null)" 2>/dev/null)"
    done
fi

metric TotalRegistrosHW "$(rec_count)" n

emit_result
