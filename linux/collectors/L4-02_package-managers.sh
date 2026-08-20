#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# L4-02_package-managers.sh
# Capa L4 - ARTEFACTOS DE SOFTWARE.
#
# Inventario de software instalado FUERA del gestor de paquetes de la
# distribucion: gestores de lenguaje y de desarrollador. Es el punto ciego
# clasico de las auditorias de inventario: paquetes con capacidad de ejecucion
# arbitraria que ningun agente de inventario tradicional reporta.
#
# Criterios de auditoria -> INV-01, SW-03, SW-04, ARQ-03
#
# EQUIVALENCIAS respecto de L4-02_Package-Managers.ps1:
#   winget / Chocolatey / Scoop -> snap, flatpak (ya inventariados en L4-01)
#   npm global                  -> npm ls -g
#   pip                         -> pip list
#   dotnet tool                 -> dotnet tool list --global
#   Modulos de PowerShell       -> gems de Ruby, modulos de Perl, crates, go
#   Get-PSRepository            -> repositorios APT/YUM/Zypper de terceros y su
#                                  verificacion de firma GPG (cadena de suministro)
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/audit_core.sh"

collector_init 'L4-02' 'Software gestionado por gestores de paquetes de lenguaje' 'L4' \
    'INV-01|SW-03|SW-04|ARQ-03' false \
    'npm global, pip, gem, cpan, cargo, go install, dotnet tool, snap, flatpak y repositorios de terceros.'
maybe_emit_manifest "${1:-}"

add_paquete() {
    rec Gestor "$1" Nombre "$(safe_str "$2" 200)" Version "$(safe_str "$3" 64)" \
        Ambito "${4:-Maquina}" Ruta "$(safe_str "${5:-}" 400)" Notas "$(safe_str "${6:-}" 300)"
}

gestores=''
registrar_gestor() {
    case " $gestores " in *" $1 "*) ;; *) gestores="$gestores $1" ;; esac
}

paquetes_usuario=0

# ---------------------------------------------------------------------------
# npm global
# ---------------------------------------------------------------------------
if has_cmd npm; then
    registrar_gestor 'npm'
    native_capture 120 npm ls -g --depth=0 --json
    if [ -n "$NC_OUT" ]; then
        raiz=$(printf '%s' "$NC_OUT" | jq -r '.path // ""' 2>/dev/null)
        printf '%s' "$NC_OUT" |
            jq -r '.dependencies // {} | to_entries[] | [.key, (.value.version // "")] | @tsv' 2>/dev/null |
        while IFS=$'\t' read -r nombre version; do
            [ -n "$nombre" ] || continue
            add_paquete 'npm (global)' "$nombre" "$version" 'Maquina' "$raiz"
        done
    else
        gap 'npm esta presente pero "npm ls -g --json" no devolvio inventario.'
    fi
fi

# ---------------------------------------------------------------------------
# pip (Python)
# ---------------------------------------------------------------------------
for pipexe in pip3 pip; do
    has_cmd "$pipexe" || continue
    registrar_gestor 'pip'
    native_capture 120 "$pipexe" list --format=json --disable-pip-version-check
    if [ -n "$NC_OUT" ]; then
        printf '%s' "$NC_OUT" |
            jq -r '.[]? | [.name, .version] | @tsv' 2>/dev/null |
        while IFS=$'\t' read -r nombre version; do
            [ -n "$nombre" ] || continue
            add_paquete "pip ($pipexe)" "$nombre" "$version" 'Maquina'
        done
    fi
    break
done

# Entornos virtuales de Python fuera del control del gestor de paquetes
for venv in /opt/*/bin/activate /srv/*/bin/activate /home/*/*/bin/activate /var/www/*/bin/activate; do
    [ -f "$venv" ] || continue
    base=$(dirname "$(dirname "$venv")")
    registrar_gestor 'venv'
    add_paquete 'Python venv' "$(basename "$base")" '' 'Maquina' "$base" \
        'Entorno virtual: sus dependencias no aparecen en el inventario del sistema'
done

# ---------------------------------------------------------------------------
# gem (Ruby)
# ---------------------------------------------------------------------------
if has_cmd gem; then
    registrar_gestor 'gem'
    native_capture 90 gem list --local --no-versions
    if [ -n "$NC_OUT" ]; then
        while read -r nombre; do
            [ -n "$nombre" ] || continue
            case $nombre in \**|'') continue ;; esac
            add_paquete 'gem' "$nombre" '' 'Maquina'
        done <<< "$NC_OUT"
    fi
fi

# ---------------------------------------------------------------------------
# cargo (Rust) y go install: binarios instalados en el perfil del usuario
# ---------------------------------------------------------------------------
for cargo_bin in /root/.cargo/bin /home/*/.cargo/bin; do
    [ -d "$cargo_bin" ] || continue
    registrar_gestor 'cargo'
    for b in "$cargo_bin"/*; do
        [ -f "$b" ] && [ -x "$b" ] || continue
        case $(basename "$b") in cargo|rustc|rustup|rustdoc|rust-gdb|rust-lldb) continue ;; esac
        ambito='Usuario'; [ "${cargo_bin#/root}" != "$cargo_bin" ] && ambito='Root'
        add_paquete 'cargo' "$(basename "$b")" '' "$ambito" "$b"
        [ "$ambito" = 'Usuario' ] && paquetes_usuario=$((paquetes_usuario + 1))
    done
done

for go_bin in /root/go/bin /home/*/go/bin /usr/local/go/bin; do
    [ -d "$go_bin" ] || continue
    registrar_gestor 'go install'
    for b in "$go_bin"/*; do
        [ -f "$b" ] && [ -x "$b" ] || continue
        case $(basename "$b") in go|gofmt) continue ;; esac
        ambito='Usuario'; case $go_bin in /root/*|/usr/*) ambito='Maquina' ;; esac
        add_paquete 'go install' "$(basename "$b")" '' "$ambito" "$b"
        [ "$ambito" = 'Usuario' ] && paquetes_usuario=$((paquetes_usuario + 1))
    done
done

# ---------------------------------------------------------------------------
# dotnet tool
# ---------------------------------------------------------------------------
if has_cmd dotnet; then
    native_capture 60 dotnet tool list --global
    if [ -n "$NC_OUT" ]; then
        # Se descarta el encabezado y la linea de guiones
        printf '%s\n' "$NC_OUT" | awk 'NR>2 && NF>=2 {print $1"\t"$2}' |
        while IFS=$'\t' read -r nombre version; do
            [ -n "$nombre" ] || continue
            registrar_gestor 'dotnet tool'
            add_paquete 'dotnet tool' "$nombre" "$version" 'Maquina'
        done
    fi
fi

# ---------------------------------------------------------------------------
# snap y flatpak (inventariados tambien en L4-01; aqui interesa el mecanismo)
# ---------------------------------------------------------------------------
if has_cmd snap; then
    registrar_gestor 'snap'
    snap list 2>/dev/null | tail -n +2 | while read -r nombre version rev tracking publisher resto; do
        [ -n "$nombre" ] || continue
        add_paquete 'snap' "$nombre" "$version" 'Maquina' "/snap/$nombre/current" \
            "Canal: $tracking | Publicador: $publisher | Revision: $rev"
    done
fi

if has_cmd flatpak; then
    registrar_gestor 'flatpak'
    flatpak list --columns=application,version,origin,installation 2>/dev/null |
    while IFS=$'\t' read -r app version origen instalacion; do
        [ -n "$app" ] || continue
        ambito='Maquina'
        [ "$instalacion" = 'user' ] && { ambito='Usuario'; paquetes_usuario=$((paquetes_usuario + 1)); }
        add_paquete 'flatpak' "$app" "$version" "$ambito" '' "Origen: $origen"
    done
    # El conteo dentro del pipe se pierde: se recalcula sobre el archivo
    paquetes_usuario=$(grep -c '"Ambito":"Usuario"' "$COL_RECORDS" 2>/dev/null || printf 0)
fi

# ---------------------------------------------------------------------------
# Repositorios de terceros y verificacion de firma (SW-04)
# ---------------------------------------------------------------------------
#
# Analogo de Get-PSRepository: un repositorio ajeno a la distribucion, o uno
# configurado sin verificacion de firma GPG, es el vector directo de cadena de
# suministro.

oficiales=$(cfg_json '.RepositoriosOficiales' | jq -r '.[]?' 2>/dev/null)
es_oficial() {
    local host=$1 o
    [ -n "$host" ] || return 1
    while IFS= read -r o; do
        [ -z "$o" ] && continue
        case $host in *"$o"*) return 0 ;; esac
    done <<< "$oficiales"
    return 1
}

repos_terceros=''
repos_sin_firma=''

case $(detect_pkg_family) in
    deb)
        # sources.list clasico y formato deb822
        for f in /etc/apt/sources.list /etc/apt/sources.list.d/*; do
            [ -r "$f" ] || continue
            while read -r linea; do
                case $linea in
                    deb\ *|deb-src\ *|URIs:*) ;;
                    *) continue ;;
                esac
                url=$(printf '%s' "$linea" | grep -oE 'https?://[^ ]+' | head -1)
                [ -n "$url" ] || continue
                host=$(printf '%s' "$url" | sed -E 's|https?://||; s|/.*||; s|.*@||')

                # [trusted=yes] desactiva la verificacion de firma del repositorio
                sin_firma=''
                case $linea in *trusted=yes*) sin_firma='trusted=yes' ;; esac

                if es_oficial "$host"; then
                    add_paquete 'Repositorio APT' "$host" '' 'Maquina' "$f" 'Repositorio oficial de la distribucion'
                else
                    repos_terceros="$repos_terceros $host"
                    add_paquete 'Repositorio APT' "$host" '' 'Maquina' "$f" \
                        "TERCERO${sin_firma:+ | SIN VERIFICACION DE FIRMA ($sin_firma)}"
                fi
                [ -n "$sin_firma" ] && repos_sin_firma="$repos_sin_firma $host($f)"
            done < "$f"
        done
        ;;
    rpm)
        for f in /etc/yum.repos.d/*.repo /etc/zypp/repos.d/*.repo; do
            [ -r "$f" ] || continue
            awk -F= '
                /^\[/       { repo=$0; gsub(/[\[\]]/,"",repo); gpg=""; url="" }
                /^gpgcheck/ { gsub(/ /,"",$2); gpg=$2 }
                /^(baseurl|mirrorlist|metalink)/ { url=$2 }
                /^$/        { if (repo!="") { print repo"\t"url"\t"gpg; repo="" } }
                END         { if (repo!="") print repo"\t"url"\t"gpg }
            ' "$f" |
            while IFS=$'\t' read -r repo url gpg; do
                [ -n "$repo" ] || continue
                host=$(printf '%s' "$url" | sed -E 's|https?://||; s|/.*||')
                sin_firma=''
                [ "$gpg" = '0' ] && sin_firma='gpgcheck=0'
                if es_oficial "$host"; then
                    add_paquete 'Repositorio RPM' "$repo" '' 'Maquina' "$f" 'Repositorio oficial de la distribucion'
                else
                    add_paquete 'Repositorio RPM' "$repo" '' 'Maquina' "$f" \
                        "TERCERO ($host)${sin_firma:+ | SIN VERIFICACION DE FIRMA}"
                fi
            done
            # Repos sin gpgcheck: se detectan aparte para el hallazgo
            if grep -qE '^gpgcheck[[:space:]]*=[[:space:]]*0' "$f" 2>/dev/null; then
                repos_sin_firma="$repos_sin_firma $(basename "$f")"
            fi
            hosts=$(grep -oE '^(baseurl|mirrorlist|metalink)=https?://[^/ ]+' "$f" 2>/dev/null |
                    sed -E 's|.*https?://||' | sort -u)
            for h in $hosts; do
                es_oficial "$h" || repos_terceros="$repos_terceros $h"
            done
        done
        ;;
    apk)
        if [ -r /etc/apk/repositories ]; then
            while read -r url; do
                [ -n "$url" ] || continue
                case $url in \#*) continue ;; esac
                host=$(printf '%s' "$url" | sed -E 's|https?://||; s|/.*||')
                if es_oficial "$host"; then
                    add_paquete 'Repositorio APK' "$host" '' 'Maquina' '/etc/apk/repositories' 'Repositorio oficial'
                else
                    repos_terceros="$repos_terceros $host"
                    add_paquete 'Repositorio APK' "$host" '' 'Maquina' '/etc/apk/repositories' 'TERCERO'
                fi
            done < /etc/apk/repositories
        fi
        ;;
esac

repos_terceros=$(printf '%s' "$repos_terceros" | tr ' ' '\n' | sort -u | grep -c . 2>/dev/null)
metric RepositoriosTerceros "${repos_terceros:-0}" n

if [ -n "$repos_sin_firma" ]; then
    finding High 'Repositorios de paquetes sin verificacion de firma' \
        -c 'CadenaDeSuministro' -a "$(safe_str "$repos_sin_firma" 300)" \
        -d "Se detectaron repositorios configurados sin verificacion criptografica de firma (gpgcheck=0 o trusted=yes). Todo paquete obtenido de esas fuentes se instala sin comprobar su autenticidad ni su integridad: es el vector directo de un ataque de cadena de suministro o de un intermediario en la red." \
        -e "$(safe_str "$repos_sin_firma" 800)" \
        -k 'SW-04|SW-03|SW-01' \
        -r 'Habilitar la verificacion de firma en todos los repositorios (gpgcheck=1, retirar trusted=yes) e importar la clave publica del proveedor por un canal verificado. Un repositorio que no puede firmarse no debe usarse en produccion.'
fi

if [ "${repos_terceros:-0}" -gt 0 ]; then
    finding Medium 'Repositorios de paquetes ajenos a la distribucion' \
        -c 'CadenaDeSuministro' -a "$repos_terceros repositorios" \
        -d "El servidor obtiene software de $repos_terceros repositorios que no pertenecen a la distribucion base. Cada uno amplia la superficie de confianza: un compromiso del proveedor se traduce en ejecucion de codigo con privilegios de root en este activo." \
        -k 'SW-04|SW-03' \
        -r 'Validar la titularidad de cada repositorio, replicarlo en un espejo interno controlado por la organizacion y fijar versiones (pinning) para que una actualizacion del proveedor no entre sin revision.'
fi

# ---------------------------------------------------------------------------
# Evaluacion transversal
# ---------------------------------------------------------------------------
metric GestoresDetectados "$(safe_str "$gestores" 300)"
metric TotalPaquetes "$(rec_count)" n

# Gestores de desarrollador en un servidor de produccion (ARQ-03 / SW-04)
gestores_dev=''
for g in npm pip gem cargo 'go install' 'dotnet tool' venv; do
    case " $gestores " in *" $g "*) gestores_dev="$gestores_dev $g" ;; esac
done
if [ -n "$gestores_dev" ]; then
    finding Medium 'Gestores de paquetes de lenguaje presentes en el servidor' \
        -c 'Segregacion' -a "$(safe_str "$gestores_dev" 200)" \
        -d "Se detectaron los siguientes gestores:$gestores_dev. Permiten instalar codigo ejecutable desde repositorios publicos sin pasar por el control de instalacion de software de la organizacion, y sus paquetes NO aparecen en el inventario de dpkg/rpm, por lo que quedan fuera del parcheo del sistema y de los escaneos de vulnerabilidades basados en el gestor nativo." \
        -e "Gestores:$gestores_dev" \
        -k 'SW-03|ARQ-03|SW-04' \
        -r 'Restringir el uso de estos gestores en produccion, o configurarlos contra un feed interno espejado (Artifactory/Nexus) y sumar sus paquetes al inventario formal de activos de software con seguimiento de vulnerabilidades propio.'
fi

if [ "${paquetes_usuario:-0}" -gt 0 ]; then
    finding Medium 'Software instalado en el perfil de usuario' \
        -c 'ControlDeInstalacion' -a "$paquetes_usuario paquetes" \
        -d "$paquetes_usuario paquetes residen en el perfil de un usuario. Este tipo de instalacion no requiere privilegios de root y suele quedar fuera del inventario, del parcheo y del alcance de los controles corporativos." \
        -k 'SW-03|INV-01' \
        -r 'Aplicar control de ejecucion que impida ejecutar binarios desde directorios escribibles por el usuario (montar /home y /tmp con noexec donde sea viable, o politica SELinux/AppArmor), e incorporar estos artefactos al inventario.'
fi

if [ "$(rec_count)" -eq 0 ]; then
    rec Gestor '(ninguno)' Nombre 'Sin gestores de paquetes de lenguaje detectados' Version '' \
        Ambito '' Ruta '' \
        Notas 'Resultado favorable: reduce la superficie de instalacion no controlada.'
fi

emit_result
