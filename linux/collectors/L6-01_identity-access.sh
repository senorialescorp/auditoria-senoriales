#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# L6-01_identity-access.sh
# Capa L6 - Identidad y control de acceso.
# Criterios de auditoria -> ACC-01, ACC-02, ACC-03, ACC-04, ACC-05
#
# EQUIVALENCIAS respecto de L6-01_Identity-Access.ps1:
#   Get-LocalUser              -> /etc/passwd + /etc/shadow + chage
#   LastLogon                  -> lastlog / last
#   PasswordNeverExpires       -> campo max de /etc/shadow (99999 = no expira)
#   Grupo Administradores      -> sudo / wheel / admin + /etc/sudoers
#   Cuenta integrada SID -500  -> uid 0 (root) y toda cuenta con uid 0 duplicado
#   net accounts               -> /etc/login.defs + pam_pwquality + faillock
#   RDP / NLA                  -> sshd_config (PermitRootLogin, autenticacion
#                                 por contrasena, PubkeyAuthentication)
#   Remote Desktop Users       -> AllowUsers/AllowGroups de sshd
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/audit_core.sh"

collector_init 'L6-01' 'Identidades locales y control de acceso' 'L6' \
    'ACC-01|ACC-02|ACC-03|ACC-04|ACC-05' false \
    'Cuentas locales, sudoers, politica de contrasenas, claves SSH y configuracion de acceso remoto.'
maybe_emit_manifest "${1:-}"

dias_inactiva=$(cfg '.Thresholds.DiasCuentaInactiva' '90')
max_admins=$(cfg '.Thresholds.MaxAdministradoresLocales' '5')
edad_max_pwd=$(cfg '.Thresholds.EdadMaxContrasenaDias' '365')

hoy_dias=$(( $(date +%s) / 86400 ))

if ! is_root; then
    gap 'La auditoria de identidades se ejecuto sin privilegios de root: /etc/shadow no es legible, por lo que no se pudo evaluar el estado de las contrasenas (bloqueo, caducidad, antiguedad ni algoritmo de hash). La cobertura del criterio ACC-03 es PARCIAL.'
fi

# ---------------------------------------------------------------------------
# 1. Cuentas locales
# ---------------------------------------------------------------------------
#
# Se distinguen las cuentas de sistema (UID por debajo de UID_MIN) de las
# nominales: aplicar los mismos criterios a ambas generaria ruido masivo, ya que
# las de sistema no tienen contrasena ni inicio de sesion por diseno.
uid_min=$(awk '/^UID_MIN/{print $2; exit}' /etc/login.defs 2>/dev/null)
[ -n "$uid_min" ] || uid_min=1000

total_cuentas=0; nominales=0; habilitadas=0
uid0=0;          lista_uid0=''
inactivas=0;     lista_inactivas=''
nunca_usadas=0;  lista_nunca=''
sin_expiracion=0;lista_sin_exp=''
pwd_antigua=0;   lista_pwd_ant=''
sin_password=0;  lista_sin_pwd=''
shell_valido=0

while IFS=: read -r usuario _ uid gid gecos home shell; do
    [ -n "$usuario" ] || continue
    total_cuentas=$((total_cuentas + 1))

    es_sistema=1
    [ "$uid" -ge "$uid_min" ] 2>/dev/null && es_sistema=0
    [ "$uid" -eq 0 ] 2>/dev/null && es_sistema=0

    tiene_shell=0
    case $shell in
        */nologin|*/false|/bin/sync|'') ;;
        *) tiene_shell=1; shell_valido=$((shell_valido + 1)) ;;
    esac

    # --- Estado de la contrasena (requiere /etc/shadow) ---
    estado_pwd='no legible'
    edad_pwd=''
    max_pwd=''
    bloqueada='desconocido'
    algoritmo=''
    if is_root && [ -r /etc/shadow ]; then
        linea_shadow=$(awk -F: -v u="$usuario" '$1==u{print; exit}' /etc/shadow 2>/dev/null)
        if [ -n "$linea_shadow" ]; then
            hash=$(printf '%s' "$linea_shadow" | cut -d: -f2)
            ultimo_cambio=$(printf '%s' "$linea_shadow" | cut -d: -f3)
            max_pwd=$(printf '%s' "$linea_shadow" | cut -d: -f5)

            case $hash in
                '')      estado_pwd='SIN CONTRASENA'; bloqueada='no' ;;
                '!'*|'*'*) estado_pwd='bloqueada / sin acceso por contrasena'; bloqueada='si' ;;
                '$6$'*)  estado_pwd='establecida'; bloqueada='no'; algoritmo='SHA-512' ;;
                '$y$'*)  estado_pwd='establecida'; bloqueada='no'; algoritmo='yescrypt' ;;
                '$5$'*)  estado_pwd='establecida'; bloqueada='no'; algoritmo='SHA-256' ;;
                '$2'*)   estado_pwd='establecida'; bloqueada='no'; algoritmo='bcrypt' ;;
                '$1$'*)  estado_pwd='establecida'; bloqueada='no'; algoritmo='MD5 (DEBIL)' ;;
                *)       estado_pwd='establecida'; bloqueada='no'; algoritmo='formato heredado (DEBIL)' ;;
            esac

            if [ -n "$ultimo_cambio" ] && [ "$ultimo_cambio" -gt 0 ] 2>/dev/null; then
                edad_pwd=$(( hoy_dias - ultimo_cambio ))
            fi

            # Cuenta activa sin contrasena: acceso sin autenticacion
            if [ "$estado_pwd" = 'SIN CONTRASENA' ] && [ "$tiene_shell" -eq 1 ]; then
                sin_password=$((sin_password + 1))
                lista_sin_pwd="$lista_sin_pwd $usuario"
            fi

            # Contrasena que no expira (99999 es el valor por omision de "nunca")
            if [ "$es_sistema" -eq 0 ] && [ "$bloqueada" = 'no' ] && [ "$tiene_shell" -eq 1 ]; then
                if [ -z "$max_pwd" ] || [ "$max_pwd" -ge 99999 ] 2>/dev/null; then
                    sin_expiracion=$((sin_expiracion + 1))
                    lista_sin_exp="$lista_sin_exp $usuario"
                fi
                if [ -n "$edad_pwd" ] && [ "$edad_pwd" -gt "$edad_max_pwd" ] 2>/dev/null; then
                    pwd_antigua=$((pwd_antigua + 1))
                    lista_pwd_ant="$lista_pwd_ant $usuario($edad_pwd d)"
                fi
            fi
        fi
    fi

    # --- Ultimo inicio de sesion ---
    ultimo_login='Nunca'
    dias_sin_uso=''
    if has_cmd lastlog; then
        info=$(lastlog -u "$usuario" 2>/dev/null | tail -n +2)
        case $info in
            *'**Never logged in**'*|'') ultimo_login='Nunca' ;;
            *)
                fecha=$(printf '%s' "$info" | awk '{for(i=NF-4;i<=NF;i++) printf "%s ", $i}')
                ts=$(date -d "$fecha" +%s 2>/dev/null)
                if [ -n "$ts" ]; then
                    ultimo_login=$(date -d "@$ts" +%Y-%m-%d 2>/dev/null)
                    dias_sin_uso=$(( ( $(date +%s) - ts ) / 86400 ))
                fi ;;
        esac
    fi

    if [ "$es_sistema" -eq 0 ]; then
        nominales=$((nominales + 1))
        [ "$bloqueada" != 'si' ] && habilitadas=$((habilitadas + 1))

        if [ "$tiene_shell" -eq 1 ] && [ "$bloqueada" != 'si' ]; then
            if [ "$ultimo_login" = 'Nunca' ]; then
                nunca_usadas=$((nunca_usadas + 1))
                lista_nunca="$lista_nunca $usuario"
            elif [ -n "$dias_sin_uso" ] && [ "$dias_sin_uso" -gt "$dias_inactiva" ] 2>/dev/null; then
                inactivas=$((inactivas + 1))
                lista_inactivas="$lista_inactivas $usuario($dias_sin_uso d)"
            fi
        fi
    fi

    # UID 0 duplicado: cuenta con privilegios totales al margen de root
    if [ "$uid" -eq 0 ] 2>/dev/null && [ "$usuario" != 'root' ]; then
        uid0=$((uid0 + 1))
        lista_uid0="$lista_uid0 $usuario"
    fi

    rec Categoria 'CuentaLocal' \
        Nombre "$usuario" \
        UID:n "$uid" \
        GID:n "$gid" \
        Descripcion "$(safe_str "$gecos" 200)" \
        Home "$home" \
        Shell "$shell" \
        ShellInteractiva:b "$tiene_shell" \
        EsSistema:b "$es_sistema" \
        EstadoContrasena "$estado_pwd" \
        AlgoritmoHash "$algoritmo" \
        Bloqueada "$bloqueada" \
        EdadContrasenaDias:n "${edad_pwd:-0}" \
        MaxDiasContrasena "${max_pwd:-}" \
        UltimoInicioSesion "$ultimo_login" \
        DiasSinUso:n "${dias_sin_uso:-0}"

done < /etc/passwd

metric CuentasTotales "$total_cuentas" n
metric CuentasNominales "$nominales" n
metric CuentasHabilitadas "$habilitadas" n
metric CuentasConShell "$shell_valido" n

# ---------------------------------------------------------------------------
# Hallazgos sobre cuentas
# ---------------------------------------------------------------------------
if [ "$uid0" -gt 0 ]; then
    finding Critical 'Cuentas distintas de root con UID 0' \
        -c 'Identidad' -a "$(safe_str "$lista_uid0" 200)" \
        -d "Se detectaron $uid0 cuentas con UID 0 ademas de root. En Linux el privilegio se deriva del UID, no del nombre: cualquier cuenta con UID 0 es root a todos los efectos, pero pasa desapercibida en las revisiones de acceso que solo miran el grupo de administradores. Es una tecnica clasica de puerta trasera." \
        -e "Cuentas:$lista_uid0" \
        -k 'ACC-02|ACC-01' \
        -r 'Verificar el origen de cada cuenta. Si no responde a una necesidad documentada, deshabilitarla y asignarle un UID no privilegiado. Anadir la comprobacion de UID 0 duplicados al monitoreo continuo.'
fi

if [ "$sin_password" -gt 0 ]; then
    finding Critical 'Cuentas con shell interactiva y sin contrasena' \
        -c 'Autenticacion' -a "$(safe_str "$lista_sin_pwd" 200)" \
        -d "Se detectaron $sin_password cuentas con shell de inicio de sesion y campo de contrasena vacio en /etc/shadow: permiten iniciar sesion sin autenticacion alguna." \
        -e "Cuentas:$lista_sin_pwd" \
        -k 'ACC-03|ACC-01' \
        -r 'Bloquear las cuentas de inmediato (passwd -l) y establecer una contrasena conforme a la politica, o cambiar su shell a /usr/sbin/nologin si son cuentas de servicio.'
fi

if [ "$inactivas" -gt 0 ]; then
    finding Medium 'Cuentas locales habilitadas sin uso reciente' \
        -c 'Identidad' -a "$inactivas cuentas" \
        -d "Las siguientes cuentas siguen habilitadas pese a no registrar inicio de sesion en mas de $dias_inactiva dias. Las cuentas latentes amplian la superficie de ataque sin aportar valor operativo." \
        -e "$(safe_str "$lista_inactivas" 1000)" \
        -k 'ACC-01|ACC-02' \
        -r 'Ejecutar la revision periodica de derechos de acceso y deshabilitar las cuentas sin dueno o sin uso justificado (usermod -L y expiracion con chage -E).'
fi

if [ "$nunca_usadas" -gt 0 ]; then
    finding Low 'Cuentas habilitadas que nunca han iniciado sesion' \
        -c 'Identidad' -a "$(safe_str "$lista_nunca" 300)" \
        -d 'Cuentas con shell interactiva creadas y habilitadas sin uso registrado. Pueden ser cuentas de servicio mal configuradas (deberian tener nologin) o cuentas residuales de aprovisionamiento.' \
        -e "Cuentas:$lista_nunca" \
        -k 'ACC-01' \
        -r 'Clasificar cada cuenta como de servicio o nominal. A las de servicio asignarles /usr/sbin/nologin; eliminar las que no tengan proposito vigente.'
fi

if [ "$sin_expiracion" -gt 0 ]; then
    finding Medium 'Cuentas con contrasena que nunca expira' \
        -c 'Autenticacion' -a "$(safe_str "$lista_sin_exp" 300)" \
        -d 'Estas cuentas tienen la caducidad de contrasena deshabilitada (campo max en 99999 o vacio). Sin rotacion, una credencial comprometida permanece valida de forma indefinida.' \
        -e "Cuentas:$lista_sin_exp" \
        -k 'ACC-03' \
        -r 'Aplicar caducidad conforme a la politica con chage -M. Para las cuentas de servicio, sustituir la autenticacion por contrasena por claves o certificados gestionados.'
fi

if [ "$pwd_antigua" -gt 0 ]; then
    finding Medium 'Contrasenas sin rotacion por periodo prolongado' \
        -c 'Autenticacion' -a "$pwd_antigua cuentas" \
        -d "Cuentas cuya contrasena no cambia desde hace mas de $edad_max_pwd dias." \
        -e "$(safe_str "$lista_pwd_ant" 1000)" \
        -k 'ACC-03' \
        -r 'Forzar el cambio de contrasena (chage -d 0) y verificar el cumplimiento de la politica corporativa de credenciales.'
fi

# Algoritmos de hash debiles
if is_root; then
    debiles=$(grep -c '"AlgoritmoHash":"MD5 (DEBIL)"\|"AlgoritmoHash":"formato heredado (DEBIL)"' "$COL_RECORDS" 2>/dev/null || printf 0)
    if [ "${debiles:-0}" -gt 0 ]; then
        finding High 'Contrasenas almacenadas con algoritmo de hash debil' \
            -c 'Criptografia' -a "$debiles cuentas" \
            -d "$debiles cuentas conservan su contrasena cifrada con MD5 o con un formato heredado. Estos algoritmos son rapidos de calcular y permiten ataques de fuerza bruta sobre el archivo de contrasenas a un costo muy bajo. Es el analogo directo del almacenamiento de hashes LM en Windows." \
            -k 'ACC-03|CRI-02' \
            -r 'Configurar yescrypt o SHA-512 en /etc/login.defs (ENCRYPT_METHOD) y en la configuracion de PAM, y forzar el cambio de contrasena de las cuentas afectadas para que se rehashee.'
    fi
fi

# ---------------------------------------------------------------------------
# 2. Acceso privilegiado: sudo y grupos de administracion
# ---------------------------------------------------------------------------
admins=''
n_admins=0
for grupo in sudo wheel admin adm root; do
    miembros=$(getent group "$grupo" 2>/dev/null | cut -d: -f4)
    [ -n "$miembros" ] || continue
    for m in ${miembros//,/ }; do
        [ -n "$m" ] || continue
        case " $admins " in *" $m "*) continue ;; esac
        admins="$admins $m"
        n_admins=$((n_admins + 1))
        rec Categoria 'MiembroPrivilegiado' Nombre "$m" UID:n 0 GID:n 0 \
            Descripcion "Miembro del grupo $grupo" Home '' Shell '' \
            ShellInteractiva:b false EsSistema:b false EstadoContrasena '' \
            AlgoritmoHash '' Bloqueada '' EdadContrasenaDias:n 0 MaxDiasContrasena '' \
            UltimoInicioSesion '' DiasSinUso:n 0
    done
done
metric AdministradoresLocales "$n_admins" n

if [ "$n_admins" -gt "$max_admins" ]; then
    finding High 'Numero excesivo de cuentas con privilegios administrativos' \
        -c 'Privilegios' -a "$n_admins cuentas" \
        -d "Los grupos de administracion (sudo/wheel/admin) tienen $n_admins miembros; el umbral definido es $max_admins. Cada miembro representa una via de compromiso total del servidor." \
        -e "Miembros:$admins" \
        -k 'ACC-02|ACC-04' \
        -r 'Aplicar el principio de privilegio minimo: retirar de los grupos a quienes no requieran administracion permanente y adoptar un modelo de acceso privilegiado just-in-time con registro de sesion.'
fi

# Reglas sudo sin contrasena o sin restriccion de comandos
if [ -r /etc/sudoers ] || is_root; then
    reglas_nopasswd=''
    reglas_all=''
    for f in /etc/sudoers /etc/sudoers.d/*; do
        [ -f "$f" ] && [ -r "$f" ] || continue
        n=$(grep -nE '^[^#]*NOPASSWD' "$f" 2>/dev/null | head -5)
        [ -n "$n" ] && reglas_nopasswd="$reglas_nopasswd | $f: $(safe_str "$n" 200)"
        a=$(grep -nE '^[^#]*ALL[[:space:]]*=[[:space:]]*\(ALL(:ALL)?\)[[:space:]]*ALL' "$f" 2>/dev/null | head -5)
        [ -n "$a" ] && reglas_all="$reglas_all | $f: $(safe_str "$a" 200)"
    done

    if [ -n "$reglas_nopasswd" ]; then
        rec Categoria 'PoliticaSudo' Nombre 'NOPASSWD' UID:n 0 GID:n 0 \
            Descripcion "$(safe_str "$reglas_nopasswd" 400)" Home '' Shell '' \
            ShellInteractiva:b false EsSistema:b true EstadoContrasena '' \
            AlgoritmoHash '' Bloqueada '' EdadContrasenaDias:n 0 MaxDiasContrasena '' \
            UltimoInicioSesion '' DiasSinUso:n 0

        finding High 'Reglas sudo que no exigen reautenticacion (NOPASSWD)' \
            -c 'Privilegios' -a 'sudoers' \
            -d 'Existen reglas sudo con NOPASSWD: permiten elevar a root sin volver a autenticarse. Si la sesion del usuario se ve comprometida (clave SSH robada, sesion secuestrada), el atacante obtiene root de inmediato y sin conocer ninguna credencial.' \
            -e "$(safe_str "$reglas_nopasswd" 1200)" \
            -k 'ACC-02|ACC-03' \
            -r 'Eliminar NOPASSWD salvo para comandos concretos y acotados que lo requieran por automatizacion. Nunca combinarlo con ALL. Registrar las sesiones sudo (Defaults log_output).'
    fi
    if [ -n "$reglas_all" ]; then
        finding Medium 'Reglas sudo sin restriccion de comandos' \
            -c 'Privilegios' -a 'sudoers' \
            -d 'Existen reglas que conceden ALL=(ALL) ALL, es decir, capacidad de ejecutar cualquier comando como cualquier usuario. Equivale a entregar la cuenta root sin la trazabilidad que aportaria una lista acotada de comandos.' \
            -e "$(safe_str "$reglas_all" 1200)" \
            -k 'ACC-02' \
            -r 'Sustituir las concesiones amplias por listas de comandos especificas por rol (Cmnd_Alias) y habilitar el registro de las sesiones elevadas.'
    fi
else
    gap 'No fue posible leer /etc/sudoers sin privilegios de root; la evaluacion del acceso privilegiado es PARCIAL.'
fi

# ---------------------------------------------------------------------------
# 3. Politica de contrasenas (analogo de net accounts)
# ---------------------------------------------------------------------------
if [ -r /etc/login.defs ]; then
    pass_max=$(awk '/^PASS_MAX_DAYS/{print $2; exit}' /etc/login.defs 2>/dev/null)
    pass_min=$(awk '/^PASS_MIN_DAYS/{print $2; exit}' /etc/login.defs 2>/dev/null)
    pass_warn=$(awk '/^PASS_WARN_AGE/{print $2; exit}' /etc/login.defs 2>/dev/null)
    metodo=$(awk '/^ENCRYPT_METHOD/{print $2; exit}' /etc/login.defs 2>/dev/null)

    rec Categoria 'PoliticaContrasena' Nombre 'login.defs' UID:n 0 GID:n 0 \
        Descripcion "PASS_MAX_DAYS=$pass_max PASS_MIN_DAYS=$pass_min PASS_WARN_AGE=$pass_warn ENCRYPT_METHOD=$metodo" \
        Home '' Shell '' ShellInteractiva:b false EsSistema:b true \
        EstadoContrasena '' AlgoritmoHash "$metodo" Bloqueada '' \
        EdadContrasenaDias:n 0 MaxDiasContrasena "$pass_max" \
        UltimoInicioSesion '' DiasSinUso:n 0

    metric PassMaxDays "${pass_max:-0}" n
    metric EncryptMethod "${metodo:-no definido}"

    if [ -z "$pass_max" ] || [ "$pass_max" -ge 99999 ] 2>/dev/null; then
        finding Medium 'Caducidad de contrasena no configurada a nivel de sistema' \
            -c 'Autenticacion' -a '/etc/login.defs' \
            -d "PASS_MAX_DAYS vale '${pass_max:-no definido}': las contrasenas de las cuentas nuevas no caducan nunca." \
            -k 'ACC-03' \
            -r 'Establecer PASS_MAX_DAYS conforme a la politica corporativa (referencia habitual: 90 a 365 dias) y aplicarlo tambien a las cuentas existentes con chage.'
    fi
fi

# Complejidad de contrasenas via PAM
pwquality=''
for f in /etc/security/pwquality.conf /etc/pam.d/common-password /etc/pam.d/system-auth; do
    [ -r "$f" ] || continue
    v=$(grep -hE '^\s*(minlen|minclass|dcredit|ucredit|ocredit|lcredit|retry)' "$f" 2>/dev/null | head -8)
    [ -n "$v" ] && pwquality="$pwquality $f: $(safe_str "$v" 200)"
done

minlen=$(grep -hoE 'minlen\s*=?\s*[0-9]+' /etc/security/pwquality.conf /etc/pam.d/common-password /etc/pam.d/system-auth 2>/dev/null |
         grep -oE '[0-9]+' | head -1)
metric LongitudMinimaContrasena "${minlen:-0}" n

rec Categoria 'PoliticaContrasena' Nombre 'Complejidad (PAM)' UID:n 0 GID:n 0 \
    Descripcion "$(safe_str "${pwquality:-No se detecto configuracion de pwquality}" 400)" \
    Home '' Shell '' ShellInteractiva:b false EsSistema:b true \
    EstadoContrasena '' AlgoritmoHash '' Bloqueada '' EdadContrasenaDias:n 0 \
    MaxDiasContrasena '' UltimoInicioSesion '' DiasSinUso:n 0

if [ -z "$minlen" ] || [ "$minlen" -lt 14 ] 2>/dev/null; then
    sev='Medium'; [ -z "$minlen" ] || [ "$minlen" -lt 8 ] 2>/dev/null && sev='High'
    finding "$sev" 'Longitud minima de contrasena por debajo de la recomendacion' \
        -c 'Autenticacion' -a 'pam_pwquality' \
        -d "La longitud minima configurada es de ${minlen:-'ninguna (sin pwquality)'} caracteres. Las lineas base actuales recomiendan al menos 14 para cuentas locales de servidor." \
        -e "$(safe_str "$pwquality" 800)" \
        -k 'ACC-03' \
        -r 'Instalar y configurar pam_pwquality con minlen=14 o superior, priorizando longitud sobre complejidad, y aplicarlo en la pila de PAM correspondiente a la distribucion.'
fi

# Bloqueo por intentos fallidos (analogo del umbral de bloqueo de cuenta)
faillock=''
for f in /etc/security/faillock.conf /etc/pam.d/common-auth /etc/pam.d/system-auth; do
    [ -r "$f" ] || continue
    v=$(grep -hE 'pam_faillock|pam_tally2|^\s*deny\s*=' "$f" 2>/dev/null | head -3)
    [ -n "$v" ] && faillock="$faillock $f: $(safe_str "$v" 150)"
done
metric BloqueoIntentosFallidos "$(if [ -n "$faillock" ]; then printf configurado; else printf 'no configurado'; fi)"

if [ -z "$faillock" ]; then
    finding High 'Bloqueo de cuenta por intentos fallidos no configurado' \
        -c 'Autenticacion' -a 'PAM' \
        -d 'No se detecto pam_faillock ni pam_tally2 en la pila de autenticacion. Sin umbral de bloqueo, el servidor no ofrece resistencia frente a ataques de fuerza bruta o de rociado de contrasenas contra las cuentas locales.' \
        -k 'ACC-03' \
        -r 'Configurar pam_faillock (referencia: deny=10, unlock_time=900) equilibrando seguridad y disponibilidad. Complementar con fail2ban sobre el servicio SSH.'
fi

# ---------------------------------------------------------------------------
# 4. Acceso remoto: SSH (analogo de la configuracion de Escritorio remoto)
# ---------------------------------------------------------------------------
sshd_conf='/etc/ssh/sshd_config'
if [ -r "$sshd_conf" ]; then
    # sshd -T da la configuracion efectiva incluidos los archivos incluidos y
    # los valores por omision; es la fuente autoritativa frente a leer el archivo.
    if is_root && has_cmd sshd; then
        native_capture 20 sshd -T
        conf_efectiva=$NC_OUT
    else
        conf_efectiva=$(grep -hvE '^\s*(#|$)' "$sshd_conf" /etc/ssh/sshd_config.d/*.conf 2>/dev/null | tr 'A-Z' 'a-z')
        gap 'La configuracion efectiva de SSH se leyo del archivo en lugar de "sshd -T" (requiere root); los valores por omision no evaluados explicitamente pueden diferir.'
    fi

    val_ssh() {
        printf '%s\n' "$conf_efectiva" | tr 'A-Z' 'a-z' |
            awk -v k="$1" '$1==k{print $2; exit}'
    }

    permit_root=$(val_ssh permitrootlogin)
    pass_auth=$(val_ssh passwordauthentication)
    pubkey=$(val_ssh pubkeyauthentication)
    permit_empty=$(val_ssh permitemptypasswords)
    x11=$(val_ssh x11forwarding)
    max_auth=$(val_ssh maxauthtries)
    allow_users=$(printf '%s\n' "$conf_efectiva" | tr 'A-Z' 'a-z' | awk '$1=="allowusers"||$1=="allowgroups"{print}' | head -3)
    puerto_ssh=$(val_ssh port)

    rec Categoria 'AccesoRemoto' Nombre 'sshd' UID:n 0 GID:n 0 \
        Descripcion "PermitRootLogin=$permit_root PasswordAuthentication=$pass_auth PubkeyAuthentication=$pubkey PermitEmptyPasswords=$permit_empty X11Forwarding=$x11 MaxAuthTries=$max_auth Puerto=$puerto_ssh" \
        Home '' Shell '' ShellInteractiva:b false EsSistema:b true \
        EstadoContrasena '' AlgoritmoHash '' Bloqueada '' EdadContrasenaDias:n 0 \
        MaxDiasContrasena '' UltimoInicioSesion '' DiasSinUso:n 0

    metric SSHPermitRootLogin "${permit_root:-no determinado}"
    metric SSHPasswordAuth "${pass_auth:-no determinado}"

    case $permit_root in
        yes)
            finding High 'SSH permite el inicio de sesion directo como root' \
                -c 'AccesoRemoto' -a 'sshd PermitRootLogin' \
                -d 'PermitRootLogin=yes permite autenticarse remotamente como root. Elimina la trazabilidad (no se puede atribuir la accion a una persona) y convierte a root en un objetivo directo de fuerza bruta, ya que es el unico nombre de cuenta que el atacante necesita adivinar.' \
                -e "PermitRootLogin=$permit_root" \
                -k 'ACC-05|ACC-02|ACC-03' \
                -r 'Establecer PermitRootLogin=no (o prohibit-password si se requiere automatizacion con clave) y operar con cuentas nominales que eleven mediante sudo.' ;;
        prohibit-password|without-password)
            finding Low 'SSH permite acceso root mediante clave publica' \
                -c 'AccesoRemoto' -a 'sshd PermitRootLogin' \
                -d "PermitRootLogin=$permit_root permite el acceso remoto como root mediante clave. Es aceptable para automatizacion, pero mantiene la perdida de trazabilidad individual." \
                -k 'ACC-05|ACC-02' \
                -r 'Restringir el acceso a las claves estrictamente necesarias con from= en authorized_keys, y preferir cuentas nominales con sudo cuando sea viable.' ;;
    esac

    if [ "$pass_auth" = 'yes' ]; then
        finding Medium 'SSH acepta autenticacion por contrasena' \
            -c 'AccesoRemoto' -a 'sshd PasswordAuthentication' \
            -d 'El servicio acepta autenticacion por contrasena, lo que lo expone a ataques de fuerza bruta y de rociado de credenciales desde cualquier origen con alcance de red.' \
            -e "PasswordAuthentication=$pass_auth" \
            -k 'ACC-03|ACC-05' \
            -r 'Migrar a autenticacion por clave publica y establecer PasswordAuthentication=no. Si debe mantenerse, exigir autenticacion multifactor y desplegar fail2ban.'
    fi

    if [ "$permit_empty" = 'yes' ]; then
        finding Critical 'SSH permite contrasenas vacias' \
            -c 'AccesoRemoto' -a 'sshd PermitEmptyPasswords' \
            -d 'PermitEmptyPasswords=yes permite autenticarse con contrasena vacia en las cuentas que la tengan. Es acceso remoto sin autenticacion.' \
            -k 'ACC-03|ACC-05' \
            -r 'Establecer PermitEmptyPasswords=no de inmediato y verificar que ninguna cuenta tenga contrasena vacia.'
    fi

    if [ -z "$allow_users" ]; then
        finding Low 'SSH sin lista explicita de usuarios o grupos autorizados' \
            -c 'AccesoRemoto' -a 'sshd' \
            -d 'No se declararon AllowUsers ni AllowGroups: toda cuenta con shell valida puede intentar autenticarse por SSH. Es el analogo de no restringir la membresia del grupo de Escritorio remoto.' \
            -k 'ACC-04|ACC-05' \
            -r 'Declarar AllowGroups con un grupo dedicado de acceso remoto y revisar su membresia contra la matriz de accesos autorizada.'
    else
        rec Categoria 'AccesoRemoto' Nombre 'Usuarios autorizados SSH' UID:n 0 GID:n 0 \
            Descripcion "$(safe_str "$allow_users" 300)" Home '' Shell '' \
            ShellInteractiva:b false EsSistema:b true EstadoContrasena '' \
            AlgoritmoHash '' Bloqueada '' EdadContrasenaDias:n 0 MaxDiasContrasena '' \
            UltimoInicioSesion '' DiasSinUso:n 0
    fi
else
    gap 'No se encontro /etc/ssh/sshd_config; no se evaluo la configuracion de acceso remoto.'
fi

# ---------------------------------------------------------------------------
# 5. Claves SSH autorizadas: acceso persistente sin contrasena
# ---------------------------------------------------------------------------
total_claves=0
claves_detalle=''
while IFS=: read -r usuario _ uid _ _ home shell; do
    [ -d "$home" ] || continue
    for ak in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
        [ -f "$ak" ] || continue
        if [ ! -r "$ak" ]; then
            gap "El archivo $ak no es legible sin privilegios de root; las claves de acceso de '$usuario' no fueron auditadas."
            continue
        fi
        n=$(grep -cvE '^\s*(#|$)' "$ak" 2>/dev/null)
        [ "${n:-0}" -gt 0 ] || continue
        total_claves=$((total_claves + n))
        perm=$(stat -c %a "$ak" 2>/dev/null)
        claves_detalle="$claves_detalle | $usuario: $n clave(s), modo $perm"

        rec Categoria 'ClaveSSH' Nombre "$usuario" UID:n "$uid" GID:n 0 \
            Descripcion "$n clave(s) autorizada(s)" Home "$home" Shell "$shell" \
            ShellInteractiva:b true EsSistema:b false EstadoContrasena '' \
            AlgoritmoHash "$(awk '{print $1}' "$ak" 2>/dev/null | sort -u | tr '\n' ' ')" \
            Bloqueada '' EdadContrasenaDias:n 0 MaxDiasContrasena "$perm" \
            UltimoInicioSesion '' DiasSinUso:n 0

        # Permisos laxos en authorized_keys permiten anadir una clave propia
        case $perm in
            *[2367]|*[2367]?)
                finding High 'Archivo authorized_keys con permisos permisivos' \
                    -c 'AccesoRemoto' -a "$ak" \
                    -d "El archivo de claves autorizadas de '$usuario' tiene modo $perm: es escribible por cuentas distintas de su propietario. Cualquiera con ese acceso puede anadir su propia clave y obtener acceso permanente como ese usuario." \
                    -e "$ak modo=$perm" \
                    -k 'ACC-05|ACC-04' \
                    -r "Restablecer los permisos a 600 y el propietario al usuario correspondiente (chmod 600 $ak)." ;;
        esac
    done
done < /etc/passwd

metric ClavesSSHAutorizadas "$total_claves" n

if [ "$total_claves" -gt 0 ]; then
    finding Info 'Claves SSH autorizadas para acceso sin contrasena' \
        -c 'AccesoRemoto' -a "$total_claves claves" \
        -d "Se registraron $total_claves claves publicas autorizadas. Cada clave es una credencial de acceso permanente que no caduca, no rota y cuya parte privada esta fuera del control del servidor. Deben inventariarse igual que las cuentas." \
        -e "$(safe_str "${claves_detalle# | }" 1200)" \
        -k 'ACC-01|ACC-05|ACC-02' \
        -r 'Inventariar cada clave con su titular y proposito, establecer un procedimiento de rotacion y revocacion, y restringir su alcance con las opciones from= y command= en authorized_keys.'
fi

emit_result
