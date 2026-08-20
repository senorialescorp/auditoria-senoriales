<#
    Audit.config.psd1
    Configuracion central de la suite de auditoria.
    Editable sin tocar el codigo de los colectores.
#>
@{

    # -----------------------------------------------------------------------
    # Identificacion del alcance de la auditoria
    # -----------------------------------------------------------------------
    Scope = @{
        Organizacion   = 'DEFINIR'
        Responsable    = 'DEFINIR'
        Area           = 'DEFINIR'
        Clasificacion  = 'Interno / Confidencial'
        Marco          = 'Marco propio de criterios de auditoria de sistemas'
    }

    # -----------------------------------------------------------------------
    # Modelo de capas. El peso alimenta el calculo de riesgo agregado.
    # La capa L4 (artefactos de software) tiene el peso mas alto por
    # requerimiento explicito del alcance de esta auditoria.
    # -----------------------------------------------------------------------
    Layers = @(
        @{ Id='L1'; Nombre='Infraestructura fisica y hardware'; Peso=0.8; Orden=1
           Descripcion='Chasis, CPU, memoria, almacenamiento, firmware/BIOS, virtualizacion.' }
        @{ Id='L2'; Nombre='Sistema operativo y hardening';     Peso=1.2; Orden=2
           Descripcion='Version de SO, parches, configuracion de seguridad, antimalware, cifrado.' }
        @{ Id='L3'; Nombre='Plataforma, runtimes y middleware'; Peso=1.5; Orden=3
           Descripcion='.NET, Java, Python, Node, IIS, bases de datos, servidores de aplicacion.' }
        @{ Id='L4'; Nombre='Artefactos de software (PRIORIDAD)';Peso=2.0; Orden=4
           Descripcion='Inventario de aplicaciones instaladas, gestores de paquetes, binarios no gestionados, integridad y ciclo de vida.' }
        @{ Id='L5'; Nombre='Servicios, procesos y persistencia';Peso=1.5; Orden=5
           Descripcion='Servicios Windows, tareas programadas, autoarranque, procesos activos.' }
        @{ Id='L6'; Nombre='Identidad y control de acceso';     Peso=1.4; Orden=6
           Descripcion='Cuentas locales, administradores, politica de contrasenas, RDP, privilegios.' }
        @{ Id='L7'; Nombre='Red y exposicion';                  Peso=1.3; Orden=7
           Descripcion='Puertos en escucha, firewall, recursos compartidos, protocolos heredados.' }
        @{ Id='L8'; Nombre='Datos, registro y resiliencia';     Peso=1.1; Orden=8
           Descripcion='Politica de auditoria, logs, respaldos, instantaneas, capacidad de disco.' }
        @{ Id='L9'; Nombre='Rendimiento y capacidad';           Peso=0.9; Orden=9
           Descripcion='Estadisticas del servidor: CPU, memoria, disco, red, top de procesos.' }
    )

    # -----------------------------------------------------------------------
    # Umbrales de evaluacion
    # -----------------------------------------------------------------------
    Thresholds = @{
        # Parcheo (VUL-01)
        DiasMaxSinParche          = 45
        DiasMaxSinReinicio        = 60

        # Capacidad (CAP-01)
        PorcentajeDiscoLibreMin   = 15
        PorcentajeDiscoLibreCrit  = 8
        PorcentajeMemoriaLibreMin = 12
        PorcentajeCpuSostenidoMax = 85

        # Software (INV-01 / SW-03)
        DiasSoftwareSinActualizar = 730   # 2 anios -> posible software abandonado
        TamMinBinarioPortableKB   = 64    # ignora binarios triviales en el escaneo

        # Identidad (ACC-01 / ACC-03)
        DiasCuentaInactiva        = 90
        MaxAdministradoresLocales = 5
        EdadMaxContrasenaDias     = 365
    }

    # -----------------------------------------------------------------------
    # Escaneo de binarios no gestionados (shadow IT) - capa L4
    # -----------------------------------------------------------------------
    UnmanagedScan = @{
        Habilitado = $true
        Rutas = @(
            'C:\Scripts'
            'C:\Apps'
            'C:\Tools'
            'C:\Temp'
            'C:\Users\Public'
            'C:\inetpub'
            'D:\'
        )
        RutasExcluidas = @(
            'C:\Windows\WinSxS'
            'C:\Windows\servicing'
            'C:\Windows\assembly'
            'C:\ProgramData\Microsoft\Windows Defender'
            'C:\Users\*\AppData\Local\Temp\*\claude'
        )
        Extensiones      = @('.exe','.dll','.msi','.ps1','.bat','.cmd','.vbs','.jar','.py')
        ProfundidadMax   = 4
        MaxArchivos      = 3000     # tope de seguridad para no saturar el servidor
        CalcularHash     = $true    # SHA256 para cadena de custodia
    }

    # -----------------------------------------------------------------------
    # Catalogo de fin de soporte (EOL). Alimenta L4-05 y L3-01.
    # Mantener actualizado: es la base de los criterios SW-02 y VUL-01.
    # Formato: patron de nombre (regex), version limite, fecha EOL, criticidad.
    # -----------------------------------------------------------------------
    EndOfLife = @(
        @{ Patron='^Microsoft \.NET Framework 3\.5';        EOL='2029-01-09'; Severidad='Medium';   Nota='Soporte ligado al SO anfitrion.' }
        @{ Patron='^Microsoft \.NET Framework (1|2|4\.0|4\.5|4\.6)'; EOL='2022-04-26'; Severidad='High'; Nota='Version de .NET Framework fuera de soporte.' }
        @{ Patron='^Microsoft \.NET Core';                  EOL='2022-12-13'; Severidad='High';     Nota='.NET Core 1.x-3.1 sin soporte. Migrar a .NET 8/10 LTS.' }
        @{ Patron='(?i)java.*\b(6|7|8)\b';                  EOL='2019-01-31'; Severidad='High';     Nota='Java 6/7/8 requiere soporte extendido de pago.' }
        @{ Patron='(?i)^python 2';                          EOL='2020-01-01'; Severidad='Critical'; Nota='Python 2 sin soporte ni parches de seguridad.' }
        @{ Patron='(?i)^python 3\.([0-7])(\D|$)';           EOL='2023-06-27'; Severidad='High';     Nota='Python 3.7 o inferior sin soporte.' }
        @{ Patron='(?i)^node\.?js.*\bv?(0|4|6|8|10|12|14|16)\b'; EOL='2023-09-11'; Severidad='High'; Nota='Rama de Node.js sin soporte LTS.' }
        @{ Patron='(?i)adobe flash';                        EOL='2020-12-31'; Severidad='Critical'; Nota='Flash Player descontinuado. Desinstalar.' }
        @{ Patron='(?i)internet explorer';                  EOL='2022-06-15'; Severidad='High';     Nota='IE fuera de soporte.' }
        @{ Patron='(?i)microsoft sql server 20(08|12|14)';  EOL='2024-07-09'; Severidad='High';     Nota='Version de SQL Server fuera de soporte extendido.' }
        @{ Patron='(?i)^microsoft office (2007|2010|2013|2016)'; EOL='2025-10-14'; Severidad='Medium'; Nota='Suite Office fuera de soporte.' }
        @{ Patron='(?i)access database engine 20(07|10)';    EOL='2020-10-13'; Severidad='High';     Nota='Motor de base de datos Access fuera de soporte. Usado con frecuencia como puente ODBC/OLEDB entre aplicaciones.' }
        @{ Patron='(?i)openssl 1\.';                        EOL='2023-09-11'; Severidad='High';     Nota='OpenSSL 1.x fuera de soporte.' }
        @{ Patron='(?i)apache (tomcat )?(7|8)\.';           EOL='2024-03-31'; Severidad='High';     Nota='Rama de Tomcat/Apache sin soporte.' }
        @{ Patron='(?i)powershell 2\.0';                    EOL='2017-01-01'; Severidad='High';     Nota='PSv2 sin registro de bloques de script. Deshabilitar la caracteristica.' }
    )

    # -----------------------------------------------------------------------
    # Software que NO deberia estar presente en un servidor de produccion.
    # Alimenta hallazgos del criterio SW-03 (control de instalacion de software).
    # -----------------------------------------------------------------------
    SoftwareNoPermitido = @(
        @{ Patron='(?i)(utorrent|bittorrent|qbittorrent|emule|ares)';  Severidad='Critical'; Categoria='P2P / Intercambio de archivos' }
        @{ Patron='(?i)(teamviewer|anydesk|ammyy|radmin|vnc|logmein|supremo)'; Severidad='High'; Categoria='Acceso remoto de terceros' }
        @{ Patron='(?i)(cain|abel|mimikatz|nmap|wireshark|cheat ?engine|john the ripper|hashcat)'; Severidad='High'; Categoria='Herramienta ofensiva / analisis' }
        @{ Patron='(?i)(steam|epic games|origin|battle\.net|minecraft)'; Severidad='Medium';  Categoria='Entretenimiento' }
        @{ Patron='(?i)(dropbox|google drive|onedrive personal|mega ?sync|box sync)'; Severidad='Medium'; Categoria='Sincronizacion en nube no corporativa' }
        @{ Patron='(?i)(spotify|itunes|vlc|winamp)';                   Severidad='Low';      Categoria='Multimedia' }
        @{ Patron='(?i)(toolbar|search ?protect|coupon|adware)';       Severidad='High';     Categoria='PUP / Adware' }
    )

    # -----------------------------------------------------------------------
    # Publicadores confiables. Un binario firmado por estos no genera hallazgo
    # de "software no gestionado" (reduce ruido en SW-03).
    # -----------------------------------------------------------------------
    PublicadoresConfiables = @(
        'Microsoft Corporation'
        'Microsoft Windows'
        'Google LLC'
        'Oracle Corporation'
        'VMware, Inc.'
        'Citrix Systems'
        'Dell Inc.'
        'Hewlett-Packard'
        'HP Inc.'
        'Intel Corporation'
        'Broadcom'
        'Adobe Inc.'
        'Mozilla Corporation'
        'Anthropic'
    )

    # -----------------------------------------------------------------------
    # Reporte
    # -----------------------------------------------------------------------
    Report = @{
        Titulo            = 'Auditoria de Sistemas y Arquitectura Empresarial'
        IncluirInventario = $true
        MaxFilasTabla     = 500
        RetencionDias     = 180   # Usado por Invoke-Audit.ps1 -Purge
    }
}
