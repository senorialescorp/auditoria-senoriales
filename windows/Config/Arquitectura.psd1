<#
    Arquitectura.psd1

    LINEA BASE DE ARQUITECTURA EMPRESARIAL

    Este archivo declara COMO DEBERIA SER el servidor. Los colectores levantan
    COMO ES. La diferencia entre ambos es el hallazgo de auditoria de sistemas.

    Tres bloques:
      1. RolServidor  -> proposito declarado del activo y roles de software admisibles
      2. Roles        -> taxonomia de clasificacion automatica de artefactos
      3. Aplicaciones -> catalogo de aplicaciones de negocio conocidas (autoridad
                         maxima sobre descripcion, propietario y criticidad)

    Mantener este archivo actualizado ES el ejercicio de arquitectura: cada
    artefacto que el colector no logre clasificar o que no figure en el catalogo
    aparece como brecha de linea base.
#>
@{

    # =======================================================================
    # 1. ROL DECLARADO DEL SERVIDOR
    #    Ajustar a la realidad del activo. Este bloque determina que artefactos
    #    se consideran alineados y cuales constituyen desviacion arquitectonica.
    # =======================================================================
    RolServidor = @{
        Nombre           = 'SRV-SAP'
        RolDeclarado     = 'Servidor de aplicaciones de negocio'
        Descripcion      = 'POR VALIDAR: servidor que aloja aplicaciones de negocio corporativas. Confirmar con el responsable del activo antes de emitir el informe final.'
        Entorno          = 'Produccion'          # Produccion | Preproduccion | Desarrollo | Pruebas
        Criticidad       = 'Alta'                # Alta | Media | Baja
        Propietario      = 'DEFINIR'
        ResponsableTecnico = 'DEFINIR'
        UnidadNegocio    = 'DEFINIR'
        ClasificacionDatos = 'Confidencial'      # Publico | Interno | Confidencial | Restringido

        # Roles de software admisibles para este tipo de servidor.
        RolesEsperados = @(
            'AplicacionNegocio'
            'MotorBaseDatos'
            'HerramientaBI'
            'ServidorAplicaciones'
            'Middleware'
            'Runtime'
            'AgenteSeguridad'
            'AgenteMonitoreo'
            'AgenteRespaldo'
            'HerramientaAdministracion'
            'ControladorFirmware'
            'UtilitarioSistema'
            'ComponenteSO'
        )

        # Roles que NO corresponden al proposito declarado. Generan hallazgo.
        RolesNoEsperados = @(
            'HerramientaDesarrollo'
            'Ofimatica'
            'Multimedia'
            'NavegadorWeb'
            'AccesoRemotoTerceros'
            'AlmacenamientoNube'
        )
    }

    # =======================================================================
    # 2. TAXONOMIA DE ROLES ARQUITECTONICOS
    #    Clasificacion automatica de cada artefacto de software.
    #    Se evalua en orden: la primera coincidencia gana. Ordenar de lo mas
    #    especifico a lo mas general.
    #
    #    CapaEA sigue el modelo de capas de arquitectura empresarial:
    #      Negocio | Aplicacion | Datos | Tecnologia | Infraestructura
    # =======================================================================
    Roles = @(
        @{ Id='AgenteSeguridad'; Nombre='Agente de seguridad'; CapaEA='Tecnologia'
           Descripcion='Antimalware, EDR, DLP, cifrado o agente de cumplimiento.'
           Patron='(?i)(defender|antivirus|endpoint protection|crowdstrike|sentinelone|carbon black|mcafee|symantec|trend micro|kaspersky|eset|sophos|cylance|tanium|qualys|nessus|rapid7|bitlocker|forcepoint)'
           EsperadoEnServidor=$true }

        @{ Id='AgenteMonitoreo'; Nombre='Agente de monitoreo y gestion'; CapaEA='Tecnologia'
           Descripcion='Recoleccion de metricas, inventario, telemetria o gestion remota corporativa.'
           Patron='(?i)(zabbix|nagios|datadog|dynatrace|appdynamics|new relic|solarwinds|prtg|splunk|elastic agent|filebeat|winlogbeat|nxlog|sccm|configuration manager|intune|ivanti|manageengine|centreon|checkmk|grafana agent|telegraf|prometheus)'
           EsperadoEnServidor=$true }

        @{ Id='AgenteRespaldo'; Nombre='Agente de respaldo y continuidad'; CapaEA='Tecnologia'
           Descripcion='Software de copia de seguridad, replicacion o recuperacion ante desastres.'
           Patron='(?i)(veeam|commvault|networker|netbackup|acronis|arcserve|backup exec|data protector|rubrik|cohesity|veritas|windows server backup|zerto)'
           EsperadoEnServidor=$true }

        @{ Id='MotorBaseDatos'; Nombre='Motor de base de datos'; CapaEA='Datos'
           Descripcion='Sistema gestor de bases de datos, sus componentes cliente y controladores de acceso a datos.'
           Patron='(?i)(sql server|sqlncli|sqlxml|odbc driver|oledb driver|mysql|mariadb|postgresql|oracle database|mongodb|redis|db2|sybase|sqlite|cassandra|influxdb|\bhana\b|firebird|informix|access database engine|jet database)'
           EsperadoEnServidor=$true }

        @{ Id='HerramientaBI'; Nombre='Inteligencia de negocios y reporteria'; CapaEA='Aplicacion'
           Descripcion='Plataforma de analitica, tableros o generacion de reportes sobre datos de negocio.'
           Patron='(?i)(tableau|power ?bi|qlik|cognos|crystal report|businessobjects|business objects|microstrategy|pentaho|looker|superset|ssrs|reporting services|analysis services)'
           EsperadoEnServidor=$true }

        @{ Id='ServidorAplicaciones'; Nombre='Servidor de aplicaciones / web'; CapaEA='Tecnologia'
           Descripcion='Contenedor de ejecucion de aplicaciones o servidor HTTP.'
           Patron='(?i)(internet information services|iis |apache tomcat|apache http|nginx|jboss|wildfly|weblogic|websphere|glassfish|payara|jetty|node.*server|kestrel)'
           EsperadoEnServidor=$true }

        @{ Id='Middleware'; Nombre='Middleware e integracion'; CapaEA='Tecnologia'
           Descripcion='Colas de mensajes, ESB, integracion de sistemas y conectores.'
           Patron='(?i)(rabbitmq|activemq|kafka|biztalk|mulesoft|tibco|websphere mq|ibm mq|msmq|nservicebus|camel|boomi|sap.*connector|sap.*gateway|rfc)'
           EsperadoEnServidor=$true }

        @{ Id='Runtime'; Nombre='Runtime / framework de ejecucion'; CapaEA='Tecnologia'
           Descripcion='Maquinas virtuales de lenguaje, frameworks y bibliotecas redistribuibles.'
           Patron='(?i)(\.net (framework|core|runtime)|microsoft \.net|visual c\+\+.*redistributable|java(?!script).*(runtime|re\b|development)|jre|jdk|openjdk|adoptium|corretto|zulu|python \d|node\.?js|ruby|perl|php|mono|erlang|golang|powershell \d)'
           EsperadoEnServidor=$true }

        @{ Id='HerramientaDesarrollo'; Nombre='Herramienta de desarrollo'; CapaEA='Tecnologia'
           Descripcion='IDE, compilador, SDK, biblioteca de componentes o utilitario de construccion de software.'
           Patron='(?i)(visual studio(?! code)?\b(?!.*redistributable)|^vs_|vs code|visual studio code|azure data studio|jetbrains|intellij|pycharm|eclipse|netbeans|android studio|xamarin|\bsdk\b|\bgit\b|github desktop|sourcetree|tortoise|docker desktop|postman|fiddler|sql server (management studio|data tools)|ssms|devexpress|telerik|syncfusion|infragistics|componentone|nuget|msbuild|\bwix\b|installshield|inno setup)'
           EsperadoEnServidor=$false }

        @{ Id='AccesoRemotoTerceros'; Nombre='Acceso remoto de terceros'; CapaEA='Tecnologia'
           Descripcion='Herramienta de control remoto no corporativa. Canal de acceso fuera del perimetro gestionado.'
           Patron='(?i)(teamviewer|anydesk|ammyy|radmin|ultravnc|tightvnc|realvnc|logmein|gotomypc|supremo|splashtop|chrome remote desktop|rustdesk)'
           EsperadoEnServidor=$false }

        @{ Id='AlmacenamientoNube'; Nombre='Sincronizacion en nube'; CapaEA='Datos'
           Descripcion='Cliente de sincronizacion de archivos hacia almacenamiento externo.'
           Patron='(?i)(dropbox|google drive|onedrive|mega ?sync|box sync|icloud|pcloud|sync\.com|nextcloud|owncloud)'
           EsperadoEnServidor=$false }

        @{ Id='NavegadorWeb'; Nombre='Navegador web'; CapaEA='Aplicacion'
           Descripcion='Navegador de internet o motor de navegacion embebido.'
           Patron='(?i)(google chrome|mozilla firefox|microsoft ?edge|edge ?webview|opera|brave|vivaldi|internet explorer|chromium)'
           EsperadoEnServidor=$false }

        @{ Id='Ofimatica'; Nombre='Ofimatica y productividad'; CapaEA='Aplicacion'
           Descripcion='Suite de productividad de usuario final.'
           Patron='(?i)(microsoft office|office 365|libreoffice|openoffice|wps office|adobe acrobat|foxit|nitro pdf|onenote|outlook|teams|zoom|skype|slack)'
           EsperadoEnServidor=$false }

        @{ Id='Multimedia'; Nombre='Multimedia y entretenimiento'; CapaEA='Aplicacion'
           Descripcion='Reproductores, editores multimedia, captura de pantalla o software de entretenimiento.'
           Patron='(?i)(\bvlc\b|winamp|spotify|itunes|media player|audacity|gimp|photoshop|premiere|steam|epic games|origin|\bobs\b|obs-|obs studio|streamlabs|camtasia|bandicam)'
           EsperadoEnServidor=$false }

        @{ Id='ControladorFirmware'; Nombre='Controlador / firmware'; CapaEA='Infraestructura'
           Descripcion='Driver de dispositivo, utilitario de fabricante o herramienta de gestion de hardware.'
           Patron='(?i)(driver|controlador|chipset|intel\(r\)|nvidia|amd |realtek|broadcom|dell (command|openmanage|emc)|hp (insight|ilo|smart)|lenovo (system|thinkvantage)|ipmi|idrac|firmware|vmware tools|hyper-v (guest|integration)|xentools|qemu guest agent|virtio)'
           EsperadoEnServidor=$true }

        @{ Id='HerramientaAdministracion'; Nombre='Herramienta de administracion'; CapaEA='Tecnologia'
           Descripcion='Utilitario de administracion de sistemas, red o infraestructura.'
           Patron='(?i)(remote server administration|rsat|windows admin center|sysinternals|putty|winscp|filezilla|7-zip|winrar|notepad\+\+|wireshark|advanced ip scanner|mremoteng|royal ts)'
           EsperadoEnServidor=$true }

        @{ Id='ComponenteSO'; Nombre='Componente del sistema operativo'; CapaEA='Tecnologia'
           Descripcion='Actualizacion, caracteristica, paquete Appx o componente propio de Windows.'
           # Cubre tres formas: nombres de actualizacion, paquetes Appx del SO
           # (Microsoft.X / Windows.X / MicrosoftWindows.X), paquetes con nombre
           # GUID, y cualquier artefacto firmado como "CN=Microsoft Windows".
           Patron='(?i)(^(update for|security update|hotfix|service pack|actualizacion|kb\d{6,})|^(microsoft|microsoftwindows|windows)\.[a-z]|^windows (feature|subsystem)|^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}|CN=Microsoft Windows)'
           EsperadoEnServidor=$true }

        @{ Id='UtilitarioSistema'; Nombre='Utilitario de sistema'; CapaEA='Tecnologia'
           Descripcion='Herramienta auxiliar de proposito general.'
           Patron='(?i)(compressor|archiver|cleaner|defrag|monitor|viewer|reader|converter|utility|utilidad|toolkit|agent\b)'
           EsperadoEnServidor=$true }
    )

    # Rol asignado cuando ningun patron coincide.
    RolPorDefecto = @{
        Id='SinClasificar'; Nombre='Sin clasificar'; CapaEA='No determinada'
        Descripcion='El artefacto no coincide con ningun rol de la taxonomia. Requiere clasificacion manual por el arquitecto.'
        EsperadoEnServidor=$null
    }

    # =======================================================================
    # 3. CATALOGO DE APLICACIONES DE NEGOCIO
    #
    #    Autoridad maxima sobre descripcion, propietario y criticidad. Lo que se
    #    declara aqui sobreescribe la clasificacion automatica.
    #
    #    Un artefacto de rol 'AplicacionNegocio' que NO figure en este catalogo
    #    se reporta como aplicacion no inventariada (brecha de linea base).
    #
    #    Deteccion: 'Patron' se evalua contra el nombre del producto, el
    #    publicador Y las rutas de instalacion, servicios y binarios detectados.
    # =======================================================================
    Aplicaciones = @(
        @{
            Id           = 'REPOFEL'
            Nombre       = 'REPOFEL - Repositorio de Factura Electronica en Linea'
            Patron       = '(?i)repofel'
            Rol          = 'AplicacionNegocio'
            CapaEA       = 'Aplicacion'
            Descripcion  = 'POR VALIDAR: repositorio de documentos tributarios electronicos (FEL). Confirmar alcance, version y responsable con el area funcional antes de dar por buena esta descripcion.'
            Proposito    = 'Resguardo y consulta de documentos tributarios electronicos.'
            Propietario  = 'DEFINIR'
            ResponsableTecnico = 'DEFINIR'
            Criticidad   = 'Alta'
            ClasificacionDatos = 'Confidencial'
            Autorizado   = $true
            RequiereRespaldo = $true
            Notas        = 'Entrada declarada, pendiente de verificacion en sitio. Ajustar Patron si la instalacion usa otro nombre de carpeta, servicio o producto.'
        }
        @{
            Id           = 'SAP'
            Nombre       = 'SAP - Sistema de planificacion de recursos empresariales'
            Patron       = '(?i)\bsap\b|saplogon|sapgui|netweaver|hana'
            Rol          = 'AplicacionNegocio'
            CapaEA       = 'Aplicacion'
            Descripcion  = 'POR VALIDAR: componentes SAP. El nombre del servidor (SRV-SAP) sugiere que este es su proposito principal; confirmar que modulos y componentes residen aqui.'
            Proposito    = 'Planificacion de recursos empresariales.'
            Propietario  = 'DEFINIR'
            ResponsableTecnico = 'DEFINIR'
            Criticidad   = 'Alta'
            ClasificacionDatos = 'Confidencial'
            Autorizado   = $true
            RequiereRespaldo = $true
            Notas        = 'Entrada declarada, pendiente de verificacion en sitio.'
        }
        # Agregar aqui el resto de aplicaciones de negocio conforme se identifiquen.
        # Plantilla:
        # @{ Id=''; Nombre=''; Patron=''; Rol='AplicacionNegocio'; CapaEA='Aplicacion'
        #    Descripcion=''; Proposito=''; Propietario=''; ResponsableTecnico=''
        #    Criticidad='Media'; ClasificacionDatos='Interno'; Autorizado=$true
        #    RequiereRespaldo=$true; Notas='' }
    )

    # =======================================================================
    # 4. REGLAS DE CONFORMIDAD DE LA LINEA BASE
    # =======================================================================
    Conformidad = @{
        # Exigir que toda aplicacion de negocio detectada figure en el catalogo
        ExigirCatalogoCompleto = $true

        # Exigir que cada artefacto tenga ruta de instalacion determinable
        ExigirRutaInstalacion  = $true

        # Exigir propietario declarado en aplicaciones criticas
        ExigirPropietario      = $true

        # Porcentaje maximo tolerado de artefactos sin clasificar
        MaxPorcentajeSinClasificar = 25

        # Severidad de cada tipo de desviacion arquitectonica
        Severidades = @{
            RolNoEsperado          = 'High'
            AplicacionNoCatalogada = 'Medium'
            SinClasificar          = 'Low'
            SinRutaInstalacion     = 'Low'
            SinPropietario         = 'Medium'
            AplicacionNoAutorizada = 'High'
        }
    }
}
