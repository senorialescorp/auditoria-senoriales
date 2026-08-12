<#
    L1-01_Hardware-Inventory.ps1
    Capa L1 - Infraestructura fisica y hardware.
    Criterios de auditoria -> INV-01, CRI-01, DAT-03, ARQ-01
#>
param([switch]$Manifest, [hashtable]$Config)

$meta = @{
    Id            = 'L1-01'
    Nombre        = 'Inventario de hardware y plataforma fisica'
    Layer         = 'L1'
    Criterios     = @('INV-01','CRI-01','DAT-03','ARQ-01')
    RequiereAdmin = $false
    Descripcion   = 'Chasis, CPU, memoria, discos, firmware y deteccion de virtualizacion.'
}
if ($Manifest) { return [pscustomobject]$meta }

$records  = New-Object System.Collections.ArrayList
$findings = New-Object System.Collections.ArrayList
$gaps     = New-Object System.Collections.ArrayList
$metrics  = @{}

# --- Sistema / chasis -------------------------------------------------------
try {
    $cs   = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
    $enc  = Get-CimInstance Win32_SystemEnclosure -ErrorAction SilentlyContinue

    $chassisMap = @{
        1='Otro';2='Desconocido';3='Escritorio';4='Escritorio bajo';5='Pizza box';6='Mini torre'
        7='Torre';8='Portatil';9='Laptop';10='Notebook';11='Handheld';12='Docking';13='All in one'
        14='Sub notebook';15='Space saving';16='Lunch box';17='Chasis de servidor principal'
        23='Rack Mount Chassis';24='Sealed-case PC';28='Blade';29='Blade Enclosure'
    }
    $chassisType = 'Desconocido'
    if ($enc -and $enc.ChassisTypes) {
        $ct = @($enc.ChassisTypes)[0]
        if ($chassisMap.ContainsKey([int]$ct)) { $chassisType = $chassisMap[[int]$ct] }
    }

    # Deteccion de virtualizacion
    $virt = 'Fisico'
    $model = [string]$cs.Model
    $manu  = [string]$cs.Manufacturer
    switch -Regex ("$manu $model") {
        '(?i)vmware'                { $virt = 'VMware'; break }
        '(?i)virtual machine'       { $virt = 'Hyper-V'; break }
        '(?i)microsoft corporation.*virtual' { $virt = 'Hyper-V'; break }
        '(?i)kvm|qemu'              { $virt = 'KVM/QEMU'; break }
        '(?i)xen'                   { $virt = 'Xen'; break }
        '(?i)virtualbox'            { $virt = 'VirtualBox'; break }
        '(?i)amazon ec2'            { $virt = 'AWS EC2'; break }
        '(?i)google'                { $virt = 'Google Cloud'; break }
    }

    $null = $records.Add([pscustomobject]@{
        Tipo             = 'Sistema'
        Nombre           = $cs.Name
        Dominio          = $cs.Domain
        Fabricante       = $manu
        Modelo           = $model
        TipoChasis       = $chassisType
        Virtualizacion   = $virt
        NumeroSerie      = if ($bios) { [string]$bios.SerialNumber } else { '' }
        BiosVersion      = if ($bios) { ([string[]]$bios.BIOSVersion -join ' ') } else { '' }
        BiosFecha        = if ($bios) { $bios.ReleaseDate } else { $null }
        ProcesadoresFisicos = $cs.NumberOfProcessors
        ProcesadoresLogicos = $cs.NumberOfLogicalProcessors
        MemoriaTotalGB   = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
        RolDominio       = $cs.DomainRole
        PartOfDomain     = $cs.PartOfDomain
    })

    $metrics['Virtualizacion']  = $virt
    $metrics['MemoriaTotalGB']  = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
    $metrics['CPULogicos']      = $cs.NumberOfLogicalProcessors

    # BIOS antiguo -> riesgo de firmware sin parchear (VUL-01 / ARQ-01)
    if ($bios -and $bios.ReleaseDate) {
        $edadBios = ((Get-Date) - $bios.ReleaseDate).Days
        if ($edadBios -gt (365 * 4) -and $virt -eq 'Fisico') {
            $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                -Severity 'Medium' -Category 'Firmware' `
                -Title 'Firmware BIOS/UEFI con antiguedad superior a 4 anios' `
                -Asset "$manu $model" `
                -Detail ("Fecha de version del BIOS: {0} ({1} dias). El firmware desactualizado puede contener vulnerabilidades sin corregir." -f $bios.ReleaseDate.ToString('yyyy-MM-dd'), $edadBios) `
                -Evidence ("BIOSVersion={0}" -f ([string[]]$bios.BIOSVersion -join ' ')) `
                -Criterios @('VUL-01','ARQ-01') `
                -Recommendation 'Revisar el catalogo de firmware del fabricante e incorporar el firmware al ciclo formal de gestion de parches.'))
        }
    }

    if (-not $cs.PartOfDomain) {
        $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
            -Severity 'Low' -Category 'Gobierno' `
            -Title 'Servidor fuera de dominio (workgroup)' `
            -Asset $cs.Name `
            -Detail 'El equipo no pertenece a un dominio, por lo que no recibe politicas de grupo centralizadas.' `
            -Criterios @('ARQ-01','ACC-04') `
            -Recommendation 'Confirmar si el aislamiento es intencional. De no serlo, incorporar al dominio o aplicar una linea base local equivalente y auditable.'))
    }
}
catch {
    $null = $gaps.Add("No se pudo consultar Win32_ComputerSystem: $($_.Exception.Message)")
}

# --- Procesadores -----------------------------------------------------------
try {
    foreach ($cpu in Get-CimInstance Win32_Processor -ErrorAction Stop) {
        $null = $records.Add([pscustomobject]@{
            Tipo            = 'CPU'
            Nombre          = $cpu.Name
            Fabricante      = $cpu.Manufacturer
            Nucleos         = $cpu.NumberOfCores
            HilosLogicos    = $cpu.NumberOfLogicalProcessors
            VelocidadMaxMHz = $cpu.MaxClockSpeed
            Arquitectura    = $cpu.AddressWidth
            SocketDesignation = $cpu.SocketDesignation
            VirtualizacionFirmware = $cpu.VirtualizationFirmwareEnabled
        })
    }
} catch { $null = $gaps.Add("Win32_Processor no disponible: $($_.Exception.Message)") }

# --- Memoria fisica ---------------------------------------------------------
try {
    foreach ($m in Get-CimInstance Win32_PhysicalMemory -ErrorAction Stop) {
        $null = $records.Add([pscustomobject]@{
            Tipo         = 'Memoria'
            Nombre       = $m.DeviceLocator
            CapacidadGB  = [math]::Round($m.Capacity / 1GB, 2)
            VelocidadMHz = $m.Speed
            Fabricante   = $m.Manufacturer
            NumeroParte  = ([string]$m.PartNumber).Trim()
            NumeroSerie  = ([string]$m.SerialNumber).Trim()
        })
    }
} catch { $null = $gaps.Add('Win32_PhysicalMemory no disponible (habitual en maquinas virtuales).') }

# --- Discos fisicos y volumenes --------------------------------------------
try {
    foreach ($d in Get-CimInstance Win32_DiskDrive -ErrorAction Stop) {
        $null = $records.Add([pscustomobject]@{
            Tipo         = 'DiscoFisico'
            Nombre       = $d.Model
            Interfaz     = $d.InterfaceType
            TamanoGB     = [math]::Round($d.Size / 1GB, 2)
            Particiones  = $d.Partitions
            NumeroSerie  = ([string]$d.SerialNumber).Trim()
            MediaType    = $d.MediaType
        })

        # Medio extraible conectado -> DAT-03
        if ($d.MediaType -match '(?i)removable') {
            $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                -Severity 'Medium' -Category 'Medios' `
                -Title 'Medio de almacenamiento extraible conectado al servidor' `
                -Asset ([string]$d.Model) `
                -Detail 'Se detecto una unidad extraible. En servidores de produccion representa un canal de fuga o de introduccion de codigo no autorizado.' `
                -Criterios @('DAT-03','DAT-02') `
                -Recommendation 'Retirar el medio si no responde a una necesidad operativa aprobada y evaluar el bloqueo de dispositivos de almacenamiento por directiva de grupo.'))
        }
    }
} catch { $null = $gaps.Add("Win32_DiskDrive no disponible: $($_.Exception.Message)") }

try {
    foreach ($v in Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop) {
        $libreGB = [math]::Round($v.FreeSpace / 1GB, 2)
        $totalGB = [math]::Round($v.Size / 1GB, 2)
        $pctLibre = if ($v.Size -gt 0) { [math]::Round(($v.FreeSpace / $v.Size) * 100, 1) } else { 0 }
        $null = $records.Add([pscustomobject]@{
            Tipo          = 'Volumen'
            Nombre        = $v.DeviceID
            Etiqueta      = $v.VolumeName
            SistemaArchivos = $v.FileSystem
            TotalGB       = $totalGB
            LibreGB       = $libreGB
            PorcentajeLibre = $pctLibre
        })

        if ($v.FileSystem -and $v.FileSystem -notmatch '(?i)ntfs|refs') {
            $null = $findings.Add((New-AuditFinding -CollectorId $meta.Id -Layer $meta.Layer `
                -Severity 'Medium' -Category 'Almacenamiento' `
                -Title 'Volumen con sistema de archivos sin control de acceso' `
                -Asset ([string]$v.DeviceID) `
                -Detail ("El volumen usa {0}, que no soporta listas de control de acceso (ACL) ni cifrado a nivel de archivo." -f $v.FileSystem) `
                -Criterios @('ACC-04') `
                -Recommendation 'Convertir el volumen a NTFS/ReFS o justificar formalmente su uso si almacena unicamente datos publicos.'))
        }
    }
} catch { $null = $gaps.Add("Win32_LogicalDisk no disponible: $($_.Exception.Message)") }

# --- Adaptadores de red (inventario, la evaluacion va en L7) ---------------
try {
    foreach ($n in Get-CimInstance Win32_NetworkAdapter -Filter 'PhysicalAdapter=True' -ErrorAction Stop) {
        $null = $records.Add([pscustomobject]@{
            Tipo         = 'AdaptadorRed'
            Nombre       = $n.Name
            MAC          = $n.MACAddress
            Estado       = $n.NetConnectionStatus
            VelocidadMbps = if ($n.Speed) { [math]::Round($n.Speed / 1MB, 0) } else { 0 }
        })
    }
} catch { }

$metrics['TotalRegistrosHW'] = $records.Count

New-CollectorResult -Meta $meta -Records $records.ToArray() -Findings $findings.ToArray() `
    -Metrics $metrics -Gaps $gaps.ToArray()
