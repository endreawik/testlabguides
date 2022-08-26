





# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
# Hyper-V - config
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
$InputHyperV = Read-Host -Prompt 'Konfigurere Hyper-V? (J/N)'

if ($InputHyperV -eq 'J') {
    if (Test-Path -Path C:\VHD) {
        Write-Host 'Skipping: C:\VHD exist' -ForegroundColor Yellow
    } else {
        New-Item -Path 'C:\' -Name 'VHD' -ItemType Directory
    }

    if (Test-Path -Path C:\HYPERV) {
        Write-Host 'Skipping: C:\HYPERV exist' -ForegroundColor Yellow
    } else {
        New-Item -Path 'C:\' -Name 'HYPERV' -ItemType Directory
    }

    if (Test-Path -Path C:\ISO) {
        Write-Host 'Skipping: C:\ISO exist' -ForegroundColor Yellow
    } else {
        New-Item -Path 'C:\' -Name 'ISO' -ItemType Directory
    }

    if ((Get-VMHost).VirtualHardDiskPath -eq 'C:\VHD') {
        Write-Host 'Skipping: VHD path set' -ForegroundColor Yellow
    } else {
        Set-VMHost -VirtualHardDiskPath 'C:\VHD'
    }

    if ((Get-VMHost).VirtualMachinePath -eq 'C:\HYPERV') {
        Write-Host 'Skipping: VM path set' -ForegroundColor Yellow
    } else {
        Set-VMHost -VirtualMachinePath 'C:\HYPERV'
    }
}

# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
# Hyper-V - network
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
# https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/setup-nat-network

if (Get-NetNat) {
    Write-Host 'Skipping: NAT network configured' -ForegroundColor Yellow
    $NATSwitch = Get-VMSwitch -SwitchType Internal | Where-Object { $_.Name -ne 'Default Switch'}
} else {
    $InputNATNet = Read-Host -Prompt 'Konfigurere NAT nettverk? (J/N) (trenger admin)'
    if ($InputNATNet -eq 'J') {

        $NATSwitch = New-VMSwitch -SwitchName 'NAT' -SwitchType Internal
    
        $NATIPAddress = New-NetIPAddress -IPAddress 172.16.1.1 -PrefixLength 24 -InterfaceIndex (Get-NetAdapter | Where-Object { $_.Name -match 'NAT' }).ifIndex
    
        $NATNet = New-NetNat -Name NATnetwork -InternalIPInterfaceAddressPrefix 172.16.1.0/24
    }
}

# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
# Hyper-V - Create VMs
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
$ISOPath = 'C:\ISO\en-us_windows_server_2022_x64_dvd_620d7eac.iso'
$VHDPath = 'C:\VHD'

if (Test-Path -Path $ISOPath) {
    
} else {
    Write-Host 'Error: ISO missing' -ForegroundColor Red
    break
}

function CreateVM ($VMName) {
    $VM = New-VM -Name $VMName.ToUpper() -Generation 2 -SwitchName 'NAT' -NewVHDPath ($VHDPath + "\" + $VMName.ToLower() + "-c.vhdx") -NewVHDSizeBytes 100GB -BootDevice VHD
    Set-VM -Name $VM.Name -ProcessorCount 4 -DynamicMemory -MemoryMinimumBytes 1024MB -MemoryMaximumBytes 8192MB
    Add-VMDvdDrive -VMName $VM.Name -Path $ISOPath
    Set-VMFirmware -VMName $VM.Name -FirstBootDevice (Get-VMDvdDrive -VMName $VM.Name)
    $HostGuardianService = Get-HgsGuardian -Name UntrustedGuardian
    $KeyProtector = New-HgsKeyProtector -Owner $HostGuardianService -AllowUntrustedRoot
    Set-VMKeyProtector -VMName $VM.Name -KeyProtector $KeyProtector.RawData
    Enable-VMTPM -VMName $VM.Name
}

$VMName = 'ADCS1'
CreateVM $VMName
$VMName = 'ADDS1'
CreateVM $VMName
$VMName = 'ADFS1'
CreateVM $VMName
$VMName = 'ADFS2'
CreateVM $VMName
$VMName = 'RAS1'
CreateVM $VMName
$VMName = 'WEB1'
CreateVM $VMName