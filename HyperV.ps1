





# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
# Hyper-V - config
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #

New-Item -Path 'C:\' -Name 'VHD' -ItemType Directory
New-Item -Path 'C:\' -Name 'HYPERV' -ItemType Directory
Set-VMHost -VirtualHardDiskPath 'C:\VHD' -VirtualMachinePath 'C:\HYPERV'

# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
# Hyper-V - network
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #

New-VMSwitch -Name 'PRIVATE' -SwitchType Private

# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
# Hyper-V - Create VMs
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #

$ISOPath = 'C:\ISO\en-us_windows_server_2022_x64_dvd_620d7eac.iso'
$VHDPath = 'C:\VHD'

function CreateVM ($VMName) {
    $VM = New-VM -Name $VMName -Generation 2 -SwitchName (Get-VMSwitch -SwitchType Private).Name -NewVHDPath ($VHDPath + "\" + $VMName.ToLower() + "-c.vhdx") -NewVHDSizeBytes 100GB -BootDevice VHD
    Set-VM -Name $VM.Name -ProcessorCount 4 -DynamicMemory -MemoryMinimumBytes 1024MB -MemoryMaximumBytes 8192MB
    Add-VMDvdDrive -VMName $VM.Name -Path $ISOPath
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