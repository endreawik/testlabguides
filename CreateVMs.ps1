





# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
# Hyper-V - Create VMs
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #

$ISOPath = 'C:\ISO\en-us_windows_server_2022_updated_aug_2022_x64_dvd_8b65e57f.iso'
$VHDPath = 'C:\VHD'
$VMSwitch = Get-VMSwitch -SwitchType Internal -Name 'NAT'

if (Test-Path -Path $ISOPath) {
    
} else {
    Write-Host 'Error: ISO missing' -ForegroundColor Red
    break
}

function CreateVM ($VMName) {
    if (Get-VM -Name $VMName) {
        Write-Host 'Skipping: ' -ForegroundColor Yellow -NoNewline
        Write-Host $VMName -ForegroundColor Yellow -NoNewline
        Write-Host ' exists' -ForegroundColor Yellow
    } else {
        $VM = New-VM -Name $VMName.ToUpper() -Generation 2 -SwitchName $VMSwitch.Name -NewVHDPath ($VHDPath + "\" + $VMName.ToLower() + "-c.vhdx") -NewVHDSizeBytes 100GB -BootDevice VHD
        Set-VM -Name $VM.Name -ProcessorCount 4 -DynamicMemory -MemoryMinimumBytes 1024MB -MemoryMaximumBytes 8192MB
        Add-VMDvdDrive -VMName $VM.Name -Path $ISOPath
        Set-VMFirmware -VMName $VM.Name -FirstBootDevice (Get-VMDvdDrive -VMName $VM.Name)
        $HostGuardianService = Get-HgsGuardian -Name UntrustedGuardian
        $KeyProtector = New-HgsKeyProtector -Owner $HostGuardianService -AllowUntrustedRoot
        Set-VMKeyProtector -VMName $VM.Name -KeyProtector $KeyProtector.RawData
        Enable-VMTPM -VMName $VM.Name
    }
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
