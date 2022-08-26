





# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
# Hyper-V - install
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #

if (Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq 'Enabled' -and $_.FeatureName -eq 'Microsoft-Hyper-V' }) {
    Write-Host 'Skipping: Hyper-V installed' -ForegroundColor Yellow
} else {
    Enable-WindowsOptionalFeature -Online -FeatureName 'Microsoft-Hyper-V' -All
}

# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
# Hyper-V - config
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #

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
