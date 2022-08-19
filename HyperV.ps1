
New-VM -Name 'A-ADCS1' -MemoryStartupBytes 1024 -Generation 2 -SwitchName (Get-VMSwitch -SwitchType Private) -




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
