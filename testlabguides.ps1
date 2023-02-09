[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $inputFile
)
$inputFile = '.\testlabguides\testlabguides.xml'
[xml]$xmlInput = Get-Content -LiteralPath $inputFile

$xmlservers = $xmlInput.infrastructure.compute.servers.server

$xmlserver = $xmlservers | Where-Object { $_.Name -eq 'adds1' }

# Create VMs

CreateVM $VMName

# Configure Operating System

$Session = New-PSSession -VMName $Computername -Credential (Get-Credential -Message 'Administrator' -UserName '~\Administrator')
RemoteSetTimeZone $Session
RemoteSetNetwork $Session $SwitchName $IPAddress
RemoteSetDNSConfig $Session $SwitchName $DNSServer $DNSSuffix
RemoteRenameComputer $Session $Computername
RemoteRestartComputer $Session
$Session = New-PSSession -VMName $Computername -Credential (Get-Credential -Message 'Administrator' -UserName '~\Administrator')
RemoteAddToDomain $Session
RemoteRestartComputer $Session
$Session = New-PSSession -VMName $Computername -Credential (Get-Credential -Message 'Administrator' -UserName '~\Administrator')

# Configure Roles and Features