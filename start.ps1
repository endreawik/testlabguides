





function RemoteScriptBlock {
    param (
        $Session,
        $ScriptBlock
    )
    
    Invoke-Command -Session $Session -ScriptBlock $ScriptBlock
}
function RemoteRenameComputer {
    param (
        $Session,
        $Computername
    )
    $ScriptBlock = { Rename-Computer -NewName $Using:Computername -Restart }
    RemoteScriptBlock $Session $ScriptBlock
}
function RemoteSetTimeZone {
    param (
        $Session
    )
    $ScriptBlock = { Set-TimeZone -Id 'W. Europe Standard Time' }
    RemoteScriptBlock $Session $ScriptBlock
}
function RemoteSetNetwork {
    param (
        $Session,
        $SwitchName,
        $IPAddress
    )
    $VMNetworkAdapter = Get-VM -Name $Computername | Get-VMNetworkAdapter | Where-Object { $_.SwitchName -eq $SwitchName }
    $MacAddress = ($VMNetworkAdapter.MacAddress).ToString()
    $IPAddress = $IPAddress
    $ScriptBlock = { 
        $NetAdapter = Get-NetAdapter | Where-Object { $_.MacAddress -eq ($Using:MacAddress -replace '..(?!$)', '$&-') }; 
        New-NetIPAddress -IPAddress $Using:IPAddress -AddressFamily IPv4 -PrefixLength 24 -InterfaceIndex ($NetAdapter.ifIndex) -DefaultGateway $Using:Gateway
        
    }
    RemoteScriptBlock $Session $ScriptBlock
}
function RemoteSetDNSConfig {
    param (
        $Session,
        $SwitchName,
        $DNSServer,
        $DNSSuffix
    )
    $VMNetworkAdapter = Get-VM -Name $Computername | Get-VMNetworkAdapter | Where-Object { $_.SwitchName -eq $SwitchName }
    $MacAddress = ($VMNetworkAdapter.MacAddress).ToString()
    $ScriptBlock = { 
        $NetAdapter = Get-NetAdapter | Where-Object { $_.MacAddress -eq ($Using:MacAddress -replace '..(?!$)', '$&-') }; 
        Set-DnsClientServerAddress -ServerAddresses $Using:DNSServer -InterfaceIndex ($NetAdapter.ifIndex)
        # Set-DnsClient -ConnectionSpecificSuffix $Using:DNSSuffix -InterfaceIndex ($NetAdapter.ifIndex)
    }
    RemoteScriptBlock $Session $ScriptBlock
}

$Computername = 'adds1'
$IPAddress = '172.16.1.3'
$Gateway = '172.16.1.1'
$DNSServer = '172.16.1.2'

$SwitchName = 'NAT'
$DNSSuffix = 'ad.endreawik.com'

$Session = New-PSSession -VMName $Computername -Credential (Get-Credential -Message 'Administrator' -UserName '~\Administrator')
RemoteRenameComputer $Session $Computername
RemoteSetTimeZone $Session
RemoteSetNetwork $Session $SwitchName $IPAddress
RemoteSetDNSConfig $Session $SwitchName $DNSServer $DNSSuffix

$Computername = 'adcs1'
$IPAddress = '172.16.1.3'
$Gateway = '172.16.1.1'
$DNSServer = '172.16.1.2'

$SwitchName = 'NAT'
$DNSSuffix = 'ad.endreawik.com'

$Session = New-PSSession -VMName $Computername -Credential (Get-Credential -Message 'Administrator' -UserName '~\Administrator')
RemoteRenameComputer $Session $Computername
RemoteSetTimeZone $Session
RemoteSetNetwork $Session $SwitchName $IPAddress
RemoteSetDNSConfig $Session $SwitchName $DNSServer $DNSSuffix


msiexec /q /i 'C:\TEMP\LAPS.x64.msi' ADDLOCAL=Management.UI,Management.PS,Management.ADMX

Import-module AdmPwd.PS
Update-AdmPwdADSchema

Add-Computer -DomainName ad.endreawik.com -Credential (Get-Credential -Message 'Administrator' -UserName '~\Administrator')

Get-ChildItem -LiteralPath .\testlabguides\GroupPolicy -Recurse -File | ForEach-Object { Copy-VMFile -VMName ADDS1 -SourcePath $_.FullName -DestinationPath $_.FullName -CreateFullPath -FileSource Host }

Import-GPO -Path 'C:\ENDREAWIK\testlabguides\GroupPolicy' -BackupId '2DD46DF8-70E8-4801-89AF-14E7C808BBF6' -TargetName 'EAW Windows Server - Domain Controller' -CreateIfNeeded
Import-GPO -Path 'C:\ENDREAWIK\testlabguides\GroupPolicy' -BackupId '356BBC58-0677-47EA-9033-2DC3C12E7E04' -TargetName 'EAW Autoenrollment Policy' -CreateIfNeeded
Import-GPO -Path 'C:\ENDREAWIK\testlabguides\GroupPolicy' -BackupId '74C66341-BF66-4E47-8D3D-9A6360CC3F07' -TargetName 'EAW Windows Server - Member Server' -CreateIfNeeded