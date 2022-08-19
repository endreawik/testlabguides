





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
        New-NetIPAddress -IPAddress $Using:IPAddress -AddressFamily IPv4 -PrefixLength 24 -InterfaceIndex ($NetAdapter.ifIndex)
        
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
        Set-DnsClientServerAddress -ServerAddresses 172.16.1.2 -InterfaceIndex ($NetAdapter.ifIndex)
        Set-DnsClient -ConnectionSpecificSuffix $Using:DNSSuffix -InterfaceIndex ($NetAdapter.ifIndex)
    }
    RemoteScriptBlock $Session $ScriptBlock
}

$Computername = 'adcs'
$IPAddress = '172.16.1.100'
$SwitchName = 'PRIVATE'
$DNSServer = '172.16.1.2'
$DNSSuffix = 'ad.endreawik.com'

$Session = New-PSSession -VMName $Computername -Credential (Get-Credential -Message 'Administrator' -UserName '~\Administrator')

RemoteRenameComputer $Session $Computername
RemoteSetTimeZone $Session
RemoteSetNetwork $Session $SwitchName $IPAddress
RemoteSetDNSConfig $Session $SwitchName $DNSServer $DNSSuffix


Import-module AdmPwd.PS
Update-AdmPwdADSchema

msiexec /q /i 'C:\Users\Administrator\Downloads\LAPS.x64.msi' ADDLOCAL=Management.UI,Management.PS,Management.ADMX
