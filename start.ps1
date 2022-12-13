





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
    $ScriptBlock = { Rename-Computer -NewName $Using:Computername }
    RemoteScriptBlock $Session $ScriptBlock
}
function RemoteSetTimeZone {
    param (
        $Session
    )
    $ScriptBlock = { Set-TimeZone -Id 'W. Europe Standard Time' }
    RemoteScriptBlock $Session $ScriptBlock
}
function RemoteAddToDomain {
    param (
        $Session
    )
    $ScriptBlock = { Add-Computer -DomainName ad.endreawik.com -Credential (Get-Credential -Message 'Administrator' -UserName '~\Administrator') }
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

function InstallAddsLaps () {
    msiexec /q /i 'C:\ENDREAWIK\testlabguides\Download\LAPS.x64.msi' ADDLOCAL=Management.UI,Management.PS,Management.ADMX

    Import-module AdmPwd.PS
    Update-AdmPwdADSchema
    
}



# -----


function adds1 () {
    $Computername = 'adds1'
    $IPAddress = '172.16.1.3'
    $Gateway = '172.16.1.1'
    $DNSServer = '8.8.8.8'
    
    $SwitchName = 'NAT'
    $DNSSuffix = 'ad.endreawik.com'    
}
function adcs1 () {
    $Computername = 'adcs1'
    $IPAddress = '172.16.1.3'
    $Gateway = '172.16.1.1'
    $DNSServer = '172.16.1.2'
    
    $SwitchName = 'NAT'
    $DNSSuffix = 'ad.endreawik.com'    
}

function adfs1 () {
    $Computername = 'adfs1'
    $IPAddress = '172.16.1.4'
    $Gateway = '172.16.1.1'
    $DNSServer = '172.16.1.2'
    
    $SwitchName = 'NAT'
    $DNSSuffix = 'ad.endreawik.com'
}

function web1 () {
    $Computername = 'web1'
    $IPAddress = '172.16.1.5'
    $Gateway = '172.16.1.1'
    $DNSServer = '8.8.8.8'

    $SwitchName = 'NAT'
    $DNSSuffix = 'ad.endreawik.com'
}

function admin1 () {
    $Computername = 'admin1'
    $IPAddress = '172.16.1.6'
    $Gateway = '172.16.1.1'
    $DNSServer = '172.16.1.2'

    $SwitchName = 'NAT'
    $DNSSuffix = 'ad.endreawik.com'
}

function dhcp1 () {
    $Computername = 'dhcp1'
    $IPAddress = '172.16.1.7'
    $Gateway = '172.16.1.1'
    $DNSServer = '172.16.1.2'

    $SwitchName = 'NAT'
    $DNSSuffix = 'ad.endreawik.com'
}

$Session = New-PSSession -VMName $Computername -Credential (Get-Credential -Message 'Administrator' -UserName '~\Administrator')
RemoteSetTimeZone $Session
RemoteSetNetwork $Session $SwitchName $IPAddress
RemoteSetDNSConfig $Session $SwitchName $DNSServer $DNSSuffix
RemoteRenameComputer $Session $Computername
RemoteAddToDomain $Session