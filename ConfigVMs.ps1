





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
    $ScriptBlock = { 
        if ($env:COMPUTERNAME -eq $Using:Computername) {
            return $false
        } else {
            Rename-Computer -NewName $Using:Computername -WarningVariable $Warn
            return $true
        }
    }
    $RestartRequired = RemoteScriptBlock $Session $ScriptBlock
    return $RestartRequired
}
function RemoteSetTimeZone {
    param (
        $Session
    )
    $ScriptBlock = { 
        if ((Get-TimeZone).Id -eq 'W. Europe Standard Time') {
        } else {
            Set-TimeZone -Id 'W. Europe Standard Time'
        }
    }
    RemoteScriptBlock $Session $ScriptBlock
}
function RemoteAddToDomain {
    param (
        $Session
    )
    $ScriptBlock = { 
        Add-Computer -DomainName ad.endreawik.com -Credential (Get-Credential -Message 'Administrator' -UserName '~\Administrator') }
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
        if ((Get-NetIPAddress -InterfaceIndex ($NetAdapter.ifIndex)).IPv4Address -eq $Using:IPAddress) {
        } else {
            $NetConfig = New-NetIPAddress -IPAddress $Using:IPAddress -AddressFamily IPv4 -PrefixLength 24 -InterfaceIndex ($NetAdapter.ifIndex) -DefaultGateway $Using:Gateway
        }
        
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
        $DNSConfig = Set-DnsClientServerAddress -ServerAddresses $Using:DNSServer -InterfaceIndex ($NetAdapter.ifIndex)
        # Set-DnsClient -ConnectionSpecificSuffix $Using:DNSSuffix -InterfaceIndex ($NetAdapter.ifIndex)
    }
    RemoteScriptBlock $Session $ScriptBlock
}

function InstallAddsLaps () {
    msiexec /q /i 'C:\ENDREAWIK\testlabguides\Download\LAPS.x64.msi' ADDLOCAL=Management.UI,Management.PS,Management.ADMX

    Import-module AdmPwd.PS
    Update-AdmPwdADSchema
    
}

function RemoteRestartComputer () {
    $ScriptBlock = { Restart-Computer -Force }
    RemoteScriptBlock $Session $ScriptBlock
}



# -----


function root1 () {
    $Computername = 'root1'
    $IPAddress = '172.16.1.2'
    $Gateway = '172.16.1.1'
    $DNSServer = '8.8.8.8'
    
    $SwitchName = 'NAT'
    $DNSSuffix = 'ad.endreawik.com'    
}
function adds1 () {
    $Computername = 'adds1'
    $IPAddress = '172.16.1.5'
    $Gateway = '172.16.1.1'
    $DNSServer = '8.8.8.8'
    
    $SwitchName = 'NAT'
    $DNSSuffix = 'ad.endreawik.com'    
}
function adds2 () {
    $Computername = 'adds2'
    $IPAddress = '172.16.1.6'
    $Gateway = '172.16.1.1'
    $DNSServer = '172.16.1.5'
    
    $SwitchName = 'NAT'
    $DNSSuffix = 'ad.endreawik.com'    
}
function adcs1 () {
    $Computername = 'adcs1'
    $IPAddress = '172.16.1.7'
    $Gateway = '172.16.1.1'
    $DNSServer = '172.16.1.5'
    
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
    $IPAddress = '172.16.1.8'
    $Gateway = '172.16.1.1'
    $DNSServer = '172.16.1.5'

    $SwitchName = 'NAT'
    $DNSSuffix = 'ad.endreawik.com'
}
function web2 () {
    $Computername = 'web2'
    $IPAddress = '172.16.1.9'
    $Gateway = '172.16.1.1'
    $DNSServer = '172.16.1.5'

    $SwitchName = 'NAT'
    $DNSSuffix = 'ad.endreawik.com'
}

function admin1 () {
    $Computername = 'admin1'
    $IPAddress = '172.16.1.9'
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
function sql1 () {
    $Computername = 'sql1'
    $IPAddress = '172.16.1.8'
    $Gateway = '172.16.1.1'
    $DNSServer = '172.16.1.2'

    $SwitchName = 'NAT'
    $DNSSuffix = 'ad.endreawik.com'
}

function client1 () {
    $Computername = 'client1'
    $IPAddress = '172.16.1.100'
    $Gateway = '172.16.1.1'
    $DNSServer = '172.16.1.2'

    $SwitchName = 'NAT'
    $DNSSuffix = 'ad.endreawik.com'
}

function client2 () {
    $Computername = 'client2'
    $IPAddress = '172.16.1.102'
    $Gateway = '172.16.1.1'
    $DNSServer = '172.16.1.2'

    $SwitchName = 'NAT'
    $DNSSuffix = 'ad.endreawik.com'
}

function azad1 () {
    $Computername = 'azad1'
    $IPAddress = '172.16.1.11'
    $Gateway = '172.16.1.1'
    $DNSServer = '172.16.1.5'
    
    $SwitchName = 'NAT'
    $DNSSuffix = 'ad.endreawik.com'    
}

function nps1 () {
    $Computername = 'nps1'
    $IPAddress = '172.16.1.12'
    $Gateway = '172.16.1.1'
    $DNSServer = '172.16.1.5'
    
    $SwitchName = 'NAT'
    $DNSSuffix = 'ad.endreawik.com'    
}
function eads2 () {
    $Computername = 'nps1'
    $IPAddress = '172.16.1.15'
    $Gateway = '172.16.1.1'
    $DNSServer = '172.16.1.5'
    
    $SwitchName = 'NAT'
    $DNSSuffix = 'ad.endreawik.com'    
}
function exch1 () {
    $Computername = 'exch1'
    $IPAddress = '172.16.1.16'
    $Gateway = '172.16.1.1'
    $DNSServer = '172.16.1.5'
    
    $SwitchName = 'NAT'
    $DNSSuffix = 'ad.endreawik.com'    
}