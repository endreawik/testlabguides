

$Credentials = Get-Credential -Message 'Administrator' -UserName '~\Administrator'
$ADCredentials = Get-Credential -Message 'Administrator' -UserName 'AD\Administrator'
[xml]$xml = Get-Content -Path .\testlabguides\testlabguides.xml

$VMName = Read-Host -Prompt 'VMName'

# set timezone on vm using powershell remoting as job
Invoke-Command -VMName $VMName -ScriptBlock { 
    Set-TimeZone -Id 'W. Europe Standard Time'
} -AsJob -Credential $Credentials

# set network on vm using powershell remoting as job, use xml file instead of read-host
$ServerConfig = $xml.infrastructure.servers.server | Where-Object { $_.name -eq $VMName }
$SwitchName = $ServerConfig.network.switch
$IPAddress = $ServerConfig.network.ip
$Gateway = $ServerConfig.network.gateway
$DNSServer = $ServerConfig.network.dns
$VMNetworkAdapter = Get-VM -Name $VMName | Get-VMNetworkAdapter | Where-Object { $_.SwitchName -eq $SwitchName }
$MacAddress = ($VMNetworkAdapter.MacAddress).ToString()
Invoke-Command -VMName $VMName -ScriptBlock {
    $NetAdapter = Get-NetAdapter | Where-Object { $_.MacAddress -eq ($Using:MacAddress -replace '..(?!$)', '$&-') };
    if ((Get-NetIPAddress -InterfaceIndex ($NetAdapter.ifIndex)).IPv4Address -eq $Using:IPAddress) {
    } else {
        $NetConfig = New-NetIPAddress -IPAddress $Using:IPAddress -AddressFamily IPv4 -PrefixLength 24 -InterfaceIndex ($NetAdapter.ifIndex) -DefaultGateway $Using:Gateway
        $DNSConfig = Set-DnsClientServerAddress -ServerAddresses $Using:DNSServer -InterfaceIndex ($NetAdapter.ifIndex)
    }
} -AsJob -Credential $Credentials

# rename vmname using powershell remoting as job
$Computername = $VMName
Invoke-Command -VMName $VMName -ScriptBlock {
    if ($env:COMPUTERNAME -ne $Using:Computername) {
        Rename-Computer -NewName $Using:Computername
    }
} -AsJob -Credential $Credentials

# restart vm using powershell remoting as job
Invoke-Command -VMName $VMName -ScriptBlock {
    Start-Sleep -Seconds 30
    Restart-Computer -Force
} -AsJob -Credential $Credentials

# wait for vm to restart
Start-Sleep -Seconds 60

# add vm to domain using powershell remoting as job
$DomainName = $xml.infrastructure.domain.name
$Computername = $VMName
Invoke-Command -VMName $VMName -ScriptBlock {
    if ($env:COMPUTERNAME -eq $Using:Computername) {
        Add-Computer -DomainName $Using:DomainName -Credential $Using:ADCredentials -Restart -Force
    }
} -AsJob -Credential $Credentials

# install ADDS using powershell remoting as job
$DomainName = $xml.infrastructure.domain.name
$NetBIOSName = $xml.infrastructure.domain.netbios
$Computername = 'adds1'
Invoke-Command -VMName $VMName -ScriptBlock {
    if ($env:COMPUTERNAME -eq $Using:Computername) {
        Add-WindowsFeature AD-Domain-Services -IncludeManagementTools

        # A-DC-Spooler
        Get-Service -Name Spooler | Stop-Service
        Get-Service -Name Spooler | Set-Service -StartupType Disabled

        Import-Module ADDSDeployment
        Install-ADDSForest `
        -CreateDnsDelegation:$false `
        -DatabasePath "C:\ADDS\NTDS" `
        -DomainMode "WinThreshold" `
        -DomainName $Using:DomainName `
        -DomainNetbiosName $using:NetBIOSName `
        -ForestMode "WinThreshold" `
        -InstallDns:$true `
        -LogPath "C:\ADDS\NTDS" `
        -NoRebootOnCompletion:$false `
        -SysvolPath "C:\ADDS\SYSVOL" `
        -SafeModeAdministratorPassword (ConvertTo-SecureString -String (New-Guid).ToString() -AsPlainText -Force) `
        -Force:$true
    }
} -AsJob -Credential $Credentials

# configure ADDS using powershell remoting as job
$Computername = 'adds1'
Invoke-Command -VMName $VMName -ScriptBlock {
    if ($env:COMPUTERNAME -eq $Using:Computername) {
        # OU Structure
        New-ADOrganizationalUnit -Name 'NEW' -Description '' -Path (Get-ADDomain).DistinguishedName
        New-ADOrganizationalUnit -Name 'tier 0' -Description '' -Path (Get-ADDomain).DistinguishedName
        New-ADOrganizationalUnit -Name 'groups' -Description '' -Path ('OU=tier 0,' + (Get-ADDomain).DistinguishedName)
        New-ADOrganizationalUnit -Name 'servers' -Description '' -Path ('OU=tier 0,' + (Get-ADDomain).DistinguishedName)
        New-ADOrganizationalUnit -Name 'users' -Description '' -Path ('OU=tier 0,' + (Get-ADDomain).DistinguishedName)
        New-ADOrganizationalUnit -Name 'tier 1' -Description '' -Path (Get-ADDomain).DistinguishedName
        New-ADOrganizationalUnit -Name 'groups' -Description '' -Path ('OU=tier 1,' + (Get-ADDomain).DistinguishedName)
        New-ADOrganizationalUnit -Name 'servers' -Description '' -Path ('OU=tier 1,' + (Get-ADDomain).DistinguishedName)
        New-ADOrganizationalUnit -Name 'users' -Description '' -Path ('OU=tier 1,' + (Get-ADDomain).DistinguishedName)
        New-ADOrganizationalUnit -Name 'tier 2' -Description '' -Path (Get-ADDomain).DistinguishedName
        New-ADOrganizationalUnit -Name 'groups' -Description '' -Path ('OU=tier 2,' + (Get-ADDomain).DistinguishedName)
        New-ADOrganizationalUnit -Name 'servers' -Description '' -Path ('OU=tier 2,' + (Get-ADDomain).DistinguishedName)
        New-ADOrganizationalUnit -Name 'users' -Description '' -Path ('OU=tier 2,' + (Get-ADDomain).DistinguishedName)
        New-ADOrganizationalUnit -Name 'tier 3' -Description '' -Path (Get-ADDomain).DistinguishedName
        New-ADOrganizationalUnit -Name 'groups' -Description '' -Path ('OU=tier 3,' + (Get-ADDomain).DistinguishedName)
        New-ADOrganizationalUnit -Name 'computers' -Description '' -Path ('OU=tier 3,' + (Get-ADDomain).DistinguishedName)
        New-ADOrganizationalUnit -Name 'users' -Description '' -Path ('OU=tier 3,' + (Get-ADDomain).DistinguishedName)

        # S-DC-SubnetMissing
        New-ADReplicationSubnet -Name "172.16.1.0/24" -Site 'Default-First-Site-Name'
        # S-ADRegistration
        Set-ADDomain -Identity (Get-ADDomain).DistinguishedName -Replace @{'ms-DS-MachineAccountQuota'='0'}
        # P-Delegated
        $ProtectedUsers = @()
        $ProtectedUsers += Get-ADGroupMember -Identity 'Protected Users'
        $ProtectedUsers += Get-ADGroupMember -Identity 'Domain Admins'
        $ProtectedUsers | Set-ADUser -AccountNotDelegated $true
        # P-RecycleBin
        Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADDomain).Forest -Confirm:$false
        # P-SchemaAdmin
        Set-ADGroup -Identity 'Schema Admins' -Clear member
        # A-MinPwdLen
        Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).Forest -MinPasswordLength 14 -LockoutDuration 00:15:00 -LockoutThreshold 10 -LockoutObservationWindow 00:15:00
        # A-NoServicePolicy
        New-ADFineGrainedPasswordPolicy -Name 'Service Accounts' -Description 'Domain Password Policy for Service Accounts' -Precedence 10 -ComplexityEnabled $true -LockoutDuration 00:15:00 -LockoutThreshold 10 -LockoutObservationWindow 00:15:00 -MinPasswordAge 1 -MaxPasswordAge 365 -MinPasswordLength 32 -PasswordHistoryCount 24 -ReversibleEncryptionEnabled $false -ProtectedFromAccidentalDeletion $true
        New-ADGroup -Name 'Service Accounts' -Description '' -GroupCategory Security -GroupScope Global -Path ('OU=groups,OU=tier 0,' + (Get-ADDomain).DistinguishedName)
        Add-ADFineGrainedPasswordPolicySubject -Identity 'Service Accounts' -Subjects (Get-ADGroup -Identity 'Service Accounts')
        # A-PreWin2000AuthenticatedUsers
        Set-ADGroup -Identity 'Pre-Windows 2000 Compatible Access' -Clear member
        # Configure time
        $PDCEmulator = (Get-ADDomain).PDCEmulator
        w32tm /config /computer:$PDCEmulator /manualpeerlist:time.windows.com /syncfromflags:manual /update
    }
} -AsJob -Credential $ADCredentials

# install additional ADDS using powershell remoting as job
$DomainName = $xml.infrastructure.domain.name
$NetBIOSName = $xml.infrastructure.domain.netbios
$Computername = 'adds2'
Invoke-Command -VMName $VMName -ScriptBlock {
    if ($env:COMPUTERNAME -eq $Using:Computername) {
        Add-WindowsFeature AD-Domain-Services -IncludeManagementTools

        # A-DC-Spooler
        Get-Service -Name Spooler | Stop-Service
        Get-Service -Name Spooler | Set-Service -StartupType Disabled

        Import-Module ADDSDeployment
        Install-ADDSDomainController `
        -CreateDnsDelegation:$false `
        -DatabasePath "C:\ADDS\NTDS" `
        -DomainName $Using:DomainName `
        -InstallDns:$true `
        -LogPath "C:\ADDS\NTDS" `
        -NoRebootOnCompletion:$false `
        -SysvolPath "C:\ADDS\SYSVOL" `
        -SafeModeAdministratorPassword (ConvertTo-SecureString -String (New-Guid).ToString() -AsPlainText -Force) `
        -Force:$true
    }
} -AsJob -Credential $ADCredentials