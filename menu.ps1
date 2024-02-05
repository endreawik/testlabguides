





# $Credentials = Get-Credential -Message 'Administrator' -UserName '.\Administrator'
# $ADCredentials = Get-Credential -Message 'Administrator' -UserName 'AD\Administrator'

[xml]$xml = Get-Content -Path '.\testlabguides\testlabguides.xml'
$VHDPath = 'C:\VHD'

# function to get ISO path
function GetISOPath {
    param (
        $NameAndType
    )
    $ServerEvalIso = Get-ChildItem -Path 'C:\ISO' -Filter '*.iso' | Where-Object { $_.Name -match 'Server' } | Where-Object { $_.Name -match 'Eval' } | Select-Object -First 1
    $ClientEvalIso = Get-ChildItem -Path 'C:\ISO' -Filter '*.iso' | Where-Object { $_.Name -match 'Client' } | Where-Object { $_.Name -match 'Eval' } | Select-Object -First 1
    $ExchangeCUIso = Get-ChildItem -Path 'C:\ISO' -Filter '*.iso' | Where-Object { $_.Name -match 'Exchange' } | Where-Object { $_.Name -match 'CU' } | Select-Object -First 1
    
    switch ($NameAndType) {
        "WindowsServerEval" { 
            $ServerEvalIso.FullName
        }
        "WindowsClientEval" {
            $ClientEvalIso.FullName
        }
        "ExchangeServer" {
            $ExchangeCUIso.FullName
        }
        Default {
            $ServerEvalIso.FullName
        }
    }
}

# function to create VM
function CreateVirtualMachine {
    param (
        $XMLServerNode
    )
    $VMName = $XMLServerNode.name
    $VMISOPath = GetISOPath -NameAndType $XMLServerNode.operatingsystem.type
    $VMSwitch = Get-VMSwitch -Name $XMLServerNode.network.switch
    if (!$VMSwitch) {
        Write-Host "VMSwitch $VMSwitch missing, skipping VM" -ForegroundColor Red
        break
    }
    $VMRAMmin = $XMLServerNode.hardware.rammin + "MB"
    $VMRAMmax = $XMLServerNode.hardware.rammax + "MB"

    $VM = New-VM -Name $VMName.ToUpper() -Generation 2 -SwitchName $VMSwitch.Name -NewVHDPath ($VHDPath + "\" + $VMName.ToLower() + "-c.vhdx") -NewVHDSizeBytes 100GB -BootDevice VHD
    Set-VM -Name $VM.Name -ProcessorCount 4 -DynamicMemory -MemoryMinimumBytes $VMRAMmin -MemoryMaximumBytes $VMRAMmax -MemoryStartupBytes $VMRAMmin
    Add-VMDvdDrive -VMName $VM.Name -Path $VMISOPath
    Set-VMFirmware -VMName $VM.Name -FirstBootDevice (Get-VMDvdDrive -VMName $VM.Name)
    $HostGuardianService = Get-HgsGuardian -Name UntrustedGuardian
    $KeyProtector = New-HgsKeyProtector -Owner $HostGuardianService -AllowUntrustedRoot
    Set-VMKeyProtector -VMName $VM.Name -KeyProtector $KeyProtector.RawData
    Enable-VMTPM -VMName $VM.Name
}

# Check if VM is configured (with correct IP)
function CheckConfiguredVM {
    param (
        $XMLServerNode
    )
    $IPv4Pattern = '^((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    $VM = Get-VM -Name $XMLServerNode.name
    $VM.NetworkAdapters.ipaddresses | ForEach-Object { if ($_ -match $XMLServerNode.network.ip) { return $true } }
}

Clear-Host
Write-Host " "
Write-Host "----- ----- ----- ----- ----- ----- ----- ----- ----- -----"
Write-Host "                      Test Lab Guides                      "
Write-Host "----- ----- ----- ----- ----- ----- ----- ----- ----- -----"
Write-Host " "
# Read-Host -Prompt 'Press enter to continue'

$showmenu = $true

while ($showmenu) {
    Clear-Host
    Write-Host " "
    Write-Host "----- ----- ----- ----- ----- ----- ----- ----- ----- -----"
    Write-Host "                      Test Lab Guides                      "
    Write-Host "----- ----- ----- ----- ----- ----- ----- ----- ----- -----"
    Write-Host " "
    Write-Host " 1. Create Virtual Machines"
    Write-Host " 2. Configure OS (name, language, network)"
    Write-Host " 3. Install and Configure ADDS"
    Write-Host " 4. Install and Configure ADCS"
    Write-Host " 5. Install and Configure Exchange"
    Write-Host " 6. Install and Configure DHCP"
    Write-Host " 9. Configure Credentials"
    Write-Host " "
    Write-Host " 0. exit"
    Write-Host " "
    Write-Host "----- ----- ----- ----- ----- ----- ----- ----- ----- -----"
    $UserInput_Menu = Read-Host -Prompt 'Menu option'

    switch ($UserInput_Menu) {
        0 {
            $showmenu = $false
        }
        1 { # Create VMs
            Clear-Host
            Write-Host " ----- ----- ----- ----- -----"
            Write-Host "  Creating Virtual Machines   "
            Write-Host " ----- ----- ----- ----- -----"
            $VMs = Get-VM

            foreach ($xmlserver in $xml.infrastructure.servers.server) {
                $VMexist = $VMs | Where-Object { $_.Name -match ($xmlserver.name) }
                if ($VMexist) {
                    Write-Host "Virtual machine $($xmlserver.name) exists, skipping" -ForegroundColor Yellow
                } else {
                    Write-Host "Virtual machine $($xmlserver.name) missing, creating" -ForegroundColor Cyan
                    CreateVirtualMachine -XMLServerNode $xmlserver
                }
            }
            Read-Host -Prompt 'Press enter to continue'
        }
        2 { # Configure VMs
            Clear-Host
            Write-Host " ----- ----- ----- ----- -----"
            Write-Host " Configuring Operating System "
            Write-Host " ----- ----- ----- ----- -----"
            $VMsRunning = Get-VM | Where-Object { $_.State -eq 'Running' }

            foreach ($xmlserver in $xml.infrastructure.servers.server) {
                $VMready = $VMsRunning | Where-Object { $_.Name -match ($xmlserver.name) }
                if ($VMready) {
                    if (CheckConfiguredVM -XMLServerNode $xmlserver) {
                        Write-Host "Virtual machine $($xmlserver.name) configured, skipping" -ForegroundColor Green
                        continue
                    }
                    Write-Host "Virtual machine $($xmlserver.name) not configured, configuring" -ForegroundColor Yellow

                    $SwitchName = $xmlserver.network.switch
                    $IPAddress = $xmlserver.network.ip
                    $Gateway = $xmlserver.network.gateway
                    $DNSServer = '1.1.1.1'
                    $VMNetworkAdapter = Get-VM -Name $xmlserver.name | Get-VMNetworkAdapter | Where-Object { $_.SwitchName -eq $SwitchName }
                    $MacAddress = ($VMNetworkAdapter.MacAddress).ToString()

                    $Computername = $xmlserver.name
                    Invoke-Command -VMName $xmlserver.name -ScriptBlock {
                        Set-TimeZone -Id 'W. Europe Standard Time'

                        $NetAdapter = Get-NetAdapter | Where-Object { $_.MacAddress -eq ($Using:MacAddress -replace '..(?!$)', '$&-') };
                        if ((Get-NetIPAddress -InterfaceIndex ($NetAdapter.ifIndex)).IPv4Address -eq $Using:IPAddress) {
                        } else {
                            $NetConfig = New-NetIPAddress -IPAddress $Using:IPAddress -AddressFamily IPv4 -PrefixLength 24 -InterfaceIndex ($NetAdapter.ifIndex) -DefaultGateway $Using:Gateway
                            $DNSConfig = Set-DnsClientServerAddress -ServerAddresses $Using:DNSServer -InterfaceIndex ($NetAdapter.ifIndex)
                        }

                        if ($env:COMPUTERNAME -ne $Using:Computername) {
                            Rename-Computer -NewName $Using:Computername
                        }
                        Start-Sleep -Seconds 30
                        Restart-Computer -Force
                    } -AsJob -Credential $Credentials
                } else {
                    Write-Host "Virtual machine $($xmlserver.name) not ready, skipping" -ForegroundColor Red
                }
            }
            Read-Host -Prompt 'Press enter to continue'
        }
        3 { # ADDS
            $showsubmenuadds = $true
            while ($showsubmenuadds) {
                Clear-Host
                Write-Host " ----- ----- ----- ----- ----- ----- ----- ----- ----- -----"
                Write-Host " 1. Install ADDS"
                Write-Host " 2. Configure ADDS (ikke kjør ale VMer er ferdig)"
                Write-Host " 3. Add Virtual Machines to domain"
                Write-Host " "
                Write-Host " 0. exit"
                Write-Host " ----- ----- ----- ----- ----- ----- ----- ----- ----- -----"
            
                $UserInput_SubMenu = Read-Host -Prompt 'Menu option'

                switch ($UserInput_SubMenu) {
                    0 {
                        $showsubmenuadds = $false
                    }
                    1 {
                        $VMsRunning = Get-VM | Where-Object { $_.State -eq 'Running' }

                        foreach ($xmlserver in $xml.infrastructure.servers.server) {
                            $VMready = $VMsRunning | Where-Object { $_.Name -match ($xmlserver.name) }
                            if ($VMready) {
                                if ($xmlserver.role -eq 'adds') {
                                    Write-Host $xmlserver.name -ForegroundColor Green
                                    $DomainName = $xml.infrastructure.domain.name
                                    $NetBIOSName = $xml.infrastructure.domain.netbios
                                    $Job = Invoke-Command -VMName $xmlserver.name -ScriptBlock {
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
                                    } -AsJob -Credential $Credentials
            
                                    Wait-Job -Job $Job
                                }
                            } else {
                                # Write-Host ($xmlserver.name)"not ready" -ForegroundColor Red
                            }
                        }
                        Read-Host -Prompt 'Press enter to continue'
                    }
                    2 {
                        $VMsRunning = Get-VM | Where-Object { $_.State -eq 'Running' }

                        foreach ($xmlserver in $xml.infrastructure.servers.server) {
                            $VMready = $VMsRunning | Where-Object { $_.Name -match ($xmlserver.name) }
                            if ($VMready) {
                                if ($xmlserver.role -eq 'adds') {
                                    Write-Host $xmlserver.name -ForegroundColor Green
                                    $Job = Invoke-Command -VMName $xmlserver.name -ScriptBlock {
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
                                    } -AsJob -Credential $ADCredentials
            
                                    Wait-Job -Job $Job
                                }
                            } else {
                                # Write-Host ($xmlserver.name)"not ready" -ForegroundColor Red
                            }
                        }
                        Read-Host -Prompt 'Press enter to continue'
                    }
                    3 {
                        Clear-Host
                        $VMsRunning = Get-VM | Where-Object { $_.State -eq 'Running' }
                        $ADCredentials = Get-Credential -Message 'AD Administrator' -UserName 'AD\Administrator'
                        foreach ($xmlserver in $xml.infrastructure.servers.server) {
                            $VMready = $VMsRunning | Where-Object { $_.Name -match ($xmlserver.name) }
                            if ($VMready) {
                                Write-Host $xmlserver.name -ForegroundColor Green

                                if ($xmlserver.type -eq 'domain') {
                                    $DomainName = $xml.infrastructure.domain.name
                                    $Computername = $xmlserver.name
                                    $SwitchName = $xmlserver.network.switch
                                    $VMNetworkAdapter = Get-VM -Name $xmlserver.name | Get-VMNetworkAdapter | Where-Object { $_.SwitchName -eq $SwitchName }
                                    $MacAddress = ($VMNetworkAdapter.MacAddress).ToString()
                                    $xmlserveradds = $xml.infrastructure.servers.server | Where-Object { $_.role -eq 'adds' }
                                    Invoke-Command -VMName $xmlserver.name -ScriptBlock {
                                        if ($env:COMPUTERNAME -eq $Using:Computername) {
                                            $xmlserveradds = $Using:xmlserveradds
                                            $NetAdapter = Get-NetAdapter | Where-Object { $_.MacAddress -eq ($Using:MacAddress -replace '..(?!$)', '$&-') };
                                            $DNSConfig = Set-DnsClientServerAddress -ServerAddresses $Using:xmlserveradds.network.ip -InterfaceIndex ($NetAdapter.ifIndex)
                                            Start-Sleep -Seconds 10
                                            Add-Computer -DomainName $Using:DomainName -Credential $Using:ADCredentials -Restart -Force
                                        }
                                    } -AsJob -Credential $Credentials
                                }
                            } else {
                                Write-Host ($xmlserver.name)"not ready" -ForegroundColor Red
                            }
                        }
                        Read-Host -Prompt 'Press enter to continue'
                    }
                    5 {
                        Clear-Host
                        $ADCredentials = Get-Credential -Message 'AD Administrator' -UserName 'AD\Administrator'
                    }
                }
            }
        }
        4 { # ADCS
            $showsubmenuadcs = $true
            while ($showsubmenuadcs) {
                Clear-Host
                Write-Host " ----- ----- ----- ----- ----- ----- ----- ----- ----- -----"
                Write-Host " "
                Write-Host " 1. Install IIS"
                Write-Host " 2. Install ROOT"
                Write-Host " 3. Distribute CRT and CRL"
                Write-Host " 4. Install ADCS (manuelle steg)"
                Write-Host " "
                Write-Host " 0. exit"
                Write-Host " ----- ----- ----- ----- ----- ----- ----- ----- ----- -----"
            
                $UserInput_SubMenu = Read-Host -Prompt 'Menu option'

                switch ($UserInput_SubMenu) {
                    0 {
                        $showsubmenuadcs = $false
                    }
                    1 {
                        $VMsRunning = Get-VM | Where-Object { $_.State -eq 'Running' }

                        foreach ($xmlserver in $xml.infrastructure.servers.server) {
                            $VMready = $VMsRunning | Where-Object { $_.Name -match ($xmlserver.name) }
                            if ($VMready) {
                                if ($xmlserver.role -eq 'iis') {
                                    Invoke-Command -VMName $xmlserver.name -ScriptBlock {
                                        Install-WindowsFeature -Name Web-Default-Doc, Web-Dir-Browsing, Web-Http-Errors, Web-Static-Content, Web-Http-Logging, Web-Stat-Compression, Web-Filtering, Web-Mgmt-Console
                                    } -AsJob -Credential $Credentials
                                }
                            } else {
                            }
                        }
                        Read-Host -Prompt 'Press enter to continue'
                    }
                    2 { # ADCS root
                        $VMsRunning = Get-VM | Where-Object { $_.State -eq 'Running' }

                        foreach ($xmlserver in $xml.infrastructure.servers.server) {
                            $VMready = $VMsRunning | Where-Object { $_.Name -match ($xmlserver.name) }
                            if ($VMready) {
                                if ($xmlserver.role -eq 'root') {
                                    $Session = New-PSSession -VMName $xmlserver.name -Credential $Credentials
                                    Copy-Item -Path '.\testlabguides\CAPolicy-root.ini' -Destination 'C:\Windows\CAPolicy.ini' -ToSession $Session
                                    Invoke-Command -VMName $xmlserver.name -ScriptBlock {
                                        Install-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools
                                        Install-AdcsCertificationAuthority -CAType StandaloneRootCA -CACommonName 'Endre A Wik Root CA' -KeyLength 384 -HashAlgorithmName SHA256 -CryptoProviderName 'ECDSA_P384#Microsoft Software Key Storage Provider' -ValidityPeriod Years -ValidityPeriodUnits 20 -Force

                                        $CRLs = Get-CACrlDistributionPoint
                                        foreach ($CRL in $CRLs) {
                                            Remove-CACrlDistributionPoint -Uri $CRL.Uri -Force
                                        }

                                        Restart-Service CertSvc

                                        Add-CACrlDistributionPoint -Uri 'C:\Windows\System32\CertSrv\CertEnroll\%3%8.crl' -PublishToServer -Force
                                        Add-CACrlDistributionPoint -Uri 'http://pki.ad.endreawik.no/%3%8.crl' -AddToCertificateCdp -Force

                                        Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } | Remove-CAAuthorityInformationAccess -Force

                                        certutil -setreg CACRLPeriod Years
                                        certutil -setreg CACRLPeriodUnits 1

                                        Restart-Service CertSvc

                                        certutil -crl

                                        Get-Item -Path 'C:\Windows\System32\CertSrv\CertEnroll\*.crt' | Rename-Item -NewName 'Endre A Wik Root CA.crt'
                                        
                                    } -AsJob -Credential $Credentials
                                }
                            } else {
                            }
                        }
                        Read-Host -Prompt 'Press enter to continue'
                    }
                    3 { # ADCS distribute
                        $VMsRunning = Get-VM | Where-Object { $_.State -eq 'Running' }
                        $Certificate = 'Endre A Wik Root CA'
                        $xml.infrastructure.servers.server | Where-Object { $_.role -eq 'root' } | ForEach-Object {
                            $Credentials = Get-Credential -Message "Local Administrator"
                            $Session = New-PSSession -VMName $_.name -Credential $Credentials
                            Copy-Item -Path "C:\Windows\System32\CertSrv\CertEnroll\$Certificate.crl" -Destination 'C:\TEMP' -FromSession $Session -Force
                            Copy-Item -Path "C:\Windows\System32\CertSrv\CertEnroll\$Certificate.crt" -Destination 'C:\TEMP' -FromSession $Session -Force
                            Remove-PSSession -Session $Session
                        }
                        $xml.infrastructure.servers.server | Where-Object { $_.role -eq 'iis' } | ForEach-Object {
                            $Credentials = Get-Credential -Message "Local Administrator"
                            $Session = New-PSSession -VMName $_.name -Credential $Credentials
                            Copy-Item -Path "C:\TEMP\$Certificate.crl" -Destination 'C:\inetpub\wwwroot' -ToSession $Session -Force
                            Copy-Item -Path "C:\TEMP\$Certificate.crt" -Destination 'C:\inetpub\wwwroot' -ToSession $Session -Force
                            Remove-PSSession -Session $Session
                        }
                        $xml.infrastructure.servers.server | Where-Object { $_.role -eq 'adds' } | ForEach-Object {
                            $ADCredentials = Get-Credential -Message "Domain Administrator"
                            $Session = New-PSSession -VMName $_.name -Credential $ADCredentials
                            Copy-Item -Path "C:\TEMP\$Certificate.crt" -Destination 'C:\' -ToSession $Session -Force

                            Start-Sleep -Seconds 10
                            Invoke-Command -VMName $_.name -ScriptBlock {
                                certutil.exe -dsPublish -f "C:\$Using:Certificate.crt" RootCA
                                Start-Sleep -Seconds 10
                                Remove-Item -Path "C:\$Using:Certificate.crt" -Force

                                Add-DnsServerResourceRecord -A -Name 'pki' -ZoneName 'ad.endreawik.no' -IPv4Address 172.16.1.10
                            } -AsJob -Credential $ADCredentials
                            Remove-PSSession -Session $Session
                        }
                        Read-Host -Prompt 'Press enter to continue'
                    }
                    4 {
                        $VMsRunning = Get-VM | Where-Object { $_.State -eq 'Running' }

                        foreach ($xmlserver in $xml.infrastructure.servers.server) {
                            $VMready = $VMsRunning | Where-Object { $_.Name -match ($xmlserver.name) }
                            if ($VMready) {
                                if ($xmlserver.role -eq 'adcs') {
                                    $Session = New-PSSession -VMName $xmlserver.name -Credential $ADCredentials
                                    Copy-Item -Path '.\testlabguides\CAPolicy-ent.ini' -Destination 'C:\Windows\CAPolicy.ini' -ToSession $Session

                                    Invoke-Command -VMName $xmlserver.name -ScriptBlock {
                                        Install-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools
                                        Install-AdcsCertificationAuthority -CAType EnterpriseSubordinateCA -CACommonName 'Endre A Wik Enterprise CA' -KeyLength 384 -HashAlgorithmName SHA256 -CryptoProviderName 'ECDSA_P384#Microsoft Software Key Storage Provider' -Force -OutputCertRequestFile 'C:\EnterpriseCA.req'
                                    } -Credential $ADCredentials

                                    Copy-Item -Path "C:\EnterpriseCA.req" -Destination 'C:\TEMP' -FromSession $Session -Force

                                    $SessionROOT = New-PSSession -VMName 'ROOT1' -Credential (Get-Credentials -Message 'Local Administrator')

                                    Copy-Item -Path "C:\TEMP\EnterpriseCA.req" -Destination 'C:\' -ToSession $SessionROOT -Force
                                    Write-Host "Submit C:\EnterpriseCA.req to ROOT1"
                                    read-host -Prompt 'Press enter to continue'
                                    Copy-Item -Path "C:\EnterpriseCA.cer" -Destination 'C:\TEMP' -FromSession $SessionROOT -Force
                                    Copy-Item -Path "C:\TEMP\EnterpriseCA.cer" -Destination 'C:\EnterpriseCA.cer' -ToSession $Session -Force

                                    write-host "Add cert to CA, gpupdate and start ca"
                                    read-host -Prompt 'Press enter to continue'

                                    Invoke-Command -VMName $xmlserver.name -ScriptBlock {
                                        <# 
                                        certutil.exe -dsPublish -f "C:\TEMP\Endre A Wik Root CA.crt" RootCA
                                        Install-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools
                                        Install-AdcsCertificationAuthority -CAType EnterpriseSubordinateCA -CACommonName 'Endre A Wik Enterprise CA' -KeyLength 384 -HashAlgorithmName SHA256 -CryptoProviderName 'ECDSA_P384#Microsoft Software Key Storage Provider' -ValidityPeriod Years -ValidityPeriodUnits 10 -Force -OutputCertRequestFile 'C:\EnterpriseCA.req'
                                        #>
                                        Restart-Service CertSvc
                                        $CRLs = Get-CACrlDistributionPoint
                                        foreach ($CRL in $CRLs) {
                                            Remove-CACrlDistributionPoint -Uri $CRL.Uri -Force
                                        }
                                        
                                        Restart-Service CertSvc
                                        
                                        Add-CACrlDistributionPoint -Uri 'C:\Windows\System32\CertSrv\CertEnroll\%3%8.crl' -PublishToServer -Force
                                        Add-CACrlDistributionPoint -Uri 'http://pki.ad.endreawik.no/%3%8.crl' -AddToCertificateCdp -Force
                                        
                                        Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } | Remove-CAAuthorityInformationAccess -Force
                                        
                                        Restart-Service CertSvc
                                        
                                    } -AsJob -Credential $ADCredentials
                                }
                            } else {
                            }
                        }
                        Read-Host -Prompt 'Press enter to continue'
                    }
                }
            }
        }
        5 { # Exchange
            $showsubmenuexch = $true
            while ($showsubmenuexch) {
                Clear-Host
                Write-Host " ----- ----- ----- ----- ----- ----- ----- ----- ----- -----"
                Write-Host " 1. Prepare Schema and AD"
                Write-Host " 2. Install Exchange ManagementTools"
                Write-Host " 3. Config Exchange Management Shell without server"
                Write-Host " "
                Write-Host " 0. exit"
                Write-Host " ----- ----- ----- ----- ----- ----- ----- ----- ----- -----"
            
                $UserInput_SubMenu = Read-Host -Prompt 'Menu option'

                switch ($UserInput_SubMenu) {
                    0 {
                        $showsubmenuexch = $false
                    }
                    1 {
                        $xml.infrastructure.servers.server | Where-Object { $_.role -eq 'exchange' } | ForEach-Object {
                            $VM = Get-VM -Name $_.name
                            $VMISOPath = GetISOPath -NameAndType "ExchangeServer"
                            Set-VMDvdDrive -VMName $VM.Name -Path $VMISOPath
                            Write-Host $_.name -ForegroundColor Green
                            $OrganizationName = $xml.infrastructure.organization.name
                            $Job = Invoke-Command -VMName $_.name -ScriptBlock {
                                Add-WindowsFeature RSAT-ADDS
                                D:\setup.exe /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF /PrepareSchema
                                $OrganizationName = $Using:OrganizationName
                                D:\setup.exe /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF /PrepareAD /OrganizationName:"$OrganizationName" /ActiveDirectorySplitPermissions:true
                            } -AsJob -Credential $ADCredentials
                            Write-Host "Waiting for job to complete, ca 10 min" -ForegroundColor Yellow
                            Wait-Job -Job $Job

                        }
                    }
                    2 {
                        $xml.infrastructure.servers.server | Where-Object { $_.role -eq 'exchange' } | ForEach-Object {
                            Write-Host $_.name -ForegroundColor Green
                            $OrganizationName = $xml.infrastructure.organization.name
                            $Job = Invoke-Command -VMName $_.name -ScriptBlock {
                                New-Item -Path C:\ -Name TEMP -ItemType Directory
                                Invoke-WebRequest -Uri 'https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe' -OutFile 'C:\TEMP\vcredist_x64.exe'
                                Start-Process -FilePath 'C:\TEMP\vcredist_x64.exe' -ArgumentList '/q /norestart' -Wait
                            
                                Enable-WindowsOptionalFeature -Online -FeatureName IIS-IIS6ManagementCompatibility,IIS-Metabase -All
        
                                $OrganizationName = $Using:OrganizationName
                                D:\setup.exe /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF /OrganizationName:"$OrganizationName" /Mode:Install /Roles:ManagementTools
                            } -AsJob -Credential $ADCredentials
                            Write-Host "Waiting for job to complete, ca 10 min" -ForegroundColor Yellow
                            Wait-Job -Job $Job
                        }
                    }
                    3 {
                        $xml.infrastructure.servers.server | Where-Object { $_.role -eq 'exchange' } | ForEach-Object {
                            Write-Host $_.name -ForegroundColor Green
                            $Job = Invoke-Command -VMName $_.name -ScriptBlock {
                                Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
                                Add-PSSnapin *RecipientManagement
                                . "C:\Program Files\Microsoft\Exchange Server\V15\Scripts\Add-PermissionForEMT.ps1"
                            } -AsJob -Credential $ADCredentials
                            Wait-Job -Job $Job
                        }
                    }
                }
            }
        }
        6 { # DHCP
            $showsubmenudhcp = $true
            while ($showsubmenudhcp) {
                Clear-Host
                Write-Host " ----- ----- ----- ----- ----- ----- ----- ----- ----- -----"
                Write-Host " 1. Install DHCP"
                Write-Host " "
                Write-Host " 0. exit"
                Write-Host " ----- ----- ----- ----- ----- ----- ----- ----- ----- -----"
            
                $UserInput_SubMenu = Read-Host -Prompt 'Menu option'

                switch ($UserInput_SubMenu) {
                    1 {
                        $xml.infrastructure.servers.server | Where-Object { $_.role -eq 'dhcp' } | ForEach-Object {
                            Write-Host $_.name -ForegroundColor Green
                            $Job = Invoke-Command -VMName $_.name -ScriptBlock {
                                Install-WindowsFeature -Name DHCP -IncludeManagementTools
                                Add-DhcpServerv4Scope -name "NAT" -StartRange 172.16.1.100 -EndRange 172.16.1.200 -SubnetMask 255.255.255.0
                                Set-DhcpServerv4OptionValue -DnsDomain ad.endreawik.no -DnsServer 172.16.1.2
                                Add-DhcpServerInDC -DnsName dhcp1.ad.endreawik.no -IPAddress 172.16.1.12
                            } -AsJob -Credential (Get-Credential -Message 'AD Administrator' -UserName 'AD\Administrator')

                            Wait-Job -Job $Job
                        }
                    Read-Host -Prompt 'Press enter to continue'
                    }
                    0 {
                        $showsubmenudhcp = $false
                    }
                    default { }
                }
            }
        }
        7 {
            $showsubmenuhybrid = $true
            while ($showsubmenuhybrid) {
                Clear-Host
                Write-Host " ----- ----- ----- ----- ----- ----- ----- ----- ----- -----"
                Write-Host " 1. Download Azure AD Connect"
                Write-Host " "
                Write-Host " 0. exit"
                Write-Host " ----- ----- ----- ----- ----- ----- ----- ----- ----- -----"
            
                $UserInput_SubMenu = Read-Host -Prompt 'Menu option'

                switch ($UserInput_SubMenu) {
                    0 {
                        $showsubmenuhybrid = $false
                    }
                    1 {
                        $Job = Invoke-Command -VMName $_.name -ScriptBlock {
                            New-Item -Path C:\ -Name TEMP -ItemType Directory
                            Invoke-WebRequest -Uri 'https://download.microsoft.com/download/B/0/0/B00291D0-5A83-4DE7-86F5-980BC00DE05A/AzureADConnect.msi' -OutFile 'C:\TEMP\AzureADConnect.msi'
                        } -AsJob -Credential $Credentials
                    }
                }
            }
        }
        9 { # Credentials
            $Credentials = Get-Credential -Message "Local Administrator"
            $ADCredentials = Get-Credential -Message "Domain Administrator"
        }
    }
}


<# 
    $IPv4Pattern = '^((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    (Get-VM -Name root1).NetworkAdapters.ipaddresses | ForEach-Object { if ($_ -match $IPv4Pattern) { $_ } }
#>

