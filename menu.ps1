





# $Credentials = Get-Credential -Message 'Administrator' -UserName '.\Administrator'
# $ADCredentials = Get-Credential -Message 'Administrator' -UserName 'AD\Administrator'

[xml]$xml = Get-Content -Path '.\testlabguides\testlabguides.xml'
$ISOPath = 'C:\ISO\en-us_windows_server_2022_updated_feb_2023_x64_dvd_76afefb5.iso'
$VHDPath = 'C:\VHD'

Clear-Host
Write-Host " "
Write-Host "----- ----- ----- ----- ----- ----- ----- ----- ----- -----"
Write-Host "                      Test Lab Guides                      "
Write-Host "----- ----- ----- ----- ----- ----- ----- ----- ----- -----"
Write-Host " "
Read-Host -Prompt 'Press enter to continue'

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
    Write-Host " 5. Configure services, roles and features"
    Write-Host " "
    Write-Host " 0. exit"
    Write-Host " "
    Write-Host "----- ----- ----- ----- ----- ----- ----- ----- ----- -----"
    $UserInput_Menu = Read-Host -Prompt 'Menu option'

    switch ($UserInput_Menu) {
        0 {
            $showmenu = $false
        }
        1 {
            Clear-Host
            Write-Host " ----- ----- ----- ----- -----"
            Write-Host "  Creating Virtual Machines   "
            Write-Host " ----- ----- ----- ----- -----"
            $VMs = Get-VM

            foreach ($xmlserver in $xml.infrastructure.servers.server) {
                $VMexist = $VMs | Where-Object { $_.Name -match ($xmlserver.name) }
                if ($VMexist) {
                    Write-Host $xmlserver.name -ForegroundColor Cyan
                } else {
                    Write-Host $xmlserver.name -ForegroundColor Green    
                    $VMName = $xmlserver.name
                    $VMSwitch = Get-VMSwitch -Name $xmlserver.network.switch
                    if (!$VMSwitch) {
                        Write-Host "VMSwitch $VMSwitch does not exist" -ForegroundColor Red
                        break
                    }
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
            Read-Host -Prompt 'Press enter to continue'
        }
        2 {
            Clear-Host
            Write-Host " ----- ----- ----- ----- -----"
            Write-Host " Configuring Operating System "
            Write-Host " ----- ----- ----- ----- -----"
            $VMsRunning = Get-VM | Where-Object { $_.State -eq 'Running' }

            foreach ($xmlserver in $xml.infrastructure.servers.server) {
                $VMready = $VMsRunning | Where-Object { $_.Name -match ($xmlserver.name) }
                if ($VMready) {
                    Write-Host $xmlserver.name -ForegroundColor Green

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
                    Write-Host ($xmlserver.name)"not ready" -ForegroundColor Red
                }
            }
            Read-Host -Prompt 'Press enter to continue'
        }
        3 {
            $showsubmenuadds = $true
            while ($showsubmenuadds) {
                Clear-Host
                Write-Host " ----- ----- ----- ----- ----- ----- ----- ----- ----- -----"
                Write-Host " 1. Install ADDS"
                Write-Host " 2. Configure ADDS"
                Write-Host " 3. Add Virtual Machines to domain"
                Write-Host " 4. Install LAPS on ADDS"
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
                        foreach ($xmlserver in $xml.infrastructure.servers.server) {
                            $VMready = $VMsRunning | Where-Object { $_.Name -match ($xmlserver.name) }
                            if ($VMready) {
                                Write-Host $xmlserver.name -ForegroundColor Green

                                if ($xmlserver.type -eq 'domain') {
                                    $DomainName = $xml.infrastructure.domain.name
                                    $Computername = $xmlserver.name
                                    $VMNetworkAdapter = Get-VM -Name $xmlserver.name | Get-VMNetworkAdapter | Where-Object { $_.SwitchName -eq $SwitchName }
                                    $MacAddress = ($VMNetworkAdapter.MacAddress).ToString()
                                    Invoke-Command -VMName $xmlserver.name -ScriptBlock {
                                        if ($env:COMPUTERNAME -eq $Using:Computername) {
                                            $xmlserveradds = $xml.infrastructure.servers.server | Where-Object { $_.role -eq 'adds' }
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
                    4 {
                        Clear-Host
                        foreach ($xmlserver in $xml.infrastructure.servers.server) {
                            $VMready = $VMsRunning | Where-Object { $_.Name -match ($xmlserver.name) }
                            if ($VMready) {
                                Write-Host $xmlserver.name -ForegroundColor Green

                                if ($xmlserver.role -eq 'adds') {
                                    $Session = New-PSSession -VMName $xmlserver.name -Credential $ADCredentials
                                    Copy-Item -Path '.\testlabguides\Programs\LAPS.x64.msi' -Destination 'C:\' -ToSession $Session
                                    Invoke-Command -VMName $xmlserver.name -ScriptBlock {
                                        New-Item -Path 'C:\TEMP' -ItemType Directory -ErrorAction SilentlyContinue
                                        Move-Item -Path 'C:\LAPS.x64.msi' -Destination 'C:\TEMP\LAPS.x64.msi' -Force
                                        msiexec /q /i 'C:\TEMP\LAPS.x64.msi' ADDLOCAL=Management.UI,Management.PS,Management.ADMX

                                        Import-module AdmPwd.PS
                                        Update-AdmPwdADSchema
                                    } -AsJob -Credential $ADCredentials
                                }
                            } else {
                                Write-Host ($xmlserver.name)"not ready" -ForegroundColor Red
                            }
                        }
                        Read-Host -Prompt 'Press enter to continue'
                    }
                }
            }
        }
        4 {
            $showsubmenuadcs = $true
            while ($showsubmenuadcs) {
                Clear-Host
                Write-Host " ----- ----- ----- ----- ----- ----- ----- ----- ----- -----"
                Write-Host " "
                Write-Host " 1. Install IIS"
                Write-Host " 2. Install ROOT"
                Write-Host " 3. Distribute CRT and CRL"
                Write-Host " 4. Install ADCS"
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
                    2 {
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
                    3 {
                        $VMsRunning = Get-VM | Where-Object { $_.State -eq 'Running' }

                        foreach ($xmlserver in $xml.infrastructure.servers.server) {
                            $VMready = $VMsRunning | Where-Object { $_.Name -match ($xmlserver.name) }
                            if ($VMready) {
                                $Certificate = 'Endre A Wik Root CA'
                                if ($xmlserver.role -eq 'root') {
                                    $Session = New-PSSession -VMName $xmlserver.name -Credential $Credentials
                                    Copy-Item -Path "C:\Windows\System32\CertSrv\CertEnroll\$Certificate.crl" -Destination 'C:\TEMP' -FromSession $Session -Force
                                    Copy-Item -Path "C:\Windows\System32\CertSrv\CertEnroll\$Certificate.crt" -Destination 'C:\TEMP' -FromSession $Session -Force
                                }
                                if ($xmlserver.role -eq 'iis') {
                                    $Session = New-PSSession -VMName $xmlserver.name -Credential $Credentials
                                    Copy-Item -Path "C:\TEMP\$Certificate.crl" -Destination 'C:\inetpub\wwwroot' -ToSession $Session -Force
                                    Copy-Item -Path "C:\TEMP\$Certificate.crt" -Destination 'C:\inetpub\wwwroot' -ToSession $Session -Force
                                }
                                if ($xmlserver.role -eq 'adds') {
                                    $Session = New-PSSession -VMName $xmlserver.name -Credential $Credentials
                                    Copy-Item -Path "C:\TEMP\$Certificate.crt" -Destination 'C:\' -ToSession $Session -Force

                                    Start-Sleep -Seconds 10

                                    Invoke-Command -VMName $xmlserver.name -ScriptBlock {
                                        certutil.exe -dsPublish -f "C:\$Using:Certificate.crt" RootCA
                                        Start-Sleep -Seconds 10
                                        Remove-Item -Path "C:\$Using:Certificate.crt" -Force

                                        Add-DnsServerResourceRecord -A -ZoneName 'ad.endreawik.com' -IPv4Address 172.16.1.10 -Name 'pki'
                                        
                                    } -AsJob -Credential $ADCredentials
                                }
                            } else {
                            }
                        }
                        Read-Host -Prompt 'Press enter to continue'
                    }
                    4 {
                        $VMsRunning = Get-VM | Where-Object { $_.State -eq 'Running' }

                        foreach ($xmlserver in $xml.infrastructure.servers.server) {
                            $VMready = $VMsRunning | Where-Object { $_.Name -match ($xmlserver.name) }
                            if ($VMready) {
                                if ($xmlserver.role -eq 'adcs') {
                                    $Session = New-PSSession -VMName $xmlserver.name -Credential $Credentials
                                    Copy-Item -Path '.\testlabguides\CAPolicy-ent.ini' -Destination 'C:\Windows\CAPolicy.ini' -ToSession $Session
                                    Invoke-Command -VMName $xmlserver.name -ScriptBlock {
                                        certutil.exe -dsPublish -f "C:\TEMP\Endre A Wik Root CA.crt" RootCA

                                        Install-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools
                                        Install-AdcsCertificationAuthority -CAType EnterpriseSubordinateCA -CACommonName 'Endre A Wik Enterprise CA' -KeyLength 384 -HashAlgorithmName SHA256 -CryptoProviderName 'ECDSA_P384#Microsoft Software Key Storage Provider' -ValidityPeriod Years -ValidityPeriodUnits 10 -Force

                                        $CRLs = Get-CACrlDistributionPoint
                                        foreach ($CRL in $CRLs) {
                                            Remove-CACrlDistributionPoint -Uri $CRL.Uri -Force
                                        }
                                        
                                        Restart-Service CertSvc
                                        
                                        Add-CACrlDistributionPoint -Uri 'C:\Windows\System32\CertSrv\CertEnroll\%3%8.crl' -PublishToServer -Force
                                        Add-CACrlDistributionPoint -Uri 'http://pki.endreawik.com/%3%8.crl' -AddToCertificateCdp -Force
                                        
                                        Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } | Remove-CAAuthorityInformationAccess -Force
                                        
                                        Restart-Service CertSvc
                                        
                                    } -AsJob -Credential $Credentials
                                }
                            } else {
                            }
                        }
                        Read-Host -Prompt 'Press enter to continue'
                    }
                }
            }
        }
        5 {
            Clear-Host
            Write-Host " ----- ----- ----- ----- -----"
            Write-Host " Configuring Virtual Machines "
            Write-Host " ----- ----- ----- ----- -----"
            $VMsRunning = Get-VM | Where-Object { $_.State -eq 'Running' }

            foreach ($xmlserver in $xml.infrastructure.servers.server) {
                $VMready = $VMsRunning | Where-Object { $_.Name -match ($xmlserver.name) }
                if ($VMready) {
                    Write-Host $xmlserver.name -ForegroundColor Green

                } else {
                    Write-Host ($xmlserver.name)"not ready" -ForegroundColor Red
                }
            }
            Read-Host -Prompt 'Press enter to continue'
            <#
            $VMName = Read-Host -Prompt 'VMName'
            # Install Roles and Features
            # install ADDS using powershell remoting as job
            $DomainName = $xml.infrastructure.domain.name
            $NetBIOSName = $xml.infrastructure.domain.netbios

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

            # install exchange part 1 using powershell remoting as job
            $Computername = 'exch1'
            Invoke-Command -VMName $VMName -ScriptBlock {
                if ($env:COMPUTERNAME -eq $Using:Computername) {
                    Add-WindowsFeature RSAT-ADDS

                    D:\setup.exe /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF /PrepareSchema

                    Restart-Computer
                }
            } -AsJob -Credential $ADCredentials

            Start-Sleep -Seconds 60

            # install exchange part 2 using powershell remoting as job
            $Computername = 'exch1'
            Invoke-Command -VMName $VMName -ScriptBlock {
                if ($env:COMPUTERNAME -eq $Using:Computername) {
                    $OrganizationName = "Endre A Wik"
                    D:\setup.exe /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF /PrepareAD /OrganizationName:"$OrganizationName" /ActiveDirectorySplitPermissions:true

                    Restart-Computer
                }
            } -AsJob -Credential $ADCredentials

            Start-Sleep -Seconds 60

            # install exchange part 3 using powershell remoting as job
            $Computername = 'exch1'
            Invoke-Command -VMName $VMName -ScriptBlock {
                if ($env:COMPUTERNAME -eq $Using:Computername) {
                    $OrganizationName = "Endre A Wik"
                    D:\setup.exe /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF /OrganizationName:"$OrganizationName" /ActiveDirectorySplitPermissions:true /Mode:Install /Roles:ManagementTools

                    Restart-Computer
                }
            } -AsJob -Credential $ADCredentials
            #>
        }
    }
}