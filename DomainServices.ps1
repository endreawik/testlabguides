





Enter-PSSession -VMName ADDS1
Enter-PSSession -VMName ADDS2

# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
# Operating System
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #

# A-DC-Spooler
Get-Service -Name Spooler | Stop-Service
Get-Service -Name Spooler | Set-Service -StartupType Disabled

# Configure time
w32tm /config /computer:adds1.ad.endreawik.com /manualpeerlist:time.windows.com /syncfromflags:manual /update

# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
# Active Directory Domain Services - Role
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #

function AddRoleADDS () {
  Add-WindowsFeature AD-Domain-Services -IncludeManagementTools

  Import-Module ADDSDeployment
  Install-ADDSForest `
  -CreateDnsDelegation:$false `
  -DatabasePath "C:\ADDS\NTDS" `
  -DomainMode "WinThreshold" `
  -DomainName "ad.endreawik.com" `
  -DomainNetbiosName "AD" `
  -ForestMode "WinThreshold" `
  -InstallDns:$true `
  -LogPath "C:\ADDS\NTDS" `
  -NoRebootOnCompletion:$false `
  -SysvolPath "C:\ADDS\SYSVOL" `
  -Force:$true
}


#
# Windows PowerShell script for AD DS Deployment
#

function AddRoleADDS2 () {
  Add-WindowsFeature AD-Domain-Services -IncludeManagementTools
  
  Import-Module ADDSDeployment
  Install-ADDSDomainController `
  -NoGlobalCatalog:$false `
  -CreateDnsDelegation:$false `
  -Credential (Get-Credential) `
  -CriticalReplicationOnly:$false `
  -DatabasePath "C:\ADDS\NTDS" `
  -DomainName "ad.endreawik.com" `
  -InstallDns:$true `
  -LogPath "C:\ADDS\NTDS" `
  -NoRebootOnCompletion:$false `
  -SiteName "Default-First-Site-Name" `
  -SysvolPath "C:\ADDS\SYSVOL" `
  -Force:$true
}


# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
# Active Directory Domain Services - Sites and Services
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #

# S-DC-SubnetMissing
New-ADReplicationSubnet -Name "172.16.1.0/24" -Site 'Default-First-Site-Name'

# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
# Active Directory Domain Services - Users and Computers
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #

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

# P-Delegated
Get-ADGroupMember -Identity 'Domain Admins' | Where-Object { $_.objectClass -eq 'user' } | Set-ADUser -AccountNotDelegated $true

# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
# Active Directory Domain Services - Domains and Trusts
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #

# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
# Domain Name Services (DNS)
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #

# A-DnsZoneAUCreateChild
$DNSServerZones = Get-DnsServerZone | Where-Object { $_.IsAutoCreated -eq $false } | Where-Object { $_.ZoneName -notmatch '_msdcs' -and $_.ZoneName -notmatch 'TrustAnchors' }

# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
# Active Directory Domain Services - Group Policy
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #

Get-ChildItem -LiteralPath .\testlabguides\GroupPolicy -Recurse -File | ForEach-Object { Copy-VMFile -VMName ADDS1 -SourcePath $_.FullName -DestinationPath $_.FullName -CreateFullPath -FileSource Host }

Import-GPO -Path 'C:\ENDREAWIK\testlabguides\GroupPolicy' -BackupId '2DD46DF8-70E8-4801-89AF-14E7C808BBF6' -TargetName 'EAW Windows Server - Domain Controller' -CreateIfNeeded
Import-GPO -Path 'C:\ENDREAWIK\testlabguides\GroupPolicy' -BackupId '356BBC58-0677-47EA-9033-2DC3C12E7E04' -TargetName 'EAW Autoenrollment Policy' -CreateIfNeeded
Import-GPO -Path 'C:\ENDREAWIK\testlabguides\GroupPolicy' -BackupId '74C66341-BF66-4E47-8D3D-9A6360CC3F07' -TargetName 'EAW Windows Server - Member Server' -CreateIfNeeded

# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
# Active Directory Domain Services - Group Mananged Service Account
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #

Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))

# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
# Active Directory Domain Services - Permissions
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #

$TargetDN = ("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + (Get-ADDomain).DistinguishedName)
$ValuedsHeuristics = (Get-ADObject -Identity $TargetDN -Properties dsHeuristics).dsHeuristics

if ($ValuedsHeuristics -eq "") {
  Set-ADObject -Identity $TargetDN -Add @{dSHeuristics='00000000010000000002000000011'}
} else {
  Write-Host "Something is wrong" -ForegroundColor Red
}

# https://support.microsoft.com/en-us/topic/kb5008383-active-directory-permissions-updates-cve-2021-42291-536d5555-ffba-4248-a60e-d6cbc849cde1