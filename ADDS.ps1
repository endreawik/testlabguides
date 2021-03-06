





# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
# Active Directory Domain Services, Sites and Services
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #

# S-DC-SubnetMissing
New-ADReplicationSubnet -Name "172.16.0.0/24" -Site 'Default-First-Site-Name'

# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
# Active Directory Domain Services, Domains and Trusts
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #

# S-ADRegistration
Set-ADDomain -Identity (Get-ADDomain).DistinguishedName -Replace @{'ms-DS-MachineAccountQuota'='0'}

# P-Delegated
$ProtectedUsers = @()
$ProtectedUsers += Get-ADGroupMember -Identity 'Protected Users'
$ProtectedUsers += Get-ADGroupMember -Identity 'Domain Admins'
$ProtectedUsers | Set-ADUser -AccountNotDelegated $true -WhatIf

# P-RecycleBin
Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADDomain).Forest -Confirm:$false

# P-SchemaAdmin
Set-ADGroup -Identity 'Schema Admins' -Clear member

# A-MinPwdLen
Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).Forest -MinPasswordLength 14 -LockoutDuration 00:15:00 -LockoutThreshold 10 -LockoutObservationWindow 00:15:00

# A-DC-Spooler
Get-Service -Name Spooler | Stop-Service
Get-Service -Name Spooler | Set-Service -StartupType Disabled

# A-NoServicePolicy
New-ADFineGrainedPasswordPolicy -Name 'Service Accounts' -Description 'Domain Password Policy for Service Accounts' -Precedence 10 -ComplexityEnabled $true -LockoutDuration 00:15:00 -LockoutThreshold 10 -LockoutObservationWindow 00:15:00 -MinPasswordAge 1 -MaxPasswordAge 365 -MinPasswordLength 32 -PasswordHistoryCount 24 -ReversibleEncryptionEnabled $false -ProtectedFromAccidentalDeletion $true
New-ADGroup -Name 'Service Accounts' -GroupCategory Security -GroupScope Global
Add-ADFineGrainedPasswordPolicySubject -Identity 'Service Accounts' -Subjects (Get-ADGroup -Identity 'Service Accounts')

# A-PreWin2000AuthenticatedUsers
Set-ADGroup -Identity 'Pre-Windows 2000 Compatible Access' -Clear member

# A-DnsZoneAUCreateChild
$DNSServerZones = Get-DnsServerZone | Where-Object { $_.IsAutoCreated -eq $false } | Where-Object { $_.ZoneName -notmatch '_msdcs' -and $_.ZoneName -notmatch 'TrustAnchors' }

# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
# Active Directory Domain Services, Users and Computers
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
  New-ADOrganizationalUnit -Name 'servers' -Description '' -Path ('OU=tier 3,' + (Get-ADDomain).DistinguishedName)
  New-ADOrganizationalUnit -Name 'users' -Description '' -Path ('OU=tier 3,' + (Get-ADDomain).DistinguishedName)

New-ADGroup -Name 'Service Accounts' -Description '' -GroupCategory Security -GroupScope Global -Path ('OU=groups,OU=tier 0,' + (Get-ADDomain).DistinguishedName)