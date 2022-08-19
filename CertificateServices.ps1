

Add-WindowsFeature -Name 'ADCS-Cert-Authority' -IncludeManagementTools

Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName 'Endre A Wik CA' -KeyLength 384 -HashAlgorithmName SHA256 -CryptoProviderName 'ECDSA_P384#Microsoft Software Key Storage Provider' -ValidityPeriod Years -ValidityPeriodUnits 20

