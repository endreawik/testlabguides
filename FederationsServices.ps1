

Install-WindowsFeature -Name 'ADFS-Federation' -IncludeManagementTools

Install-AdfsFarm `
-CertificateThumbprint:"9E034885BAB06462B42092E911AB350EF8CDDD21" `
-FederationServiceDisplayName:"Endre A Wik" `
-FederationServiceName:"fs.endreawik.com" `
-GroupServiceAccountIdentifier:"AD\svc-adfs`$"