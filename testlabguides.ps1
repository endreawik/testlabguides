[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $inputFile
)
$inputFile = '.\testlabguides\testlabguides.xml'
[xml]$xmlInput = Get-Content -LiteralPath $inputFile

$xmlservers = $xmlInput.infrastructure.compute.servers.server

$xmlserver = $xmlservers | Where-Object { $_.Name -eq 'adds1' }

# Create VMs


# Configure Operating System

# Configure Roles and Features