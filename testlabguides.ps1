[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $inputFile
)
$inputFile = '.\testlabguides\testlabguides.xml'
[xml]$xmlInput = Get-Content -LiteralPath $inputFile

$xmlservers = $xmlInput.infrastructure.servers.server

# Create VMs

Write-Host "Available servers to create (GREEN exists)"

$VMs = Get-VM

foreach ($xmlserver in $xmlservers) {
    $VMexists = $VMs | Where-Object { $_.Name -match ($xmlserver.name) }
    if ($VMexists) {
        Write-Host $xmlserver.name -ForegroundColor Green
    } else {
        Write-Host $xmlserver.name
    }
}

CreateVM $VMName

# Configure Operating System

$Session = New-PSSession -VMName $Computername -Credential (Get-Credential -Message 'Administrator' -UserName '~\Administrator')
RemoteSetTimeZone $Session
RemoteSetNetwork $Session $SwitchName $IPAddress
RemoteSetDNSConfig $Session $SwitchName $DNSServer $DNSSuffix
RemoteRenameComputer $Session $Computername
RemoteRestartComputer $Session
$Session = New-PSSession -VMName $Computername -Credential (Get-Credential -Message 'Administrator' -UserName '~\Administrator')
RemoteAddToDomain $Session
RemoteRestartComputer $Session
$Session = New-PSSession -VMName $Computername -Credential (Get-Credential -Message 'Administrator' -UserName '~\Administrator')

# Configure Roles and Features


function ShowMenu () {

    Write-Host "----- ----- ----- ----- -----"
    Write-Host " 0. "
    Write-Host " 1. "
    Write-Host " 2. "
    Write-Host " 3. "
    Write-Host " 4. "
    Write-Host " 5. "
    Write-Host " 6. "
    Write-Host " 7. "
    Write-Host " 8. "
    Write-Host " 9. "
    Write-Host "----- ----- ----- ----- -----"

    $UserInput_Menu = Read-Host -Prompt 'Menu option'

    switch ($UserInput_Menu) {
        0 {
            $SwitchName = 'NAT'
            $DNSSuffix = 'ad.endreawik.com'
            $Gateway = '172.16.1.1'
            $DNSServer = '172.16.1.5'
            ShowMenu
        }
        1 { 
            # Create virtual machine
            $UserInput_VMName = Read-Host -Prompt 'VMName'
            if ($UserInput_VMName.Length -gt 15) {
                Write-Error -Message 'Max length is 15 characters'
            } else {
                CreateVM $UserInput_VMName
                ShowMenu
            }
        }
        2 {
            $UserInput_VMName = Read-Host -Prompt 'VMName'
            $VMCheck = Get-VM -Name $UserInput_VMName -ErrorAction SilentlyContinue
            if ($VMCheck) {
                $Session = New-PSSession -VMName $UserInput_VMName -Credential (Get-Credential -Message 'Administrator' -UserName '~\Administrator')
                RemoteSetTimeZone $Session
                RemoteSetNetwork $Session $SwitchName $IPAddress
                RemoteSetDNSConfig $Session $SwitchName $DNSServer $DNSSuffix
                $RestartRequired = RemoteRenameComputer $Session $UserInput_VMName
                if ($RestartRequired) {
                    RemoteRestartComputer $Session
                    Write-Host "Restarting $UserInput_VMName" -ForegroundColor Yellow
                    ShowMenu
                } else {
                    RemoteAddToDomain $Session
                    RemoteRestartComputer $Session
                }
            }
        }
        3 {
            $VMName = 'ADDS1'
            CreateVM $VMName
        }
        3 {
            $VMName = 'ADDS2'
            CreateVM $VMName
        }
        3 {
            $VMName = 'ADFS1'
            CreateVM $VMName
        }
        4 {
            $VMName = 'ADFS2'
            CreateVM $VMName
        }
        5 {
            $VMName = 'RAS1'
            CreateVM $VMName
        }
        6 {
            $VMName = 'AZAD1'
            CreateVM $VMName
        }
        7 {
            $VMName = 'WEB1'
            CreateVM $VMName
        }
        8 {
            $VMName = 'WEB2'
            CreateVM $VMName
        }
        9 {
            Clear-History
            Clear-Host
            break
        }
        Default {
            ShowMenu
        }
    }
}

ShowMenu