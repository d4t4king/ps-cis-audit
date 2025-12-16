<#
    .SYNOPSIS
    Does some automated checking for CIS Level 1 workstation complance.

    .DESCRIPTION
    Does some automated checking for CIA Level 1 workstation compliance.

    .INPUTS

    .OUTPUTS

    .PARAMETERS

    .EXAMPLE

#>
# Doesn't seem to be working???
#Import-Module SecurityPolicy

function Get-NetAccountsOutput {
    param ( )
    $netCmdOutput = net accounts
    $lines = $netCmdOutput -split "\r\n"
    $passwdPol = [PSCustomObject]@{
        ForceUserLogoff = $(-split $lines[0])[8]
        MinPasswordAge = $(-split $lines[1])[4] + " days"
        MaxPasswordAge = $(-split $lines[2])[4] + " days"
        MinPassLength = $(-split $lines[3])[3]
        PassHistoryLength = $(-split $lines[4])[5]
        LockoutThreshold = $(-split $lines[5])[2]
        LockoutDuration = $(-split $lines[6])[3] + "minutes"
        LockoutWindow = $(-split $lines[7])[4] + "minutes"
        ComputerRole = $(-split $lines[8])[2]
    }
    #Write-Output $lines
    # Does this put it "in the pipline?
    $passwdPol
}

# function Get-ThisComputerInfo {
#     param ( ) 
#     $pcinfo = Get-ComputerInfo -ProgressAction SilentlyContinue -ErrorAction Stop
#     $computerInfo = [PSCustomObject]@{
#         WindowsInstallationType = $pcinfo.WindowsInstallationType
#         WindowsProductName = $pcinfo.WindowsProductName
#         WindowsRegisteredOrganization = $pcinfo.WindowsRegisteredOrganization
#         WindowsRegisteredOwner = $pcinfo.WindowsRegisteredOwner
#         WindowsSystemRoot = $pcinfo.WindowsSystemRoot
#     }
# }

function Get-DriveLetters {
    param ( )
    $DriveLetters = @()
    foreach ($drive in Get-PSDrive -PSProvider FileSystem | Select-Object Root) {
        $DriveLetters += $drive
    }
    $DriveLetters
}

function Get-ThisBitLockerVolumes {
    param ( )
    $BLStatus = @{}
    foreach ($drv in Get-DriveLetters) {
        Write-Verbose $drv.Root
        # if ([string]::IsNullOrEmpty($drv.Root)) { 
        #     Write-Verbose "Skipping drives with no drive letter.  (These are usually Recovery or Extended Partitions.)"
        #     continue
        # }
        try {
            $status = (Get-BitLockerVolume -MountPoint $drv.Root -ErrorAction Continue).ProtectionStatus
            $BLStatus[$drv.Root] = $status
        }
        catch [Microsoft.Management.Infrastructure.CimException] {
            $BLStatus[$drv.Root] = "ERROR: $($_.Exception.Message)"
        }
        catch {
            Write-Error "ERROR: There was an unknown error."
        }
    }
    $BLStatus
}

[int]$RunningCheckTotal = 0
[int]$ChecksPassed = 0
[int]$ChecksFailed = 0
Write-Output "##################  1.0 Inventory and Control if Enterprise Assets                ##################"
Write-Output "Getting computer info.....standby......"
$pcinfo = Get-ComputerInfo -ProgressAction SilentlyContinue
if ($pcinfo.CsDomain -eq 'WORKGROUP') {
    Write-Host "    Computer does not appear to be joined to a domain.  (Domain = $($pcinfo.CsDomain))"  -ForegroundColor "Red"
    $ChecksFailed += 1
} else {
    Write-Host "    Computer is part of a domain. ($($pcinfo.CsDomain))"
    $ChecksPassed += 1
}
$RunningCheckTotal += 1
Write-Output "##################    1.1 Asset Inventory                                         ##################"
Write-Output "##################    1.2 Address Unauthorized Assets                             ##################"
Write-Output "##################    1.3 Utilize and Active Directory Tool                       ##################"
Write-Output "##################    1.4 DHCP Logging                                            ##################"
Write-Output "##################    1.5 Passive AssetDiscovery                                  ##################"
Write-Output "##################  2.0 Inventory and Control of Software Assets                  ##################"
Write-Output "##################    2.1 Establish and Maintain a Software Inventory             ##################"
Write-Output "##################    2.2 Ensure Authorized Software is Currently Supported       ##################"
Write-Output "##################    2.3 Address Unauthorized Software                           ##################"
Write-Output "##################    2.4 Automated Software Inventory Tools                      ##################"
Write-Output "##################    2.5 Allowlist Authorized Software                           ##################"
Write-Output "##################    2.6 Allowlist Authorizerd Libraries                         ##################"
Write-Output "##################    2.7 Allowlist Authorized Scripts                            ##################"
Write-Output "##################  3.0 Data Protection                                           ##################"
Write-Output "##################    3.1 Establish and Maintain Data Manegement Process          ##################"
Write-Output "##################    3.2 Establish and Maintain Data Inventory                   ##################"
Write-Output "##################    3.3 Configure Data ACLs                                     ##################"
Write-Output "##################    3.4 Enforce Data Retention                                  ##################"
Write-Output "##################    3.5 Securely Dispose of Data                                ##################"
Write-Output "##################    3.6 Encrypt Data on End-User Devices                        ##################"
Get-ThisBitLockerVolumes
Write-Output "##################    3.7 Establish and Maintain Data Classification Scheme       ##################"
Write-Output "##################    3.8 Document Data Flows                                     ##################"
Write-Output "##################    3.9 Encrypt data on Removable Media                         ##################"
Write-Output "##################    3.10 Encrypt Sensitive Data in Transit                      ##################"
Write-Output "##################    3.11 Encrypt Sensitive Date at Rest                         ##################"
Write-Output "##################    3.12 Segment Data Processing and Storage Based on Sensitity ##################"
Write-Output "##################    3.13 Deploy a Data Loss Prevention Solution                 ##################"
Write-Output "##################    3.14 Log Sensitive Data Access                              ##################"

Write-Output "##################  Identification and Authentication                             ##################"
Write-Output "##################      Password Policies                                         ##################"

$passPol = Get-NetAccountsOutput
#Write-Output "Force User Logoff: $forceUserLogoff"
if ($passPol.ComputerRole -eq "WORKSTATION") {
    Write-Output "    Computer role is $($passPol.ComputerRole)."
}
# Minimum Password Age is the required duration before a user's password can be changed.
if ($passPol.MinPasswordAge -ne 1) {
    Write-Host "    Insufficient minimum password age: $($passPol.MinPasswordAge)" -ForegroundColor "Red"
    $ChecksFailed += 1
} else {
    Write-Host "    Minimum password age is within acceptable parameters: $($passPol.MinPasswordAge)" -ForegroundColor "Green"
    $ChecksPassed += 1
}
$RunningCheckTotal += 1
if ($passPol.MaxPasswordAge -lt 1) {
    Write-Host "    Maximum password age is within acceptable parameters: $($passPol.MaxPasswordAge)" -ForegroundColor "Green"
    $ChecksPassed += 1
} else {
    if ($passPol.MaxPasswordAge -ge 365) {
        Write-Host "    Maximum password age is potentially too long. $($passPol.MaxPasswordAge)" -ForegroundColor "Yellow"
        $ChecksPassed += 1
    } else {
        Write-Host "    Insufficient maximum password age: $($passPol.MaxPasswordAge)" -ForegroundColor "Red"
        $ChecksFailed += 1
    }
}
$RunningCheckTotal += 1
if ($passPol.PassHistoryLength -lt 3 -and $passPol.PassHistoryLength -ne 0) {
    Write-Host "    Insufficient password history length.  ($($passPol.PassHistoryLength))" -ForegroundColor "Red"
    $ChecksFailed += 1
} else {
    Write-Host "    Password history is within acceptable parameters.  ($($passPol.PassHistoryLength))" -ForegroundColor "Green"
    $ChecksPassed += 1
}
$RunningCheckTotal += 1

Write-Output "___Checks Passed: $ChecksPassed"
Write-Output "___Checks Failed: $ChecksFailed"
Write-Output "Total Checks: $RunningCheckTotal"