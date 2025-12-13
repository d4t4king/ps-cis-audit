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

Write-Output "##################  Identification and Authentication  ##################"
Write-Output "##################      Password Policies              ##################"
$passPol = Get-NetAccountsOutput
#Write-Output "Force User Logoff: $forceUserLogoff"
$passPol