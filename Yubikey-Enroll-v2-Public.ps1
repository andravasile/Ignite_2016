## Version Information
## 03-May-2017 v1.0 Tanner Slayton - Initial Creation and Testing of Script for Yubikey enrollment
##
## Reviewer Information
## 
##
## Known Issues
##
##
## Usage Examples:
## .\Yubikey-Enroll-v2.ps1 -PIN <PIN Input>
##
## .\Yubikey-Enroll-v2.ps1
##

Param (
    [Parameter(Mandatory=$true)]$PIN, # Make sure to initialize with the YubiKey with this PIN
    $YubicoPIVPath = 'C:\Program Files (x86)\Yubico\YubiKey PIV Manager' # Wherever the yubico piv tool resides
)

Clear-Host
$Component = 'Yubikey'
[string]$CertUtilPath = 'C:\Windows\System32\certutil.exe'
[string]$CertReqPath = 'C:\Windows\System32\certreq.exe'
$TempRead = "$ENV:Temp\Yubikey-$(Get-Random -Minimum 10000 -Maximum 20000).out"
$TempOuptut = "$ENV:Temp\Yubikey-O-$(Get-Random -Minimum 10000 -Maximum 20000).out"
$CSRRequestFile = "$ENV:Temp\Request-$(Get-Random -Minimum 10000 -Maximum 20000).csr"
$CertFile = "$ENV:Temp\Cert-$(Get-Random -Minimum 10000 -Maximum 20000).crt"
$PubPEM = "$ENV:Temp\Public.pem"
$CANameFile = "$ENV:Temp\CAName.txt"
$DefaultPIN = '123456'
$DefaultPUK = '12345678'

#region Write-TransLog
Function Write-TransLog
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string[]]$Message,
        [string]$Component,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateSet('Normal','Warning','Error')]
        [string]$TypeName,
        [switch]$WriteEvent,
        [switch]$DebugWriteEvent
        )

    [string]$Invocation = $MyInvocation.ScriptName.ToString()
    [string]$ScriptName = Split-Path -Path $Invocation -Leaf
    [string]$LogFilePath = 'C:\TransLogs'
    [string]$LogFileName = $ScriptName.Replace('.ps1','.log')

    If($Component -eq $null)
    {
        $Component = 'Generic'
    }

    If((Test-Path -Path $LogFilePath) -eq $false)
    {
        New-Item -Path $LogFilePath -ItemType Directory -Force | Out-Null
    }

    If($LogFileName -eq '.log')
    {
        Write-Warning 'No log name specified, using generic log file name'
        $LogFileName = "PoSH-Log-$(Get-Date -Format MMddyyyy-HHMMss).log"
    }

    [string]$FullLogPath = Join-Path -Path $LogFilePath -ChildPath $LogFileName
    $LogType = Switch($TypeName)
    {
        'Normal' { 1 }
        'Warning' { 2 }
        'Error' { 3 }
        Default { 1 }
    }

    [string]$LogTime = (Get-Date -Format HH\:mm\:ss) + ".000+000"
    [string]$LogDate = (Get-Date -Format MM\-dd\-yyyy)
    [string]$Component = "$Component - Line:$($MyInvocation.ScriptLineNumber)"
    [string]$ScriptName = If(((($MyInvocation.ScriptName) -split '\\')[-1]) -ne "\$MyInvocation") { ((($MyInvocation.ScriptName) -split '\\')[-1])}
    [string[]]$LogLine = "<![LOG[" + $Message + "]LOG]!><time=""" + $LogTime + """ date=""" + $LogDate + """ component=""" + $Component + """ context="""" type=""" + $LogType + """ thread=""" + $PID + """ + file=""" + $ScriptName.Replace('.ps1','') + """>"

    Add-Content -Path $FullLogPath -Value $LogLine
    [string]$EventSource = 'SecEnable'

    If($WriteEvent)
    {
        If(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") -eq $false)
        {
            [string]$Message = 'Write to event log is enabled, but script is not executing with privledges to write to event log, bypassing event log'
            [string[]]$LogLine = "<![LOG[" + $Message + "]LOG]!><time=""" + $LogTime + """ date=""" + $LogDate + """ component=""" + $Component + """ context="""" type=""" + $LogType + """ thread=""" + $PID + """ + file=""" + $ScriptName.Replace('.ps1','') + """>"
            Add-Content -Path $FullLogPath -Value $LogLine
        }
        Else
        {
            Switch($TypeName)
            {
                'Normal'
                    {
                        If($DebugWriteEvent -eq $true)
                        {
                            New-EventLog -LogName Application -Source $EventSource -ErrorAction SilentlyContinue
                            [string]$EventLogMessage = "$Message `nLogPath: $FullLogPath"
                            Write-EventLog -EventId 6596 -EntryType Information -LogName Application -Source $EventSource -Message $EventLogMessage -Category 1
                        }
                    }
                'Warning'
                    {
                        New-EventLog -LogName Application -Source $EventSource -ErrorAction SilentlyContinue
                        [string]$EventLogMessage = "$Message `nLogPath: $FullLogPath"
                        Write-EventLog -EventId 6596 -EntryType Warning -LogName Application -Source $EventSource -Message $EventLogMessage -Category 2
                    }
                'Error'
                    {
                        New-EventLog -LogName Application -Source $EventSource -ErrorAction SilentlyContinue
                        [string]$EventLogMessage = "$Message `nLogPath: $FullLogPath"
                        Write-EventLog -EventId 6596 -EntryType Error -LogName Application -Source $EventSource -Message $EventLogMessage -Category 3
                    }
                Default 
                    {
                        If($DebugWriteEvent -eq $true)
                        {
                            New-EventLog -LogName Application -Source $EventSource -ErrorAction SilentlyContinue
                            [string]$EventLogMessage = "$Message `nLogPath: $FullLogPath"
                            Write-EventLog -EventId 6596 -EntryType Information -LogName Application -Source $EventSource -Message $EventLogMessage -Category 1
                        }
                    }
            }
        }
    }
}

#endregion

Write-Host "Starting Yubikey Certificate Enrollment Utility" -ForegroundColor Cyan -NoNewline
If((([regex]"^.{6,8}$").Match($PIN)).Success -eq $False)
{
    Write-Host "`n`tPIN Does not meet the requirements, must be between 6 and 8 characters" -NoNewline -ForegroundColor Red
    Break
}

If((([regex]"^(?:(.)\1*|0?1?2?3?4?5?6?7?8?9?|9?8?7?6?5?4?3?2?1?0?)$").Match($PIN)).Success -eq $True)
{
    Write-Host "`n`tPIN Does not meet the requirements, cannot be in sequence" -NoNewline -ForegroundColor Red
    Break
}

#region CertificateAuthorityName
$Component = 'CA-Name'
[string]$CertificateTemplate = "$($ENV:USERDOMAIN) Smartcard Logon"

If((Test-Path -Path $CertUtilPath) -eq $true)
{
    Write-Host "`nPre-Requirements:`n`tFound Certificate Authority:" -ForegroundColor Cyan -NoNewline
    Write-TransLog -Message "Certutil found :: $CertificateTemplate will be requested for Issuing" -Component $Component-CAName -TypeName Normal
    Start-Process $CertUtilPath -ArgumentList "-TemplateCAs `"$CertificateTemplate`"" -RedirectStandardOutput $CANameFile -Wait -NoNewWindow
    $retVal = Get-Content -Path $CANameFile
    [string]$CertAuthFQDN = $retVal[0].Split('\')[0]
    [string]$CertAuthNETBIOS = $retVal[0].Split('.')[0]
    [string]$CAConfigName = $retVal[0]
    If($CertAuthNETBIOS -eq $null)
    {
        Write-Host " Failed :: $Results" -NoNewline -ForegroundColor Red
        Write-TransLog "Certificate Authority not found" -Component $Component -TypeName Error
        Write-TransLog "Check :: $CANameFile" -Component $Component -TypeName Error
        Break
    }
    Else
    {
        Write-Host " Success" -NoNewline -ForegroundColor Green
        Write-TransLog "Certificate Authority found :: $CertAuthNETBIOS" -Component $Component -TypeName Normal
    }
}
Else
{
    Write-Host " Failed :: $Results" -NoNewline -ForegroundColor Red
    Write-TransLog -Message "Certutil not found :: $CertUtilPath" -Component $Component -TypeName Error
    Break
}

$CertAuthFQDN = $CertAuthFQDN.ToLower()
[string]$CertAuthDomain = $CertAuthFQDN.Split(".")[$CertAuthFQDN.Split(".").Length - 2] + "." + $CertAuthFQDN.Split(".")[$CertAuthFQDN.Split(".").Length -1]
[string]$CAPath = "/CN=$CertAuthFQDN/OU=CA/O=$CertAuthDomain"
[string]$UserUPN = "$($env:USERNAME)@$($env:USERDNSDOMAIN)"

Write-TransLog -Message "CertAuthFQDN :: $CertAuthFQDN" -Component "$Component-Variables" -TypeName Normal
Write-TransLog -Message "CAPath :: $CAPath" -Component "$Component-Variables" -TypeName Normal
Write-TransLog -Message "CertAuthDomain :: $CAPath" -Component "$Component-Variables" -TypeName Normal
Write-TransLog -Message "UserUPN :: $UserUPN" -Component "$Component-Variables" -TypeName Normal

#endregion

#region YubiKeyPIVPath

### Checking to ensure YubiKey PIV Management tool is installed
### Exit script if YubiKey is not properly configured
$YubicoPIVPath = Join-Path -Path $YubicoPIVPath -ChildPath 'yubico-piv-tool.exe'
Write-host "`n`tYubikey PIV Tool Installed:" -ForegroundColor Cyan -NoNewline
If((Test-Path -Path $YubicoPIVPath) -eq $false)
{
    Write-host " Failed :: $Results" -NoNewline -ForegroundColor Red
    Write-TransLog -Message 'Yubikey PIV Management software not installed' -Component "$Component-PIVTool" -TypeName Error
    Write-TransLog -Message "Yubikey :: $YubicoPIVPath missing" -Component "$Component-PIVTool" -TypeName Error
    Break
}
Else
{
    Write-Host " Success" -NoNewline -ForegroundColor Green
    Write-TransLog -Message 'Yubikey PIV Management software was installed' -Component "$Component-PIVTool" -TypeName Normal
}

#endregion

#region YubiKey Inserted
### Checking to determine if YubiKey is inserted and proper drivers are installed
### Exit script if YubiKey is not properly configured

Write-Host "`n`tYubikey Inserted:" -ForegroundColor Cyan -NoNewline
$YubiKeyInserted = Get-WmiObject -Query 'Select ConfigManagerErrorCode FROM Win32_PnPEntity WHERE Name LIKE "%Yubikey 4%"'
If($YubiKeyInserted.ConfigManagerErrorCode -ne 0)
{
    Write-Host " Failed :: Please insert Yubikey 4 or check Device Manager" -ForegroundColor Red -NoNewline
    Write-TransLog -Message "Yubikey 4 was not detected or there is a problem with device drivers :: $YubiKeyInserted" -Component "$Component-Detection" -TypeName Error -WriteEvent
    Break
}
Else
{
    Write-Host " Success" -ForegroundColor Green -NoNewline
}
#endregion

Try
{
Write-Host "`nValidate if Yubikey has a config:" -NoNewline -ForegroundColor Cyan
Start-Process $YubicoPIVPath -ArgumentList "-a verify-pin -P $DefaultPIN" -Wait -NoNewWindow -RedirectStandardError $TempRead
    $Results = Get-Content -Path $TempRead
    If($Results -eq 'Successfully verified PIN.')
    {
        Write-Host " False (Continuing provisioning of Yubikey)" -NoNewline -ForegroundColor Green
        Write-TransLog -Message 'Yubikey is a default Yubikey.' -Component $Component -TypeName Normal
        Remove-Item -Path $TempRead -Force -ErrorAction SilentlyContinue
    }
    Else
    {
        Write-Host " True" -NoNewline -ForegroundColor Red
        Write-Host "`n`tYubikey does not have the default PIN, which could mean it has a config" -ForegroundColor Yellow
        $Confirmation = (Read-Host "`tPress Y and Enter to Continue to WIPE YUBIKEY (Any other key exits)").ToLower()
        If($Confirmation -eq 'y')
        {
            Write-Host "`tReseting Yubikey to default" -ForegroundColor Yellow -NoNewline
            Write-TransLog "Reseting Yubikey to default configuration" -Component $Component -TypeName Normal
            $i = 0
            Do{
                Start-Process $YubicoPIVPath -ArgumentList '-a change-pin -P 56565656 -N 12345644' -Wait -NoNewWindow -RedirectStandardError $TempRead
                Start-Process $YubicoPIVPath -ArgumentList '-a change-puk -P 56565656 -N 12345644' -Wait -NoNewWindow -RedirectStandardError $TempRead
                $i++
            }
            While($i -le 6)
            Start-Process $YubicoPIVPath -ArgumentList '-a reset' -Wait -NoNewWindow -RedirectStandardError $TempRead
            Remove-Item -Path $TempRead -Force -ErrorAction SilentlyContinue
        }
        Else
        {
            Write-Host "`tExiting Script upon user request`n" -NoNewline -ForegroundColor Cyan
            Write-TransLog "Exiting Script - Configuration Found on Yubikey" -Component $Component -TypeName Warning
            Break
        }
    }

}
Catch
{
        Write-Host " Failed :: $Results" -NoNewline -ForegroundColor Red
        Write-TransLog -Message 'Unable to generate a new private key' -Component $Component -TypeName Error
        Write-TransLog -Message $_ -Component $Component -TypeName Error
        Break
}

#region Setting-Yubikey-ManagementKey
$Component = 'Set-MgMt-Key'

Try
{

    $RndMgMt_Block1 = Get-Random -Minimum 11111111 -Maximum 99999999
    $RndMgMt_Block2 = Get-Random -Minimum 11111111 -Maximum 99999999
    $RndMgMt_Block3 = Get-Random -Minimum 11111111 -Maximum 99999999
    $RndMgMt_Block4 = Get-Random -Minimum 11111111 -Maximum 99999999
    $RndMgMt_Block5 = Get-Random -Minimum 11111111 -Maximum 99999999
    $RndMgMt_Block6 = Get-Random -Minimum 11111111 -Maximum 99999999

    [string]$ManagementKey = "$RndMgMt_Block1$RndMgMt_Block2$RndMgMt_Block3$RndMgMt_Block4$RndMgMt_Block5$RndMgMt_Block6"
    Write-Host "`nYubikey Work:`n`tYubikey Management Code:" -ForegroundColor Cyan -NoNewline
    Write-TransLog -Message "Setting Yubikey Management Key onto device" -Component $Component -TypeName Normal

    Start-Process $YubicoPIVPath -ArgumentList "-a set-mgm-key -n $ManagementKey" -Wait -NoNewWindow -RedirectStandardError $TempRead
    $Results = Get-Content -Path $TempRead
    If($Results -eq 'Successfully set new management key.')
    {
        Write-Host " Success" -NoNewline -ForegroundColor Green
        Write-TransLog -Message 'Successfully set new management key' -Component $Component -TypeName Normal
        Remove-Item -Path $TempRead -Force -ErrorAction SilentlyContinue
    }
    Else
    {
        Write-Host " Failed :: $Results" -NoNewline -ForegroundColor Red
        Write-TransLog -Message 'Unable to set management key' -Component $Component -TypeName Error
        Write-TransLog -Message $Results -Component $Component -TypeName Error
        Break
    }

}
Catch
{
        Write-Host " Failed :: $Results" -NoNewline -ForegroundColor Red
        Write-TransLog -Message 'Unable to set management key' -Component $Component -TypeName Error
        Write-TransLog -Message $_ -Component $Component -TypeName Error
        Break
}

#endregion


#region Generate-New-Private-Key
$Component = 'NewPrivateKey'

Try
{
    Write-TransLog -Message "Generating new YubiKey Private key" -Component $Component -TypeName Normal
    Write-Host "`n`tYubikey Private Key:" -ForegroundColor Cyan -NoNewline
    Start-Process $YubicoPIVPath -ArgumentList "-s9a -a generate -o $PubPEM --key=$ManagementKey"  -Wait -NoNewWindow -RedirectStandardError $TempRead
    $Results = Get-Content -Path $TempRead
    If($Results -eq 'Successfully generated a new private key.')
    {
        Write-Host " Success" -NoNewline -ForegroundColor Green
        Write-TransLog -Message 'Successfully generated a new private key.' -Component $Component -TypeName Normal
        Remove-Item -Path $TempRead -Force -ErrorAction SilentlyContinue
    }
    Else
    {
        Write-Host " Failed :: $Results" -NoNewline -ForegroundColor Red
        Write-TransLog -Message 'Unable to generate a new private key' -Component $Component -TypeName Error
        Write-TransLog -Message $Results -Component $Component -TypeName Error
        Break
    }

}
Catch
{
        Write-Host " Failed :: $Results" -NoNewline -ForegroundColor Red
        Write-TransLog -Message 'Unable to generate a new private key' -Component $Component -TypeName Error
        Write-TransLog -Message $_ -Component $Component -TypeName Error
        Break
}
#endregion

#region Set-New-PIN
$Component = 'SetPIN'
Write-TransLog -Message "Set Yubikey PIN from something other than default" -Component $Component -TypeName Normal
Try
{
    Write-Host "`n`tSet PIN:" -ForegroundColor Cyan -NoNewline
    Start-Process $YubicoPIVPath -ArgumentList "-a change-pin -P $DefaultPIN -N $PIN" -Wait -NoNewWindow -RedirectStandardError $TempRead
    $Results = Get-Content -Path $TempRead
    If($Results -eq 'Successfully changed the pin code.')
    {
        Write-Host " Success" -NoNewline -ForegroundColor Green
        Write-TransLog -Message 'Successfully changed the pin code.' -Component $Component -TypeName Normal
        Remove-Item -Path $TempRead -Force -ErrorAction SilentlyContinue
    }
    Else
    {
        Write-Host " Failed :: $Results" -NoNewline -ForegroundColor Red
        Write-TransLog -Message 'Unable to set new pin' -Component $Component -TypeName Error
        Write-TransLog -Message $Results -Component $Component -TypeName Error
        Break
    }

}
Catch
{
        Write-Host " Failed :: $Results" -NoNewline -ForegroundColor Red
        Write-TransLog -Message 'Unable to set new pin' -Component $Component -TypeName Error
        Write-TransLog -Message $_ -Component $Component -TypeName Error
        Break
}
#endregion

#region Set-New-PUK
$Component = 'SetPUK'

Try
{
   
    Write-TransLog -Message "Set Yubikey PUK from something other than default" -Component $Component -TypeName Normal
    Write-Host "`n`tSet PUK:" -ForegroundColor Cyan -NoNewline
    ## $PUK = '23456789' - Used for testing
    $PUK_Block1 = Get-Random -Minimum 10 -Maximum 99
    $PUK_Block2 = Get-Random -Minimum 10 -Maximum 99
    $PUK_Block3 = Get-Random -Minimum 10 -Maximum 99
    $PUK_Block4 = Get-Random -Minimum 10 -Maximum 99
    $PUK = "$PUK_Block1$PUK_Block2$PUK_Block3$PUK_Block4"

    Start-Process $YubicoPIVPath -ArgumentList "-a change-puk -P $DefaultPUK -N $PUK" -Wait -NoNewWindow -RedirectStandardError $TempRead
    $Results = Get-Content -Path $TempRead
    If($Results -eq 'Successfully changed the puk code.')
    {
        Write-Host " Success" -NoNewline -ForegroundColor Green
        Write-TransLog -Message 'Successfully changed the puk code.' -Component $Component -TypeName Normal
        Remove-Item -Path $TempRead -Force -ErrorAction SilentlyContinue
    }
    Else
    {
        Write-Host " Failed :: $Results" -NoNewline -ForegroundColor Red
        Write-TransLog -Message 'Unable to set new PUK' -Component $Component -TypeName Error
        Write-TransLog -Message $Results -Component $Component -TypeName Error
        Break
    }

}
Catch
{
        Write-Host " Failed :: $Results" -NoNewline -ForegroundColor Red
        Write-TransLog -Message 'Unable to set new PUK' -Component $Component -TypeName Error
        Write-TransLog -Message $_ -Component $Component -TypeName Error
        Break
}
#endregion

#region Generate_CSR
$Component = 'GenerateCSR'

Try
{
    Write-Host "`n`tGenerate CSR:" -ForegroundColor Cyan -NoNewline
    Write-TransLog -Message "Generating new CSR request" -Component $Component -TypeName Normal
    Start-Process $YubicoPIVPath -ArgumentList "-a verify-pin -P $PIN -s9a -a request-certificate -S $CAPath -i $PubPEM -o $CSRRequestFile"  -Wait -NoNewWindow -RedirectStandardError $TempRead
    $Results = Get-Content -Path $TempRead
    If($Results -eq 'Successfully generated a certificate request.')
    {
        Write-Host " Success" -NoNewline -ForegroundColor Green
        Write-TransLog -Message 'Successfully generated a certificate request.' -Component $Component -TypeName Normal
        Remove-Item -Path $TempRead -Force -ErrorAction SilentlyContinue
    }
    Else
    {
        Write-Host " Failed :: $Results" -NoNewline -ForegroundColor Red
        Write-TransLog -Message 'Unable to generate CSR' -Component $Component -TypeName Error
        Write-TransLog -Message $Results -Component $Component -TypeName Error
        Break
    }

}
Catch
{
        Write-Host " Failed :: $Results" -NoNewline -ForegroundColor Red
        Write-TransLog -Message 'Unable to generate CSR' -Component $Component -TypeName Error
        Write-TransLog -Message $_ -Component $Component -TypeName Error
        Break
}
#endregion

#region Request-Cert-PKI
$Component = 'Request-Cert-PKI'

Try
{
    Write-Host "`n`tRequesting Certificate from `n`t`t ($CAConfigName):" -ForegroundColor Cyan -NoNewline
    Write-TransLog -Message "Requesting Certificate from PKI Issuing Authority ($CAConfigName)" -Component $Component -TypeName Normal
    Start-Process $CertReqPath -ArgumentList "-submit -config `"$CAConfigName`" -attrib CertificateTemplate:`"$CertificateTemplate`" $CSRRequestFile $CertFile" -Wait -NoNewWindow -RedirectStandardError $TempRead -RedirectStandardOutput $TempOuptut
    $Results = Get-Content -Path $TempOuptut
    If($Results.Contains('Certificate retrieved(Issued) Issued'))
    {
        Write-Host " Success" -NoNewline -ForegroundColor Green
        Write-TransLog -Message 'Successfully submitted CSR request to PKI server.' -Component $Component -TypeName Normal
        Remove-Item -Path $TempRead -Force -ErrorAction SilentlyContinue
    }
    Else
    {
        Write-Host " Failed :: $Results" -NoNewline -ForegroundColor Red
        Write-TransLog -Message 'Unable to submit CSR request to PKI server' -Component $Component -TypeName Error
        Write-TransLog -Message $Results -Component $Component -TypeName Error
        Break
    }

}
Catch
{
        Write-Host " Failed :: $Results" -NoNewline -ForegroundColor Red
        Write-TransLog -Message 'Unable to submit CSR request to PKI server' -Component $Component -TypeName Error
        Write-TransLog -Message $_ -Component $Component -TypeName Error
        Break
}
#endregion

#region Load-Cert
$Component = 'Load-Cert'

Try
{
    Write-Host "`n`tLoad Certificate:" -ForegroundColor Cyan -NoNewline
    Write-TransLog -Message "Loading Certificate onto the Yubikey" -Component $Component -TypeName Normal
    Start-Process $YubicoPIVPath -ArgumentList "-s 9a -a import-certificate -i $CertFile --key=$ManagementKey" -Wait -NoNewWindow -RedirectStandardError $TempRead
    $Results = Get-Content -Path $TempRead
    If($Results -eq 'Successfully imported a new certificate.')
    {
        Write-Host " Success" -NoNewline -ForegroundColor Green
        Write-TransLog -Message 'Successfully imported a new certificate.' -Component $Component -TypeName Normal
        Remove-Item -Path $TempRead -Force -ErrorAction SilentlyContinue
    }
    Else
    {
        Write-Host " Failed :: $Results" -NoNewline -ForegroundColor Red
        Write-TransLog -Message 'Unable to import certificate onto Yubikey' -Component $Component -TypeName Error
        Write-TransLog -Message $Results -Component $Component -TypeName Error
        Break
    }

}
Catch
{
        Write-Host " Failed :: $Results" -NoNewline -ForegroundColor Red
        Write-TransLog -Message 'Unable to import certificate onto Yubikey' -Component $Component -TypeName Error
        Write-TransLog -Message $_ -Component $Component -TypeName Error
        Break
}
#endregion

#region Set-CHUID
$Component = 'Set-CHUID'

Try
{
    Write-Host "`n`tSet CHUID:" -ForegroundColor Cyan -NoNewline
    Write-TransLog -Message "Attempting to set new CHUID onto Yubikey" -Component $Component -TypeName Normal
    Start-Process $YubicoPIVPath -ArgumentList "-a set-chuid --key=$ManagementKey" -Wait -NoNewWindow -RedirectStandardError $TempRead
    $Results = Get-Content -Path $TempRead
    If($Results -eq 'Successfully set new CHUID.')
    {
        Write-Host " Success" -NoNewline -ForegroundColor Green
        Write-TransLog -Message 'Successfully set new CHUID.' -Component $Component -TypeName Normal
        Remove-Item -Path $TempRead -Force -ErrorAction SilentlyContinue
    }
    Else
    {
        Write-Host " Failed :: $Results" -NoNewline -ForegroundColor Red
        Write-TransLog -Message 'Unable to set new CHUID' -Component $Component -TypeName Error
        Write-TransLog -Message $Results -Component $Component -TypeName Error
        Break
    }

}
Catch
{
        Write-Host " Failed :: $Results" -NoNewline -ForegroundColor Red
        Write-TransLog -Message 'Unable to import certificate onto Yubikey' -Component $Component -TypeName Error
        Write-TransLog -Message $_ -Component $Component -TypeName Error
        Break
}
#endregion

#region Cleanup-Script
    Write-TransLog -Message "Removing temporary files from system" -Component 'Cleanup' -TypeName Normal
    Remove-Item -Path $TempRead -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $TempOuptut -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $CSRRequestFile -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $CertFile -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $CANameFile -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $PubPEM -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $CANameFile -Force -ErrorAction SilentlyContinue

    Write-Host "`nYubikey Setup Successfully for user: $UserUPN`n" -ForegroundColor Cyan

    Get-Variable | Remove-Variable -ErrorAction SilentlyContinue
#endregion

