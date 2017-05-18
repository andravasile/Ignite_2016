## Version Information
## 03-May-2017 v1.0 Tanner Slayton - Initial Creation and Testing of Script for Yubikey wipe
##
## Reviewer Information
## 
##
## Feature Request
##     
##
## Known Issues
##
##
## Usage Examples:
## .\Yubikey-Wipe.ps1
##

$YubicoPIVPath = 'C:\Program Files (x86)\Yubico\YubiKey PIV Manager'
$YubicoPIVPath = Join-Path -Path $YubicoPIVPath -ChildPath 'yubico-piv-tool.exe'
$TempRead = "$ENV:Temp\Yubikey-$(Get-Random -Minimum 10000 -Maximum 20000).out"
$i = 0

Do{
    Start-Process $YubicoPIVPath -ArgumentList '-a change-pin -P 56565656 -N 12345644' -Wait -NoNewWindow -RedirectStandardError $TempRead
    Start-Process $YubicoPIVPath -ArgumentList '-a change-puk -P 56565656 -N 12345644' -Wait -NoNewWindow -RedirectStandardError $TempRead
    $i++
}
While($i -le 6)
Start-Process $YubicoPIVPath -ArgumentList '-a reset' -Wait -NoNewWindow -RedirectStandardError $TempRead