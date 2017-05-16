$modules = 'C:\Users\peppe\OneDrive\GitHub\CS-Onboarding-PFSENSE'
$modulename = 'pfSenseConfigurator'
$Version = '1.0.0'
$Description = 'This module is used to configure a pfSense Linux VM from within a Cloud Suite environment. Functionality is limited one-time config'

$modulefolder = join-path $modules $modulename
If (!(Test-Path $modulefolder)){mkdir $modulefolder}
$versionfolder = join-path $modulefolder $Version
If (!(Test-Path $versionfolder)){mkdir $versionfolder}
New-ModuleManifest -Path (join-path $versionfolder "$modulename.psd1") -Guid $([system.guid]::newguid().guid) -Author 'Peppe Kerstens' -CompanyName 'ITON Services BV' -Copyright '2016' -ModuleVersion $Version -Description $Description -PowerShellVersion '5.0'
