[cmdletbinding()]
Param (
 [Parameter(Mandatory=$True)]
    [string[]] $BackupFilePath
)

#import modules
Import-Module dbatools
Import-Module d365fo.tools

$NewDBName = "AxDB_restored"

#restore DB from File
Restore-DbaDatabase -SqlInstance . -Path $BackupFilePath -DatabaseName $NewDBName -ReplaceDbNameInFile
Rename-DbaDatabase -SqlInstance . -Database $NewDBName -LogicalName "<DBN>_<FT>"


#stop ENV
Stop-D365Environment

#check if the Orig DB is present and remove it

If (Get-DbaDatabase -SqlInstance . -Database Axdb_original) {
Remove-DbaDatabase -SqlInstance . -Database Axdb_original -Confirm:$false
}

#Change active DB
Switch-D365ActiveDatabase -DatabaseServer . -DatabaseName AxDB -SourceDatabaseName $NewDBName 


#get-users to be imported in AX
$users = Get-LocalUser

#get the email addresses
$emails = $users | where {$_.Description -like  "*@*"} | select -expand Description

#g
# create LocalUsers and provision
foreach ($email in $emails) {

$pieces = $Email -split '@'

$FullName = $pieces[0] -replace "\.", " " 
$Names = $pieces[0] -split "\." 

$name = ($names[0])[0] + $Names[1] 

#add user in AX instance
Import-D365ExternalUser -Id $Name -Name $FullName -Email $Email -DatabaseServer . -DatabaseName AxDB
}

#Start ENV
Start-D365Environment

Invoke-D365DbSync -MetadataDir "C:\AOSService\PackagesLocalDirectory"  -DatabaseServer . -DatabaseName AxDB -SyncMode fullall -LogPath C:\temp -ShowOriginalProgress
