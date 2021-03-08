[cmdletbinding()]
Param (
 [Parameter(Mandatory = $true)]
	[string[]] $BackupFilePath
)

if ($BackupFilePath -eq "devtest") {
	$BackupFile = Get-ChildItem -Path $env:devtest  -Filter "*.bak" -Recurse| Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1
	$BackupFilePath = $env:devtest + "\" + $BackupFileFull.Name
}
else {
	Write-host "Use the path indicated: $BackupFilePath"
}

if ($BackupFilePath -notlike "*.bak") {
	write-host "please provide a .bak file path"
}
else {
	#import modules
	Import-Module dbatools
	Import-Module d365fo.tools

	$NewDBName = "AxDB"
	$Date = Get-Date -format "yyyyMMdd"
	$timenow = Get-date -Format "HHMM"
	$name = $NewDBName + "_" + $Date + "_" + $timenow


	$BackupInfo = Get-DbaBackupInformation -Path $BackupFilePath -SqlInstance .
	$BackupInfo.FileList | % { If ($_.Type -eq "D") { $LogicaData = $_.LogicalName }
		Elseif ($_.Type -eq "L") { $LogicalLog = $_.LogicalName }
	}

	$FileStructure = @{
		"$LogicaData" = "C:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\DATA\$name.mdf"
		"$LogicalLog" = "C:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\DATA\$name.ldf"
 }

	#restore DB from File
	Restore-DbaDatabase -SqlInstance . -Path $BackupFilePath -DatabaseName $name -ReplaceDbNameInFile -FileMapping $FileStructure -WithReplace


	#stop ENV
	Stop-D365Environment

	#check if the Orig DB is present and remove it

	If (Get-DbaDatabase -SqlInstance . -Database Axdb_original) {
		Remove-DbaDatabase -SqlInstance . -Database Axdb_original -Confirm:$false
	}

	#Change active DB
	Switch-D365ActiveDatabase -DatabaseServer . -DatabaseName AxDB -SourceDatabaseName $name 


	#get-users to be imported in AX
	$users = Get-LocalUser

	#get the email addresses
	$emails = $users | where { $_.Description -like "*@*" } | select -expand Description

	#g
	# create LocalUsers and provision
	foreach ($email in $emails) {

		$pieces = $Email -split '@'

		$FullName = $pieces[0] -replace "\.", " " 
		$Names = $pieces[0] -split "\." 

		$name = ($names[0])[0] + $Names[1] 

		#remove users before reimport if already present to maintent the worker. 
		$D365user = Get-D365User -Email $email
		If ($D365user) {
			Remove-D365User -Email $email -ErrorAction SilentlyContinue

			#add user in AX instance
			Import-D365ExternalUser -Id $D365user.UserId -Name $FullName -Email $Email -DatabaseServer . -DatabaseName AxDB
		}
		else {
			Import-D365ExternalUser -Id $pieces[0] -Name $FullName -Email $Email -DatabaseServer . -DatabaseName AxDB
		}
	}

	#Start ENV
	Start-D365Environment

	Invoke-D365DbSync -MetadataDir "C:\AOSService\PackagesLocalDirectory"  -DatabaseServer . -DatabaseName AxDB -SyncMode fullall -LogPath C:\temp -ShowOriginalProgress 
}