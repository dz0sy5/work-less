<# temp
parm (
    $ServerRole,$AdminPassword
)
#>

<# Preparation:
    #  Windows updated
    #  Antimalware scan
    #
    # Execute this script:
    # Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/dz0sy5/work-less/master/D365FFo/DevT1/InitT1VM.ps1'))

    #$ErrorActionPreference="Stop";If(-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")){throw "Run command in an administrator PowerShell prompt"};If($PSVersionTable.PSVersion -lt (New-Object System.Version("3.0"))){ throw "The minimum version of Windows PowerShell that is required by the script (3.0) does not match the currently running version of Windows PowerShell." };$DefaultProxy=[System.Net.WebRequest]::DefaultWebProxy;$securityProtocol=@();$securityProtocol+=[Net.ServicePointManager]::SecurityProtocol;$securityProtocol+=[Net.SecurityProtocolType]::Tls12;[Net.ServicePointManager]::SecurityProtocol=$securityProtocol;Register-PSRepository -Default -ErrorAction SilentlyContinue; Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted;Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/dz0sy5/work-less/DEV/D365FFo/DevT1/InitT1VM.ps1'))
    #ToDo:
    #  Change Hostname 
    #  Check the static IP config
    #  Implement the server roles (DEV, BUILD, DEV Test, GOLD, etc..)
    #  Logoff Icon copy it to public Desktop
    #  BUILD VM registry configuration
    # add ENV path to the EnvironmentVariablepath
    # add Automatic BACKUP DEV TEST into a share daily with retantion 3 days. 
    # Create a SHare into DEV test to be accessed by all developers
    # create the Security users into the dev TEST
    # automatic import DEV test users from DEV OPS
    # azure Storage configuration (conf file 127.0.0.1 change with the static IP)
    # Add the confgiuration in WEB CONFIG for DEV test sytem
    #update the storage emulator file with

            cd "C:\Program Files (x86)\Microsoft SDKs\Azure\Storage Emulator"

            tasklist /FI "IMAGENAME eq AzureStorageEmulator.exe" 

            SETLOCAL EnableExtensions
            set EXE=AzureStorageEmulator.exe
            FOR /F %%x IN ('tasklist /NH /FI "IMAGENAME eq %EXE%"') DO IF %%x == %EXE% goto FOUND
            echo Not running, starting
            AzureStorageEmulator.exe start
            goto FIN
            :FOUND
            echo Already Running
            :FIN

    #reg key for BUILD
    #  Windows Registry Editor Version 5.00

    # [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Dynamics\AX\7.0\SDK]
    # "DynamicsSDK"="C:\\DynamicsSDK"
    # "TeamFoundationServerUrl"="https://dev.azure.com/dz0Sy5"
    # "AosWebsiteName"="AOSService"
    # "BinariesPath"="C:\\AOSService\\PackagesLocalDirectory\\Bin"
    # "MetadataPath"="C:\\AOSService\\PackagesLocalDirectory"
    # "PackagesPath"="C:\\AOSService\\PackagesLocalDirectory"
    # "DatabaseName"="AxDB"
    # "DatabaseServer"="localhost"
    # "BackupPath"="C:\\DynamicsBackup"
#>
 

#region Vars
$Owner = 'dz0sy5';
$Repository = 'work-less';
$Path = 'D365FFo/DevT1/DevTools';
$DestinationPath = 'C:\Scripts'

#endregion

Function SetStrongCryptography {
    #set tls 1.2 for the current PS session if missing
    if ([Net.ServicePointManager]::SecurityProtocol -ne 'Tls12') {
        Write-Host "Update the TLS settings"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }

    # set strong cryptography on 64 bit .Net Framework (version 4 and above)
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord

    # set strong cryptography on 32 bit .Net Framework (version 4 and above)
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord 
}

#region github download function to be used by the script
function DownloadFilesFromGitHub {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Owner,
        [Parameter(Mandatory = $true)]
        [string]$Repository,
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )
    
    $baseUri = "https://api.github.com/"
    $args = "repos/$Owner/$Repository/contents/$Path"
    $wr = Invoke-WebRequest -Uri $($baseuri + $args)
    $objects = $wr.Content | ConvertFrom-Json
    $files = $objects | where { $_.type -eq "file" } | Select -exp download_url
    $directories = $objects | where { $_.type -eq "dir" }
        
    $directories | ForEach-Object { 
        DownloadFilesFromRepo -Owner $Owner -Repository $Repository -Path $_.path -DestinationPath $($DestinationPath + $_.name)
    }
    
        
    if (-not (Test-Path $DestinationPath)) {
        # Destination path does not exist, let's create it
        try {
            New-Item -Path $DestinationPath -ItemType Directory -ErrorAction Stop
        }
        catch {
            throw "Could not create path '$DestinationPath'!"
        }
    }
    Else {
        # Destination path exist, recreate
        try {
            Remove-Item -Path $DestinationPath -Force -Recurse
            New-Item -Path $DestinationPath -ItemType Directory -ErrorAction Stop
        }
        catch {
            throw "Could not create path '$DestinationPath'!"
        }

    }
    
    foreach ($file in $files) {
        $fileDestination = Join-Path $DestinationPath (Split-Path $file -Leaf)
        try {
            Invoke-WebRequest -Uri $file -OutFile $fileDestination -ErrorAction Stop -Verbose 
            "Grabbed '$($file)' to '$fileDestination'"
        }
        catch {
            throw "Unable to download '$($file.path)'"
        }
    }
    
}


#endregion

#region Install additional apps using Chocolatey
#how the package list must be provided
<#
$packages = @(
            "dotnet4.7.2"
            "vscode"
            "vscode-mssql"
            #"vscode-azurerm-tools"
            "peazip"
            "microsoft-edge"
            "windirstat"
            "notepadplusplus.install"
            #"git.install"
            #"sysinternals"
            "postman"  # or insomnia-rest-api-client
            "fiddler"
        )
        #>
function InstallAdditionalApps {
    param (
        [Parameter(Mandatory = $true)]
        [Array]$packages
    )

    if ($packages) {

        If (Test-Path -Path "$env:ProgramData\Chocolatey") {
            choco upgrade chocolatey -y -r
            choco upgrade all --ignore-checksums -y -r
        }
        Else {

            Write-Host "Installing Chocolatey"
 
            [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
            iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

            #Determine choco executable location
            #   This is needed because the path variable is not updated
            #   This part is copied from https://chocolatey.org/install.ps1
            $chocoPath = [Environment]::GetEnvironmentVariable("ChocolateyInstall")
            if ($chocoPath -eq $null -or $chocoPath -eq '') {
                $chocoPath = "$env:ALLUSERSPROFILE\Chocolatey"
            }
            if (!(Test-Path ($chocoPath))) {
                $chocoPath = "$env:SYSTEMDRIVE\ProgramData\Chocolatey"
            }
            $chocoExePath = Join-Path $chocoPath 'bin\choco.exe'

            # Install each program
            foreach ($packageToInstall in $packages) {

                Write-Host "Installing $packageToInstall" -ForegroundColor Green
                & $chocoExePath "install" $packageToInstall "-y" "-r"
            }
        }
    }
    else {
        Write-host "No aditional software to install/update"
    }
}
#endregion

function StandardConfiguration {
    #region Privacy

    # Disable Windows Telemetry (requires a reboot to take effect)
    Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -Type DWord -Value 0
    Get-Service DiagTrack, Dmwappushservice | Stop-Service | Set-Service -StartupType Disabled

    # Start Menu: Disable Bing Search Results
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name BingSearchEnabled -Type DWord -Value 0


    # Start Menu: Disable Cortana
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
    #endregion


    #region general config
    # Set power settings to High Performance
    Write-Host "Setting power settings to High Performance"
    powercfg.exe /SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c


    Write-Host "Setting web browser homepage to the local environment"
    Get-D365Url | Set-D365StartPage

    Write-Host "Setting Management Reporter to manual startup to reduce churn and Event Log messages"
    Get-D365Environment -FinancialReporter | Set-Service -StartupType Manual

    Write-Host "Setting Windows Defender rules to speed up compilation time"
    Add-D365WindowsDefenderRules -Silent
    #endregion

    #region Installing d365fo.tools

    # This is requried by Find-Module, by doing it beforehand we remove some warning messages
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

    # Installing d365fo.tools
    If ($null -eq (Get-Module d365fo.tools -ListAvailable)) {
        Write-Host "Installing d365fo.tools"
        Write-Host "    Documentation: https://github.com/d365collaborative/d365fo.tools"
        Install-Module -Name d365fo.tools 
    }
    else {
        Write-Host "Updating d365fo.tools"
        Update-Module -name d365fo.tools
    }

    #endregion
}

#region Install and run Ola Hallengren's IndexOptimize

Function Execute-Sql {
    Param(
        [Parameter(Mandatory = $true)][string]$server,
        [Parameter(Mandatory = $true)][string]$database,
        [Parameter(Mandatory = $true)][string]$command
    )
    Process {
        $scon = New-Object System.Data.SqlClient.SqlConnection
        $scon.ConnectionString = "Data Source=$server;Initial Catalog=$database;Integrated Security=true"
        
        $cmd = New-Object System.Data.SqlClient.SqlCommand
        $cmd.Connection = $scon
        $cmd.CommandTimeout = 0
        $cmd.CommandText = $command

        try {
            $scon.Open()
            $cmd.ExecuteNonQuery()
        }
        catch [Exception] {
            Write-Warning $_.Exception.Message
        }
        finally {
            $scon.Dispose()
            $cmd.Dispose()
        }
    }
}




#region Update PowerShell Help, power settings, and Logoff icon
function UpdatePowershellHelp {
    Write-Host "Updating PowerShell help"
    $what = ""
    Update-Help  -Force -Ea 0 -Ev what
    If ($what) {
        Write-Warning "Minor error when updating PowerShell help"
        Write-Host $what.Exception
    }
}


# Create Logoff Icon and copy it to public Desktop dev vm's
function LogOffIcon {
    Write-Host "Creating logoff icon on desktop of the current user"
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($env:HOMEDRIVE + $env:HOMEPATH + "\Desktop\logoff.lnk")
    $Shortcut.TargetPath = "C:\Windows\System32\logoff.exe"
    $Shortcut.Save()

    #move the shortcut for all users
    #C:\Users\Public\Desktop - Local VHD
    $source = ($env:HOMEDRIVE + $env:HOMEPATH + "\Desktop\logoff.lnk")
    if ((Test-Path "C:\Users\Public\Desktop\logoff.lnk") -eq $false) {
        Move-item -path $source -Destination "C:\Users\Public\Desktop\"
    }
}

#endregion

#region Local User Policy
function ConfigureLocalAdmin {
    # Set the password to never expire
    Get-WmiObject Win32_UserAccount -filter "LocalAccount=True" | ? { $_.SID -Like "S-1-5-21-*-500" } | Set-LocalUser -PasswordNeverExpires 1

    # Disable changing the password
    $registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $name = "DisableChangePassword"
    $value = "1"

    If (!(Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    }
    Else {
        $passwordChangeRegKey = Get-ItemProperty -Path $registryPath -Name $Name -ErrorAction SilentlyContinue

        If (-Not $passwordChangeRegKey) {
            New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
        }
        Else {
            Set-ItemProperty -Path $registryPath -Name $name -Value $value
        }
    }
}
#endregion

#region Configure Windows Updates when Windows 10 and restart during the windows
Function ConfigureWindowsUpdates {
    if ((Get-WmiObject Win32_OperatingSystem).Caption -Like "*Windows 10*") {

        #Write-Host "Changing Windows Updates to -Notify to schedule restart-"
        #Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name UxOption -Type DWord -Value 1

        Write-Host "Disabling P2P Update downlods outside of local network"
        Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config -Name DODownloadMode -Type DWord -Value 1
        Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization -Name SystemSettingsDownloadMode -Type DWord -Value 3
    }
    elseif ((Get-WmiObject Win32_OperatingSystem).Caption -Like "*Windows Server 2016*") {
        #set the update to auto download and schedule the install 
        Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name AUOptions -Value 4

        #Setting the Scheduled Install Day to Tuesday:
        Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name ScheduledInstallDay -Value 7

        #Setting the Scheduled Install time to 6 AM:
        Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name ScheduledInstallTime -Value 0

        #old style same result, temporary note
        <#
        $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Default')
        $wu = $hklm.CreateSubKey('SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU')
        $wu.SetValue('NoAutoUpdate', 0, 'DWord')
        $wu.SetValue('AUOptions', 4, 'DWord')
        $wu.SetValue('ScheduledInstallDay', 7, 'DWord')
        $wu.SetValue('ScheduledInstallTime', 0, 'DWord')
        $wu.Dispose()
        $hklm.Dispose()
        #>
    }
}
#endregion


#region Remove Windows 10 Metro apps
function RemoveWindowsApps {
    if ((Get-WmiObject Win32_OperatingSystem).Caption -Like "*Windows 10*") {

        # Windows 10 Metro App Removals
        # These start commented out so you choose

        Write-Host "Removing Metro Apps"
        Get-AppxPackage king.com.CandyCrushSaga | Remove-AppxPackage
        Get-AppxPackage Microsoft.BingWeather | Remove-AppxPackage
        Get-AppxPackage Microsoft.BingNews | Remove-AppxPackage
        Get-AppxPackage Microsoft.BingSports | Remove-AppxPackage
        Get-AppxPackage Microsoft.BingFinance | Remove-AppxPackage
        Get-AppxPackage Microsoft.XboxApp | Remove-AppxPackage
        Get-AppxPackage Microsoft.WindowsPhone | Remove-AppxPackage
        Get-AppxPackage Microsoft.MicrosoftSolitaireCollection | Remove-AppxPackage
        Get-AppxPackage Microsoft.People | Remove-AppxPackage
        Get-AppxPackage Microsoft.ZuneMusic | Remove-AppxPackage
        Get-AppxPackage Microsoft.ZuneVideo | Remove-AppxPackage
        Get-AppxPackage Microsoft.Office.OneNote | Remove-AppxPackage
        Get-AppxPackage Microsoft.Windows.Photos | Remove-AppxPackage
        Get-AppxPackage Microsoft.WindowsSoundRecorder | Remove-AppxPackage
        Get-AppxPackage microsoft.windowscommunicationsapps | Remove-AppxPackage
        Get-AppxPackage Microsoft.SkypeApp | Remove-AppxPackage
    }
}
#endregion

#region SQL agent 

function ConfigureSQLandAgent {

    If ((Get-Service SQLSERVERAGENT | select -expand StartType) -ne "Automatic") {
        #SQL agent startup 
        Set-Service SQLSERVERAGENT -StartupType Automatic 
        Start-Service SQLSERVERAGENT
    }

    #configure SQL service account
    if (Get-WmiObject Win32_Service -filter 'STARTNAME LIKE "%Administrator%" AND NAME LIKE "MSSQLSERVER"') {
        Write-host "SQL service already configured"
    }
    else {

        $service = gwmi win32_service -filter "name='MSSQLSERVER'"
        $AdminPassword = Read-Host "Enter the Administrator Password:" 
        $service.change($null, $null, $null, $null, $null, $null, ".\administrator", "$AdminPassword")
        
        Restart-Service -Name MSSQLSERVER -Force
        If ((Get-Service -name MSSQLSERVER | select -expand Status) -ne "Running" ) {
            Write-host "Please check the SQL server Credentials and start the service!"
        }

    }
}


function ConfigureBackup {

    #create the folder for the backup if not present
    if (!(Test-Path $env:HOMEDRIVE\BackupShared)) {
        #create Folder
        New-Item -Path $env:HOMEDRIVE\BackupShared -ItemType directory

    }
    #create a share for the backup if not present
    If (!(Get-SmbShare -Name BackupShared -ErrorAction SilentlyContinue)) {
        New-SmbShare -Name "BackupShared" -Path "$env:HOMEDRIVE\BackupShared" -ChangeAccess "Users" -FullAccess "Administrators"
    }

   
    $DailyBackupJob = "
DECLARE @jobId BINARY(16)
EXEC  msdb.dbo.sp_add_job @job_name=N'Backup - full - axdb - daily', 
        @enabled=1, 
        @notify_level_eventlog=0, 
        @notify_level_email=0, 
        @notify_level_netsend=0, 
        @notify_level_page=0, 
        @delete_level=0, 
        @description=N'No description available.', 
        @category_name=N'[Uncategorized (Local)]', 
        @owner_login_name=N'sa', @job_id = @jobId OUTPUT

EXEC  msdb.dbo.sp_add_jobstep @job_id=@jobId, @step_name=N'AXDB backup', 
        @step_id=1, 
        @cmdexec_success_code=0, 
        @on_success_action=1, 
        @on_success_step_id=0, 
        @on_fail_action=2, 
        @on_fail_step_id=0, 
        @retry_attempts=0, 
        @retry_interval=0, 
        @os_run_priority=0, @subsystem=N'TSQL', 
        @command=N'EXECUTE dbo.DatabaseBackup
@Databases = ''AXDB'',
@Directory = ''$env:HOMEDRIVE\BackupShared'',
@BackupType = ''FULL'',
@Verify = ''Y'',
@Compress = ''Y'',
@CheckSum = ''Y'',
@CleanupTime = 24

', 
        @database_name=N'master', 
        @flags=0

EXEC msdb.dbo.sp_update_job @job_id = @jobId, @start_step_id = 1

EXEC  msdb.dbo.sp_add_jobschedule @job_id=@jobId, @name=N'daily', 
        @enabled=1, 
        @freq_type=4, 
        @freq_interval=1, 
        @freq_subday_type=1, 
        @freq_subday_interval=0, 
        @freq_relative_interval=0, 
        @freq_recurrence_factor=0, 
        @active_start_date=20210118, 
        @active_end_date=99991231, 
        @active_start_time=40000, 
        @active_end_time=235959, 
        @schedule_uid=N'95f27eb5-82b9-48ca-8681-e21faaa235ed'

EXEC  msdb.dbo.sp_add_jobserver @job_id = @jobId, @server_name = N'(local)'
"
    Execute-Sql -server "." -database "master" -command $DailyBackupJob
}


function OlaHallengrens {

    #Ola Hallengrens index optimization
    If (Test-Path "HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL") {

        Write-Host "Installing dbatools PowerShell module"
        If ($null -eq (Get-Module dbatools -ListAvailable)) {
            Write-Host "Installing dbatools"
            Write-Host "    Documentation: https://dbatools.io/"
            Install-Module -Name dbatools 
        }
        else {
            Write-Host "Updating dbatools"
            Update-Module -name dbatools
        }

        Write-Host "Installing Ola Hallengren's SQL Maintenance scripts"
        Import-Module -Name dbatools
        Install-DbaMaintenanceSolution -SqlInstance . -Database master

        Write-Host "Running Ola Hallengren's IndexOptimize tool"

        #Index optimization
        $sqlIndex = "EXECUTE master.dbo.IndexOptimize
    @Databases = 'ALL_DATABASES',
    @FragmentationLow = NULL,
    @FragmentationMedium = 'INDEX_REORGANIZE,INDEX_REBUILD_ONLINE,INDEX_REBUILD_OFFLINE',
    @FragmentationHigh = 'INDEX_REBUILD_ONLINE,INDEX_REBUILD_OFFLINE',
    @FragmentationLevel1 = 5,
    @FragmentationLevel2 = 25,
    @LogToTable = 'N',
    @UpdateStatistics = 'ALL',
    @OnlyModifiedStatistics = 'Y'"

        Execute-Sql -server "." -database "master" -command $sqlIndex
    }
    Else {
        Write-Verbose "SQL not installed.  Skipped Ola Hallengrens index optimization"
    }
    #endregion

}

#region Defragment all drives

# Adapted from https://gallery.technet.microsoft.com/scriptcenter/Perform-a-disk-defragmentat-dfe4274c
Function Start-DiskDefrag { 
    [CmdletBinding()]
    [OutputType([Object])]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)] [string] $DriveLetter, 
        [Parameter()] [switch] $Force
    )
    
    Process {
 
        Write-Verbose "Attempting to get volume information for $driveletter via WMI"
        Try {
            #Use WMI to get the disk volume via the Win32_Volume class
            $Volume = Get-WmiObject -Class win32_volume -Filter "DriveLetter='$DriveLetter'"
            Write-Verbose "Volume retrieved successfully.."
        }
        Catch { }
        

        #Check if the force switch was specified, if it was begin the disk defragmentation
        If ($force) {

            Write-Verbose "force parameter detected, disk defragmentation will be performed regardless of the free space on the volume"
            Write-Host "Defragmenting volume $driveletter" -NoNewline
            $Defrag = $Volume.Defrag($true)
            Write-Host "Complete"
        }
        #If force was not specified check the available disk space the volume specified
        Else {
            
            Write-Verbose "Checking free space for volume $driveletter"
            
            #Check the free space on the volume is greater than 15% of the total volume size, if it isn't write an error
            if (($Volume.FreeSpace / 1GB) -lt ($Volume.Capacity / 1GB) * 0.15) {
                Write-Error "Volume $Driveletter does not have sufficient free space to allow a disk defragmentation, to perform a disk defragmentation either free up some space on the volume or use Start-DiskDefrag with the -force switch"
            }
            Else {
                #Sufficient free space is available, perform the disk defragmentation
                Write-Verbose "Volume has sufficient free space for a defragmentation to be performed"
                Write-Host "Defragmenting volume $driveletter" -NoNewline
                $Defrag = $Volume.Defrag($false)
                Write-Host "Complete"
            }
            
        }

        
        #Check the defragmentation results and inform the user of any errors
        Switch ($Defrag.ReturnValue) {
            0 { Write-Verbose "Defragmentation completed successfully..." }
            1 { Write-Error -Message "Defragmentation of volume $DriveLetter failed: Access Denied" }
            2 { Write-Error -Message "Defragmentation of volume $DriveLetter failed: Defragmentation is not supported for this volume" }
            3 { Write-Error -Message "Defragmentation of volume $DriveLetter failed: Volume dirty bit is set" }
            4 { Write-Error -Message "Defragmentation of volume $DriveLetter failed: Insufficient disk space" }
            5 { Write-Error -Message "Defragmentation of volume $DriveLetter failed: Corrupt master file table detected" }
            6 { Write-Error -Message "Defragmentation of volume $DriveLetter failed: The operation was cancelled" }
            7 { Write-Error -Message "Defragmentation of volume $DriveLetter failed: The operation was cancelled" }
            8 { Write-Error -Message "Defragmentation of volume $DriveLetter failed: A disk defragmentation is already in process" }
            9 { Write-Error -Message "Defragmentation of volume $DriveLetter failed: Unable to connect to the defragmentation engine" }
            10 { Write-Error -Message "Defragmentation of volume $DriveLetter failed: A defragmentation engine error occurred" }
            11 { Write-Error -Message "Defragmentation of volume $DriveLetter failed: Unknown error" }
        }
    }
}

# Loop through the disks and defrag each one
<# ForEach ($res in Get-Partition) {
    $dl = $res.DriveLetter
    If ($dl -ne $null -and $dl -ne "") {
        Write-Host "Defraging disk $dl"

        $dl = $dl + ":"

       # Start-DiskDefrag $dl
    }
}
#>
#endregion

#region Configure DEV users permissions read to DEV test
function ConfigureDevUsersInDevTEST {
    [CmdletBinding()]
    param (
        $DevTESTServerIP
    )
    #get-users to be imported in AX
    $users = Get-LocalUser

}

#endregion

#Region Set ENV VAR

function SetEnvVariables {
    
    if (!$devtest) {
        $devtest = Read-Host "Please enter the ip of the DevTest system: "
    }
    #Write-Host "Delete the variable"
    #[Environment]::SetEnvironmentVariable("devtest", $null ,"Machine")
    Write-Host "Update the Devtest to: $devtest"
    [System.Environment]::SetEnvironmentVariable('devtest', "\\$devtest\BackupShared", [System.EnvironmentVariableTarget]::Machine)
   
}

#endregion


#region init logic

$ServerRole = Read-Host "Please enter the server role: "

while (($ServerRole -ne "dev") -and ($ServerRole -ne "devtest") -and ($ServerRole -ne "build")) {
    write-host "The valid server roles are: dev, devtest or build"
    $ServerRole = Read-Host "Please enter the server role: "
}

switch ($ServerRole) {
    dev { 
        Write-Host "Starting the DEV configuration"
        
        #TLS settings 
        SetStrongCryptography 
        
        #standard config 
        StandardConfiguration
        LogOffIcon
        ConfigureLocalAdmin
        RemoveWindowsApps
        #Enabled, Auto download and schedule the install (4) , Every Saturday (7)
        ConfigureWindowsUpdates
        ConfigureSQLandAgent
        OlaHallengrens

        #region Download usefull powershell scripts tools  on dev VM's am
        DownloadFilesFromGitHub -Owner $Owner -Repository $Repository -Path $Path -DestinationPath $DestinationPath
        #endregion

        #list of apps to be installed.
        $packages = @(
            "vscode"
            "vscode-mssql"
            "peazip"
            "microsoft-edge"
            "windirstat"
            "notepadplusplus.install"
            "postman"  
            "fiddler"
        )

        #install the additional apps. 
        InstallAdditionalApps -packages $packages
        SetEnvVariables


    }
    devtest { 
        Write-Host "Starting the DevTest configuration" 
        SetStrongCryptography
        #standard config 
        StandardConfiguration
        LogOffIcon
        ConfigureLocalAdmin
        RemoveWindowsApps
        #Enabled, Auto download and schedule the install (4) , Every Saturday (7)
        ConfigureWindowsUpdates
        ConfigureSQLandAgent


        #list of apps to be installed.
        $packages = @(
            "vscode"
            "vscode-mssql"
            "peazip"
            "microsoft-edge"
            "windirstat"
            "notepadplusplus.install"
        )

        #install the additional apps. 
        InstallAdditionalApps -packages $packages


    }
    build { Write-Host "build" }
    Default { Write-Host "Incorect Selection. The valid server roles are: dev, devtest or build " }
}

