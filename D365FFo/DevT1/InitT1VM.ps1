?<# Preparation:
    #  Windows updated
    #  Antimalware scan
    #
    # Execute this script:
    # Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/dz0sy5/work-less/master/D365FFo/DevT1/InitT1VM.ps1'))
    #$ErrorActionPreference="Stop";If(-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent() ).IsInRole( [Security.Principal.WindowsBuiltInRole] "Administrator")){ throw "Run command in an administrator PowerShell prompt"};If($PSVersionTable.PSVersion -lt (New-Object System.Version("3.0"))){ throw "The minimum version of Windows PowerShell that is required by the script (3.0) does not match the currently running version of Windows PowerShell." };$DefaultProxy=[System.Net.WebRequest]::DefaultWebProxy;$securityProtocol=@();$securityProtocol+=[Net.ServicePointManager]::SecurityProtocol;$securityProtocol+=[Net.SecurityProtocolType]::Tls12;[Net.ServicePointManager]::SecurityProtocol=$securityProtocol;Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/dz0sy5/work-less/master/D365FFo/DevT1/InitT1VM.ps1'))
    #
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

#set tls 1.2
if ([Net.ServicePointManager]::SecurityProtocol -ne 'Tls12') {
    Write-Host "Update the TLS settings"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

#region Functions to be used by the script

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
            Remove-Item -Path $DestinationPath -Force 
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

If (Test-Path -Path "$env:ProgramData\Chocolatey") {
    choco upgrade chocolatey -y -r
    choco upgrade all --ignore-checksums -y -r
}
Else {

    Write-Host “Installing Chocolatey”
 
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

    # Install each program
    foreach ($packageToInstall in $packages) {

        Write-Host “Installing $packageToInstall” -ForegroundColor Green
        & $chocoExePath "install" $packageToInstall "-y" "-r"
    }
}
 
#endregion


#region Installing d365fo.tools

# This is requried by Find-Module, by doing it beforehand we remove some warning messages
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

# Installing d365fo.tools
If ((Find-Module -Name d365fo.tools).InstalledDate -eq $null) {
    Write-Host "Installing d365fo.tools"
    Write-Host "    Documentation: https://github.com/d365collaborative/d365fo.tools"
    Install-Module -Name d365fo.tools -SkipPublisherCheck -Scope AllUsers
}
else {
    Write-Host "Updating d365fo.tools"
    Update-Module -name d365fo.tools -SkipPublisherCheck -Scope AllUsers
}

Write-Host "Setting web browser homepage to the local environment"
Get-D365Url | Set-D365StartPage

Write-Host "Setting Management Reporter to manual startup to reduce churn and Event Log messages"
Get-D365Environment -FinancialReporter | Set-Service -StartupType Manual

Write-Host "Setting Windows Defender rules to speed up compilation time"
Add-D365WindowsDefenderRules -Silent


#endregion


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

If (Test-Path “HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL”) {

    Write-Host “Installing dbatools PowerShell module”
    Install-Module -Name dbatools -SkipPublisherCheck -Scope AllUsers

    Write-Host “Installing Ola Hallengren's SQL Maintenance scripts”
    Import-Module -Name dbatools
    Install-DbaMaintenanceSolution -SqlInstance . -Database master

    Write-Host “Running Ola Hallengren's IndexOptimize tool”


    $sql = "EXECUTE master.dbo.IndexOptimize
        @Databases = 'ALL_DATABASES',
        @FragmentationLow = NULL,
        @FragmentationMedium = 'INDEX_REORGANIZE,INDEX_REBUILD_ONLINE,INDEX_REBUILD_OFFLINE',
        @FragmentationHigh = 'INDEX_REBUILD_ONLINE,INDEX_REBUILD_OFFLINE',
        @FragmentationLevel1 = 5,
        @FragmentationLevel2 = 25,
        @LogToTable = 'N',
        @UpdateStatistics = 'ALL',
        @OnlyModifiedStatistics = 'Y'"

    Execute-Sql -server "." -database "master" -command $sql
}
Else {
    Write-Verbose “SQL not installed.  Skipped Ola Hallengrens index optimization”
}

#endregion


#region Update PowerShell Help, power settings, and Logoff icon

Write-Host "Updating PowerShell help"
$what = ""
Update-Help  -Force -Ea 0 -Ev what
If ($what) {
    Write-Warning "Minor error when updating PowerShell help"
    Write-Host $what.Exception
}

# Set power settings to High Performance
Write-Host "Setting power settings to High Performance"
powercfg.exe /SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

# Create Logoff Icon and copy it to public Desktop
Write-Host “Creating logoff icon on desktop of the current user”
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($env:HOMEDRIVE + $env:HOMEPATH + "\Desktop\logoff.lnk")
$Shortcut.TargetPath = "C:\Windows\System32\logoff.exe"
$Shortcut.Save()

#move the shortcut for all users
#C:\Users\Public\Desktop - Local VHD
$source = ($env:HOMEDRIVE + $env:HOMEPATH + "\Desktop\logoff.lnk")
Move-item -path $source -Destination "C:\Users\Public\Desktop\"

#endregion

#region Local User Policy

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

#endregion

#region Configure Windows Updates when Windows 10

if ((Get-WmiObject Win32_OperatingSystem).Caption -Like "*Windows 10*") {

    #Write-Host "Changing Windows Updates to -Notify to schedule restart-"
    #Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name UxOption -Type DWord -Value 1

    Write-Host "Disabling P2P Update downlods outside of local network"
    Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config -Name DODownloadMode -Type DWord -Value 1
    Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization -Name SystemSettingsDownloadMode -Type DWord -Value 3
}

#endregion


#region Remove Windows 10 Metro apps


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

#endregion


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
ForEach ($res in Get-Partition) {
    $dl = $res.DriveLetter
    If ($dl -ne $null -and $dl -ne "") {
        Write-Host "Defraging disk $dl"

        $dl = $dl + ":"

        Start-DiskDefrag $dl
    }
}

#endregion


#region Download usefull powershell scripts tools 

DownloadFilesFromGitHub -Owner $Owner -Repository $Repository -Path $Path -DestinationPath $DestinationPath

#endregion