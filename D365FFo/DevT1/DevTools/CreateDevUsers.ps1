[cmdletbinding()]
Param (
    [Parameter(Mandatory = $True)]
    [string[]] $users,
    [Parameter(Mandatory = $False)]
    $Pass = "pass@word1"
)

#todo
#add condition when user is already created and present

Import-Module d365fo.tools -ErrorAction SilentlyContinue

Function ProvisionDBUser {
    Param(
        [Parameter(Mandatory = $True)]
        [string] $databaseServerName,
        [Parameter(Mandatory = $True)]
        [string[]] $users
    )
    
    $AdminUsers = {}

    #
    # Check if the current user has admin privileges. User must be an administrator or part of builtin\administrators group
    #
    Try {
        $AdminUsers = invoke-command { net localgroup administrators | Where-Object { $_ -AND $_ -notmatch "command completed successfully" } |  Select-Object -skip 4 }

        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal -ArgumentList $identity
        $userName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        
        If (($principal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator ) -eq $false) -AND ($AdminUsers -contains $userName -eq $false )) {
            Write-Host "You must be an administrator to run this script"
            return -1
        }
    } 
    Catch {
        $ErrorRecord = $Error[0]
        $ErrorRecord | Format-List * -Force
        $ErrorRecord.InvocationInfo | Format-List *
        $Exception = $ErrorRecord.Exception

        For ($i = 0; $Exception; $i++, ($Exception = $Exception.InnerException)) {
            "$i" * 80
            $Exception | Format-List * -Force
        }
        Throw "Failed to determine if the current user has elevated privileges. The error was: '{0}'." -f $_
    }

    If ($PSBoundParameters.Count -lt 1) {
        Write-Host "Usage: \n PrepareAxTools.ps1 <user1>,<user2>,<user3>...\n Users must be part of Administrators group"
        return -1
    }

    $AdminUsers = Invoke-command { net localgroup administrators | where { $_ -AND $_ -notmatch "command completed successfully" } |  select -skip 4 }

    #
    # Validate if the user[s] argument are part of Administrators group
    #

    #Begin Validation
    $quit = $false

    Foreach ($user in $users) {
        $userNameComponents = $user.Split('\')
        $username = ''
        $domain = ''
        
        If ($userNameComponents.Count -eq 2) {
            $domain = $userNameComponents[0]
            $username = $userNameComponents[1]

            #
            # For the local user accounts, windows does not store the Computer Name in the administrators user group.
            #
            If ($domain -eq $env:computername) {
                $user = $username
            }
        }
        Else {
            Write-Host "Invalid format. User name must of format 'domain or hostname\username'"
            return -1
        }

        If (-NOT ($AdminUsers -contains $user)) {   
            Write-Host $user "is not part of Administrators group."
            $quit = $true       
        }
    }

    If ($quit -eq $true) {
        Write-Host "Users must be part of Administrators group. Please add the user[s] to builtin\Administrators group and re-run the script"
        return -1
    }
    #End Validation

    #
    # Provision SQL access to the users
    #
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SqlWmiManagement") | out-null
    $databaseServerName = $env:databaseServerName
    $ManagedComputer = New-Object ('Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer') $databaseServerName

    $serverInstance = ""


    #
    # Provision user access
    #

    #Begin Provision
    Foreach ($user in $users) {
        Try {

            $sqlSrv = New-Object 'Microsoft.SqlServer.Management.Smo.Server' "$databaseServerName"
	
            $login = $sqlSrv.Logins.Item($user)
            $dbName = "DYNAMICSXREFDB"
            $database = $sqlSrv.Databases[$dbName]
            $dbRoleName = "db_owner"
            $dbRole = $database.Roles[$dbRoleName]

            If (-Not ($login)) {
                $login = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Login -ArgumentList $sqlSrv, $user
                $login.LoginType = "WindowsUser"
                $login.Create()
    
            }
            else {
                Write-Host "User $user already exists"
            }
        
            If (-Not ($login.IsMember("sysadmin"))) {
                $login.AddToRole("sysadmin")
                $login.Alter()
                $sqlSrv.Refresh()
            }
            else {
                Write-Host "User $user is already a member of sysadmin"
            }
        
            If (-Not $database.Users[$user] ) {
                #
                # Map the user to database 
                #
                $sql = "CREATE USER `"$user`" FOR LOGIN `"$user`" WITH DEFAULT_SCHEMA=[dbo];
            EXEC sp_addrolemember 'db_owner', `"$user`""
                $SqlConnection = New-Object System.Data.SqlClient.SqlConnection
                $sqlConnection.ConnectionString = "server=$databaseServerName;integrated security=TRUE;database=$dbName" 
                $sqlConnection.Open()
                $sqlCommand = new-object System.Data.SqlClient.SqlCommand
                $sqlCommand.CommandTimeout = 120
                $sqlCommand.Connection = $sqlConnection
                $sqlCommand.CommandText = $sql
                $text = $sql.Substring(0, 50)
                Write-Progress -Activity "Executing SQL" -Status "Executing SQL => $text..."
                Write-Host "Executing SQL => $text..."
                $result = $sqlCommand.ExecuteNonQuery()
                $sqlConnection.Close()
            }
            else {
                Write-Host "User $user is already mapped to database $database"
            }
        }
        Catch {
            $ErrorRecord = $Error[0]
            $ErrorRecord | Format-List * -Force
            $ErrorRecord.InvocationInfo | Format-List *
            $Exception = $ErrorRecord.Exception

            for ($i = 0; $Exception; $i++, ($Exception = $Exception.InnerException)) {
                "$i" * 80
                $Exception | Format-List * -Force
            }

            Throw "Failed to provision database access for the user: $user"
        }  
    }
    #End Provision


}


#region Get Database configuration
#webconfig file
$webConfig = (Get-WebConfigFile 'IIS:\Sites\AOSService')

$XML = (gc $webConfig) -as [xml]


#get server and database info
foreach ($node in $xml.configuration.appSettings.add) {
    if ($node.key -eq "DataAccess.DbServer" ) {
        $databaseServerName = $node.Value
    }
    Elseif ($node.key -eq "DataAccess.Database") {
        $database = $node.Value
    }

}
#endregion



#Region create LocalUsers and provision
foreach ($user in $users) {

    $pieces = $user -split '@'
    $FullName = $pieces[0] -replace "\.", " " 
    $Names = $pieces[0] -split "\." 
    $name = ($names[0])[0] + $Names[1] 
    $Password = ConvertTo-SecureString $pass -AsPlainText -Force

    if (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) {
        Write-Host "User: $name is already created" -ForegroundColor Green 
    }
    Else {
        New-LocalUser -Name $name -AccountNeverExpires -Password $Password -FullName $FullName -Description $user -PasswordNeverExpires 
        Write-Host "User: $name was succesfully created" -ForegroundColor Green 
    
        #add to administrators
        Add-LocalGroupMember -Group "Administrators" -Member $name
        Write-Host "User: $name was succesfully added to local Administrators group" -ForegroundColor Green 
    }

    $DOMAIN = HOSTNAME
    Write-Host "Provision DB USER" 
    ProvisionDBUser -databaseServerName $databaseServerName -users $DOMAIN\$name


    #add user in AX instance
    Import-D365ExternalUser -Id $Name -Name $FullName -Email $user -DatabaseServer $databaseServerName -DatabaseName $database

}

#endregion


#ADD CONFIGURATION FOR VISUAL STUDIO WORKSPACE

<#
#get local Administrators
$LocalUsers = Get-LocalGroupMember ADministrators | select -expand Name 
Write-Host "Local Administrators" -ForegroundColor Green
Write-Output $LocalUsers 


#>
