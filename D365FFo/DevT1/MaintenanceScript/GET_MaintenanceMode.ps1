
Import-Module sqlps
$status = Invoke-Sqlcmd -ServerInstance Localhost -Database axdb -Query "select value from SQLSYSTEMVARIABLES where PARM = 'CONFIGURATIONMODE'"
#Restart-Service -Name WinRM #W3SVC


if ($status.value -eq 0) {
    Write-host "maintenance mode is OFF" -BackgroundColor Black -ForegroundColor Green
    }
Else
    {
    write-host "Maintenance mode is ON"  -ForegroundColor Green -BackgroundColor black
    }

Start-Sleep 5;
[Environment]::Exit(1)


