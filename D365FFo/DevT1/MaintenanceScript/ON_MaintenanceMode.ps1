
Import-Module sqlps
Invoke-Sqlcmd -ServerInstance Localhost -Database axdb -Query "update SQLSYSTEMVARIABLES SET VALUE = 1 where PARM = 'CONFIGURATIONMODE'"
#Restart-Service -Name WinRM #W3SVC

Start-Process "$psHome\powershell.exe" -WindowStyle Minimized -Verb Runas -ArgumentList '-command "restart-Service -name W3SVC"'
write-host "maintenance ON"  -ForegroundColor Green -BackgroundColor black

Start-Sleep 5;
[Environment]::Exit(1)