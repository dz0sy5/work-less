
Import-Module sqlps
Invoke-Sqlcmd -ServerInstance Localhost -Database axdb -Query "update SQLSYSTEMVARIABLES SET VALUE = 0 where PARM = 'CONFIGURATIONMODE'"
#Restart-Service -Name WinRM #W3SVC

Start-Process "$psHome\powershell.exe" -WindowStyle Minimized -Verb Runas -ArgumentList '-command "restart-Service -name W3SVC"'
write-host "Maintenance mode OFF"  -ForegroundColor Green -BackgroundColor black


Start-Sleep 5;
[Environment]::Exit(1)