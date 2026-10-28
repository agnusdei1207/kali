# Windows 기본 (CMD)

## 디렉토리/파일 탐색
```cmd
dir
dir /s /b flag.txt
dir /s /b *.txt
dir /s /b *.log
dir /s /b *flag*
dir /s /b *root*
findstr password *.txt
findstr /s /i "flag" *.*
cd Windows
cd ..
type flag.txt
```

## 파일/폴더 작업
```cmd
copy flag.txt C:\temp\flag.txt
move flag.txt C:\temp\flag.txt
del flag.txt
mkdir loot
rmdir loot
```

## 시스템 정보
```cmd
systeminfo
hostname
whoami
net user
net localgroup
```

## 네트워크
```cmd
ipconfig
ping 10.10.107.58
netstat -ano
```

## 프로세스/서비스
```cmd
tasklist
taskkill /PID 1234
sc query
```
```cmd
set
path
ver
systeminfo | more
driverquery | more
ipconfig /all
netstat -abon
tree
dir /a
del file.txt
type flag.txt
tasklist /FI "imagename eq sshd.exe"
taskkill /F /PID 4567
shutdown /r
shutdown /s
```