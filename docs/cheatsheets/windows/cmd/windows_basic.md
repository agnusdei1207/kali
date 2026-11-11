# Windows 기본 (CMD)

> 무엇: Windows cmd 기본 명령 모음 — dir /s /b·findstr로 파일·문자열 검색, copy·move·del로 파일 작업, systeminfo·net user로 시스템·계정 정보, netstat·tasklist·sc query로 네트워크·프로세스·서비스 확인
> 언제: Windows 셸을 딴 직후부터 flag.txt·password 검색, 계정·그룹 열거 등 초기 열거 전반에 반복해서 꺼내 쓴다
> 조건: cmd 셸 필요, 전부 Windows 내장 명령이라 별도 설치가 없다

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