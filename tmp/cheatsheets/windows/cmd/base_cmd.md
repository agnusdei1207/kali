# env

- Windows cmd의 초기 열거 기본 명령 모음 — set·path·ver·systeminfo·driverquery·ipconfig /all·netstat -abon·tasklist·dir /a·type 등
- cmd 셸을 확보한 직후 환경변수·OS 버전·네트워크·프로세스 정보를 한 바퀴 돌릴 때
- cmd 셸 필요, 전부 Windows 내장 명령이라 추가 설치가 없다

set

## check path

path=

## version

ver
Microsoft Windows [Version 10.0.20348.2655]

## systeminfo

systeminfo | more

## search driver

driverquery | more

## hostname & ip

ipconfig /all

## network

netstat -abon

## tree

tree

## ls -a

dir /a

## delete

del file.txt

## cat

type flag.txt

## ps

tasklist
tasklist /FI "imagename eq sshd.exe"

## pkill -9

taskkill /F /PID 4567

## restart

shutdown /r

## shutdown

shutdown /s
