# install

# lts

sudo apt install metasploit-framework

# latest

curl https://raw.githubusercontent.com/rapid7/metasploit-framework/master/msfupdate | sudo bash

# msfconsole -> msf start

msfconsole

# options

show options

# set target

set rhosts 10.10.15.10
set rhosts 10.10.15.10 - 10.10.15.255
set rhosts 10.10.15.10/24

# check

show options

# flushing datastore

unset all
unset payload

# set global env across modules

setg

# exploit

# background mode: -z

exploit -z

# background mode -> go to msfconsole as soon as || ctrl+z

background

# session list

sessions

# interacte session

sessions -i 2

# search

sesarch portscan

# use

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

# back

back
