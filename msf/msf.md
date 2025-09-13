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
