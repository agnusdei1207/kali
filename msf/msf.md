# docker

docker run -it --platform linux/amd64 --name msf -v $HOME/.msf4:/home/msf/.msf4 metasploitframework/metasploit-framework

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
