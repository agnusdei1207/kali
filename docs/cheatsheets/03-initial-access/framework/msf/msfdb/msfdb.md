sudo systemctl start postgresql

msfdb init
sudo -u postgres msfdb init

# status

db_status
[*] Connected to msfdb. Connection type: postgresql.

# list workspace

workspace
workspace default

# help

workspace -h

workspace -a tryhackme
workspace -d tryhackme

hosts
services
hosts -R

# search

services -S netbios

# Once all parameters are set, we launch the exploit using the run or exploit command.
