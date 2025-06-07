# 호스트 정보 수집
#!/bin/bash

# host
hostname
cat /etc/os-release

# user
id
uname -a
whoami
sudo -l

# other users
cat /etc/passwd
cat /etc/shadow
cat /etc/group

ls -alh
find / -type f -perm -4000 2>/dev/null

# network
arp -a 
# arp
ifconfig
# routing table
route -n
# host interative other device
netstat -tulpna
# DNS
cat /etc/resolv.conf
# DNS cache
cat /etc/hosts

# service
systemctl --type=service --state=running

# open ports
ss -ltnp 
netstat -tulpna

# package with apt
dpkg --list

# package omit apt
 ls -hal /opt


# find config file
find / -type f \( -name "*.conf" -o -name "*.cfg" \) 2>/dev/null
# find log file
find / -type f \( -name "*.log" -o -name "*.log.*" \) 2>/dev/null
# find SUID
find / -type f -perm -4000 2>/dev/null


# env
env
# env with sudo
sudo env
# export
export

# kubernetes
ls -alh /.dockerenv