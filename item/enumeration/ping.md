```bash
sudo apt install iputils-ping

# 1회만 전송

ping -c 1 10.10.10.10


```

# 핑 오는지 확인 -> RS -> 핑이 온다면? RS 가능성 Up!

tcpdump -i tun0 icmp
