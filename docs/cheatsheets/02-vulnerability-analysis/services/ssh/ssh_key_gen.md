```bash
apt install openssh-client
apt install openssh-server

ssh-keygen

ssh -i id_ed25519 comte@10.10.184.98
```

┌──(root㉿docker-desktop)-[/]
└─# ssh-keygen
Generating public/private ed25519 key pair.
Enter file in which to save the key (/root/.ssh/id*ed25519):
Enter passphrase for "/root/.ssh/id_ed25519" (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /root/.ssh/id_ed25519
Your public key has been saved in /root/.ssh/id_ed25519.pub
The key fingerprint is:
SHA256:qnl77ebZO2ZVigRWMblteFIxPxaeJg8NeAitMYKdyRo root@docker-desktop
The key's randomart image is:
+--[ED25519 256]--+
| + o.o.*+oo |
| E \_ oo+.o=oo|
| o ..+..B B.|
| . . = X o|
| S . = + |
| . . o |
| . . . |
| o. . oo+ |
| o..o ++ooo |
+----[SHA256]-----+

┌──(root㉿docker-desktop)-[/]
└─# cat /root/.ssh/id_ed25519.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJmlWmqRlmMIc40OFLpAQwuH+Dvu7WWOVDaK/djJ2F3I root@docker-desktop
