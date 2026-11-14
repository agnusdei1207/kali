# 기본 자격증명 점검

- foothold 단계에서 서비스 로그인 창·API·DB에 흔히 남는 기본 크리덴셜을 먼저 시험해 보는 절차. 브루트포스보다 먼저, 비용 없이 계정을 얻는 첫 시도다.
- 서비스 열거가 끝나 로그인 프롬프트가 보였을 때, 최초 설치 계정이 변경되지 않았는지 확인할 때. 문서화·설정 파일에서 계정 흔적을 찾았을 때도 여기서 검증한다.
- 서비스별 기본 계정·패스워드 목록과 시험 순서, 성공 판정 방법만 정리한다. 대량 대입은 bruteforce(hydra) 문서를 쓴다.

## 점검 순서

```text
1. 서비스 식별 (banner, nmap -sV, whatweb)
2. 벤더·제품명 검색 -> 기본 크리덴셜 문서 확인 (제조사 매뉴얼, internet search)
3. 대표 조합부터 수동 시도 (admin:admin, admin:password 등)
4. 응답 차이로 성공·실패 판정 (로그인 거부 vs 401 vs 빈 화면)
5. 안 되면 워드리스트 브루트포스로 전환 (bruteforce/hydra)
```

## 대표 기본 크리덴셜

```text
일반 웹 관리자      admin:admin / admin:password / admin:<빈값>
Tomcat              admin:admin, manager 계정 (manager/html)
JBoss               admin:admin
WebLogic            weblogic:weblogic, welcome1
Jenkins             초기 설정 마법사 / scripts 초기 콘솔
MSSQL               sa:sa, sa:<빈값>
MySQL               root:<빈값>, root:root
PostgreSQL          postgres:postgres
MongoDB             설치 기본 인증 없음 (인증 미설정 상태 점검)
Redis               인증 미설정(requirepass 없음) 점검
Oracle              system:manager, sys:change_on_install
VNC                 패스워드 없음 / vncpassword 기본값
SSH                 계정:계정 (root:root 등), 설치 스크립트 계정
FTP                 anonymous:anonymous, ftp:ftp
IPMI/BMC            ADMIN:ADMIN, root:calvin (Dell), admin:superuser
프린터·IoT          admin:<빈값>, 1234, 0000
```

- 구형 장비·온프레미스 소프트웨어일수록 기본값이 남아 있는 비율이 높다. 최신 클라우드 서비스는 설치 시 강제 변경이 흔하다.

## 서비스별 시험 명령

```bash
# MSSQL - sqsh 또는 impacket
mssqlclient.py sa:'sa'@10.10.10.10

# MySQL
mysql -h 10.10.10.10 -u root -proot

# PostgreSQL
psql -h 10.10.10.10 -U postgres -W

# Redis (인증 없이 접속되는지)
redis-cli -h 10.10.10.10

# FTP 익명
ftp anonymous@10.10.10.10

# SSH
ssh root@10.10.10.10
```

## 흔적에서 크리덴셜 찾기

```bash
# 소스·설정에 남는 계정 정보 (테이블·설정 파일)
grep -ri "password" /var/www/ 2>/dev/null
# 기본 페이지의 문서·댓글
# -> "default password" 키워드로 검색
```

- 설치 매뉴얼 PDF·README 파일이 웹루트에 남아 있으면 기본 계정 정보가 적혀 있는 경우가 많다.

## 트러블슈팅

- `admin:admin`이 거부됐는데 계정명이 맞는 것 같으면 패스워드만 브루트포스한다. 계정 열거가 먼저다.
- 로그인 시도가 몇 번만에 잠기면(계정 잠금) 기본 크리덴셜 수동 시도에서 멈추고 다른 foothold 경로를 찾는다.
- DB에 접속됐는데 권한이 없으면(쿼리 거부) 계정 권한이 제한된 것이다. 다른 계정(SA·root)을 시험한다.
- 성공 판정이 모호한 웹 폼은 응답 길이·쿠키 발급 여부로 구분한다. 200 + 로그인 폼 재출력은 실패다.
- 관련 문서: bruteforce/hydra(대량 대입), methodology/enumeration(열거), services/database(DB별 상세)
