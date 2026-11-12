# BloodHound — AD 공격 경로 분석

- BloodHound — AD 객체(사용자·그룹·컴퓨터·ACL·세션) 관계를 그래프 DB에 넣어 "내 계정에서 Domain Admin까지" 최단 공격 경로를 시각화하는 도구. 수집기(collector)로 데이터를 뽑고 GUI로 분석한다.
- 도메인 계정을 하나 확보해 초기 열거가 끝났을 때, Kerberoast·ACL 남용·세션 하이재킹 같은 다음 경로를 찾을 때. 경로가 안 보이는 대형 도메인에서 특히 유용하다.
- Kali에 bloodhound(GUI)와 수집기 필요. 수집기는 bloodhound-python(원격 수집, 권장) 또는 SharpHound(Windows에서 실행). 유효한 도메인 계정 크리덴셜과 DC 접근이 전제다.

## 설치 (Kali)

```bash
sudo apt install bloodhound
# Neo4j는 의존성으로 함께 설치된다
sudo neo4j start
# 초기 비밀번호 neo4j -> 첫 로그인 시 변경 요구
bloodhound --no-sandbox
```

GUI 로그인은 neo4j 계정 정보를 묻는다. 비밀번호를 바꾼 뒤 그 값으로 로그인한다.

## 데이터 수집 — bloodhound-python (원격, 권장)

Linux에서 도는 Python 수집기. 타깃에 아무것도 올리지 않는다.

```bash
pip install bloodhound-python

bloodhound-python -u <사용자> -p '<패스워드>' -ns <DC_IP> -d <도메인> -c All
# 예: bloodhound-python -u fsmith -p 'Thestuffs' -ns 10.10.10.161 -d htb.local -c All
```

- `-c All`: 사용자·그룹·ACL·세션·트러스트 전부 수집. 시간이 오래 걸리면 `-c User,Group,LocalAdmin,Session`처럼 줄인다.
- `-ns`: DNS 서버(보통 DC) 지정. 도메인명을 IP로 풀어야 하므로 생략하지 않는다.
- 성공하면 `*_machines.json`, `*_users.json` 같은 JSON 여러 개가 현재 디렉터리에 생긴다.

## 데이터 수집 — SharpHound (Windows 셸 확보 시)

```powershell
# PowerShell .NET 데이터 수집기
Import-Module .\SharpHound.ps1
Invoke-SharpHound -CollectionMethod All -Domain htb.local
```

```bash
# 실행 파일 버전 — cmd에서
SharpHound.exe -c All --zipfilename SH
```

## 분석 (GUI)

```text
1. GUI 우측 메뉴에서 JSON 파일(또는 zip) 업로드
2. Analysis 탭에서 쿼리 선택:
   - Find all Domain Admins
   - Shortest Path to Domain Admin from Owned Object
   - Find Kerberoastable Users
   - Find AS-REP Roastable Users (Don't Require Preauth)
3. 노드 우클릭 → Mark as Owned 로 내 계정 표시
```

자주 쓰는 경로 쿼리:

- Kerberoastable 사용자 → SPN 보유 계정을 찾아 hashcat으로 티켓 크래킹
- Shortest Path to Domain Admin → ACL 남용·세션 경로를 한눈에
- Find Shortest Paths to Unconstrained Delegation Systems

## 수집 결과와 다음 행동 연결

```text
Kerberoastable            -> GetUserSPNs.py (impacket)로 티켓 뽑고 hashcat -m 13100
AS-REP Roastable          -> GetNPUsers.py -no-preauth
Local Admin on N machines -> 세션/관리자 경로로 피벗 대상 선정
WriteDacl/GenericAll ACL  -> 대상 계정 패스워드 리셋·Kerberoastable 부여
```

## 트러블슈팅

- JSON 업로드가 안 되면 파일이 여러 개로 쪼개져 있어도 전부 선택해 한 번에 올린다.
- 빈 그래프가 나오면 `-ns`로 DC를 지정하지 않아 DNS 조회가 실패한 경우가 흔하다.
- 시간이 너무 오래 걸리면 `-c All` 대신 필요한 컬렉션만 지정한다. 세션·ACL이 경로 탐색에 핵심이다.
- GUI가 안 뜨면 neo4j가 켜져 있는지 `sudo neo4j status`로 확인한다.
