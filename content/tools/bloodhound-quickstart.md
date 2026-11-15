---
title: "BloodHound — 셋업과 사용 가이드"
date: 2026-03-24
weight: 10
draft: false
tags: ["bloodhound", "active-directory", "enumeration"]
summary: "BloodHound 수집부터 공격 경로 분석까지. AD 권한 관계를 한눈에 보는 방법."
---

BloodHound 는 Active Directory 관계를 매핑하고 수동 열거로는 보이지 않는 공격 경로를 찾는다. Forest 에서는 5개의 중첩 그룹을 통한 WriteDACL 경로를 드러냈다. 손으로는 절대 찾지 못했을 것이다.

이것은 내가 셋업하고, 데이터를 수집하고, 임포트하고, 중요한 경로를 찾는 방법이다.

## 셋업 — Kali 의 BloodHound CE

BloodHound CE (Community Edition) 가 구 BloodHound 를 대체했다. 웹 UI 가 있는 Docker 컨테이너로 동작한다.

### 설치와 시작

```bash
# BloodHound CE pull & start
curl -L https://ghst.ly/getbhce | docker compose -f - up

# 첫 실행은 이미지 pull 로 몇 분 걸린다
# 웹 UI: http://localhost:8080
```

### 첫 로그인 — neo4j 비밀번호 gotcha

첫 실행 시 BloodHound CE 가 랜덤 admin 비밀번호를 생성한다. Docker 로그에 출력되며 놓치기 쉽다.

```bash
# 초기 비밀번호 찾기
docker compose logs | grep "Initial Password"
# 또는 생성된 자격 증명을 찾기 위해 로그 스크롤백 확인
```

**Active 에서 내가 겪은 gotcha:** 비밀번호가 터미널 출력에서 지나가버려 찾지 못했다. Docker 로그를 뒤져야 했다. 처음에 저장해 두어라.

기본 자격 증명은 보통 `admin` / `<random>`. 첫 로그인 시 비밀번호 변경을 강제한다.

### 동작 확인

`http://localhost:8080` 으로 이동한다. BloodHound CE 로그인 페이지가 보여야 한다. 초기 자격 증명으로 로그인하고 새 비밀번호를 설정한다.

---

## 데이터 수집 — bloodhound-python

`bloodhound-python` 은 Linux 수집기다. DC 에 원격으로 쿼리한다 — 대상에 아무것도 실행할 필요가 없다.

### 내가 매번 쓰는 명령

```bash
bloodhound-python -u 'USERNAME' -p 'PASSWORD' -ns $ip -d DOMAIN.local -c All
```

### 플래그 분해

| 플래그 | 하는 일 |
| --- | --- |
| `-u` | 사용자명 |
| `-p` | 비밀번호 |
| `-ns` | 네임서버 (DC IP) — **결정적**, DNS 를 어디서 해석할지 알려준다 |
| `-d` | 도메인 이름 |
| `-c All` | 모든 것 수집 — 사용자, 그룹, 세션, ACL, 트러스트, 컨테이너, GPO |

### 출력

현재 디렉터리에 여러 JSON 파일 생성:

```fallback
20260324_computers.json
20260324_domains.json
20260324_groups.json
20260324_users.json
```

### 내 박스의 실제 예

```bash
# Active — GPP creds
bloodhound-python -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' -ns 10.129.3.112 -d active.htb -c All

# Forest — AS-REP creds
bloodhound-python -u 'svc-alfresco' -p 's3rvice' -ns 10.129.95.210 -d htb.local -c All

# Blackfield — AS-REP creds
bloodhound-python -u 'support' -p '#00^BlackKnight' -ns $ip -d BLACKFIELD.local -c All
```

### Gotchas

- **`-ns` 는 실질적으로 필수다.** 없으면 Kali 박스가 도메인을 해석하는 방법을 모르기 때문에 DNS 해석이 실패한다. 항상 DC IP 로 설정한다.

- **`-c All` 이 올바른 기본값이다.** 어떤 가이드는 stealth 를 위해 `-c DCOnly` 를 쓰라고 한다. CTF 박스와 OSCP 에서는 그냥 모든 것을 가져온다.

- **도메인 이름이 중요하다.** 어떤 박스는 `domain.htb`, 다른 박스는 `domain.htb.local`, 또 다른 박스는 `domain.local` 을 쓴다. nmap LDAP 출력이나 `nxc smb` 출력에서 가져온다. 잘못된 도메인 이름 = 수집이 조용히 실패하거나 불완전한 데이터를 반환.

- 비밀번호에 특수 문자 (`$`, `!`, `#`) 가 있으면 bash 에서 **작은따옴표**를 쓴다.

---

## BloodHound CE 에 데이터 임포트

1. `http://localhost:8080` 에서 BloodHound CE 에 로그인

2. **Upload** 버튼 클릭 (우상단, 화살표 아이콘)

3. bloodhound-python 의 모든 JSON 파일 선택

4. 수집 완료까지 대기

끝. 그래프 데이터베이스가 채워졌다. 이제 쿼리할 시간.

---

## 중요한 쿼리

내가 실제로 실행하는 쿼리들. 순서대로.

### 1. Shortest Path to Domain Admin

가장 먼저 확인한다. 매번.

BloodHound CE 에서:

- **Explore** → **Pathfinding** 으로 이동

- 시작 노드: 내가 owned 한 사용자

- 끝 노드: DOMAIN `ADMINS@DOMAIN.LOCAL`

- 검색 클릭

**Forest** 에서 이것은 다음을 보여줬다:

```fallback
svc-alfresco → Service Accounts → Privileged IT Accounts → Account Operators
→ GenericAll over Exchange Windows Permissions
→ WriteDACL over HTB.LOCAL domain
```

5단계 깊이의 그룹. BloodHound 없이는 보이지 않는다.

### 2. Kerberoastable Users

```fallback
MATCH (u:User) WHERE u.hasspn=true RETURN u
```

또는 Analysis 탭의 내장 **"List all Kerberoastable Users"** 쿼리.

**Active** 에서 이것은 Administrator 계정이 SPN `active/CIFS:445` 를 가진다고 보여줬다. 보통 Kerberoast 하는 것은 서비스 계정이지 실제 Administrator 가 아닌데, SPN 이 거기 있었다. 비밀번호도 약했다.

### 3. AS-REP Roastable Users

```fallback
MATCH (u:User) WHERE u.dontreqpreauth=true RETURN u
```

또는 내장 **"List all AS-REP Roastable Users"** 쿼리.

Forest 의 `svc-alfresco` 와 Blackfield 의 `support` 를 이렇게 찾았다.

### 4. DCSync 권한이 있는 사용자

```fallback
MATCH p=(u)-[:MemberOf|GetChanges|GetChangesAll*1..]->(d:Domain) RETURN p
```

권한 상승 없이 이미 DCSync 할 수 있는 사람을 보여준다. 이런 계정 중 하나를 장악했다면 바로 `impacket-secretsdump` 로 간다.

### 5. 위험한 권한을 가진 Principal 찾기

**Analysis** 탭의 내장 쿼리를 본다:

- Shortest path from owned principals

- Find all paths to Domain Admins

- Users with local admin rights

- Group memberships for a specific user

---

## 그래프 이해 — 중요한 Edge 타입

BloodHound 에서 경로를 보면 **edge** (노드 사이의 화살표) 가 어떤 종류의 접근 권한을 가졌는지 알려준다. 내가 실제로 악용한 것들:

### GenericAll

대상 객체에 대한 **완전한 제어**. 할 수 있는 것:

- 비밀번호 재설정

- 그룹에 추가

- 속성 수정

- SPN 설정 (targeted Kerberoasting)

**Forest** 에서 svc-alfresco 의 그룹 체인이 Exchange Windows Permissions 에 대한 GenericAll 을 주었다. 그 그룹에 나 자신을 추가할 수 있다는 뜻이었다.

### WriteDACL

대상 객체의 **접근 제어 리스트를 수정**할 수 있다. 이게 큰 것이다. 도메인 객체에 대한 WriteDACL 은 DCSync 권한을 포함한 어떤 권한이든 자신에게 부여할 수 있다는 뜻이다.

**Forest** 에서 Exchange Windows Permissions 가 HTB.LOCAL 도메인에 WriteDACL 을 가졌다. 그 그룹에 나 자신을 추가한 후 PowerView 로 DCSync 권한을 부여했다:

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity svc-alfresco -Rights DCSync
```

그 다음 `impacket-secretsdump` 가 도메인의 모든 해시를 뽑았다.

### ForceChangePassword

현재 비밀번호를 모르는 상태에서 **대상 사용자의 비밀번호를 변경**할 수 있다. rpcclient 로:

```bash
rpcclient -U 'support%#00^BlackKnight' $ip
rpcclient $> setuserinfo2 audit2020 23 'Password@1234'
```

**Blackfield** 에서 `support` 가 `audit2020` 에 ForceChangePassword 를 가졌다. 비밀번호를 변경하고, audit2020 의 접근으로 forensic 공유에 들어가, LSASS 덤프를 잡았다.

### 알아둘 만한 다른 Edge

| Edge | 의미 | 악용 |
| --- | --- | --- |
| **GenericWrite** | 속성 수정 가능 | SPN 설정 → Kerberoast, 또는 logon script 설정 |
| **WriteOwner** | 소유권 가져오기 가능 | 소유권 가져오기 → 자신에게 GenericAll 부여 |
| **AddMember** | 그룹에 사용자 추가 가능 | 자신 또는 장악한 사용자 추가 |
| **ReadLAPSPassword** | LAPS 비밀번호 읽기 가능 | 그 머신의 local admin 비밀번호 획득 |
| **AllowedToDelegate** | Kerberos delegation | Constrained/unconstrained delegation 공격 |

---

## 내가 본 공격 경로

### Path 1: 중첩 그룹 악용 → DCSync (Forest)

```fallback
Owned User → Group → Group → Group → GenericAll → Target Group → WriteDACL → Domain
```

**플레이:** WriteDACL 을 가진 그룹에 자신을 추가한다. WriteDACL 로 자신에게 DCSync 권한을 부여한다. secretsdump 실행.

### Path 2: ForceChangePassword → 측면 이동 (Blackfield)

```fallback
Owned User → ForceChangePassword → Target User → 새 리소스 접근
```

**플레이:** 대상의 비밀번호를 변경한다. 그들로 로그인한다. 자신이 없던 것에 무엇에 접근할 수 있는지 본다.

### Path 3: 직접 Kerberoasting (Active)

```fallback
Owned User → GetUserSPNs → Administrator 에 SPN → TGS 크랙 → Domain Admin
```

**플레이:** BloodHound 가 어떤 고가치 계정에 SPN 이 있는지 보여준다. Administrator 나 다른 DA 계정에 SPN 이 있으면 Kerberoast 한다.

---

## 내 BloodHound 워크플로

모든 AD 박스, 같은 프로세스:

1. **유효한 자격 증명 하나 얻기** — null session, AS-REP Roast, 파일의 creds, password spray, 뭐든

2. `-c All` 로 **bloodhound-python 실행**

3. JSON 파일을 BloodHound CE 에 **업로드**

4. **자신의 사용자를 owned 로 표시** — 우클릭 → Mark as Owned

5. **pathfinding 실행** — owned 사용자 → Domain Admins

6. **내장 쿼리 확인** — Kerberoastable, AS-REP Roastable, DCSync rights

7. BloodHound 가 보여주는 **경로를 걸어간다**

5단계가 마법이 일어나는 곳이다. BloodHound 는 도메인의 모든 그룹 멤버십, ACL, delegation 을 가로질러 그래프 탐색을 한다. 수동으로는 절대 찾지 못할 경로를 찾는다.

> **진실:** BloodHound 가 내가 놓친 것을 보여주지 않은 AD 박스는 한 번도 없다. Forest 에서 경로는 5개의 중첩 그룹을 통했다. Blackfield 에서는 ForceChangePassword edge 를 보여줬다. Active 에서는 Administrator SPN 을 확인했다. BloodHound 는 선택이 아니다. 지도다.

- [Bloodhound](https://heretek.dev/tags/bloodhound/)
- [Active-Directory](https://heretek.dev/tags/active-directory/)
- [Enumeration](https://heretek.dev/tags/enumeration/)