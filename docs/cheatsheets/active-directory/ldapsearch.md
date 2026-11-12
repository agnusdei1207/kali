# ldapsearch (ldap-utils)

- ldapsearch — OpenLDAP 클라이언트 도구로 AD 데이터베이스에 LDAP 질의를 던져 유저·그룹·SPN·계정 플래그를 텍스트로 뽑아보는 도구. BloodHound 이전의 수동 열거 기본기.
- 가벼운 열거(계정 목록, kerberoast 후보 SPN, AS-REP 개체)를 즉시 할 때, 도메인 구조·특정 개체 속성을 정확히 확인하고 싶을 때, 도구 설치 없이 ldap-utils만으로 갈 때.
- ldap-utils 패키지(칼리 기본), 도메인 유저 계정 1개(읽기 권한은 보통 전 유저에게 있음), DC의 LDAP(389/636) 접근.

## 기본 구조

```bash
ldapsearch -x -H ldap://DC.corp.local -D 'user@corp.local' -w 'Password1' -b "DC=corp,DC=local" "(필터)" 속성...
```

- `-x`: simple 인증. `-H`: LDAP URI. `-D`: bind DN(AD는 user@domain 형태 허용). `-w`: 암호. `-b`: base DN(검색 시작점).

## 대표 쿼리

```bash
# 전체 유저
ldapsearch -x -H ldap://DC.corp.local -D 'user@corp.local' -w 'Password1' -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName

# SPN 보유 계정 (kerberoast 후보)
ldapsearch -x -H ldap://DC.corp.local -D 'user@corp.local' -w 'Password1' -b "DC=corp,DC=local" "(servicePrincipalName=*)" servicePrincipalName sAMAccountName

# AS-REP Roast 가능 개체 (DONT_REQ_PREAUTH 플래그)
ldapsearch -x -H ldap://DC.corp.local -D 'user@corp.local' -w 'Password1' -b "DC=corp,DC=local" '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' sAMAccountName

# 비활성 계정 (ACCOUNTDISABLE 플래그)
ldapsearch -x -H ldap://DC.corp.local -D 'user@corp.local' -w 'Password1' -b "DC=corp,DC=local" '(userAccountControl:1.2.840.113556.1.4.803:=2)' sAMAccountName
```

## 주요 옵션

- `-LLL`: LDIF 설명·빈 줄 제거. 스크립트 파싱용 필수 조합.
- `-s sub|one|base`: 검색 범위(기본 sub).
- `-E pr=1000/noprompt`: paged result. 대규모 도메인에서 1000건 제한 우회.
- `-y <파일>`: 암호를 파일에서 읽음(히스토리 유출 방지).
- `-o ldif-wrap=no`: LDIF 줄바꿈 방지.
- `(userAccountControl:1.2.840.113556.1.4.803:=비트)`: AD OID 확장 매칭으로 비트플래그 검색. 4194304(AS-REP), 2(disabled), 524288(TRUSTED_FOR_DELEGATION) 등.

## 실전 흐름 예시

```bash
ldapsearch -x -H ldap://DC.corp.local -D 'user@corp.local' -w 'Password1' -b "DC=corp,DC=local" -LLL -E pr=1000/noprompt '(objectClass=user)' sAMAccountName description
```

- description 필드에 패스워드를 적어두는 관리자 습관을 바로 잡아낼 수 있다.

## 팁·트러블슈팅

- bind 실패가 나오면 -D 형식(user@domain)과 암호를 재확인. 계정 잠금 상태도 의심.
- 결과가 1000건에서 끊기면 -E pr=1000/noprompt로 페이징.
- LDAPS는 `-H ldaps://DC.corp.local -x`로 접속.
- 필요한 속성명을 명시하면 출력이 깔끔해진다. 생략하면 전체 속성이 나온다.
- 관계 그래프 전체가 필요해지면 BloodHound로 갈아탄다. ldapsearch는 특정 개체를 빠르게 확인하는 용도.
