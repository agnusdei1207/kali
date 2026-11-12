# SeChangeNotifyPrivilege — 무시 목록

- SeChangeNotifyPrivilege — 디렉터리·파일 순회(Traversal) 권한 검사를 우회하는 특권. 표준 사용자를 포함해 모든 프로세스에 기본 부여되는 정상 권한이다.
- whoami /priv에서 보여도 권한 상승에 쓸 수 없는 항목이다. 특권 목록을 훑을 때 이 항목은 확인 즉시 넘어가는 무시 목록이다.
- 전제 조건 없음 — 모든 계정에 기본 부여되므로 항상 보인다. 악용 가능한 권한 상승 시나리오가 없다.

## 확인

```powershell
whoami /priv
# SeChangeNotifyPrivilege      Bypass traverse checking   Enabled
whoami /priv | findstr /i "SeChangeNotify"
```

- 출력에 `Bypass traverse checking` 설명이 붙어 Enabled로 보인다. 이것이 정상 상태다.

## 의미와 판정

```text
역할        디렉터리 트리를 내려갈 때 각 폴더의 읽기 권한 검사를 건너뛰게 한다
기본 부여   Administrators, Users 등 사실상 모든 계정
공격 가치   없음 — 순회 우회는 이미 모두에게 허용된 동작을 그대로 나타낸다
판정        목록에서 보이면 무시하고 다음 특권으로 넘어간다
```

- "Enabled" 표시에 익숙해지면 모든 Enabled 특권을 공격 경로로 오해하기 쉽다. 이 특권은 whoami /priv에 상시 보이는 노이즈 중 하나다.

## 진짜로 봐야 할 특권

```text
SeImpersonatePrivilege  서비스 계정 SYSTEM 상승 (Potato 계열)
SeDebugPrivilege        LSASS 덤프·프로세스 인젝션
SeBackupPrivilege       파일 전체 읽기 (robocopy /b 등)
SeRestorePrivilege      파일 덮어쓰기
SeTakeOwnershipPrivilege 소유권 탈취
SeLoadDriverPrivilege   커널 드라이버 로드
```

- 전체 판정 절차는 windows/privileges/overview.md와 scenarios-tools.md를 따른다.

## 트러블슈팅

- 이 항목이 Disabled로 보여도 문제가 아니다. 어차피 공격 가치가 없으니 상태 자체가 무관하다.
- winPEAS 같은 도구가 "SeChangeNotifyPrivilege"를 알림으로 출력하면 일반 항목이다. 경고 목록에서 공격 가능 특권(SeImpersonate·SeDebug·SeBackup)과 구분해 읽는다.
