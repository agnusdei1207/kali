# whoami /priv 권한 해석

- whoami /priv — 현재 프로세스에 부여된 Windows 권한(privilege) 목록을 출력하는 내장 명령. Impersonate, Backup, TakeOwnership, Debug 같은 권한은 곧바로 권한 상승 경로가 된다.
- 셸 확보 직후 계정이 관리자가 아닌 것 같아도 권한 목록에 상승 가능 권한이 있는지 확인할 때. 상승 경로 선정의 첫 단계다.
- Windows 내장 명령. 일부 권한은 관리자 그룹 멤버에게 기본 부여되므로, Disabled 표시가 있어도 경로 후보로 기록해둔다.

## 기본 확인

```powershell
whoami /priv
whoami /user
whoami /groups
```

- /priv는 권한 목록을 State(Enabled/Disabled)와 함께 출력한다. /user, /groups와 함께 계정 소속을 대조한다.
- SeShutdownPrivilege처럼 무해해 보이는 권한도 상황에 따라 경로가 되므로 목록은 통째로 기록해둔다.

## 상승 경로가 되는 대표 권한

```text
SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege
  -> Potato 계열 공격 경로. IIS, SQL Server 같은 서비스 계정에 기본 부여되어 흔하다.
  -> windows\privileges\SeImpersonatePrivilege.md, PrintSpoofer.md 참조.

SeBackupPrivilege / SeRestorePrivilege
  -> SAM/SYSTEM/SECURITY 레지스트리 하이브와 NTDS.dit 복사 가능.
  -> robocopy /b, diskshadow, reg save 등으로 읽기 제한 파일을 덤프한다.

SeTakeOwnershipPrivilege
  -> 임의 객체(파일, 레지스트리 키)의 소유자를 자신으로 바꿔 접근을 확보한다.
  -> SeBackup과 조합해 읽기 거부 파일을 열 때 쓴다.

SeDebugPrivilege
  -> 임의 프로세스에 메모리 접근·핸들 획득. LSASS 덤프가 대표 경로다.
  -> windows\privileges\SeDebugPrivilege.md 참조.
```

- 권한 이름 앞의 Se는 Security privilege를 뜻하고 State는 현재 활성화 여부다. Disabled여도 도구가 토큰 조작으로 활성화해 쓰는 경우가 많다.

## 실전 예시

```powershell
whoami /priv
# SeImpersonatePrivilege Enabled -> Potato 계열 시도
# windows\privileges\PrintSpoofer.md 참조:
.\PrintSpoofer.exe -i -c cmd
```

- IIS APPPOOL·svc 계정에서 SeImpersonate가 Enabled면 PrintSpoofer·GodPotato를 먼저 시도한다.

## 관련 문서

- `windows\privileges\overview.md` — 권한·토큰 개념 정리
- `windows\privileges\scenarios_tools.md` — 상황별 도구 선택
- `windows\privileges\SeImpersonatePrivilege.md`, `PrintSpoofer.md` — Potato 계열 상세
- `windows\privileges\SeDebugPrivilege.md`, `SeTcbPrivilege.md`, `SeShutdownPrivilege.md` — 권한별 상세
- `windows\privileges\winPEASany.exe.md` — 자동 점검 도구

## 팁·트러블슈팅

1. UAC 제한 토큰 상태라면 관리자 권한이 빠져 보일 수 있다. /groups에서 Builtin Administrators 소속을 확인하고 세션 재접속으로 풀 토큰을 시도한다.
2. 권한이 전부 빠져 있으면 whoami /groups로 멤버십 기반 경로(Backup Operators, DNSAdmins 등)를 먼저 본다.
3. winPEAS·PowerUp 같은 자동화 도구로 일괄 점검하고 whoami /priv는 수동 확인용으로 남긴다.
