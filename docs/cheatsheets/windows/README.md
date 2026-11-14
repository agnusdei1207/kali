# Windows

Windows 타깃 점검 문서 폴더. 권한 상승 절차 전체는 methodology/privilege-escalation의 windows.md를 함께 본다.

## 루트 파일

- `certutil.md` 내장 도구로 파일 다운로드 (urlcache)
- `evil_winrm.md` WinRM 셸 접속
- `find_string.md` findstr로 시크릿 문자열 검색
- `invoke_request.md` Invoke-WebRequest 전송·다운로드
- `switch_ps.md` PowerShell 실행 정책 우회
- `windows_privileges.md` Windows 권한 개념 정리
- `tools.md` Windows 도구 모음 인덱스 — `tools/` 상세

## cmd/ — 명령줄

- `base_cmd.md` cmd 기본 명령
- `windows_basic.md` 시스템 정보·네트워크 기본 명령
- `route_print.md` 라우팅 테이블 확인
- `schtasks.md` 예약 작업 확인·생성
- `seek.md` 파일·디렉터리 탐색

## powershell/ — PowerShell (상세는 powershell/README.md)

- 기초: base_powershell, replace, file_operations
- 열거: system_reconnaissance, network_enumeration, active_directory
- 활용: privilege_escalation, user_management, defense_evasion, file_transfer, invoke_webrequest

## privileges/ — 권한 상승 (상세는 privileges/overview.md)

- 개념·절차: overview, scenarios-tools, winPEASany.exe
- 개별 권한: SeDebugPrivilege, SeImpersonatePrivilege, SeTcbPrivilege, SeChangeNotifyPrivilege, SeShutdownPrivilege, PrintSpoofer

## tools/ — 도구

- `sysinternals.md` Sysinternals 세트
- `systeminformer.md` System Informer (구 Process Hacker)
- `dnspy.md` .NET 디컴파일·디버깅
- `trivy.md` 의존성·컨테이너 스캐너

## rdp/ · smb/ — 서비스 접속

- `rdp/rdp.md` RDP 접속·활성화
- `rdp/evil_winrm.md` RDP 환경에서의 WinRM 활용
- `smb/unc.md` UNC 경로 접근
