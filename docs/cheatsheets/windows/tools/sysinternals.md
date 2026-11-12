# SysinternalsSuite 핵심 도구

- SysinternalsSuite — Microsoft의 Windows 내부 진단 도구 모음. PsExec(원격 실행), Procmon(이벤트 추적), Procexp(프로세스), Autoruns(자동실행), TCPView(소켓), AccessChk(권한) 등을 포함한다.
- Windows 권한상승 힌트(서비스·자동실행 경로의 권한 결함)를 찾을 때, 원격 명령 실행과 SYSTEM 셸이 필요할 때, 프로세스·레지스트리·네트워크 이벤트를 실시간 추적할 때.
- Windows 전용. workspace\windows\tools\SysinternalsSuite\ 아래 exe 사용. 첫 실행마다 EULA를 묻는데 -accepteula 플래그로 생략한다.

## PsExec (원격·SYSTEM 실행)

```powershell
workspace\windows\tools\SysinternalsSuite\PsExec64.exe \\10.0.0.5 -u DOMAIN\admin -p "P@ss" cmd.exe
PsExec64.exe -s -i cmd.exe                 # 로컬 SYSTEM 대화형 셸
PsExec64.exe \\10.0.0.5 -c payload.exe     # 로컬 바이너리 복사 후 원격 실행
```

- `-c`: 로컬 파일을 원격 %SystemRoot%로 복사해 실행.
- RDP 세션 조작은 SYSTEM 셸에서 `query user` 후 `tscon <세션ID> /dest:console` 조합으로 처리한다.

## Procmon (프로세스 모니터)

```powershell
Procmon64.exe /Quiet /Minimized /BackingFile trace.pml
Procmon64.exe /OpenLog trace.pml
```

- 파일·레지스트리·네트워크 이벤트를 한 스트림으로 기록. Filter(Ctrl+L)로 Process Name·Path 조건을 건다.

## Procexp (프로세스 익스플로러)

- 트리 뷰로 부모-자식 프로세스 관계, 핸들·DLL 목록, 서명 검증(Verify)을 확인한다. procexp64.exe를 관리자로 실행.

## Autoruns (자동실행 열거)

```powershell
autorunsc64.exe -a * -c -accepteula > autoruns.csv
```

- 서비스·스케줄 작업·Run 키·WMI 등 모든 자동실행 위치를 나열. 권한 없는 위치의 항목이 권한상승 후보다.
- `-a *`: 전체 항목, `-c`: CSV 출력.

## TCPView / tcpvcon

```powershell
tcpvcon.exe -a -c -n
```

- 프로세스별 소켓(포트와 PID 매핑) 확인. `-n`은 역방향 DNS 끔, `-c`는 CSV 출력.

## AccessChk (권한 확인)

```powershell
accesschk64.exe -uws "Users" "C:\Program Files"
accesschk64.exe -uwcqv "Authenticated Users" svc*
accesschk64.exe -q -u -accepteula "Everyone" C:\Tools\helper.exe
```

- `-u`: 권한 있는 항목만, `-w`: 쓰기 권한, `-s`: 재귀, `-q`: 헤더 생략. 쓰기 가능 서비스·파일 탐색이 권한상승 기본기.

## 기타

- PsLoggedon: `psloggedon.exe \\10.0.0.5` — 원격 로그온 세션 확인.
- AD Explorer: AD 스냅샷 저장·탐색.
- SigCheck: `sigcheck64.exe -a -h target.exe` — 서명·해시 확인.

## 팁·트러블슈팅

1. 자동화에서는 항상 -accepteula를 붙인다. 없으면 EULA 창에서 멈춘다.
2. Procmon 로그가 급격히 커지므로 필터를 먼저 걸고 캡처를 시작한다.
3. PsExec 원격 실행이 막히면 Admin$ 공유 접근과 서비스 관리 권한부터 확인한다.
