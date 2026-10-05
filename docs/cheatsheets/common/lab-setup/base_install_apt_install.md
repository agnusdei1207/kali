# 기본 패키지 설치 (apt install)

slim Kali 이미지(`agnusdei1207/kali`)를 compose로 띄운 컨테이너에 설치하는 공통 패키지 모음이다. GUI 도구(브라우저, Burp Suite, Wireshark)는 호스트 Windows에서 실행하므로 컨테이너에는 CLI 도구 위주로만 설치한다. 컨테이너가 root로 동작하면 `sudo`는 생략한다.

## 한 번에 설치

```bash
apt update

apt install -y \
  net-tools dnsutils iproute2 procps iputils-ping lsof whois traceroute \
  tcpdump openvpn netcat-openbsd socat \
  vim less wget curl httpie jq file tar unzip p7zip-full rsync xxd \
  rlwrap bash-completion man-db xclip \
  git python3 python3-pip python3-venv php \
  openssh-client openssh-server ssh-client \
  seclists wordlists exploitdb \
  gobuster ffuf sqlmap nikto whatweb sublist3r \
  smbclient enum4linux ldap-utils snmp rpcbind nfs-common \
  hydra john \
  firefox-esr dpkg
```

- 실습 문서에서 `sudo apt install <패키지>`로 먼저 깔라고 나오는 것(seclists, xclip 등)은 이 명령으로 대부분 한 번에 해결된다.
- firefox-esr은 GUI를 호스트에서 쓰는 원칙과 중복되지만 기존 설치 목록에 있어 유지한다. 컨테이너에서 브라우저를 안 쓰면 목록에서 빼도 된다.
- dpkg는 패키지 관리자라 보통 이미 설치돼 있다.

## 그룹별 용도

| 그룹 | 패키지 | 용도 |
|---|---|---|
| 네트워크 기본 | `net-tools`, `iproute2`, `dnsutils`, `iputils-ping`, `procps`, `lsof`, `whois`, `traceroute` | `ifconfig`/`netstat`, `ip`/`ss`, `dig`/`nslookup`, `ping`, `ps`, 열린 파일 확인, 도메인·경로 추적 |
| 스니핑·터널 | `tcpdump`, `openvpn`, `netcat-openbsd`, `socat` | 패킷 캡처, 랩 VPN 연결, 포트 리스너·바인드 셸, 포트 포워딩 |
| 파일·텍스트 | `wget`, `curl`, `httpie`, `vim`, `less`, `file`, `tar`, `unzip`, `p7zip-full`, `rsync`, `xxd`, `jq` | 다운로드, HTTP 요청, 편집·페이징, 파일 타입 식별, 압축 해제, hex·JSON 확인 |
| 셸 편의 | `rlwrap`, `bash-completion`, `man-db`, `xclip` | `nc` 등에 라인 편집·히스토리 부여, 탭 완성, 매뉴얼, 클립보드 복사(페이로드 복사 등) |
| 스크립팅 | `git`, `python3`, `python3-pip`, `python3-venv`, `php` | 익스플로잇 도구 클론, PoC 스크립트 실행, 가상환경 |
| SSH | `openssh-client`, `openssh-server`, `ssh-client` | 원격 접속·파일 전송(`scp`), 컨테이너 sshd |
| 워드리스트·익스플로잇 DB | `seclists`, `wordlists`, `exploitdb` | ffuf/hydra용 단어 목록, `rockyou.txt`, `searchsploit` |
| 웹·열거 | `gobuster`, `ffuf`, `sqlmap`, `nikto`, `whatweb`, `sublist3r`, `smbclient`, `enum4linux`, `ldap-utils`, `snmp`, `rpcbind`, `nfs-common` | 경로·파라미터 브루트포스, SQLi 자동화, 웹 취약점 스캔, 웹 기술 식별, 서브도메인, SMB/LDAP/SNMP/NFS 열거 |
| 크래킹 | `hydra`, `john` | 온라인 로그인 브루트포스, 오프라인 해시 크래킹 |

설치 후 워드리스트 위치:

```bash
ls /usr/share/seclists/                       # ffuf -w 에 쓰는 목록
gunzip /usr/share/wordlists/rockyou.txt.gz    # john/hydra용 rockyou (처음 1회)
```

## 필요할 때 추가 설치

| 패키지 | 용도 |
|---|---|
| `feroxbuster` | Rust 기반 경로 브루트포스(ffuf/gobuster 대체) |
| `wpscan` | WordPress 취약점 스캔 |
| `wfuzz`, `dirb` | 경로·파라미터 퍼징(구식 환경 대응) |
| `hashcat` | GPU 해시 크래킹 |
| `medusa` | 병렬 로그인 브루트포스(hydra 대체) |
| `netexec`(구 crackmapexec) | SMB/WinRM/LDAP/MSSQL 통합 열거·익스플로잇 |
| `responder`, `mitm6` | LLMNR/NBT-NS/DHCPv6 스푸핑 해시 수집 |
| `impacket` | SMB/MSRPC 익스플로잇 스크립트 모음(psexec, secretsdump 등) |
| `krb5-user` | Kerberos 인증(AD 실습, 설치 시 대화형 입력 있음) |

패키지로 제공되지 않는 도구는 가상환경에 pip로 설치한다: [python_venv.md](python_venv.md)

## 관련 문서

- [open_vpn.md](open_vpn.md) - VPN 연결
- [docker_install.md](docker_install.md) - Docker 설치
- [git.md](git.md) - Git 설정
- [python_venv.md](python_venv.md) - Python 가상환경
- [rlwrap.md](rlwrap.md) - rlwrap 사용 예
