# rpcdump (Impacket)

MSRPC Endpoint Mapper(135/tcp)에 질의해 "어떤 RPC 인터페이스가 어느 동적 포트에 붙어 있는지"를 출력하는 도구. nmap으로 135가 열린 것을 확인한 뒤, 그 안에 무엇이 돌아가는지 지도를 그릴 때 쓴다.

## 1. 설치

### 1.1 Kali / Debian

```bash
sudo apt update
sudo apt install -y python3-impacket
```

설치되면 `rpcdump.py`가 `/usr/bin` 또는 `/usr/share/doc/python3-impacket/examples` 아래에 놓인다. 경로가 잡히지 않으면 아래처럼 찾는다.

```bash
find / -name 'rpcdump.py' 2>/dev/null
```

### 1.2 pip / pipx

```bash
pip3 install impacket
# 또는 격리 설치
pipx install impacket
```

### 1.3 이름 주의

Kali 최신 버전에서는 실행 파일 이름이 바뀌어 있다.

| 버전                     | 실행 이름          |
| ------------------------ | ------------------ |
| 구버전 (apt 구버전, pip) | `rpcdump.py`       |
| 신버전 (Kali 최신, pipx) | `impacket-rpcdump` |

동일한 도구다. 명령이 안 잡히면 `impacket-rpcdump`로 다시 시도한다. 예시에서는 `rpcdump.py`를 쓰되, 동일하게 `impacket-rpcdump`로 대체 가능하다.

## 2. 기본 사용법

```bash
# 익명(null session)으로 EPM 덤프
rpcdump.py @192.168.165.180

# 계정으로
rpcdump.py 'DOMAIN/user:pass@192.168.165.180'

# NTLM 해시
rpcdump.py -hashes :<NTHASH> 'DOMAIN/user@192.168.165.180'

# Kerberos
rpcdump.py -k -no-pass 'DOMAIN/user@dc01.domain.local'
```

`@IP` 형식은 "호스트에 익명으로 붙는다"는 뜻이다. 도메인 환경이면 `DOMAIN/user:pass@HOST` 형식을 쓴다.

## 3. 주요 옵션

```bash
-h, --help           # 도움말
-debug               # 상세 디버그 출력
-hashes LMHASH:NTHASH # PtH
-no-pass             # 비밀번호 없음 (Kerberos와 함께)
-k                   # Kerberos 인증
-dc-ip <IP>          # KDC 주소 (Kerberos 시)
-target-ip <IP>      # 이름 해석 우회, IP 직접 지정
-port <PORT>         # EPM 포트 (기본 135)
```

## 4. 출력 읽는 법

```
Protocol: ncacn_ip_tcp
Provider: (null)
UUID    : 12345678-1234-abcd-ef00-0123456789ab v1.0
Bindings:
          ncacn_ip_tcp:192.168.165.180[49668]
```

- `UUID`: RPC 인터페이스 식별자. 이것으로 서비스를 식별한다.
- `ncacn_ip_tcp`: TCP 전송 바인딩.
- `[49668]`: 실제 요청을 받는 동적 포트. `-p-` 스캔에 뜨는 49xxx 포트가 이것이다.
- `Provider: (null)`: 인터페이스가 어떤 DLL/서비스에 구현됐는지. null이면 EPM이 이름을 모른다는 뜻이다.

자주 보이는 UUID:

| UUID                                   | 인터페이스 | 의미                        |
| -------------------------------------- | ---------- | --------------------------- |
| `12345678-1234-abcd-ef00-0123456789ab` | srvsvc     | 공유 열거 (NetShareEnumAll) |
| `3919286a-b10c-11d0-9ba8-00c04fd92ef5` | dssetup    | 도메인 컨트롤러 설정 정보   |
| `12345778-1234-abcd-ef00-0123456789ac` | samr       | 계정·그룹 열거              |
| `378e10ed-9304-1d42-84d4-00a0247b757a` | (null)     | DCOM / WMI 계열             |
| `99fcfec4-5260-101b-bbcb-00aa0021347a` | (null)     | (null)                      |

UUID만으로 서비스를 특정하기 어려우면 `rpcmap.py`로 인터페이스를 직접 호출해본다.

## 5. rpcmap.py: 인터페이스 직접 호출

`rpcdump.py`는 EPM이 알려주는 것만 보여준다. 특정 인터페이스가 실제로 응답하는지 확인하려면 `rpcmap.py`를 쓴다.

```bash
# EPM 전체 매핑 (rpcdump와 유사)
rpcmap.py 'ncacn_ip_tcp:192.168.165.180'

# 특정 인터페이스 UUID로 직접 호출
rpcmap.py 'ncacn_ip_tcp:192.168.165.180[49668]' -brute-uuids   # UUID 브루트 (느림)

# 인증 포함
rpcmap.py 'ncacn_ip_tcp:192.168.165.180' -username user -password pass -domain WORKGROUP
```

`rpcmap.py`는 opnum 브루트포스도 가능해, EPM에 등록되지 않은 인터페이스를 찾을 때 쓴다.

## 6. 실전 흐름

1. `nmap -p135 <IP>`로 135가 열렸는지 확인한다.
2. `rpcdump.py @<IP>`로 UUID → 포트 지도를 뽑는다.
3. `srvsvc` UUID가 있으면 `rpcclient`로 공유를 열거한다.
4. `samr` UUID가 있으면 계정·그룹을 열거한다.
5. 지도에 없는 인터페이스가 의심되면 `rpcmap.py`로 직접 호출한다.

```bash
# 한 번에 계정·그룹·공유·정책
rpcclient -U '' -N 192.168.165.180 -c 'enumdomusers; enumdomgroups; netshareenumall; getdompwinfo'
```

## 7. 자주 만나는 오류

| 오류                                                    | 원인                 | 대응                                                                 |
| ------------------------------------------------------- | -------------------- | -------------------------------------------------------------------- |
| `rpcdump.py: command not found`                         | 구버전 이름 차이     | `impacket-rpcdump` 시도, 또는 `python3 -m impacket.examples.rpcdump` |
| `STATUS_ACCESS_DENIED`                                  | 익명 EPM 차단        | 계정을 넣어 재시도: `DOMAIN/user:pass@IP`                            |
| `Connection refused`                                    | 135 닫힘 또는 방화벽 | `nmap -p135`로 먼저 확인                                             |
| `The NETBIOS connection with the remote host timed out` | 이름 해석 실패       | `-target-ip <IP>` 추가                                               |
| `EPM returned no entries`                               | EPM이 비어 있음      | `rpcmap.py`로 직접 호출, 또는 nmap `msrpc-enum` 스크립트             |
| `Protocol not supported`                                | 전송 프로토콜 불일치 | `ncacn_ip_tcp` 명시                                                  |

nmap 대체 명령:

```bash
nmap -p135 --script msrpc-enum <IP>
```

## 8. nmap으로 같은 정보 얻기

rpcdump가 없을 때 nmap으로 대체할 수 있다.

```bash
nmap -p135 --script msrpc-enum <IP>
nmap -p135,445 --script smb-enum-users,smb-enum-shares,smb-os-discovery <IP>
```

nmap의 `msrpc-enum`은 EPM을 질의해 인터페이스 목록을 보여주지만, rpcdump처럼 UUID → 포트 매핑을 자세히 보여주지는 않는다.

## 9. 한 줄 정리

- 135가 열려 있으면 `rpcdump.py @IP` 한 줄로 RPC 지도가 나온다.
- UUID로 `srvsvc`(공유), `samr`(계정)을 찾아 `rpcclient`와 연결한다.
- 이름이 안 잡히면 `impacket-rpcdump` 또는 `nmap msrpc-enum`으로 폴백한다.
