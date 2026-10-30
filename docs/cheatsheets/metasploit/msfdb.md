# msfdb (workspace / hosts)

## 개요

`msfdb`는 PostgreSQL 기반의 Metasploit 데이터베이스 관리 도구다.
`msfconsole` 세션, 저장된 workspace, 열린 exploit 정보를 관리한다.

## 설치

```bash
sudo systemctl start postgresql
sudo apt install postgresql -y

sudo -u postgres msfdb init
```

## 초기화 및 상태

```bash
msfdb init
db_status
```

```
[*] Connected to msfdb. Connection type: postgresql.
[*] msfdb initialized.
```

## workspace / hosts / services

```bash
workspace            # 현재 workspace
workspace default    # 기본 workspace 지정
workspace -h         # 도움말

hosts                # 열린 hosts 목록
services            # 열린 services 목록
hosts -R             # services까지 모두 열기
services -S netbios # 특정 서비스만 열기
```

## search

```bash
services -S smb        # SMB 관련 서비스만
search eternalblue    # exploit 검색
```

## run

```bash
# exploit 실행
exploit

# 세션 관리
sessions -l
sessions -i 1
```

## 주의

- Kali 기본 설치에는 `msfdb`가 포함되어 있다.
- PostgreSQL을 직접 다루는 일은 거의 없다. `msfdb` 명령만 익히면 충분하다.
