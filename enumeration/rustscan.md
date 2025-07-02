# RustScan

## 설치

```bash
# GitHub에서 설치 (Kali apt로는 더 이상 사용 불가)
git clone https://github.com/RustScan/RustScan.git
cd RustScan
cargo build --release
sudo cp target/release/rustscan /usr/local/bin/

# Cargo로 설치 (Rust가 설치되어 있어야 함)
cargo install rustscan

# Docker 이용 (가장 간편한 방법, 추천)
docker pull rustscan/rustscan:latest
alias rustscan='docker run -it --rm --name rustscan rustscan/rustscan:latest'
```

## 기본 사용법

```bash
# 기본 스캔 (5분이면 모든 포트 스캔 가능)
rustscan -a 10.10.10.10

# 특정 포트 범위 스캔
rustscan -a 10.10.10.10 -p 1-1000

# 특정 포트만 스캔
rustscan -a 10.10.10.10 -p 22,80,443,3306

# 여러 타겟 스캔
rustscan -a 10.10.10.10,10.10.10.11
rustscan -a 10.10.10.0/24
```

## Nmap과 연동 (실전 사용)

```bash
# 발견된 포트에 대해 nmap 상세 스캔 진행
rustscan -a 10.10.10.10 -- -sC -sV -oN scan.txt

# 전체 포트 스캔 후 발견된 모든 포트 상세 스캔
rustscan -a 10.10.10.10 --range 1-65535 -- -sC -sV -oN full_scan.txt

# 스텔스 스캔 (SYN)
rustscan -a 10.10.10.10 -- -sS -sV
```

## 주요 옵션

```
-a, --address [IP]       : 스캔할 IP 주소
-p, --ports [PORT]       : 스캔할 포트 지정 (기본: 1-1000)
--range [RANGE]          : 스캔할 포트 범위 (기본: 1-65535)
-b, --batch-size [SIZE]  : 동시에 스캔할 포트 수 (기본: 4500)
-t, --timeout [TIME]     : 타임아웃 설정 (기본: 1500ms)
-r, --rate [RATE]        : 초당 패킷 전송 수 (기본: 3000)
--ulimit [LIMIT]         : 시스템 ulimit 설정 (대규모 스캔 시 중요)
-- [ARGS]                : nmap 명령어 전달 (이후 인수는 nmap에 전달됨)
```

## 실전 활용 예시

```bash
# 웹서버 스캔 시나리오
rustscan -a 10.10.10.10 -t 2000 -- -sV -sC -oN web_scan.txt

# ulimit 설정으로 대규모 네트워크 스캔
rustscan --ulimit 5000 -a 10.10.0.0/16 -b 2000 -t 5000 -- -v -oN network_scan.txt

# 느린 네트워크에서 더 안정적으로 스캔
rustscan -a 10.10.10.10 -r 100 -t 5000 -- -v -A

# nmap 스크립트 사용 예시
rustscan -a 10.10.10.10 -p 445 -- --script=smb-vuln* -oN smb_vuln.txt
```

## 성능 조절 팁

- 느린 네트워크: `-r 100 -t 5000` (속도↓ 정확도↑)
- 빠른 스캔: `-b 10000 -r 5000` (속도↑ 정확도↓)
- 일반적인 환경: `-b 4500 -t 2000` (기본값보다 조금 안정적)

## 장점

- nmap보다 초기 포트 스캔 속도가 훨씬 빠름 (약 5-10배)
- nmap의 모든 기능을 그대로 사용 가능
- 대량의 IP 동시 스캔 가능
- OSCP 시험에서 시간 절약 가능
