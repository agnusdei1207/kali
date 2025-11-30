# RustScan

### 1. Cargo를 통한 설치 (권장)

```bash
# Rust 설치 (없는 경우)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# RustScan 설치
cargo install rustscan
```

### 2. Docker를 통한 사용

```bash
# Docker 이미지 다운로드 및 실행
docker run -it --rm --name rustscan --net=host rustscan/rustscan:2.1.1 -a [Target IP]
```

## 기본 사용법

### 1. 단일 호스트 스캔

```bash
# 기본 스캔 (상위 1000개 포트)
rustscan -a 10.10.10.1

# 모든 포트 스캔
rustscan -a 10.10.10.1 -r 1-65535

# 특정 포트 스캔
rustscan -a 10.10.10.1 -p 80,443,22,21
```

### 2. 여러 호스트 스캔

```bash
# 여러 IP 주소
rustscan -a 10.10.10.1,10.10.10.2,10.10.10.3

# IP 범위
rustscan -a 10.10.10.1-10.10.10.100

# 서브넷 스캔
rustscan -a 10.10.10.0/24
```

### 3. 파일에서 호스트 목록 읽기

```bash
# hosts.txt 파일에서 읽기
rustscan -a hosts.txt

# 파일 내용 예시 (hosts.txt)
10.10.10.1
10.10.10.2
192.168.1.1-192.168.1.100
```

## 고급 옵션

### 1. 속도 및 성능 설정

```bash
# 배치 크기 조정 (기본값: 4500)
rustscan -a 10.10.10.1 -b 1000

# 타임아웃 설정 (밀리초, 기본값: 1500)
rustscan -a 10.10.10.1 -t 3000

# 동시 스레드 수 조정
rustscan -a 10.10.10.1 --ulimit 5000
```

### 2. Nmap 통합

```bash
# 스캔 후 Nmap 실행
rustscan -a 10.10.10.1 -- -sV -sC

# 스크립트 스캔과 함께
rustscan -a 10.10.10.1 -- -A

# 특정 Nmap 스크립트 실행
rustscan -a 10.10.10.1 -- --script vuln
```

### 3. 출력 형식 설정

```bash
# JSON 형식으로 출력
rustscan -a 10.10.10.1 -o json

# 결과를 파일로 저장
rustscan -a 10.10.10.1 -o json > scan_results.json

# 조용한 모드 (배너 숨김)
rustscan -a 10.10.10.1 -q
```

## 실용적인 사용 예시

### 1. 빠른 네트워크 발견

```bash
# 네트워크 내 활성 호스트 찾기
rustscan -a 192.168.1.0/24 -p 80,443,22,21,23,25,53,135,139,445

# 웹 서버만 찾기
rustscan -a 192.168.1.0/24 -p 80,443,8080,8443
```

### 2. CTF/모의해킹에서의 활용

```bash
# 빠른 초기 스캔
rustscan -a 10.10.10.1 -r 1-1000

# 발견된 포트에 대한 상세 스캔
rustscan -a 10.10.10.1 -p 22,80,443 -- -sV -sC -A

# 전체 포트 스캔 (시간이 오래 걸림)
rustscan -a 10.10.10.1 -r 1-65535 -t 5000 -b 2000
```

### 3. 스테가노그래피와 결합

```bash
# 스캔 결과를 기반으로 추가 작업
rustscan -a 10.10.10.1 -o json | jq '.[] | select(.port == 80)'
```

## 설정 파일 사용

### config.toml 파일 생성

```bash
# 설정 파일 위치
~/.config/rustscan/config.toml
```

### 설정 파일 내용 예시

```toml
# ~/.config/rustscan/config.toml
[scanning]
batch_size = 4500
timeout = 1500
tries = 1
port_strategy = "serial"

[misc]
accessible = false
```

## 일반적인 명령어 조합

### 1. 기본 정찰

```bash
# 빠른 상위 포트 스캔
rustscan -a target.com -t 2000 -b 3000

# 전체 TCP 포트 스캔
rustscan -a target.com -r 1-65535 -- -sV
```

### 2. 스텔스 스캔

```bash
# 느린 스캔으로 탐지 회피
rustscan -a target.com -t 5000 -b 500 -- -T2 -sS
```

### 3. 서비스 식별

```bash
# 서비스 버전 탐지
rustscan -a target.com -- -sV -sC

# OS 탐지 포함
rustscan -a target.com -- -O -sV -sC
```

## 문제 해결

### 1. 권한 문제

```bash
# 원시 소켓 사용을 위해 sudo 필요한 경우
sudo rustscan -a 10.10.10.1

# 또는 capabilities 설정
sudo setcap cap_net_raw+ep /usr/local/bin/rustscan
```

### 2. ulimit 설정

```bash
# 파일 디스크립터 제한 확인
ulimit -n

# 제한 증가
ulimit -n 5000
```

### 3. 방화벽 문제

```bash
# TCP SYN 스캔이 차단되는 경우
rustscan -a target.com -- -sU  # UDP 스캔

# ACK 스캔 사용
rustscan -a target.com -- -sA
```

## 성능 최적화 팁

1. **배치 크기 조정**: 네트워크 상황에 따라 `-b` 옵션 조정
2. **타임아웃 설정**: 느린 네트워크에서는 `-t` 값 증가
3. **포트 범위 제한**: 필요한 포트만 스캔하여 시간 단축
4. **병렬 처리**: `--ulimit` 옵션으로 동시 연결 수 증가

## 보안 고려사항

- RustScan은 매우 빠르므로 탐지될 가능성이 높음
- 스텔스가 필요한 경우 타임아웃을 늘리고 배치 크기를 줄임
- 대상 시스템에 부하를 줄 수 있으므로 주의 필요
- 합법적인 모의해킹이나 자신의 시스템에서만 사용

## 유용한 별칭 설정

```bash
# ~/.bashrc 또는 ~/.zshrc에 추가
alias rs='rustscan'
alias rsfast='rustscan -t 1000 -b 5000'
alias rsslow='rustscan -t 5000 -b 1000'
alias rsall='rustscan -r 1-65535'
```
