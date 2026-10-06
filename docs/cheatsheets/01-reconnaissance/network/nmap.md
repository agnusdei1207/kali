# Nmap

네트워크에서 열려있는 포트와 서비스를 찾는 포트 스캔 도구입니다.

Root/Admin → SYN 스캔(-sS, stealth scan) 가능
일반 사용자 → TCP Connect Scan(-sT) 기본

## 설치

Kali는 기본 설치되어 있습니다.

```bash
# 설치 확인
nmap --version
```

## 옵션

- `-sS` : SYN 스캔 (Stealth Scan, 빠르고 흔적이 적음)
- `-sn` : 포트스캔 X 호스트 살아있는지만 체크
- `-sT` : TCP Connect 스캔 (SYN 불가 시 사용)
- `-sL` : 스캔 없이 호스트만 나열 (네트워크 영향 거의 없음)
- `-sU` : UDP 스캔 (UDP 서비스 탐지)
- `-sV` : 서비스 버전 탐지
- `-O` : 운영체제(OS) 탐지
- `-A` : 종합 정보 수집 (OS, 버전, 스크립트, traceroute 등)
- `-sC` : 기본 NSE 스크립트 실행
- `--script=<name>` : 특정 NSE 스크립트 실행 (예: `--script=vuln`)
- `-p <포트>` : 특정 포트 지정 (예: `-p 80,443,8080`)
- `-p-` : 모든 포트(1-65535) 스캔
- `-T<0-5>` : 스캔 속도 조절 (0: 느림, 5: 매우 빠름)
- `-Pn` : Ping 없이 스캔 (ICMP 차단 우회)
- `-F` : 빠른 스캔 (기본 포트만)
- `-iL <파일>` : 타겟 목록 파일로 지정
- `-oN <파일>` : 결과를 일반 텍스트로 저장
- `-oX <파일>` : 결과를 XML로 저장
- `-oA <prefix>` : 모든 포맷으로 저장
- `-oG <파일>` : grep 가능한 형식으로 저장 (파이프 처리용)
- `-D <decoy>` : Decoy IP 사용 (탐지 우회)
- `-f` : 패킷 fragment (IDS/IPS 우회)
- `--source-port <포트>` : 소스 포트 지정
- `--reason` : 포트 상태의 이유 출력
- `-vv` : 상세 출력 (verbose)
- `--open` : 열린 포트만 출력
- `--top-ports <N>` : 가장 많이 사용되는 N개 포트만 스캔
- `--min-rate <N>` : 초당 최소 패킷 수 보장 (빠른 스캔)
- `--max-retries <N>` : 포트당 재시도 횟수 제한 (속도 향상)
- `-n` : DNS 역조회 생략 (속도 향상, 흔적 감소)

## 포트 상태 해석

- Open: 서비스가 응답 중
- Closed: 포트가 닫혔음 (방화벽 차단 X)
- Filtered: 방화벽이 응답 차단
- Unfiltered: 상태 불명 (드물음)
- Open|Filtered: 열려있거나 필터링됨

## 예시

```bash
# TCP 1~2000 포트, 서비스 버전 탐지 + 기본 NSE 스크립트, 속도 적당, 열린 포트만, 일반 텍스트 결과 저장

nmap -sS -sV -sC -Pn -O -p 1-2000 -T3 --open -oN tcp_scan.txt 10.10.11.68

# --open을 빼고 -vv (Very Verbose)를 추가하여 포트의 정확한 상태(Closed인지 Filtered인지)를 확인
nmap -sS -sV -sC -Pn -O -p 1-2000 -T3 -vvv -oN tcp_scan.txt 10.10.11.68

# TCP 상위 100개 포트, 빠른 스캔, 열린 포트만, 일반 텍스트 결과 저장

nmap -sS -sV -O --top-ports 100 -T4 --open -oN tcp_fast.txt 10.10.11.68/24

# UDP 상위 100개 포트, 적당 속도, 열린 포트만, 일반 텍스트 결과 저장

nmap -sU -O --top-ports 100 -T3 --open -oN udp_scan.txt 10.10.11.68/16

# Ping 차단 우회 (Ping 없이), TCP 1~2000 포트, 서비스+기본 스크립트, 적당 속도, 열린 포트만, 결과 저장

nmap -sS -sV -sC -O -p 1-2000 -T3 -Pn --open -oN no_ping_scan.txt 10.10.11.68

# TCP 1~2000 포트, 적당 속도, 열린 포트만, grep용 결과 저장

nmap -sS -O -p 1-2000 -T3 --open -oG scan.grep 10.10.11.68

# --reason 사용하면 포트가 열리거나 닫힌 이유 출력

nmap -sS -sV -O -sC -Pn -T3 --reason --open -oN scan.txt 10.10.11.68

# 매우 빠르게 확인

nmap -p- -T5 --max-retries 2 --min-rate 1000 -Pn -n -oN quick_full.txt 10.10.11.64

# 192.168.1.0/24 네트워크에서 살아있는 호스트만 확인

nmap -sn 192.168.1.0/24

# 포트 20~80 스캔

nmap -p 20-80 192.168.1.10

# 192.168.1.1 ~ 192.168.1.50 스캔

nmap -sn 192.168.1.1-50

# /24 → 255.255.255.0 대역 전체 스캔

nmap -sn 192.168.1.0/24

# /16 → 255.255.0.0 대역 스캔

nmap -sn 10.10.0.0/16

# 호스트만 나열

nmap -sL 192.168.0.1/24

# debug

nmap -d 10.10.11.0/24

# vuln

nmap -sC --script vuln 10.10.11.0/24

# specify scripts

nmap -sC --script smb-vuln-ms17-010,script2.nse  10.10.11.0/24

# wildcard

nmap -sC --script "http-*" 10.10.11.0/24

# 찾은 포트만 상세 검증 (전체 스캔으로 열린 포트 확인 후 후속 조사)

nmap -sS -sV -sC -A -p 22,80,443 10.10.11.68 -oN detailed.txt

# IDS/IPS 우회: Decoy IP 5개 + 패킷 분할

nmap -sS -sV -D RND:5 -f 10.10.11.68

# 타겟 목록 파일로 스캔 (-iL, -sn -oG로 만든 목록과 연계)

nmap -sS -sV -iL alive.txt -oN list_scan.txt

# UDP 핵심 서비스 심층 (DNS/SNMP/IKE)

nmap -sU -sV -p 53,161,500 10.10.11.68

# 웹 경로 자동 열거 (http-enum)

nmap --script http-enum -p 80,443 10.10.11.68

# 여러 형식으로 동시 저장 (-oA: .nmapxmlgnmap 생성)

nmap -sS -sV --top-ports 100 10.10.11.68 -oA scan_result
```

## 단계별 스캔 흐름

### 1단계: 대상이 살아있는지 확인

```bash
# 단일 호스트 확인
nmap 10.10.11.68

# 서브넷 내 살아있는 호스트만 확인
nmap -sn 192.168.1.0/24
```

결과: 응답하는 호스트만 표시

### 2단계: 열린 포트 빠르게 찾기

```bash
# Top 100 포트 빠르게 스캔
nmap -sS --top-ports 100 -T4 10.10.11.68

# 모든 포트 매우 빠르게 (65535개)
nmap -p- -T5 --max-retries 2 --min-rate 1000 -Pn 10.10.11.68
```

결과: 포트 번호와 상태(Open/Closed/Filtered)

### 3단계: 서비스와 버전 파악

```bash
# 서비스 버전까지 파악
nmap -sS -sV --top-ports 100 10.10.11.68

# 기본 NSE 스크립트까지 실행
nmap -sS -sV -sC --top-ports 100 10.10.11.68
```

결과: 포트번호/서비스명/버전 정보

### 4단계: 운영체제 감지

```bash
# OS 탐지 추가
nmap -sS -sV -sC -O --top-ports 100 10.10.11.68
```

결과: 예상되는 OS 정보

## 실전 시나리오

### 시나리오 1: 침투테스트 시작 (전체 파악)

목표: 대상 서버의 모든 열린 포트와 서비스 파악

```bash
# 1단계: 빠른 포트 스캔
nmap -p- -T4 10.10.11.68 -oN ports.txt

# 2단계: 찾은 포트들만 상세 스캔
nmap -sS -sV -sC -A -p 22,80,443 10.10.11.68 -oN detailed.txt

# 3단계: NSE 취약점 스크립트 실행
nmap --script vuln -p 22,80,443 10.10.11.68 -oN vuln.txt
```

결과 해석:
- ports.txt: 포트 번호 확인
- detailed.txt: 각 포트의 서비스/버전
- vuln.txt: 알려진 취약점 여부

### 시나리오 2: 특정 서비스 탐색 (웹 서버)

목표: 웹 서버 관련 포트와 스크립트 실행

```bash
# 웹 관련 포트 집중 스캔
nmap -sS -sV -sC --script "http-*" -p 80,443,8080,8443 10.10.11.68

# 웹 취약점 전용
nmap --script "http-vuln-*" -p 80,443 10.10.11.68
```

### 시나리오 3: SMB/Windows 서버 탐색

목표: Windows 시스템의 SMB 취약점 확인

```bash
# SMB 관련 스크립트
nmap -sS -sV -sC --script "smb-*" -p 139,445 10.10.11.68

# MS17-010 (Eternal Blue) 확인
nmap --script smb-vuln-ms17-010 -p 445 10.10.11.68
```

### 시나리오 4: 네트워크 전체 스캔 (피 재기)

목표: /24 대역의 모든 호스트와 포트 파악

```bash
# 1단계: 살아있는 호스트만 찾기
nmap -sn 192.168.1.0/24 -oG alive.grep

# 2단계: 각 호스트의 주요 포트 스캔
nmap -sS --top-ports 20 -iL alive.txt -oN network_scan.txt
```

## 스캔 속도 설정

```bash
# T1: 매우 느림 (IDS 회피)
nmap -T1 -p- 10.10.11.68

# T3: 기본 (균형)
nmap -T3 --top-ports 1000 10.10.11.68

# T4: 빠름 (일반 LAN)
nmap -T4 --top-ports 100 10.10.11.68

# T5: 매우 빠름 (위험, 정확도 낮음)
nmap -T5 --top-ports 50 10.10.11.68
```

## NSE 스크립트 활용

```bash
# 취약점 스캔
nmap --script vuln -p 80,443 10.10.11.68

# 와일드카드 사용
nmap --script "http-*" -p 80 10.10.11.68
nmap --script "smb-*" -p 445 10.10.11.68
nmap --script "ftp-*" -p 21 10.10.11.68

# 특정 스크립트 여러 개
nmap --script smb-vuln-ms17-010,smb-os-discovery -p 445 10.10.11.68

# 스크립트 목록 확인
ls /usr/share/nmap/scripts/ | grep http
```

## 명령어 조합 팁

```bash
# 발견된 호스트를 자동으로 다음 스캔의 대상으로
nmap -sn 10.10.0.0/16 -oG - | grep "Up" | awk '{print $2}' | nmap -sS -sV -iL - -oN detailed.txt

# 특정 포트 열린 호스트만 찾기
nmap -p 22 -sn 192.168.1.0/24 | grep "Host is up"

# 결과 병합
nmap -sS -p- 10.10.11.68 -oG scan1.txt
nmap -sV -p 22,80,443 10.10.11.68 -oG scan2.txt
# 두 결과를 함께 보려면 nmap-formatter 등 사용
```

## 팁과 주의사항

- 팁 1: 포트 스캔 이전에 항상 -sn으로 호스트 확인
- 팁 2: 느린 스캔(T1)은 IDS를 피하지만, 시간이 오래 걸림
- 팁 3: 결과를 grep 형식(-oG)으로 저장하면 파이프 처리 가능
- 팁 4: --open을 빼면 Closed/Filtered 포트도 확인 가능
- 주의: 허가 없는 스캔은 불법입니다
- 주의: 프로덕션 서버는 -T1, -T2로 조용히 스캔하세요

## 관련 도구

- masscan: nmap보다 빠른 초기 포트 스캔
- rustscan: Rust로 작성된 빠른 포트 스캔
- zenmap: nmap의 GUI 버전
- 다음: 발견된 포트의 서비스에 따라 dirb, sqlmap, wpscan 등

---

공식 문서: https://nmap.org/
