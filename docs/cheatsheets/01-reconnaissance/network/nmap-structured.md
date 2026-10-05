# Nmap 포트 스캔 가이드

네트워크에서 열려있는 포트와 서비스를 찾는 포트 스캔 도구입니다.

## 설치

Kali는 기본 설치되어 있습니다.

```bash
# 설치 확인
nmap --version
```

## 기본 개념

스캔 권한에 따라 스캔 방식이 달라집니다

- Root 권한: SYN 스캔(-sS) 가능 (반쪽 연결, 빠르고 조용함)
- 일반 사용자: TCP Connect Scan(-sT) (전체 연결)
- Ping 차단: -Pn 옵션으로 Ping 없이 스캔

## 주요 옵션

| 옵션 | 의미 | 사용 시기 |
|------|------|---------|
| `-sS` | SYN 스캔 (Stealth) | Root 권한 있을 때, 조용히 스캔 |
| `-sT` | TCP Connect | 일반 사용자, 느림 |
| `-sU` | UDP 스캔 | DNS/SNMP 등 UDP 서비스 찾을 때 |
| `-sn` | Ping 스캔만 | 살아있는 호스트만 확인 |
| `-sV` | 버전 탐지 | 서비스 버전 파악 필요할 때 |
| `-sC` | 기본 NSE 스크립트 | 기본 정보와 취약점 확인 |
| `-O` | OS 탐지 | 운영체제 추측 |
| `-A` | 공격적 스캔 | -sV -sC -O --traceroute 포함 |
| `-p 20-80` | 포트 범위 | 특정 포트 범위만 스캔 |
| `-p-` | 전체 포트 | 1~65535 모두 스캔 |
| `--top-ports N` | 상위 N개 포트 | 빠른 스캔 (top-ports 100) |
| `-T1~T5` | 속도 (T1=느림, T5=매우빠름) | T3=기본, T4=빠름, T5=위험 |
| `-Pn` | Ping 없이 스캔 | Ping 차단된 대상 |
| `--open` | 열린 포트만 표시 | 결과 간결히 |
| `-oN` | 일반 텍스트 저장 | 결과 저장 |
| `-oG` | grep 형식 저장 | 파이프로 처리할 때 |
| `-v` | Verbose | 상세 출력 |
| `--script` | NSE 스크립트 실행 | vuln, http-*, smb-* 등 |
| `--reason` | 포트 상태 이유 표시 | 왜 Open인지 설명 |

## 빠른 시작 (단계별)

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

## 실제 사용 시나리오

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

## 포트 상태 해석

- Open: 서비스가 응답 중
- Closed: 포트가 닫혔음 (방화벽 차단 X)
- Filtered: 방화벽이 응답 차단
- Unfiltered: 상태 불명 (드물음)
- Open|Filtered: 열려있거나 필터링됨

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

## 결과 파일 형식

```bash
# 여러 형식으로 동시 저장
nmap -sS -sV --top-ports 100 10.10.11.68 -oA scan_result
# scan_result.nmap (일반)
# scan_result.xml (XML)
# scan_result.gnmap (Grep)
```

## 팁과 주의사항

- 팁 1: 포트 스캔 이전에 항상 -sn으로 호스트 확인
- 팁 2: 느린 스캔(T1)은 IDS를 피하지만, 시간이 오래 걸림
- 팁 3: 결과를 grep 형식(-oG)으로 저장하면 파이프 처리 가능
- 팁 4: --open을 빼면 Closed/Filtered 포트도 확인 가능
- 주의: 허가 없는 스캔은 불법입니다
- 주의: 프로덕션 서버는 -T1, -T2로 조용히 스캔하세요

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

## 관련 도구

- masscan: nmap보다 빠른 초기 포트 스캔
- rustscan: Rust로 작성된 빠른 포트 스캔
- zenmap: nmap의 GUI 버전
- 다음: 발견된 포트의 서비스에 따라 dirb, sqlmap, wpscan 등

---

공식 문서: https://nmap.org/
