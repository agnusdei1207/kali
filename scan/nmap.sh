
# TCP 1~2000 포트, 서비스 버전 탐지 + 기본 NSE 스크립트, 속도 적당, 열린 포트만, 일반 텍스트 결과 저장
nmap -sS -sV -sC -p 1-2000 -T3 --open -oN tcp_scan.txt 10.10.11.68

# TCP 상위 100개 포트, 빠른 스캔, 열린 포트만, 일반 텍스트 결과 저장
nmap -sS -sV --top-ports 100 -T4 --open -oN tcp_fast.txt 10.10.11.68

# UDP 상위 100개 포트, 적당 속도, 열린 포트만, 일반 텍스트 결과 저장
nmap -sU --top-ports 100 -T3 --open -oN udp_scan.txt 10.10.11.68

# Ping 차단 우회 (Ping 없이), TCP 1~2000 포트, 서비스+기본 스크립트, 적당 속도, 열린 포트만, 결과 저장
nmap -sS -sV -sC -p 1-2000 -T3 -Pn --open -oN no_ping_scan.txt 10.10.11.68

# TCP 1~2000 포트, 적당 속도, 열린 포트만, grep용 결과 저장
nmap -sS -p 1-2000 -T3 --open -oG scan.grep 10.10.11.68

# --reason 사용하면 포트가 열리거나 닫힌 이유 출력
nmap -sS -sV -sC -Pn -T3 --reason --open -oN scan.txt 10.10.11.68

# 매우 빠르게 확인
nmap -p- -T5 --max-retries 2 --min-rate 1000 -Pn -n -oN quick_full.txt 10.10.11.64


# 옵션
- `-sS` : SYN 스캔 (Stealth Scan, 빠르고 흔적이 적음)
- `-sT` : TCP Connect 스캔 (SYN 불가 시 사용)
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
- `-D <decoy>` : Decoy IP 사용 (탐지 우회)
- `-f` : 패킷 fragment (IDS/IPS 우회)
- `--source-port <포트>` : 소스 포트 지정
- `--reason` : 포트 상태의 이유 출력
- `-vv` : 상세 출력 (verbose)
- `--open` : 열린 포트만 출력
- `--top-ports <N>` : 가장 많이 사용되는 N개 포트만 스캔
