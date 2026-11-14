# Recon 인덱스

정보 수집 문서 폴더. 네트워크 → DNS → 웹 표면 → 시크릿 순서가 기본 흐름이다.

## curl/ — HTTP 요청 조작

- `requests.md` 기본 요청 (GET·POST·헤더)
- `headers_and_cookies.md` 헤더·쿠키 조작
- `post_data.md` POST 데이터 전송
- `query_parameters.md` 쿼리 파라미터
- `proxies_and_tls.md` 프록시(-x·--socks5)·TLS 검증 생략(-k)
- `remote_command_execution.md` 요청으로 명령 실행 테스트
- `vulnerability_tests.md` 취약점 수동 테스트 모음

## dns/

- `dns.md` dig·nslookup 기본 질의
- `amass.md` 서브도메인 종합 열거
- `subfinder.md` 빠른 서브도메인 수집
- `dnsrecon.md` DNS 레코드·존 전이
- `dnsx.md` DNS 질의·역방향 조회
- `dns_troubleshooting.md` DNS 문제 진단
- `hosts.md` /etc/hosts 활용
- `Sublist3r.md` 서브도메인 수집기
- `tor.md` Tor 네트워크 관련

## network/

- `nmap.md` 포트 스캔 기본
- `rustscan.md` 빠른 포트 스캐너
- `masscan.md` 대량 대역 스캔
- `naabu.md` 포트 스캔 (Go)
- `arp_scan.md` ARP로 로컬 호스트 발견
- `netdiscover.md` 서브넷 호스트 탐지
- `netcat.md` TCP/UDP 접속·포트 확인
- `ping.md` 생존 확인
- `hostname.md` 호스트명 확인
- `iproute2.md` ip 명령 (라우팅·주소)
- `socket.md` 소켓 조작
- `tcpdump.md` 패킷 캡처

## web-surface/ — 웹 표면

- `ffuf.md` 디렉토리·파라미터·vhost 퍼징 (골든 예시 문서)
- `gobuster.md`·`feroxbuster.md`·`dirsearch.md` 디렉토리 브루트포스 대체재
- `httpx.md` 호스트 대량 생존 확인
- `whatweb.md` 기술 스택 식별
- `nikto.md`·`nuclei.md`(상위) 취약점 스캔
- `katana.md` 크롤링
- `arjun.md` 숨은 파라미터 발견
- `wfuzz.md`·`wafw00f.md`·`browsh.md` 퍼징·WAF 판별·텍스트 브라우저
- `http_status_codes.md` 상태 코드 정리
- `wpscan.md` WordPress 스캔

## secrets/ — 시크릿 스캔

- `gitleaks.md`·`trufflehog.md` 저장소·파일 시크릿 탐지

## wireshark/

- `pcap_pcapng.md` 캡처 파일 형식
- `wireshark_display_filter.md` 디스플레이 필터

## 루트 파일

- `nuclei.md` 템플릿 기반 취약점 스캔
