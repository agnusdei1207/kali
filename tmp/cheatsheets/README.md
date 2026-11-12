# 치트시트

폐쇄망(오프라인) 금융권 모의진단용 도구·기법 치트시트 모음. 모든 도구는 최종 ZIP에 동봉된 오프라인 패키지로 설치되며, 인터넷 접속 없이 동작한다.

## 진단 흐름 (methodology/)

절차 중심 문서. 처음 왔다면 여기부터.

- `methodology/README.md` 전체 흐름 개요
- `methodology/enumeration/` 열거 — 절차, port-by-port 체크리스트
- `methodology/foothold/` 초기 접근 — 취약점 활용, default-creds
- `methodology/web-attacks/` 웹 취약점 수동 테스트 절차
- `methodology/post-exploitation/` 셸 안정화, 자격증명 수집
- `methodology/privilege-escalation/` Linux·Windows 권한 상승 절차
- `methodology/tools/` 단계별 도구 배치

## 단계별 도구 폴더

- `recon/` 정보 수집 — network(포트 스캔)·dns·web-surface(디렉토리 퍼징)·curl·secrets·wireshark
- `services/` 서비스별 점검 — ssh·tls·mqtt·database(MySQL·MSSQL·Oracle·Postgres·MongoDB·Redis·SQLite)·openssl
- `web/` 웹 취약점 — sqli·xss·ssrf·file-inclusion·burp·upload·idor·jwt·wordpress
- `active-directory/` AD 열거·공격 — enum·relay·coerce·AD CS·BloodHound·impacket
- `windows/` Windows 타깃 — cmd·powershell·privileges·tools·rdp·smb
- `linux/` Linux 타깃 — cli 명령, privesc(SUID·sudo·cron·GTFOBins)
- `pivoting/` 터널·프록시 — ligolo-ng·chisel·socat·sshuttle·proxychains
- `metasploit/` MSF 프레임워크 — 설치·payload·meterpreter
- `shells/` 리버스·바인드 셸, 업그레이드, 웹셸
- `cracking/` hashcat·john·hydra, 워드리스트
- `bruteforce/` cewl 등 사전 생성·프록시 경유 브루트포스
- `forensics/` 메모리·디스크·바이너리 분석 (volatility3·sleuthkit·binwalk·ghidra)
- `mobile/` 안드로이드 분석 (adb·apktool·jadx·mobsf)
- `cve/` 개별 CVE 정리, searchsploit 사용법
- `python/`·`scripts/` 자체 스크립트 — 브루트포스·포트 스캔 생성기
- `common/` 공통 참조 — crypto·encoding·markup·lab-setup·yescript
- `util/` 범용 유틸 — tmux·exiftool·clip

## 규칙

- 본문은 오프라인 동작을 전제로 쓴다. 인터넷 다운로드가 필요한 절차는 넣지 않는다.
- 도구 설치는 최종 ZIP의 setup-kali.sh·setup-windows.ps1이 담당한다.
- 각 폴더의 README.md가 그 폴더의 문서 인덱스다.
