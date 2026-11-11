# 금융권 보안 모의해킹 패키지 - 최종 요구사항 문서

## 개요

본 패키지는 금융권 모의해킹 수행을 위한 도구·문서 모음입니다.
기존 `docs/cheatsheets/` 내용이 `cheatsheets/` 폴더로 이전되었습니다.

## 파일 구성

### 1. cheatsheets/ (355개 파일)

도구별·기법별 치트시트 모음입니다.

#### 주요 폴더

| 폴더 | 내용 |
|---|---|
| `recon/` | 네트워크 스캔, 웹 표면, DNS, Wireshark |
| `web/` | 웹 취약점 (SQLi, XSS, 업로드, SSRF, IDOR 등) |
| `active-directory/` | AD 열거/공격, SMB, BloodHound, CrackMapExec |
| `windows/` | cmd, PowerShell, 권한 상승, SMB, RDP |
| `linux/` | CLI, 권한 상승, GTFOBins, LinPEAS |
| `metasploit/` | MSF 사용법, msfvenom, meterpreter, scanner |
| `cracking/` | hashcat, john, hydra, wordlists, 암호 크래킹 |
| `shells/` | 리버스/바인드 쉘, 업그레이드, 웹셸 |
| `services/` | DB, FTP, SSH, TLS/SSL, OpenSSL |
| `pivoting/` | 프록시, 터널링, 포트 스캔 |
| `bruteforce/` | 로그인/폼 브루트포스 |
| `forensics/` | volatility3, rizin |
| `metasploit/` | MSF 설정, exploit, meterpreter |
| `shells/` | 리버스 쉘, 업그레이드, 웹셸 |

#### 본 폴더 (최상위)

- `README.md` - 전체 개요

### 2. methodology/ (13개 파일)

침투 테스트 절차를 정리한 방법론 문서입니다.

| 폴더 | 내용 |
|---|---|
| `README.md` | 침투 테스트 전체 흐름 |
| `enumeration/` | 열거 절차, 포트별 확인 |
| `foothold/` | 초기 접근, 기본 자격증명 |
| `post-exploitation/` | 침투 후, 셸 안정화, 자격증명 수집 |
| `privilege-escalation/` | Linux/Windows 권한 상승 |
| `tools/` | 도구 목록 |
| `web-attacks/` | 웹 공격 절차 |

## 도구별 치트시트

각 도구별 사용법·옵션·예시가 포함되어 있습니다.

| 도구 | 폴더 |
|---|---|
| nmap | `recon/network/` |
| rustscan | `recon/network/` |
| masscan | `recon/network/` |
| subfinder | `recon/dns/` |
| ffuf | `recon/web-surface/` |
| gobuster | `recon/web-surface/` |
| dirsearch | `recon/web-surface/` |
| nuclei | `recon/` |
| dalfox | `recon/` |
| wafw00f | `recon/` |
| sqlmap | `web/sqli/` |
| bloodhound | `active-directory/` |
| crackmapexec | `active-directory/` |
| impacket | `active-directory/` |
| kerbrute | `active-directory/` |
| metasploit | `metasploit/` |
| winPEAS | `windows/privileges/` |
| linPEAS | `linux/privesc/` |
| hashcat | `cracking/hashcat/` |
| john | `cracking/john/` |
| hydra | `cracking/hydra/` |

## 설치 및 활용 안내

### 도구 실행 방법

1. 도구 설치
   ```bash
   # Kali: apt install <package>
   # Windows: 다운로드 후 설치
   ```

2. 경로 추가
   ```bash
   # PowerShell
   $env:PATH += ";C:\tools"

   # CMD
   set PATH=%PATH%;C:	ools
   ```

### 실행 예시

```bash
# 기본 포트 스캔
nmap -sS -sV -T4 -p 1-65535 target

# 웹 디렉터리 열거
gobuster dir -u https://target -w /usr/share/wordlists/dirb/common.txt

# SQL 인젝션 점검
sqlmap -u "http://target/search" --dbs
```

## 문서 참조

- 원본: `docs/cheatsheets/`
- 본 폴더: `cheatsheets/`
- 메타스플로잇 문서: `metasploit/`
