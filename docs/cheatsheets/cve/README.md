# CVE 치트시트

- 이 폴더 — 서비스 버전에서 해당 CVE를 찾고, 검증된 PoC를 선별해 적용하는 절차와 개별 CVE 문서를 모은다.
- nmap·배너·페이지 소스에서 버전이 나왔을 때 그 버전의 취약점과 PoC를 찾아야 할 때, 여러 PoC 중 무엇을 쓸지 골라야 할 때.
- Kali 기본 searchsploit(exploitdb 패키지) 필요. 최신 CVE는 `searchsploit -u`로 인덱스를 최신화해야 검색된다.

## 폴더 구성

- `searchsploit_exploitdb.md` — searchsploit(Exploit-DB 로컬 인덱스) 사용법과 검색 옵션
- `cve_2024_21413.md` — CVE-2024-21413(MonikerLink, Outlook RCE) 정리

## CVE 검색 표준 절차

```bash
# 1. 대상 서비스·버전 확인 (배너, nmap, 페이지 소스 등)
nmap -sV -p 80,445,3389 10.10.10.10
searchsploit --nmap nmap_output.xml     # nmap 결과에서 바로 검색

# 2. 제품·버전 키워드로 로컬 인덱스 검색
searchsploit "Apache 2.4.49"
searchsploit -j "Apache 2.4.49"         # EDB-ID 포함 JSON 결과

# 3. PoC를 로컬로 내려받아 검토
searchsploit -m 50383                    # EDB-ID 파일을 현재 디렉터리로 복사
searchsploit --www                       # Exploit-DB 웹 링크 출력
```

- 서비스 버전을 정확히 확정하는 게 첫 단계다. 버전이 다른 PoC는 실패하거나 대상을 망가뜨린다.
- 결과가 여러 개면 최근 날짜, 신뢰 등급(Verified/Alphanumeric), 대상 버전 일치 여부 순으로 선별한다.
- PoC는 실행 전에 소스를 읽어 무엇을 하는지 확인한다. 수정이 필요한 경우가 대부분이고 경로·페이로드를 대상에 맞게 고친다.

## MSF·외부 소스 연계

```bash
msfconsole -x "search cve:2024 type:exploit platform:windows"
```

- Exploit-DB에 없는 최신 CVE는 MSF 모듈 검색, GitHub PoC 검색, 공급사 advisories 순으로 확인한다.
- advisories에서 패치 버전 범위를 확인해 대상이 실제로 취약 범위에 드는지 재검증한다.

## 팁·트러블슈팅

1. searchsploit은 오프라인 인덱스다. `searchsploit -u`로 Exploit-DB를 최신화해야 신규 CVE가 검색된다.
2. CVE 번호로 직접 검색은 잘 안 걸린다. 제품명·버전·키워드(remote, rce, traversal) 조합이 잘 걸린다.
3. 패치된 환경에서 오래된 PoC는 불필요한 크래시만 유발하므로, 적용 전 대상 버전이 취약 범위에 드는지 advisories로 확인한다.
