# 금융권 모의해킹 폐쇄망 패키지 — 요구사항·상태·절차 문서

이 문서는 작업 컨텍스트의 단일 출처다. 어떤 AI든 이 문서만 읽고 이어서 진행할 수 있어야 한다.

## 제출 대상 (이것만 전송한다)

- 최종 전달물: C:\workspace\kali\tmp\preferred-vulnerability-tools.zip (단 하나)
- 내부 9 엔트리(preferred-vulnerability-tools/ 접두): README.md, TOOL_LIST.md, HASH_LIST.md,
  setup-windows.ps1, setup-kali.sh, unzip_6.0-31_amd64.deb,
  preferred-vulnerability-tools-windows.zip, preferred-vulnerability-tools-kali.zip, cheatsheets-final.zip
- 그 외 파일은 전부 소스·원본이며 전송 대상이 아니다:
  - lists/ — 플랫폼 ZIP 2개의 최신 빌드 산물 (최종 ZIP에 복사되어 들어간다)
  - final-package/ — deb·문서 원본 트리 (플랫폼 ZIP의 재빌드 소스, 삭제 금지)
  - cheatsheets/ — 치트시트 원본 트리 (cheatsheets-final.zip의 소스)
  - deliverables/ — 문서·셋업·빌드 스크립트 원본
  - cheatsheets-final.zip, tool_inventory.txt — 중간 산물
- 파일명이 비슷하니 주의: 최종 전달물은 tmp 바로 아래 zip 하나뿐이다.

## 전제 (모든 문서·스크립트에 공통)

금융권 모의해킹 현장은 인터넷이 안 되는 폐쇄망이다. 패키지를 들고 가는 이유다.
- 모든 문서(README, TOOL_LIST)와 셋업 스크립트에 "오프라인 전제"를 명시한다.
- 셋업 스크립트는 인터넷에 접속하지 않는다. wheel/deb/설치 파일을 전부 패키지 내부에서 해결한다.
- 인터넷이 필요한 예외(있다면)는 문서에 명시적으로 표기한다.

## 요구사항 (완료 상태 표기)

1. [완료] 최종 ZIP 하나로 통합: 툴 ZIP + 치트시트 ZIP + 사용법 md + 도구 목록 md + 셋업 스크립트 + 해시 문서.
2. [완료] ZIP 내부 도구 전부 리스트업한 TOOL_LIST.md 동봉 (§별 용도·버전·실측 검증 결과).
3. [완료] 도구 동작 실측 테스트 + 로그 확인:
   - Kali: Docker --network none 최소 kali-rolling 컨테이너에서
     unzip 부트스트랩 → 무결성 1,604줄 전부 일치 → deb 1,602개 설치 RC=0 → 도구 77/77 PASS.
   - Windows: SHA256 287개, 오프라인 wheel 및 DNSRecon 설치 성공. setup 자동 검증 PASS 32 / BLOCKED 7 / WARN 7 / FAIL 0, 종료 코드 0. WDAC 차단을 우회하지 않고 경고로 반환.
4. [완료] 셋업 스크립트 동봉 + 실제 실행 확인: Kali 전체 검증 통과. Windows는 무인 오프라인 설치 검증을 수행하고 호스트 차단·누락·시간 초과를 분리해 보고.
5. [완료] 모든 도구에 치트시트 md 존재 — 문서 402개, 품질 게이트 ALL CLEAN
   (볼드·표·금지 문구·얇은 본문 문서 0건. 폴더 인덱스 README는 파일 목록이 본문이라 얇은 문서 기준 제외).
6. [완료] 사용법 md(README.md)에 사용법·해제 후 폴더 구조·도구 위치 정리.
7. [완료] 최종 체크: 7z t 전 엔트리 통과 + HASH_LIST.md의 해시를 실측값과 전 항목 교차 대조 일치.
8. [규칙] 해시는 보고 텍스트에만 기록. 검증용 사이드카(.sha256 등)를 새로 만들지 않는다.
9. [예외] HASH_LIST.md는 제출 서류로 ZIP 내부 동봉. 도구별 용도·버전·SHA-256을 정리해 사전 검토 승인용으로 쓴다.
   8번의 사이드카 금지는 검증 부산물에 대한 것이고 HASH_LIST.md는 서류다.

## 최종 ZIP 해시 (보고용 — 문서에 못 넣음, 자기 참조)

- preferred-vulnerability-tools.zip
  9,395,791,935 바이트
  SHA256 889CF6E0042578A6B363C78BAAC5F69BCE2A6835451A21B614579AD9B273073F
- HASH_LIST.md 자체와 최종 ZIP 해시는 자기 참조라 문서에 못 넣는다. 전달 시 위 값을 별도로 알려준다.

## 재빌드 절차 (치트시트·문서·도구를 바꿨을 때)

순서를 지켜야 한다. 이전 단계의 산물이 다음 단계의 입력이다.

1. 치트시트 수정: cheatsheets/ 아래 md를 고친다.
2. 품질 게이트: C:\Users\kali\py313\python.exe tmp\deliverables\check-cheatsheets.py → ALL CLEAN 확인
   (Python은 C:\Users\kali\py313\python.exe. `python`은 Windows Store 스텁이라 안 됨).
3. 치트시트 ZIP: 7z로 빌드 — cd tmp 후
   "C:\Users\kali\AppData\Local\7-Zip\7z.exe" a cheatsheets-final.zip cheatsheets
   (-r을 붙이지 않는다. -r은 tmp 전체에서 cheatsheets라는 이름의 폴더를 전부 매칭해
   final-package\cheatsheets·kali-test\cheatsheets 같은 옛 사본을 함께 넣어버린 실측 사례가 있다.
   PS 5.1 ZipArchive 스트림 복사는 이 환경에서 실패해 0바이트 엔트리를 만든다. 7z 고정.
   7z t 출력에 "Size: 0"이 보이면 전 엔트리 0바이트 신호다.)
4. HASH_LIST 재생성: powershell -File tmp\deliverables\build-hash-list.ps1
   (TOOL_LIST·setup-kali.sh 같은 루트 문서를 고쳤다면 반드시 다시 돌린다 — 해시가 갱신된다.)
5. 최종 ZIP: powershell -File tmp\deliverables\build-final.ps1
   (스테이징 폴더 tmp\final-stage 만들어 7z 압축, 완료 후 자동 삭제.)
6. 검증: 7z t 최종 ZIP 전 엔트리 통과, 7z e로 내부 HASH_LIST·TOOL_LIST 꺼내 실측 해시와 대조.
7. 정리: 테스트용 해제 폴더는 삭제. final-package/와 lists/는 소스라 유지.

## Kali 실측 테스트 절차 (재실행할 때)

setup-kali.sh가 전 과정(무결성 → 설치 → 도구 점검)을 수행한다.

```
# 1. kali zip 해제 (Kali 도구 원본)
7z x lists\preferred-vulnerability-tools-kali.zip -o<작업폴더>

# 2. Docker: 네트워크 없는 kali-rolling 컨테이너로 설치·점검
#    (MSYS Git Bash 기준. 경로 변환 방지와 마운트에 주의)
MSYS_NO_PATHCONV=1 docker run --rm --network none \
  -v 'C:\workspace\kali\tmp\<작업폴더>:/test' -w //test \
  kalilinux/kali-rolling:latest bash -lc "/test/setup-kali.sh"
```

- apt --no-download는 넘긴 경로를 무시하고 캐시 디렉터리에서 벌겟만으로 deb을 찾는다.
  setup-kali.sh는 -o Dir::Cache::archives=<deb폴더>로 해결한다.
- Windows 빌드 산물 SHA256SUMS.txt는 BOM·CRLF·백슬래시를 정규화해야 sha256sum -c가 통과한다(스크립트에 구현됨).
- 도구 검증 교훈: 버전 출력 첫 줄이 빈 줄일 수 있다(grep -m1 .로 뽑기). 실행명 주의 —
  impacket 스크립트는 impacket-smbclient 형태, testssl은 testssl. gobuster는 version 서브커맨드 없음(--help).

## Windows 실측 테스트

- setup-windows.ps1을 관리자 PowerShell로 실행(무인 설치 + PATH 등록 + 실행 점검).
- 이 호스트 WDAC가 무서명 바이너리 일부(naabu, dalfox, kerbrute, hashcat 모듈 등)를 차단한다(CodeIntegrity 3077).
  패키지 결함이 아니라 이 호스트 정책 문제다. 현장(대상 환경)에서는 별개로 판단해야 한다.

## 문서 규칙 (치트시트 작성·수정 시)

- 볼드(**텍스트**) 금지, 표 금지(목록·코드 블록으로), 금지 문구(합법·교육 목적·법적 등 면책 문장) 금지.
- BOM·CRLF 금지. 각 폴더 README.md가 그 폴더의 인덱스(파일 목록)다. 인덱스에 개수·번호를 넣지 않는다.
- 최상위 폴더는 19개: recon, services, web, active-directory, windows, linux, pivoting, metasploit,
  shells, cracking, bruteforce, forensics, mobile, cve, python, scripts, common, util, methodology.
- 사이드카 부산물·로그 파일 금지. 검증은 실제 실행으로 한다.
