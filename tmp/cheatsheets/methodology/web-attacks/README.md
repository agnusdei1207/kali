# 웹 공격 인덱스

웹 서비스 대상 공격 절차와 관련 치트시트 위치를 정리한 인덱스.

## 문서

- 이 폴더의 절차 문서는 README 하나다. 기법별 상세는 web/ 폴더가 담당한다.

## 공격 절차

1. 정보 수집 — 포트·CMS·기술 스택 파악 (recon/web-surface/, whatweb·wpscan)
2. 표면 탐색 — 디렉토리·파라미터·vhost 브루트포싱 (ffuf·gobuster·feroxbuster)
3. 취약점 확인 — sqli·xss·LFI·SSRF·IDOR 순서로 수동 테스트 + nuclei·nikto 자동 스캔
4. 공격 — 취약점별 상세 문서로 이동 (web/)
5. 결과 확인 — 셸 확보·데이터 접근을 입증하고 기록한다
6. 보고서 작성 — 판단 근거와 재현 절차를 남긴다

## web/ 폴더 지도

```text
web/file-inclusion.md + file-inclusion/   LFI·RFI (php filter, null byte, 실습)
web/file-upload.md                        업로드 우회·웹셸 심기
web/idor.md                               객체 참조 권한 검증 누락
web/ssrf.md + ssrf/                       서버 측 요청 위조
web/xss.md + xss/                         반사·저장·DOM (dalfox, blind xss)
web/sqli.md + sqli/                       SQL 인젝션 (sqlmap, union, blind)
web/wordpress.md                          wpscan 점검 절차
web/jwt_tool.md                           JWT 조작
web/commix.md                             명령 인젝션 자동화
web/burp/                                 Burp Suite·확장
web/cookie-decode.md·url-encoding.md      인코딩 유틸
web/flask.md                              Flask 디버그 콘솔 등
```

## 지원 문서

```text
리스너·셸 확보      shells/README.md
셸 안정화          methodology/post-exploitation/shell.md
웹셸               shells/web-shell/
recon              recon/README.md (ffuf·curl·whatweb)
```
