# 웹 취약점

웹 애플리케이션 진단 문서 폴더. 수동 테스트 절차는 methodology/web-attacks, 도구 치트시트는 recon/web-surface(ffuf·gobuster 등)를 함께 본다.

## 진단 도구

- `sqlmap.md` SQL 인젝션 자동화 — `sqli/` 상세 참조
- `commix.md` 명령 삽입 자동화
- `jwt_tool.md` JWT 검증·변조·크래킹
- `burp/` Burp Suite 기본 사용법과 확장(Autorize·LoggerPlusPlus·turbo-intruder)

## 취약점별

- `sqli/` SQL 인젝션 상세 — sqlmap 옵션, UNION·ORDER BY·인증 우회, blind, 커스텀 주입
- `xss/` XSS 상세 — dalfox, blind XSS, 탈취·피싱·정찰 시나리오
- `ssrf/` SSRF 상세
- `file-inclusion.md` LFI·RFI 개요 — `file-inclusion/` 상세 (PHP 필터 체인, null byte, 스트림 래퍼)
- `file-upload.md` 업로드 취약점 — 확장자·MIME·경로 우회
- `idor.md` IDOR — 객체 참조 직접 접근
- `wordpress.md` WordPress 진단 (wpscan 연계)

## 지원 문서

- `cookie-decode.md` 쿠키 인코딩·디코딩
- `url-encoding.md` URL 인코딩 참조
- `flask.md` Flask 디버그·세션 관련 정리
