gobuster dir -u http://example.com -w /path/to/wordlist.txt -x php,html,txt -t 50 -s 200,204,301,302,307,401,403 -H "Authorization: Bearer your_token_here" -o gobuster_results.txt -r -k -q

# 칼리리눅스 기준 일반적인 경로
/usr/share/seclists/Discovery/Web-Content/common.txt


-u URL : 탐색 대상 URL 지정
-w WORDLIST : 탐색할 단어 리스트 파일 지정
-x EXTENSIONS : 파일 확장자 추가 (예: php, html)
-t THREADS : 동시 실행 스레드 수 지정 (기본 10)
-s STATUSCODES : 특정 HTTP 상태코드만 결과로 표시
-H HEADER : HTTP 헤더 추가 (예: 인증 토큰)
-o OUTPUT : 결과를 파일로 저장
-r : 리다이렉션 자동 추적
-k : SSL 인증서 검증 무시

