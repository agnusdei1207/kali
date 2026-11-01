# curl 요청 기본과 출력 제어

## 기본 GET 요청

```bash
curl http://target.com                # GET 요청, 응답 본문을 터미널에 출력
curl -o page.html http://target.com   # 응답을 지정한 파일로 저장
curl -O http://target.com:8080/wordpress.old.zip   # URL의 파일명 그대로 저장 (wget이 없을 때 대용)
curl -s http://target.com             # 진행 표시·오류 메시지 숨김 (grep 등 다른 명령과 조합할 때)
curl -L http://target.com             # 리다이렉트(3xx) 따라가기
```

## 상태 확인용 옵션

```bash
curl -v http://target.com   # 요청·응답 전체(헤더, TLS 핸드셰이크) 표시
curl -i http://target.com   # 응답 헤더 + 본문
curl -I http://target.com   # 헤더만 요청 (HEAD 메소드)
curl -k https://target.com  # TLS 인증서 검증 무시 (자체 서명 인증서)
curl -f http://target.com || echo "페이지 없음"   # HTTP 오류(4xx·5xx) 시 본문 대신 실패 반환
```

- `-v`는 기본으로 켜고 시작한다고 생각한다. 요청이 예상과 다르게 갈 때는 -v부터 확인한다
- `-I`(HEAD)는 서버가 HEAD를 별도 처리하는 경우 GET 응답과 다를 수 있으니 `-i` 결과와 비교해서 본다
