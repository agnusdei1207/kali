# curl 프록시·TLS

```bash
curl -x http://127.0.0.1:8080 http://target.com            # HTTP 프록시 (Burp 8080, mitmproxy 80)
curl -x http://192.168.199.189:3128 http://127.0.0.1:8080  # 원격 프록시(Squid)를 경유해 그 쪽에서만 열린 포트로 접근
curl --socks5 127.0.0.1:9050 http://target.com             # SOCKS5 프록시 (Tor)
curl -k https://target.com                                 # TLS 인증서 검증 무시 (자체 서명 인증서)
```

- `-x` 앞이 프록시 주소, 뒤가 최종 목적지다
- 프록시가 Location 헤더를 조작하는 등 응답을 가공해야 할 때는 mitmproxy 스크립트를 `-x`와 조합한다 (pivoting/mitmproxy 참고)
