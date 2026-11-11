# curl 프록시·TLS

- curl의 프록시 연결(-x, --socks5)과 TLS 인증서 검증 생략(-k) — Burp·mitmproxy 로컬 프록시, Squid 원격 프록시, Tor SOCKS5.
- 요청을 Burp·mitmproxy로 들여다보고 싶을 때, Squid 뒤에서만 열린 포트로 우회 접근해야 할 때.
- 프록시 주소:포트에 접근 가능해야 하고(-x 앞이 프록시, 뒤가 목적지), 자체 서명 인증서 대상에는 -k가 필요하다.

```bash
curl -x http://127.0.0.1:8080 http://target.com            # HTTP 프록시 (Burp 8080, mitmproxy 80)
curl -x http://192.168.199.189:3128 http://127.0.0.1:8080  # 원격 프록시(Squid)를 경유해 그 쪽에서만 열린 포트로 접근
curl --socks5 127.0.0.1:9050 http://target.com             # SOCKS5 프록시 (Tor)
curl -k https://target.com                                 # TLS 인증서 검증 무시 (자체 서명 인증서)
```

- `-x` 앞이 프록시 주소, 뒤가 최종 목적지다
- 프록시가 Location 헤더를 조작하는 등 응답을 가공해야 할 때는 mitmproxy 스크립트를 `-x`와 조합한다 (pivoting/mitmproxy 참고)
