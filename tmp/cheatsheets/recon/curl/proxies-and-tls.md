# curl 프록시·TLS 옵션

- curl의 프록시 연결(-x, --socks5)과 TLS 인증서 검증 생략(-k) 옵션 정리. Burp·mitmproxy 같은 로컬 인터셉트 프록시, Squid 같은 원격 포워드 프록시, Tor SOCKS5까지 한 줄 옵션으로 붙인다.
- 요청을 Burp·mitmproxy로 경유시켜 요청·응답을 들여다보고 싶을 때, 피벗 머신(Squid) 뒤에서만 열린 포트로 우회 접근해야 할 때, 자체 서명 인증서 서비스에 HTTPS 테스트를 할 때.
- 프록시 주소:포트에 접근 가능해야 하고, `-x` 앞이 프록시, 뒤가 최종 목적지라는 순서를 정확히 지켜야 한다. 자체 서명 인증서 대상에는 -k가 필요하다.

## 프록시 지정

```bash
# HTTP 프록시 (Burp Suite 8080, mitmproxy 8080 등)
curl -x http://127.0.0.1:8080 http://target.com

# 원격 프록시(Squid 3128)를 경유해 그 쪽 네트워크에서만 열린 포트로 접근
curl -x http://192.168.199.189:3128 http://127.0.0.1:8080

# SOCKS5 프록시 (Tor 9050)
curl --socks5 127.0.0.1:9050 http://target.com
# DNS 조회까지 프록시로 돌리려면 --socks5-hostname
curl --socks5-hostname 127.0.0.1:9050 http://target.com
```

- `-x` 뒤 형식은 `[프로토콜://]주소:포트`. 목적지 URL은 옵션 밖 마지막 인자다.
- 원격 프록시 경유 예: 공격 머신에서 직접 닿지 않는 내부 서비스(127.0.0.1:8080)를 Squid가 있는 피벗 머신 관점에서 조회한다.
- `--socks5`와 `--socks5-hostname`의 차이는 DNS 해석 위치다. 도메인 기반 대상은 hostname 쪽이 안전하다.

## TLS 인증서 검증 생략

```bash
# 자체 서명 인증서 / CN 불일치를 무시
curl -k https://10.10.10.10/
curl --insecure https://10.10.10.10:8443/
```

- `-k`/`--insecure`는 검증만 건너뛴다. 암호화는 계속된다.
- 실서버 인증서를 확인해야 할 때는 반대로 `-v`로 체인을 보거나 openssl s_client을 쓴다(services/openssl 참고).

## 조합 — 프록시 + HTTPS + 헤더

```bash
# Burp로 HTTPS 요청 경유시키기 (TLS 검증 생략 필요)
curl -x http://127.0.0.1:8080 -k https://target.com/

# Squid 프록시 경유 + 자체 서명 HTTPS
curl -x http://192.168.199.189:3128 -k https://127.0.0.1:8443/

# User-Agent 위장을 프록시와 함께
curl -x http://127.0.0.1:8080 -k -A "Mozilla/5.0" https://target.com/
```

## 응답 확인 팁

```bash
# 프록시가 붙었는지 -v로 CONNECT 터널 확인
curl -x http://127.0.0.1:8080 -k -v https://target.com/ -o /dev/null
# 프록시가 Location을 조작하는지 헤더만 확인
curl -x http://192.168.199.189:3128 -I http://127.0.0.1:8080/
```

- `-v` 출력에서 `CONNECT target.com:443 HTTP/1.1` 뒤에 `CONNECT established`가 나오면 터널이 정상이다.
- 프록시가 응답을 가공해야 하는 상황(헤더 조작·리다이렉트 변조)은 curl로 못 한다. mitmproxy 스크립트를 `-x` 대신 쓴다 → [pivoting/proxy/mitmproxy](../../pivoting/proxy/mitmproxy/mitmproxy_proxy.md)

## 트러블슈팅

- `Failed to connect to ... port 8080`이 나오면 프록시 자체가 안 떠 있거나 포트가 다른 것이다. Burp 기본은 127.0.0.1:8080.
- 프록시 경유 요청이 502/504를 돌려주면 프록시가 목적지에 접근하지 못하는 것이다. 프록시 머신 관점에서 목적지가 열려 있는지 확인한다.
- TLS 오류(`certificate verify failed`)가 나오면 -k를 붙인다. 반대로 -k를 붙였는데도 실패하면 TLS 버전·암호화 스위트 문제로 `--tlsv1.2` 같은 버전 강제를 시도한다.
- SOCKS5 프록시가 켜져 있는지는 `nc -vz 127.0.0.1 9050`으로 먼저 확인한다.
