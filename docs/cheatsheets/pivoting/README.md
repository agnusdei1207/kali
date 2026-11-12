# Pivoting 인덱스

침투한 내부 호스트를 넘어 더 깊은 네트워크로 확장하는 문서 폴더. 터널·프록시·포트포워드 도구별 문서로 구성된다.

## 루트 파일

- `chisel.md` TCP 터널·SOCKS5 프록시 리버스 연결
- `ligolo-ng.md` TUN 기반 터널 — 라우팅 추가만으로 내부망 접근
- `plink.exe` Windows 타깃에서 SSH 터널 열기 (plink)
- `socat.md` 포트 포워딩·리레이
- `sshuttle.md` SSH 기반 "가난한 VPN"

## proxy/ — 프록시

- `proxychains.md` 명령별 프록시 강제 (proxychains4)
- `burpsuite_proxy_setting.md` Burp 프록시 설정
- `mitmproxy_quick.md` mitmproxy 빠른 시작
- `mitmproxy/` mitmproxy 상세 — 기본 프록시, 원격 위치 경유, X-Forwarded-For 조작

## proxy-port-scan/ — 프록시 경유 포트 스캔

- `proxy_port_scan.sh` 프록시를 경유한 포트 스캔 스크립트
- `generate_all_port.sh` 전체 포트 스캔 명령 생성
- `generate_nmap_top_port.sh` nmap 상위 포트 스캔 명령 생성

## 선택 가이드

```text
Linux 타깃 + 안정적 내부망 접근   -> ligolo-ng (TUN 라우팅, 가장 편함)
리버스 연결이 필요한 환경         -> chisel
Windows 타깃만 있을 때            -> plink
한 포트만 포워딩                  -> socat
SSH 자격증명이 있을 때            -> sshuttle / ssh -L·-D
명령마다 프록시 붙이기            -> proxychains
```

## 관련 문서

- recon/curl/proxies-and-tls.md — curl을 프록시로 물리는 조합
- pivoting/proxy/mitmproxy/ — 응답 가공이 필요할 때
