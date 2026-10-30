# dnsrecon

## 개요

`dnsrecon`은 DNS 서버에 대해 표적 도메인의 정보를 열거하는 도구이다.
서브도메인 퍼징, zone transfer, PTR 조회를 한 번에 할 수 있다.

## 설치

```bash
sudo apt update
sudo apt install dnsrecon -y
```

## 사용법

```bash
dnsrecon -d <도메인>            # 대상 도메인 (예: smol.thm)
dnsrecon -t brt -d smol.thm   # 가장 광고 많은 열거 (best result type)
```

## 주요 옵션

| 옵션 | 설명 |
|------|------|
| `-d <domain>` | 대상 도메인 |
| `-t <type>` | 테스트 타입: `std`, `axfr`, `brt`, `srv`, `tld`, `ptr`, `cache`, `rpz` |
| `-D <dict>` | 브루트포스 딜리트 (예: SecLists의 `Discovery/DNS/subdomains-top1mil-5000.txt`) |
| `-n <nameserver>` | NS 서버 (예: `8.8.8.8`) |
| `-r <from-to>` | IP 대역 (예: `192.168.1.1-192.168.1.100`) |
| `-x <file.xml>` | XML 출력 |
| `-j <file.json>` | JSON 출력 |
| `-v` | 상세 출력 |
| `-f` | 실패한 쿼리(NXDOMAIN) 무시 |
| `--threads <N>` | 병렬 스레드 수 (최대 50) |

## 실전 예시

```bash
# 서브도메인 브루트포싱
dnsrecon -t brt -d smol.thm -D /usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt

# zone transfer 시도
dnsrecon -t axfr -d smol.thm

# PTR 기록 확인 (외부 IP를 알 때)
dnsrecon -t ptr -d smol.thm
```

## 결과 해석

- 결과에서 발견한 서브도메인은 이어서 whatweb/nikto/gobuster로 테스트한다.
- zone transfer가 났다면 공격 표면이 커진 것이므로, 이후 모든 vhost를 열거한다.
- DNS 관련 서비스(53)는 AD 도메인 정보를 담고 있을 수 있다. [enum4linux](../../active-directory/enum4linux.md)도 함께 확인한다.
