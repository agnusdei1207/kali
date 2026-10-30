# hosts

## 개요

`hosts`는 두 가지를 다룬다: 시스템의 호스트-IP 매핑 파일(`/etc/hosts`)과, 이름 조회를 확인하는 도구(`getent hosts`).

## /etc/hosts 파일

```bash
# 현재 설정 확인
cat /etc/hosts

# 특정 도메인이 어떤 IP에 매핑되어 있는지 확인
grep smol.thm /etc/hosts
```

형식:

```text
127.0.0.1   localhost
10.10.10.10 smol.thm
```

- 도메인을 직접 IP에 매핑해 DNS 없이 접속할 수 있다.
- 랩 환경(HTB/THM VPN 등)에서 도메인 기반 취약점을 테스트할 때 추가한다.

## getent hosts

```bash
# 도메인 → IP 조회 (DNS + /etc/hosts 모두 참조)
getent hosts smol.thm

# 특정 이름 서버로만 확인 (선택)
nslookup smol.thm 8.8.8.8

echo "192.168.236.180 monster.pg" >> /etc/hosts
```

- `nslookup`은 DNS 서버만 참조한다. `/etc/hosts`의 수동 매핑은 보이지 않을 수 있다.
- 둘의 결과가 다르면, 우선순위를 확인해 둔다(OSCP 웹 단계에서 vhost 테스트에 필요).

## 연관 치트시트

- 호스트명 확인: [hostname.md](../network/hostname.md)
