# listener setup

페이로드를 실행하기 전에 리스너가 먼저 떠 있어야 한다.

## 기본 리스너

```bash
rlwrap nc -lvnp 4444
```

```text
-l listen  -v 상세 출력  -n DNS 역조회 생략  -p 포트
rlwrap     방향키·히스토리 지원. PowerShell 셸을 받을 때 특히 유용
```

- rlwrap 설치·설정 → [../../common/lab-setup/rlwrap.md](../../common/lab-setup/rlwrap.md)

## 내 IP 확인 (LHOST)

```bash
ip a show tun0        # VPN 환경 (HTB/OSCP)
```

## 포트 선택

- 4444는 outbound 필터에 걸리기 쉽다. 실패하면 443, 80, 8080 순으로 바꾼다.
- 타깃 아웃바운드가 80/443만 허용이면 리스너도 그 포트로 띄운다.

## 연결 테스트 (타깃에서)

```bash
ping -c 2 10.10.10.10         # ICMP 허용 여부
nc -zv 10.10.10.10 4444       # TCP 도달 여부 (-z 연결만)
```

- ping은 되고 `nc -zv`는 실패 → 해당 포트 막힘. 포트를 바꿔 재시도.
- ping도 실패 → TCP·ICMP 전부 필터 환경 → [icmp_reverse_shell.md](./icmp_reverse_shell.md)

## 연결이 안 될 때 체크

- 리스너 떠 있는지: `ss -tlnp | grep 4444`
- 페이로드의 LHOST/LPORT 오타
- 공격자 방화벽: `sudo ufw status`
