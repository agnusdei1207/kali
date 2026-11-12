# ssh-audit SSH 설정 감사

- ssh-audit — SSH 서버·클라이언트 설정을 감사해 배너, 키 교체(kex), 호스트 키, 암호(cipher), MAC 목록을 [info]/[warn]/[fail] 등급으로 판정해주는 Python 도구.
- 22 포트 발견 직후 SSH 하드닝 수준을 파악할 때, 배너로 OpenSSH 버전을 추정해 CVE와 매칭할 때, 침투 테스트 결과에 하드닝 권고 리포트를 붙일 때.
- Python 필요. Kali는 apt install ssh-audit, pip은 pip install ssh-audit 또는 GitHub clone.

## 기본 명령어 구조

```bash
ssh-audit [옵션] HOST[:PORT]
```

## 기본 실행

```bash
ssh-audit 10.10.10.10
ssh-audit -p 2222 10.10.10.10
```

- 기본 포트는 22이다. 결과는 배너와 알고리즘 카테고리별 섹션으로 나뉜다.

## 출력 해석

```text
# general
(gen) banner: SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1
# key exchange algorithms
(kex) diffie-hellman-group14-sha1          -- [warn] using weak SHA-1 hash
# host-key algorithms
(key) ssh-rsa                              -- [fail] using weak SHA-1 signatures
# encryption algorithms (ciphers)
(enc) aes128-ctr                           -- [info] available since OpenSSH 3.7
# message authentication code algorithms
(mac) hmac-sha2-256                        -- [info] available since OpenSSH 5.9
```

- [info]: 정상. [warn]: 더 강한 알고리즘으로 교체 권장. [fail]: 즉시 제거 대상.
- 카테고리 접두어: (gen) 일반, (kex) 키 교체, (key) 호스트 키, (enc) 암호, (mac) MAC.
- fail 항목이 많으면 구형 OpenSSH일 가능성이 높고, banner로 버전을 추정해 CVE 매칭을 이어간다.

## 등급 필터 (-l)

```bash
ssh-audit -l info 10.10.10.10   # info 이상 전부 표시
ssh-audit -l fail 10.10.10.10   # fail만 표시
```

- -l info|warn|fail은 표시할 최소 등급이다. fail만 뽑아 최소 수정 목록을 빠르게 만들 때 쓴다.

## 정책 대조 (policy)

```bash
# 내장 정책 목록 (OpenSSH 버전별 harden/prod)
ssh-audit -L

# 정책과 대조 (일치해야 PASS)
ssh-audit -P policy_hardened.txt -p 22 10.10.10.10
```

- -P는 서버 설정이 정책과 전부 일치하는지 판정한다. 하드닝 전후 비교, 회귀 확인에 쓴다.
- -L로 내장 정책을 확인해 그대로 -P에 사용하고, 타깃 설정을 정책으로 추출하려면 -t를 쓴다.

## SSH 하드닝 체크 용도

```text
1. ssh-audit <host>로 fail 항목 추출
2. fail 알고리즘을 sshd_config의 KexAlgorithms / HostKeyAlgorithms /
   Ciphers / MACs에서 제거
3. ssh-audit 재실행으로 warn·fail 소멸 확인
4. -P 정책 대조로 최종 판정
```

## 실전 예시

```bash
# 배너만 빠르게 추출
ssh-audit -p 2222 10.10.10.10 | grep -i banner

# fail 항목만 저장
ssh-audit -l fail 10.10.10.10 > ssh_fail.txt
```

- -c는 클라이언트 모드다. 서버가 아니라 접속에 쓰는 클라이언트 설정(ssh-audit -c localhost)을 감사한다.

## 팁·트러블슈팅

- 알고리즘이 하나도 출력되지 않으면 접속 자체가 실패한 것이다. 포트·방화벽을 재확인한다.
- banner에 버전이 표시되지 않으면 SSH 소프트웨어를 숨긴 설정이다. 알고리즘 조합으로 계열만 추정할 수 있다.
- fail 항목 출력에는 대체 가능한 권장 알고리즘 힌트가 함께 나온다. 그대로 리포트에 옮겨 쓸 수 있다.
- 감사 결과는 시점 의존적이다. OpenSSH 업데이트 후 ssh-audit도 최신 버전으로 재실행한다.
