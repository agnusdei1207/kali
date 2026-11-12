# rpcdump로 RPC 엔드포인트 열거

- rpcdump.py — impacket 스위트의 스크립트. 대상의 RPC Endpoint Mapper에 질의해 노출된 RPC 인터페이스(UUID·바인딩·프로토콜) 목록을 덤프한다.
- NTLM relay 대상 프로토콜(MS-EFSR, MS-SCMR, MS-DFSNM 등)이 살아 있는지 확인할 때, RPC over HTTP(593)나 SMB 파이프(445/139)로 서비스되는 RPC를 찾을 때.
- impacket 필요(Kali는 apt install python3-impacket, 또는 pip install impacket).

## 기본 명령어 구조

```bash
rpcdump.py [[domain/]username[:password]@]<target>
rpcdump.py -port 135 <target>    # 기본값. EP Mapper에 직접 접속
rpcdump.py -port 593 <target>    # RPC over HTTP
rpcdump.py -port 445 <target>    # SMB named pipe 경유(epmapper 파이프)
rpcdump.py -port 139 <target>    # 구형 SMB 경유
```

- 포트 플래그는 `-p`가 아니라 `-port`이며 선택지는 135, 139, 443, 445, 593으로 제한되고 기본값은 135다.
- 135와 593은 인증 없이 접근하므로 자격증명이 없어도 실행할 수 있다. 139/445 경유는 SMB 인증을 요구한다.

## 출력 해석

```text
Protocol: [MS-EFSR EfsrpcOpenEncryptedFileRaw]
Provider: N/A
UUID    : c681d488-d850-11d0-8c52-00c04fd90f7e v0.0
Bindings:
          ncacn_np:\\DC01[\PIPE\lsarpc]
          ncacn_ip_tcp:10.10.10.10[49666]
```

- Protocol: EP Mapper가 알려주는 인터페이스 이름. MS-EFSR, MS-SCMR(서비스 관리), MS-DFSNM 같은 이름이 보이면 NTLM relay 후보다.
- UUID: 인터페이스 식별자. relay 도구가 타깃으로 쓰는 잘 알려진 UUID 목록과 대조한다.
- Bindings: 접근 가능한 전송 경로. ncacn_ip_tcp는 동적 포트(49xxx), ncacn_np는 SMB 파이프다.

## 실전 예시

```bash
# 자격증명 없이 EP Mapper 조회
rpcdump.py 10.10.10.10

# SMB 인증 경유(자격증명 또는 해시)
rpcdump.py 'CORP/user:Passw0rd@10.10.10.10'
rpcdump.py -hashes aad3b435b51404ee:31d6cfe0d4166315 'administrator@10.10.10.10'

# RPC over HTTP 프록시 환경
rpcdump.py -port 593 10.10.10.10

# 인터페이스 이름만 빠르게 훑기
rpcdump.py 10.10.10.10 | grep -iE 'Protocol:|UUID'
```

- `-hashes LMHASH:NTHASH`로 NTLM 해시 인증도 가능하다.

## 팁·트러블슈팅

1. 2018년 3월 업데이트(KB4088772) 이후 RPC over TCP에 인증이 강제되어, 패치된 호스트에서는 인증 없는 덤프 결과가 크게 줄어든다. 결과가 비어 있어도 relay 자체가 불가능한 건 아니다.
2. 동적 포트 바인딩(49xxx)은 방화벽 정책에 따라 닫혀 있을 수 있고, 이 경우 ncacn_np(SMB 파이프) 바인딩 위주로 접근한다.
3. 출력이 수백 줄에 달하면 grep으로 Protocol·UUID 라인만 걸러 relay 후보(대표적으로 MS-EFSR, MS-SCMR)를 우선 추린다.
