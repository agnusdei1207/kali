# rpcclient로 SAMR 도메인 열거

- rpcclient — Samba 스위트의 RPC 클라이언트. SMB를 통해 도메인 컨트롤러와 SAMR/LSA 대화를 맺어 사용자·그룹·패스워드 정책을 열거한다. enum4linux가 내부적으로 호출하는 하위 도구이기도 하다.
- 445 포트가 열려 있고 인증 정보(유효 계정 또는 익명 세션)를 확보한 도메인 환경에서 사용자 목록·RID·패스워드 정책을 뽑아낼 때. 익명 세션(null session) 허용 여부를 점검할 때.
- Kali 기본 포함(samba 패키지). 유효한 자격증명 또는 null session이 허용된 대상 필요.

## 접속 기본 구조

```bash
rpcclient -U 'user%Passw0rd' 192.168.1.10
rpcclient -U user 192.168.1.10                    # 패스워드 프롬프트로 입력
rpcclient -U 'CORP\user%Passw0rd' 192.168.1.10    # 도메인 포함 형식
```

- `-U`는 `user%password` 형식이며, `DOMAIN\user%password`처럼 도메인을 함께 줄 수 있다.

## 익명 세션(null session) 점검

```bash
rpcclient -U '' -N 192.168.1.10     # 빈 사용자명 + 패스워드 없음
rpcclient -U '%' 192.168.1.10       # 빈 패스워드
```

- 접속 후 `srvinfo`가 서버 정보를 출력하면 null session이 허용된 것이고, NT_STATUS_ACCESS_DENIED가 나오면 막힌 것이다.
- null session이 열려 있으면 enumdomusers, querydominfo 같은 읽기 계열 명령이 동작하는 경우가 많다.

## 접속 후 SAMR/LSA 명령

```text
rpcclient $> srvinfo                    # 서버 OS·역할 정보
rpcclient $> querydominfo               # 도메인 이름·계정 수·잠금 정책
rpcclient $> enumdomusers               # 사용자 목록 + RID
rpcclient $> queryuser 0x1f4            # RID 500(기본 Administrator) 상세 정보
rpcclient $> enumdomgroups              # 그룹 목록 + RID
rpcclient $> querygroupmem 0x200        # Domain Admins(RID 512) 멤버 확인
rpcclient $> querydispinfo              # 계정 설명 필드(패스워드 노출 빈도 높음)
rpcclient $> getdompwinfo               # 패스워드 최소 길이·복잡도 정책
rpcclient $> lookupnames administrator  # 계정명 -> RID 변환
```

- `queryuser 0x1f4`: 0x1f4는 10진수 500, 즉 기본 Administrator의 RID다. 출력의 logon_time, last_logon, logon_domain, profilepath, home_dir 필드가 후속 경로를 잡아준다.
- 다른 사용자는 enumdomusers에서 확인한 RID(0x3e9 형태의 16진수)를 그대로 queryuser에 넣는다.

## 실전 예시

```bash
# 자격증명 있을 때의 전체 열거 흐름
rpcclient -U 'CORP\user%Passw0rd' 10.10.10.10
rpcclient $> enumdomusers
rpcclient $> queryuser 0x1f4
rpcclient $> querydispinfo
rpcclient $> getdompwinfo
```

- enumdomusers 결과는 kerbrute userenum의 워드리스트, RID cycling 범위의 입력으로 그대로 쓴다.

## 팁·트러블슈팅

1. NT_STATUS_ACCESS_DENIED가 계속 나오면 null session이 막힌 것으로 유효 계정이 필요하다. enum4linux-ng의 -A 결과가 비어 있을 때 rpcclient로 직접 확인하면 원인(인증 문제인지 열거 차단인지)을 구분할 수 있다.
2. enumdomusers가 막혀도 querydispinfo나 srvinfo는 열려 있는 경우가 있어, 명령별로 하나씩 시도해본다.
3. 출력을 남기려면 `rpcclient ... > out.txt 2>&1`로 실행하고, 대화형 중에는 `exit`로 빠져나온다.
