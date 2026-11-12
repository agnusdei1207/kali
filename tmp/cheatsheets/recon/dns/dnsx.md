# dnsx를 이용한 DNS 질의와 해석

- dnsx — A/AAAA/CNAME/MX/NS/TXT 레코드 질의, 리버스 DNS, 서브도메인 브루트포스를 처리하는 빠른 DNS 툴킷. stdin으로 도메인 목록을 받아 한꺼번에 해석한다.
- subfinder·amass 결과에서 실제로 풀리는(살아있는) 서브도메인만 걸러낼 때, 특정 레코드 유형(TXT, MX)이나 리버스 DNS를 대량 조회할 때.
- v1.3.1 기준. kali: sudo apt install dnsx, Windows는 workspace\recon\dnsx\dnsx.exe 형태로 PATH 등록. 질의에는 UDP 53이 뚫려 있어야 하고 회선 리졸버가 막혀 있으면 -r로 다른 리졸버를 지정한다.

## 기본 사용법

```bash
echo example.com | dnsx -silent
echo example.com | dnsx -a -resp
cat domains.txt | dnsx -silent -a -o resolved.txt
```

- `-silent`가 없으면 로고와 진행 상태가 섞여 파이프로 넘길 수 없다.

## 레코드 유형별 질의

```bash
echo example.com | dnsx -a -resp        # A 레코드
echo example.com | dnsx -aaaa -resp     # AAAA (IPv6)
echo example.com | dnsx -cname -resp    # CNAME
echo example.com | dnsx -mx -resp       # MX
echo example.com | dnsx -ns -resp       # NS
echo example.com | dnsx -txt -resp      # TXT (SPF, 도메인 검증 토큰 등)
```

## 주요 옵션

- `-a / -aaaa / -cname / -mx / -ns / -txt`: 조회할 레코드 유형 지정. 여러 개를 함께 쓸 수 있다.
- `-resp`: 응답 본문(IP, 레코드 값)까지 출력. 없으면 도메인 이름만 나온다.
- `-r resolvers.txt`: 사용할 리졸버 지정. 파일은 한 줄당 IP 하나. 기본은 시스템 리졸버.
- `-w wordlist.txt`: 서브도메인 브루트포스 모드. 지정한 단어를 앞에 붙여 질의한다.
- `-ptr`: 리버스 DNS(PTR) 조회. IP 목록을 stdin으로 넣는다.
- `-o resolved.txt`: 결과 파일 저장.

## subfinder·amass와의 연계

```bash
subfinder -d example.com -all -silent | dnsx -silent -a -resp
amass subs -d example.com -names -silent | dnsx -a -resp -o live_subs.txt
```

- 와일드카드가 걸린 도메인은 없는 이름도 전부 같은 IP로 응답한다. -resp로 IP가 함께 찍히는지 보고, 의심되면 다른 리졸버로 재검증한다.

## 팁과 트러블슈팅

- 대량 조회 시 -r로 공용 리졸버를 섞으면 로컬 리졸버 한도에 안 걸린다. 단, 내부 DNS만 답하는 사내 대상에는 -r에 내부 리졸버를 명시해야 한다.
- 결과가 전부 NXDOMAIN이면 대상 도메인 이름이 틀렸거나 리졸버가 막힌 것이다. echo example.com | dnsx로 기본 동작부터 확인한다.
- Windows에서는 Get-Content domains.txt | dnsx.exe -silent -a 형태로 PowerShell 파이프를 쓴다.
