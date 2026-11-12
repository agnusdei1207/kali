# amass(OWASP)를 이용한 서브도메인 열거

- amass — 수십 개의 오픈 데이터 소스 조회에 DNS 브루트포스·인증서 수집을 더해 서브도메인을 그래프 DB에 축적하는 공격 표면 매핑 도구. kali deb은 5.x(OAM 기반 재작성판)다.
- 단발 도구보다 오래 걸리는 대신 결과가 크다. 같은 도메인을 반복 스캔하며 신규 서브도메인 변화를 추적(track)할 때, 최대한 많은 소스를 붙여 자산 목록을 완성할 때.
- kali: sudo apt install amass (5.1.x). v5 하위명령은 enum·subs·track·viz·assoc·engine뿐이며 v4의 intel은 제거됐다. 구 튜토리얼의 amass intel ...은 v4 문법이라 v5에서 동작하지 않는다.

## 하위명령 구조

```bash
amass enum -d example.com    # 열거 실행 (패시브가 기본)
amass subs -d example.com    # 그래프 DB에 쌓인 결과 조회
amass track -d example.com   # 실행 간 신규·사라진 서브도메인 비교
amass viz -d example.com     # 결과 그래프 시각화
```

## 열거 (enum)

```bash
amass enum -d example.com -silent
amass enum -d example.com -active -silent -oA example_com
amass enum -d example.com -brute -w wordlist.txt -max-depth 2 -silent
```

- enum은 내부에서 수집 엔진을 자동으로 기동한다(기본 http://127.0.0.1:4000). 첫 실행이 오래 걸리는 건 엔진 기동과 소스 조회 대기 때문이다.

## 주요 옵션 (enum)

- `-d example.com`: 대상 도메인. 콤마 구분 다중 지정 가능, -df로 파일 지정.
- `-active`: 존 전이 시도와 인증서 기반 이름 수집 등 능동 기법 추가. 기본은 패시브 전용이며 -passive는 "패시브가 기본값"이라는 안내만 남은 deprecated 플래그다.
- `-brute`: 소스 조회 후 DNS 브루트포스 실행. -w로 워드리스트, -norecursive로 재귀 브루트포스 중단.
- `-oA prefix`: 텍스트·JSON 등 모든 출력 파일에 붙는 공통 경로 접두어.
- `-silent`: 실행 중 상태 출력을 끄고 결과만 남긴다.
- `-timeout 30`: 진행이 없는 시간이 이 분(기본 30)을 넘으면 종료한다.

## 결과 조회와 추적 (subs, track)

```bash
amass subs -d example.com -show -ip
amass subs -d example.com -names -silent > subs.txt
amass track -d example.com -since 2026-01-01
```

- `-show`: 열거 인덱스와 지정 도메인의 결과 출력(subs). -ip, -ipv6로 주소도 함께 표시.
- `-names`: 발견된 이름만 출력(subs). 파이프 연계에 쓴다.
- `-since 2026-01-01`: 이 시각 이후 발견분만 표시(track). -dir로 그래프 DB 위치 지정.

## 팁과 트러블슈팅

- -active는 대상 인프라에 실제 요청(존 전이 AXFR 등)을 보낸다. 굳이 필요 없으면 기본 패시브로 충분하다.
- 열거 결과는 DB에 누적된다. 같은 도메인을 주기적으로 enum 후 track으로 돌리면 신규 자산만 걸러낼 수 있다.
- -brute는 워드리스트 크기만큼 DNS 질의를 낸다. 대상 DNS 서버가 약하면 -max-depth를 1~2로 제한한다.
- Windows는 GitHub releases의 amass_windows_amd64.tar.gz를 사용한다. kali deb과 동일한 v5 문법이다.
