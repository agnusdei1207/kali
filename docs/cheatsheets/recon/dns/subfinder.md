# subfinder를 이용한 패시브 서브도메인 열거

- subfinder — VirusTotal, SecurityTrails, Shodan 등 온라인 데이터 소스의 DNS 기록만 뒤져 서브도메인을 수집하는 패시브 열거 도구. 대상 인프라에 직접 패킷을 보내지 않는다.
- 서브도메인 수집의 첫 단계. 대상에 트래픽을 남기지 않고 빠르게 도메인 자산 목록을 뽑아 dnsx, httpx-toolkit 같은 후속 도구에 넘길 때.
- v2.17.0 기준. 키 없이도 동작하지만 API 키를 등록하면 결과가 몇 배로 늘어난다. 설정 파일은 ~/.config/subfinder/provider-config.yaml (Windows는 %USERPROFILE%\.config\subfinder\provider-config.yaml).

## 설치

```bash
sudo apt install subfinder
# 또는 최신 빌드
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

## 기본 사용법

```bash
subfinder -d example.com
subfinder -d example.com -silent
subfinder -d example.com -all -recursive -silent -o subs.txt
```

## 주요 옵션

- `-d example.com`: 대상 도메인. 콤마로 여러 개를 한 번에 지정할 수 있다.
- `-all`: 응답이 느리거나 조회 한도가 걸린 소스까지 전부 사용. 시간은 몇 배로 걸리지만 결과가 가장 많다.
- `-recursive`: 재귀를 지원하는 소스만 사용(subdomain.domain.tld 형태 질의). 하위 레벨까지 파고들 때 붙인다.
- `-silent`: 서브도메인만 한 줄씩 출력. 로고·진행 상태가 사라져 파이프 연계에 필수다.
- `-o subs.txt`: 결과를 파일로 저장. -oJ로 JSONL도 가능.
- `-pc provider-config.yaml`: provider 설정 파일 경로 지정. 기본값은 전제조건의 경로.
- `-ls`: 데이터 소스 목록과 등록 상태 확인.

## API 키 등록

```bash
subfinder -ls   # 첫 실행 시 설정 파일이 자동 생성된다
```

```yaml
# ~/.config/subfinder/provider-config.yaml — 키를 받은 소스만 채운다
virus_total:
  - your_vt_api_key
security_trails:
  - your_st_api_key
github:
  - your_github_token
```

키를 등록하면 별도 지정 없이 자동으로 그 소스가 붙는다.

## 파이프라인 연계

```bash
# 서브도메인 -> A 레코드 해석
subfinder -d example.com -silent | dnsx -silent -a -resp

# 서브도메인 -> 살아있는 웹서버 프로브
subfinder -d example.com -all -silent | dnsx -silent | httpx-toolkit -title -tech-detect -status-code
```

## 팁과 트러블슈팅

- -all은 소스별 요청 한도(429)에 걸리며 오래 걸린다. 정식 자산 목록 작업일 때만 쓰고, 평소엔 기본 소스로 충분하다.
- 결과에 DNS로 안 풀리는 이름이 섞여 있다. 반드시 dnsx로 해석 검증을 거쳐 살아있는 호스트만 다음 단계로 넘긴다.
- Windows 포터블 빌드는 workspace\recon\subfinder\subfinder.exe 형태로 PATH에 넣어두면 위 명령이 그대로 동작한다.
