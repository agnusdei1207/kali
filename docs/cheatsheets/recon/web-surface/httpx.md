# httpx-toolkit을 이용한 웹서버 프로브

- httpx-toolkit — URL·호스트 목록을 받아 살아있는 HTTP 서비스만 걸러내고, 제목·기술 스택·상태 코드·IP·CDN 여부를 한 줄씩 뽑아주는 프로브 도구. 이름은 httpx지만 바이너리는 httpx-toolkit이다.
- 서브도메인·포트 스캔 결과 중 웹으로 접근 가능한 자산만 걸러낼 때. 수백 개 호스트의 웹 지문을 한 줄씩 빠르게 수집할 때.
- httpx 1.12.0 기준. kali: sudo apt install httpx-toolkit, Windows는 workspace\recon\httpx\httpx.exe. stdin으로 목록을 받는 파이프라인형 도구이며 -l로 파일 입력도 지원한다.

## 기본 사용법

```bash
echo example.com | httpx-toolkit -silent
cat subs.txt | httpx-toolkit -title -tech-detect -status-code
httpx-toolkit -l hosts.txt -ip -cdn -o live.txt
```

- 주어진 이름에 기본으로 http/https를 모두 시도하고 응답이 오면 살아있는 것으로 판정한다.

## 주요 옵션

- `-title`: 페이지 타이틀 출력.
- `-tech-detect`: Wappalyzer 기반 기술 스택(Nginx, WordPress 등) 탐지.
- `-status-code`: 상태 코드 표시.
- `-ip`: 해석된 IP 표시.
- `-cdn`: CDN/WAF(Cloudflare 등) 경유 여부 표시.
- `-ports 80,443,8080,8443`: 호스트만 주어졌을 때 이 포트들을 각각 프로브.
- `-silent`: 결과만 출력. 파이프 연계에 필수.
- `-c 50` (-threads): 동시 프로브 수.
- `-o live.txt`: 결과 저장. -json으로 구조화 저장도 가능.

## 표준 파이프라인

```bash
# 서브도메인 -> DNS 해석 -> 웹 프로브
subfinder -d example.com -all -silent | dnsx -silent | httpx-toolkit -title -tech-detect -status-code -ip -cdn

# naabu로 찾은 포트 중 웹만
naabu -host 10.10.10.1 -top-ports 100 -silent | httpx-toolkit -title -status-code
```

## 실전 예시

```bash
# 결과를 파일로 남기고 화면에도 보기
subfinder -d example.com -silent | httpx-toolkit -title -tech-detect -ip -cdn -o web_inventory.txt

# 특정 포트대만 빠르게
httpx-toolkit -l subs.txt -ports 80,443,8080,8443,8000 -silent -status-code
```

## 팁과 트러블슈팅

- CDN 플래그가 붙은 호스트는 원본 IP가 가려져 있다. -cdn 결과를 확인하고 나중에 WAF 영향을 고려한다.
- 응답이 없는(죽은) 호스트는 조용히 사라진다. 몇 개가 빠졌는지 알고 싶으면 -silent를 빼고 진행 로그를 본다.
- 403·401 응답도 살아있는 것으로 나온다. 접근 제어 여부는 상태 코드로 별도 판단해야 한다.
- Windows에서는 Get-Content subs.txt | httpx.exe -title 형태로 PowerShell 파이프를 쓴다.
