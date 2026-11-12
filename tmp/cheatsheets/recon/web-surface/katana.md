# katana를 이용한 크롤링

- katana — ProjectDiscovery의 빠른 웹 크롤러. 링크를 따라가며 엔드포인트를 수집하고, JavaScript 파싱, 알려진 파일(robots.txt/sitemap.xml) 탐색, 폼 요소 추출까지 지원한다.
- 웹 애플리케이션의 엔드포인트·파라미터 목록을 만들 때. nuclei 템플릿 스캔이나 ffuf 퍼징에 넣을 URL 풀을 채울 때.
- katana 1.8.0 기준. kali: sudo apt install katana, Windows는 workspace\recon\katana\katana.exe. 크롤링은 대상에 수많은 요청을 보내므로 -d로 깊이를 제한해야 한다.

## 기본 사용법

```bash
katana -u https://example.com -d 3
katana -u https://example.com -d 5 -jc -ef png,css,js -o endpoints.txt
cat urls.txt | katana -d 2 -silent
```

## 주요 옵션

- `-u`: 대상 URL. -list로 파일 입력도 가능.
- `-d 3`: 크롤링 깊이(기본 3). 늘리면 요청 수가 기하급수적으로 늘어난다.
- `-jc` (-js-crawl): JavaScript 파일도 파싱해 SPA·API 엔드포인트를 끌어낸다.
- `-ef png,css` (-extension-filter): 제외할 확장자. 정적 리소스를 빼면 결과가 깔끔해진다. 반대로 특정 확장자만 보려면 -em.
- `-kf all` (-known-files): robots.txt·sitemap.xml 같은 알려진 파일 크롤링. 값은 all, robotstxt, sitemapxml. 깊이 3 이상 필요.
- `-fx` (-form-extraction): JSONL 출력에 폼·input·textarea·select 요소를 추출한다.
- `-c 10` (-concurrency): 동시 fetcher 수(기본 10). -p는 입력 동시 처리 수.
- `-o endpoints.txt`: 결과 저장. -j로 JSONL 형식.
- `-silent`: 결과만 출력.

## nuclei와 연계

```bash
# 크롤링한 엔드포인트를 nuclei CVE 템플릿으로 스캔
katana -u https://example.com -d 3 -jc -silent | nuclei -silent -t /usr/share/nuclei-templates/http/cves/

# 크롤링 -> 프로브 -> 취약점 스캔 파이프라인
katana -u https://example.com -d 2 -kf all -silent | httpx-toolkit -silent | nuclei -severity high,critical -rl 50
```

## 실전 예시

```bash
# SPA 대상: JS 파싱 + 정적 리소스 제외 + 알려진 파일
katana -u https://example.com -d 4 -jc -ef png,jpg,css,woff2 -kf all -o endpoints.txt

# 폼 파라미터 조사
katana -u https://example.com -d 2 -fx -j -o forms.jsonl
```

## 팁과 트러블슈팅

- 깊이를 5 이상으로 올리면 요청이 폭증해 대상에 부하가 간다. 먼저 -d 2~3으로 스코프를 잡는다.
- SPA라도 JS 번들이 난독화되어 있으면 -jc로도 놓치는 엔드포인트가 있다. -jsl(jsluice 파싱, 메모리를 많이 씀)로 보완한다.
- 로그인이 필요한 구간은 인증 세션 없이는 크롤링이 안 된다. -H "Cookie: session=..."로 쿠키를 넘겨 범위를 넓힌다.
- Windows에서는 Get-Content urls.txt | katana.exe -d 2 형태로 PowerShell 파이프를 쓴다.
