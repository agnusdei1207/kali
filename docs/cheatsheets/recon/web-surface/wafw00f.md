# wafw00f를 이용한 WAF 탐지

- wafw00f — 대상 웹서버에 특징적인 요청을 보내 응답 차이로 WAF(Web Application Firewall) 제품과 버전을 추정하는 탐지 도구. Cloudflare, AWS WAF, ModSecurity 등 수백 종의 서명을 내장한다.
- 스캔 전에 WAF가 앞에 있는지 확인해 후속 도구의 스레드·속도·페이로드 전략을 정할 때. 같은 대상을 여러 방식으로 재확인할 때.
- kali: sudo apt install wafw00f. 탐지 결과는 추정이므로 100% 확신은 아니다. 이 도구는 탐지만 하고, 우회 기법 자체는 별도 후속 조사다.

## 기본 사용법

```bash
wafw00f https://example.com
wafw00f -a https://example.com
wafw00f -a -v https://example.com
```

## 주요 옵션

- `-a`: 첫 매치에서 멈추지 않고 가능한 모든 WAF 서명을 검사한다. 기본은 첫 발견 시 중단.
- `-v`: 상세 출력. 어떤 테스트 요청을 보냈는지 보인다.
- `-i hosts.txt`: URL 목록 일괄 검사.
- `-o result.xml`: 결과 파일 저장.
- `--no-logo`: 배너 없이 결과만 출력.

## 결과 해석

- "is behind ... WAF": 해당 제품이 탐지됐다. 제품명과 함께 신뢰도가 출력된다.
- "No WAF detected by the default scanning mode": 기본 모드로는 못 찾았다. -a로 재시도하거나 정말 없는 것일 수 있다.
- "Generic Detection": 제품 특정은 안 됐지만 WAF 같은 차단 응답이 관찰됐다는 뜻. 커스텀 WAF·프록시일 가능성이 높다.

```bash
wafw00f -a https://example.com
# Cloudflare가 걸린 경우의 예시 출력
# [+] The site https://example.com is behind Cloudflare (Cloudflare Inc.) WAF.
```

## 후속 조사 방향

- WAF가 확인되면: 스캔 도구의 -t(스레드)를 낮추고, feroxbuster --auto-tune이나 Arjun --ratelimit처럼 속도 제어 옵션을 붙여 차단 임계를 건드리지 않는다.
- WAF가 없으면: nuclei·ffuf 등 공격적 스캔을 바로 돌려도 된다.
- 우회 시도(인코딩 변조, 헤더 조작 등)는 이 도구의 기능이 아니다. 탐지 결과를 바탕으로 별도로 조사한다.

## 팁과 트러블슈팅

- -a를 붙이면 요청 수가 늘어난다. 서명 하나만 확인하려면 기본 모드로 충분하다.
- Generic Detection만 나오면 실제 차단 페이지(403/406/429 본문)를 직접 열어 어떤 제품인지 흔적을 본다.
- CDN이 프록시 역할을 하면 원서버 앞의 제품이 잡힌다. httpx-toolkit -cdn 결과와 교차 확인하면 정확도가 올라간다.
