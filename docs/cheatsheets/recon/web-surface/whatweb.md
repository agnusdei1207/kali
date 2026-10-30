# whatweb

## 개요

`whatweb`은 HTTP 서버의 기술 스택(웹서버, 프레임워크, CMS, 운영체제)을 헤더·소스·디렉터리를 보고 추론하는 도구이다.
정찰 단계에서 "지금 뭘 다루고 있는지"를 빠르게 파악하는 첫 번째 도구이다.

## 설치

```bash
sudo apt update
sudo apt install whatweb -y
```

## 사용법

```bash
whatweb http://192.168.132.65:9998
whatweb https://target.example.com
```

## 자주 쓰는 옵션

| 옵션 | 설명 |
|------|------|
| `-v` | 더 자세한 추론 출력 |
| `-h` | 도움말 |

## 실전 예시

```bash
# 9998 포트의 IIS 서버 확인
whatweb http://192.168.132.65:9998

# 결과 예시
# http://192.168.132.65:9998 [200 OK] ASP.NET MVC5.2
# http://192.168.132.65:9998/interface/root [200 OK] HTML5
```

## 결과 해석

- `ASP.NET`, `PHP`, `Joomla` 등이 보이면 해당 애플리케이션의 취약점 공부가 가능해진다.
- CMS 여부가 보이면 CMS별 전용 스캐너/익스플로잇이 공개되어 있다는 뜻이다.
- 서브도메인/vhost가 보이면 01-curriculum의 단계 1(서브도메인)으로 진입한다.
