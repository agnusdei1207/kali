# nuclei를 이용한 템플릿 기반 취약점 스캔

- nuclei — YAML 템플릿 하나하나가 취약점·노출 정보·오구성을 검사하는 스캐너. 커뮤니티 템플릿(nuclei-templates) 수천 개로 CVE, 노출된 패널, 기본 화면 등을 검증한다.
- URL·호스트 목록이 정리된 상태에서 실제 취약점을 걸러낼 때. 특정 심각도(severity) 이상만 골라 빠르게 돌릴 때. katana·httpx-toolkit 파이프라인의 마지막 단계.
- nuclei v3.11.1 기준. kali 템플릿 디렉터리는 /usr/share/nuclei-templates, Windows는 workspace\recon\nuclei-templates-main에 풀어둔 템플릿을 -t로 지정한다. 템플릿 최신화(nuclei -update-templates)는 인터넷이 필요하고, 오프라인이면 로컬 템플릿을 그대로 쓴다.

## 기본 사용법

```bash
nuclei -u https://example.com -t /usr/share/nuclei-templates/http/cves/ -severity high,critical -silent
nuclei -l urls.txt -severity critical -rl 100 -o findings.txt
```

## 주요 옵션

- `-u`: 단일 대상. -l로 URL 목록 파일 입력.
- `-t`: 템플릿 파일·디렉터리. 디렉터리를 주면 그 아래 전체가 실행된다.
- `-severity critical,high`: 심각도 필터. 쉼표로 조합.
- `-rl 100`: 초당 최대 요청 수(rate limit). 대상이 약하면 30~50으로 낮춘다.
- `-silent`: 결과 라인만 출력. 파이프·파일 저장에 필수.
- `-o findings.txt`: 결과 저장. -json으로 구조화 저장도 가능.
- `-tags tech,wordpress`: 템플릿 태그 필터. -t 대신 태그로 고르는 방식.
- `-exclude-tags fuzz`: 특정 태그 제외. 부하가 큰 fuzz 템플릿을 빼고 돌릴 때.

## 템플릿 위치

```bash
# kali (패키지 또는 수동 설치)
nuclei -u https://example.com -t /usr/share/nuclei-templates/

# Windows 포터블 (workspace\recon\nuclei-templates-main에 압축 해제해둔 경우)
nuclei.exe -l urls.txt -t workspace\recon\nuclei-templates-main ```

- 템플릿 업데이트: nuclei -update-templates (인터넷 필요). 오프라인 환경에서는 로컬에 있는 템플릿 그대로 사용한다.

## 파이프라인 연계

```bash
# 서브도메인 -> DNS -> 프로브 -> 취약점 스캔
subfinder -d example.com -all -silent | dnsx -silent | httpx-toolkit -silent | nuclei -severity high,critical -rl 50 -silent

# katana 엔드포인트 -> CVE 템플릿
katana -u https://example.com -d 3 -silent | nuclei -t /usr/share/nuclei-templates/http/cves/ -silent
```

## 팁과 트러블슈팅

- 전체 템플릿 디렉터리(-t /usr/share/nuclei-templates/)는 오래 걸리고 부하가 크다. -severity와 -tags로 좁혀서 돌린다.
- false positive가 나온다. 다수 템플릿이 응답 패턴 기반이라, 잡힌 결과는 직접 재확인 후 보고에 넣는다.
- 인터넷이 막힌 환경에서 -update-templates가 실패해도 스캔 자체는 로컬 템플릿으로 동작한다. 템플릿 디렉터리만 -t로 정확히 지정하면 된다.
