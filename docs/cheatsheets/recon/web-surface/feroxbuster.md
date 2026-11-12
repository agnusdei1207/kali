# feroxbuster를 이용한 재귀 콘텐츠 발견

- feroxbuster — Rust로 만든 웹 콘텐츠 브루트포서. 워드리스트를 대입해 숨은 디렉토리·파일을 찾으며, 발견된 디렉토리를 자동으로 다시 스캔하는 재귀가 기본 동작이다.
- ffuf·gobuster와 같은 자리다. 깊은 디렉토리 구조를 한 번에 끝까지 스캔하고 싶을 때, 403·429 같은 저품질 응답을 자동으로 거르고 싶을 때.
- kali: sudo apt install feroxbuster. Windows는 releases의 x86-windows-feroxbuster.exe.zip을 푼 뒤 workspace\recon\feroxbuster\feroxbuster.exe로 둔다. 워드리스트는 /usr/share/seclists/Discovery/Web-Content/common.txt 계열을 쓴다.

## 기본 사용법

```bash
feroxbuster -u http://10.10.10.1 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
feroxbuster -u http://10.10.10.1:8080 -w common.txt -x php,html,bak -t 50 -d 3
```

## 주요 옵션

- `-u`: 대상 URL. 포트가 80/443이 아니면 반드시 명시한다.
- `-w`: 워드리스트 경로.
- `-x php,html,bak`: 각 단어에 붙여볼 확장자. 대상 기술(PHP/ASP/JSP)에 맞춘다.
- `-t 50`: 스레드 수. 대상이 약하면 10~20으로 낮춘다.
- `-d 3`: 재귀 최대 깊이. 너무 깊으면 시간이 폭증한다.
- `-s 200,301,302,403`: 통과시킬 상태 코드. 나머지는 버린다.
- `-S 5000`: 응답 크기 필터(바이트). 커스텀 404 페이지를 거를 때 -N(라인)·-W(단어)·-X(정규식)도 함께 쓴다.
- `--auto-tune` / `--auto-bail`: 에러·403·429가 임계치를 넘으면 스캔 속도를 자동 조절(auto-tune)하거나 해당 디렉토리 스캔을 포기(auto-bail)한다.
- `--no-recursion`: 재귀 끄기. gobuster 스타일의 단일 레벨 스캔.
- `-o result.txt`: 결과 저장.

## gobuster·ffuf와 비교

- gobuster: 재귀 없음. 빠르고 가볍지만 하위 디렉토리를 직접 다시 돌려야 한다.
- ffuf: FUZZ 키워드로 헤더·바디·파라미터까지 퍼징 가능. 필터가 가장 정교하다.
- feroxbuster: 재귀가 기본이라 디렉토리 트리 전체를 한 번에 커버한다. 디렉토리 발견 목적이라면 보통 이게 가장 편하다.

## 실전 예시

```bash
# 커스텀 404가 있는 대상: 크기 필터 + 자동 속도 조절
feroxbuster -u https://example.com -w raft-medium-directories.txt -x php,txt -S 4242 -s 200,301,302,403 --auto-tune -k -o ferox.txt

# 단일 레벨만 빠르게
feroxbuster -u http://10.10.10.1 -w common.txt --no-recursion -t 30
```

## 팁과 트러블슈팅

- HTTPS 자체서명 인증서 대상엔 -k를 붙인다. 없으면 모든 요청이 실패한다.
- 재귀 때문에 결과가 예상보다 훨씬 많다. -d로 깊이를 제한하거나 --no-recursion으로 단계별로 나눠 돌린다.
- Windows의 x86(32bit) 빌드가 실행 시 DLL 오류를 내면 Visual C++ 재배포 패키지(VC_redist.x86.exe)를 설치하면 해결된다. x86_64 빌드는 해당이 없다.
