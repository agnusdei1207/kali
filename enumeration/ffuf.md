# ffuf를 통한 디렉토리 브루트포싱

sudo apt install fuff

# ffuf 사용 -> 대회용 -t 100 적절

ffuf -u http://10.10.178.114/FUZZ -w /usr/share/wordlists/dirb/common.txt -fs 74
ffuf -u http://10.10.178.114 -H "Host:FUZZ.10.10.178.114" -w /usr/share/seclists/Discovery/DNS/namelist.txt -fs 178 -t 100

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

# ffuf 도구 사용법 치트시트

## 기본 개념

ffuf(Fuzz Faster U Fool)는 OSCP에서 허용되는 웹 애플리케이션 퍼저 도구입니다. 디렉토리 탐색, 가상 호스트 발견, 파라미터 퍼징에 유용합니다.

## 기본 명령어 구조

```bash
ffuf -u http://대상URL/FUZZ -w 워드리스트경로 [옵션]
```

## 주요 옵션 설명

### `-H` 옵션 (HTTP 헤더 지정)

```bash
ffuf -u http://planning.htb -H "Host:FUZZ.planning.htb" -w /usr/share/seclists/Discovery/DNS/namelist.txt -fs 178 -t 50 -mc 200,302
```

- `-H "Host:FUZZ.planning.htb"`: HTTP 요청에 사용할 헤더를 지정합니다.

  - `Host:`: HTTP 헤더 이름입니다. 서버에 어떤 가상 호스트에 접근할지를 알려줍니다.
  - `FUZZ`: 워드리스트의 각 단어로 대체될 위치 표시자입니다.
  - `.planning.htb`: 도메인 접미사입니다.

  이 명령어는 서브도메인 열거(가상 호스트 디스커버리)에 사용됩니다. 각 요청마다 워드리스트의 단어가 `FUZZ` 위치에 삽입되어 해당 서브도메인이 존재하는지 확인합니다.

### 필터링 옵션

- `-fs 178`: 응답 크기(바이트)가 178인 결과를 필터링합니다. 이는 일반적으로 "찾을 수 없음" 페이지와 같은 특정 응답을 제외하는 데 유용합니다.
- `-mc 200, 302`: 200, 302 상태만 보고 싶은 경우

### 성능 옵션

- `-t 100`: 동시에 실행할 스레드 수를 100개로 설정합니다. 스레드 수가 많을수록 스캔 속도가 빨라지지만, 대상 서버에 부하를 줄 수 있습니다.

## 디렉토리 브루트포싱

```bash
ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt
```

- `-u http://target.com/FUZZ`: 대상 URL을 지정합니다. `FUZZ` 위치에 워드리스트의 단어가 삽입됩니다.
- `-w /usr/share/wordlists/dirb/common.txt`: 사용할 워드리스트 파일을 지정합니다.

## TOR를 통한 익명 스캔 (선택적)

```bash
torsocks ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt
```

- `torsocks`: TOR 네트워크를 통해 요청을 라우팅합니다. 이는 익명성을 제공하지만 속도가 느려질 수 있습니다.

## OSCP 시험에서 유용한 ffuf 사용 사례

### 1. 숨겨진 디렉토리/파일 탐색

```bash
ffuf -u http://target.ip/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .php,.txt,.html
```

- `-e .php,.txt,.html`: 지정된 확장자를 추가하여 검색합니다.

### 2. 특정 응답 코드만 표시

```bash
ffuf -u http://target.ip/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302
```

- `-mc 200,301,302`: 지정된 HTTP 상태 코드를 가진 응답만 표시합니다.

### 3. 파라미터 퍼징

```bash
ffuf -u http://target.ip/script.php?FUZZ=value -w /usr/share/wordlists/dirb/common.txt
```

### 4. POST 요청 퍼징

```bash
ffuf -X POST -u http://target.ip/login -d "username=admin&password=FUZZ" -w /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt


find / -name bypass\*
/usr/share/seclists/Web-Shells/WordPress/bypass-login.php

ffuf -w bypass.txt -X POST -u http://lookup.thm/login.php -d 'username=FUZZ&password=asdf' -H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" -fw 10

```

- `-X POST`: HTTP 메소드를 POST로 지정합니다.
- `-d "username=admin&password=FUZZ"`: POST 데이터를 지정합니다.

### 5. 결과 저장

```bash
ffuf -u http://target.ip/FUZZ -w /usr/share/wordlists/dirb/common.txt -o results.json -of json
```

- `-o results.json`: 결과를 저장할 파일을 지정합니다.
- `-of json`: 출력 형식을 JSON으로 지정합니다.

## 주의사항

1. 스레드 수(-t)는 대상 서버 환경에 따라 적절히 조절해야 합니다.
2. 너무 큰 워드리스트는 시간이 오래 걸릴 수 있으므로, 시험 환경에 맞게 최적화해야 합니다.
3. 필터링 옵션(-fs, -fc, -fl 등)을 사용하여 불필요한 결과를 제거하면 효율적입니다.
4. OSCP 시험에서는 대상 서버에 과도한 부하를 주는 공격적인 스캔은 피해야 합니다.

# OSCP용 FFUF 옵션 치트시트

## FFUF 기본 개요

FFUF(Fuzz Faster U Fool)는 OSCP에서 허용되는 웹 퍼징 도구로, 웹 애플리케이션의 숨겨진 디렉토리, 파일, 파라미터 등을 찾는 데 사용됩니다.

## 주요 필터링 옵션

### `-fl [값]` - 라인 수 기준 필터링

```bash
ffuf -w 워드리스트.txt -u http://대상URL/FUZZ -fl 124
```

- **설명**: 응답에 포함된 줄(라인) 수가 정확히 124개인 결과를 제외합니다.
- **사용 예**: `-fl 124`는 124줄을 가진 응답은 출력하지 않습니다.
- **활용 상황**: 오류 페이지나 '찾을 수 없음' 페이지가 항상 동일한 줄 수를 가질 때 유용합니다.

### `-fs [값]` - 크기 기준 필터링

```bash
ffuf -w 워드리스트.txt -u http://대상URL/FUZZ -fs 4162
```

- **설명**: 응답 크기가 정확히 4162바이트인 결과를 제외합니다.
- **사용 예**: `-fs 4162`는 4162바이트 크기의 응답은 출력하지 않습니다.
- **활용 상황**: 기본 웹 페이지나 오류 페이지의 크기가 항상 동일할 때 이를 제외하는 데 사용합니다.

### `-fc [값]` - 상태 코드 기준 필터링

```bash
ffuf -w 워드리스트.txt -u http://대상URL/FUZZ -fc 404,403
```

- **설명**: 지정된 HTTP 상태 코드를 가진 응답을 제외합니다.
- **사용 예**: `-fc 404,403`은 404(찾을 수 없음)와 403(금지됨) 상태 코드를 가진 응답을 제외합니다.
- **활용 상황**: 일반적인 오류 응답을 필터링하여 실제 유용한 결과만 확인할 때 사용합니다.

### `-fw [값]` - 단어 수 기준 필터링

```bash
ffuf -w 워드리스트.txt -u http://대상URL/FUZZ -fw 42
```

- **설명**: 응답에 포함된 단어 수가 정확히 42개인 결과를 제외합니다.
- **사용 예**: `-fw 42`는 42개 단어를 포함한 응답은 출력하지 않습니다.
- **활용 상황**: 오류 페이지가 항상 동일한 단어 수를 가질 때 유용합니다.

## 매칭 옵션 (필터링의 반대)

### `-mc [값]` - 상태 코드 기준 매칭

```bash
ffuf -w 워드리스트.txt -u http://대상URL/FUZZ -mc 200,301,302
```

- **설명**: 지정된 HTTP 상태 코드를 가진 응답만 표시합니다.
- **사용 예**: `-mc 200,301,302`는 200(성공), 301(영구 이동), 302(임시 이동) 상태 코드를 가진 응답만 표시합니다.
- **활용 상황**: 성공적인 요청이나 리디렉션만 확인하고 싶을 때 사용합니다.

### `-ml [값]` - 라인 수 기준 매칭

```bash
ffuf -w 워드리스트.txt -u http://대상URL/FUZZ -ml 10
```

- **설명**: 응답에 포함된 줄 수가 정확히 10개인 결과만 표시합니다.
- **활용 상황**: 특정 형태의 응답만 확인하고 싶을 때 사용합니다.

### `-ms [값]` - 크기 기준 매칭

```bash
ffuf -w 워드리스트.txt -u http://대상URL/FUZZ -ms 1024
```

- **설명**: 응답 크기가 정확히 1024바이트인 결과만 표시합니다.
- **활용 상황**: 특정 크기의 응답만 확인하고 싶을 때 사용합니다.

### `-mw [값]` - 단어 수 기준 매칭

```bash
ffuf -w 워드리스트.txt -u http://대상URL/FUZZ -mw 100
```

- **설명**: 응답에 포함된 단어 수가 정확히 100개인 결과만 표시합니다.
- **활용 상황**: 특정 형태의 응답만 확인하고 싶을 때 사용합니다.

## 출력 옵션

### `-o [파일명]` - 결과 저장

```bash
ffuf -w 워드리스트.txt -u http://대상URL/FUZZ -o results.txt
```

- **설명**: 결과를 지정된 파일에 저장합니다.
- **사용 예**: `-o results.txt`는 결과를 results.txt 파일에 저장합니다.

### `-of [형식]` - 출력 형식

```bash
ffuf -w 워드리스트.txt -u http://대상URL/FUZZ -o results.json -of json
```

- **설명**: 출력 형식을 지정합니다 (json, ejson, html, md, csv, ecsv).
- **사용 예**: `-of json`은 JSON 형식으로 결과를 저장합니다.

## 성능 옵션

### `-t [값]` - 동시 처리 스레드 수

```bash
ffuf -w 워드리스트.txt -u http://대상URL/FUZZ -t 50
```

- **설명**: 동시에 처리할 스레드 수를 지정합니다.
- **사용 예**: `-t 50`은 50개의 스레드를 동시에 실행합니다.
- **주의**: OSCP 시험 환경에서는 대상 서버에 과부하를 주지 않도록 적절한 값(10-50)을 사용하는 것이 좋습니다.

### `-p [초]` - 요청 간 지연 시간

```bash
ffuf -w 워드리스트.txt -u http://대상URL/FUZZ -p 0.5
```

- **설명**: 요청 간 지연 시간을 초 단위로 설정합니다.
- **사용 예**: `-p 0.5`는 각 요청 사이에 0.5초 지연을 추가합니다.
- **활용 상황**: IDS/IPS 탐지를 회피하거나 서버 부하를 줄이기 위해 사용합니다.

## 기타 유용한 옵션

### `-e [확장자]` - 확장자 추가

```bash
ffuf -w 워드리스트.txt -u http://대상URL/FUZZ -e .php,.txt,.html
```

- **설명**: 워드리스트의 각 단어에 지정된 확장자를 추가하여 검색합니다.
- **사용 예**: `-e .php,.txt,.html`은 각 단어에 .php, .txt, .html 확장자를 붙여서 검색합니다.

### `-r` - 리디렉션 따라가기

```bash
ffuf -w 워드리스트.txt -u http://대상URL/FUZZ -r
```

- **설명**: HTTP 리디렉션을 따라갑니다.
- **활용 상황**: 30x 리디렉션이 사용되는 웹사이트에서 최종 대상을 확인할 때 사용합니다.

### `-b [쿠키]` - 쿠키 설정

```bash
ffuf -w 워드리스트.txt -u http://대상URL/FUZZ -b "session=1234abcd"
```

- **설명**: HTTP 요청에 쿠키를 추가합니다.
- **활용 상황**: 인증이 필요한 부분을 테스트할 때 사용합니다.

## OSCP 시험 최적화 명령어 예시

### 1. 디렉토리 브루트포싱 (기본)

```bash
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://대상IP/FUZZ -mc 200,301,302,403 -o directory_scan.txt
```

- **설명**: 기본 디렉토리 스캔을 수행하고, 유용한 상태 코드만 필터링하여 파일로 저장합니다.

### 2. 파일 확장자 브루트포싱

```bash
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://대상IP/FUZZ -e .php,.txt,.bak -mc 200 -o files_scan.txt
```

- **설명**: 파일 확장자를 추가하여 스캔하고, 200 응답만 저장합니다.

### 3. 가상 호스트 디스커버리 (서브도메인)

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://대상IP -H "Host: FUZZ.대상도메인" -fs 4162 -o vhosts.txt
```

- **설명**: 서브도메인을 탐색하고, 기본 페이지 크기를 필터링하여 파일로 저장합니다.

### 4. 파라미터 퍼징

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u "http://대상IP/index.php?FUZZ=test" -fl 42 -o params.txt
```

- **설명**: 가능한 GET 파라미터를 탐색하고, 특정 라인 수를 가진 응답을 필터링합니다.

### 5. 파일 인클루전 취약점 테스트

```bash
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -u "http://대상IP/page.php?file=FUZZ" -fl 124 -o lfi_results.txt
```

- **설명**: LFI 취약점을 테스트하고, 특정 라인 수를 가진 응답을 필터링합니다.

## 주의사항

1. OSCP 시험에서는 과도한 요청으로 서버에 부담을 주지 않도록 `-t` 값을 적절히 조정하세요.
2. 필터링 옵션(`-fl`, `-fc`, `-fs`, `-fw`)을 활용하여 불필요한 결과를 제거하는 것이 중요합니다.
3. 큰 워드리스트 사용 시 `-o` 옵션으로 결과를 저장하여 나중에 분석할 수 있도록 하세요.
4. 웹 서버 로그를 분석하여 404 오류와 다른 페이지의 패턴을 확인한 후 필터링하면 효과적입니다.
