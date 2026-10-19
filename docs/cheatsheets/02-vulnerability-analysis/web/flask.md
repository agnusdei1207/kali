# flask

## 개요

Flask 기반 애플리케이션에서 자주 보이는 패턴: `app.run()`, `app.config`, 라우트 함수의 `request` 사용.
웹 취약점 분석에서 "이 서비스는 Flask다"를 확인한 뒤, 플래그가 어디서 쓰이는지 추적하는 것이 목적이다.

## Flask 기초 문법

```python
from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def hello():
    return '<h1>Hello</h1>'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

## 요청 값 확인 (요청 조작)

```python
# GET 파라미터
{{ request.args.get('id') }}

# POST 데이터
{{ request.form.get('username') }}

# 헤더
{{ request.headers.get('User-Agent') }}
```

## 실전 예시: 파일 업로드 후 RFI

Flask 앱 특유의 취약점:

```python
# 취약한 예시 (실무에서는 절대 쓰지 않는다)
@app.route('/download')
def download():
    path = request.args.get('file')   # path traversal / RFI 위험
    return send_file(open(path, 'rb'))
```

## 방어

- 파일 경로는 화이트리스트로 검증한다.
- `send_file` 대신 매핑된 경로만 허용한다.
- 최신 Flask(2.x+)은 `app.run(host=..., port=...)` 인자 표준을 유지한다.

## 활용

- 업로드된 파일(`wp-content/uploads/`) 내에 webshell가 숨어 있는지 확인한다.
- 업로드된 파일의 파일시스템 권한을 확인해, 웹서버가 실행할 수 있는지 점검한다.
- 모든 시도는 합법적인 대상(본인 소유·허가받은 시스템)에서만 실행한다.
