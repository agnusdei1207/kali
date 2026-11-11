# url encode decode

> 무엇: python3 urllib.parse의 quote(%XX 인코딩)/unquote(복원)로 URL 인코딩을 수행하는 함수 정리 문서다.
> 언제: 웹 요청 값·쿠키·리버스 셸 페이로드를 URL에 붙이기 전에 인코딩하고, %7B 같은 인코딩된 값(플래그 등)을 해석할 때 쓴다.
> 조건: python3만 있으면 되고 bash에서는 `python3 -c "import urllib.parse; print(urllib.parse.unquote('...'))"` 한 줄로 처리한다. quote는 기본적으로 `/`도 %2F로 바꾸므로 필요하면 safe 옵션을 확인한다.

## 개요

URL 인코딩/디코딩을 python3로 수행하는 안내 문서다. 웹 요청 값, 쿠키, 리버스 셸 payload를 조립할 때 필요하다.

## 함수 정리

```python
import urllib.parse

def url_encode(text: str) -> str:
    return urllib.parse.quote(text)          # 예약어를 %XX로 치환

def url_decode(encoded_text: str) -> str:
    return urllib.parse.unquote(encoded_text)  # %XX를 복원
```

## 사용 예시

```python
original = "<script>alert('XSS')</script>"
encoded = url_encode(original)
decoded = url_decode(encoded)

print("original:", original)
print("encoded:", encoded)
print("decoded:", decoded)
```

## bash에서 한 줄로

```bash
python3 -c "import urllib.parse; print(urllib.parse.unquote('THM%7B83789a69074f636f64a38879cfcabe8b62305ee6%7D'))"
python3 -c "import urllib.parse; print(urllib.parse.quote('THM{83789a69074f636f64a38879cfcabe8b62305ee6}'))"
```

## 실전 팁

- `quote`는 기본적으로 `/`를 `%2F`로 치환한다. `safe='/'`를 주면 이를 피할 수 있다.
- 요청값 조립 시 반드시 디코딩된 값을 서버가 다시 인코딩하는지 확인한다.
