import urllib.parse

def url_encode(text: str) -> str:
    return urllib.parse.quote(text)

def url_decode(encoded_text: str) -> str:
    return urllib.parse.unquote(encoded_text)

# 테스트 예시
original = "<script>alert('XSS')</script>"
encoded = url_encode(original)
decoded = url_decode(encoded)

print("original:", original)
print("encoded:", encoded)
print("decoded:", decoded)
