```python
import urllib.parse

def url_encode(text: str) -> str:
return urllib.parse.quote(text)

def url_decode(encoded_text: str) -> str:
return urllib.parse.unquote(encoded_text)

original = "<script>alert('XSS')</script>"
encoded = url_encode(original)
decoded = url_decode(encoded)

print("original:", original)
print("encoded:", encoded)
print("decoded:", decoded)
```

```bash
# encode
python3 -c "import urllib.parse; print(urllib.parse.quote('THM{83789a69074f636f64a38879cfcabe8b62305ee6}'))"

# decode
python3 -c "import urllib.parse; print(urllib.parse.unquote('THM%7B83789a69074f636f64a38879cfcabe8b62305ee6%7D'))"

```
