```bash
# 원격 서버(`10.201.81.37:443`)에 TLS(SSL)로 접속하여, 해당 서버가 제공하는 **X.509 인증서**를 가져오고 상세 정보 출력
echo | openssl s_client -servername support.futurevera.thm -connect 10.201.81.37:443 2>/dev/null | openssl x509 -text -noout
```