# ip 10.64.141.130

you can download the PCAP file via  http://10.65.157.12:8000/traffic.pcapng.

PCAP MD5: 0d0027855661b4eb8a9d3c52eec370c7

The flag is base64 encoded and divided into three parts.
                                                                                                                              
┌──(kali㉿kali)-[~/workspace]
└─$ wget http://10.65.157.12:8000/traffic.pcapng 
--2025-11-29 18:03:35--  http://10.65.157.12:8000/traffic.pcapng
Connecting to 10.65.157.12:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4051124 (3.9M)
Saving to: 'traffic.pcapng'

traffic.pcapng                  100%[=====================================================>]   3.86M   717KB/s    in 6.0s    

2025-11-29 18:03:41 (657 KB/s) - 'traffic.pcapng' saved [4051124/4051124]

                                                                                                                              
┌──(kali㉿kali)-[~/workspace]
└─$ ls
kali  traffic.pcapng

frame.number == 2448


![](https://velog.velcdn.com/images/agnusdei1207/post/3198a89c-474d-438d-99b2-3c61cfa66ab8/image.png)

- 2448 번째
- 로그인 시도


frame.number == 2886


![](https://velog.velcdn.com/images/agnusdei1207/post/5c4b0331-d275-4ed4-aa72-d5084b978d11/image.png)


- 로그인 성공



aGF6ZWxAcHJlc3NlZC50aG0=
cGFzc3dvcmQ=

https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=YUdGNlpXeEFjSEpsYzNObFpDNTBhRzA9Cg

![](https://velog.velcdn.com/images/agnusdei1207/post/84cf8c25-bf1a-4fa8-94a8-596019f5773c/image.png)

- 디코딩




![](https://velog.velcdn.com/images/agnusdei1207/post/7848fe7a-a369-4245-835e-79a4eaa9e72c/image.png)

- 시트 파일 전송 기록 -> 내부 정보 유출?