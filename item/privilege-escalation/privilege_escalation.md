```bash
# SUID 설정된 거 찾기
find / -perm -4000 -type f 2>/dev/null
find / -perm -4000 -a -perm /111 -type f 2>/dev/null

# SUID + SGID 동시 설정된 파일 찾기 (강력한 권한 상승 가능)
find / -perm -6000 -type f 2>/dev/null

# 쓰기 권한이 가능한 디렉토리 찾기
find / -writable -type d 2>/dev/null

권한 유형,8진수 값,설명
Set User ID (SUID),4000,파일 소유자의 권한으로 실행되도록 합니다.
Set Group ID (SGID),2000,파일 그룹의 권한으로 실행되도록 합니다.
Sticky Bit,1000,디렉터리 내에서 소유자만 파일 삭제를 가능하게 합니다.
```
