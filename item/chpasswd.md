```bash
get_root_shell() {
    # 1 방법
    echo "think:새로운비밀번호" | chpasswd

    # 2 방법
    chpasswd < /tmp/passwd.txt
}
```
