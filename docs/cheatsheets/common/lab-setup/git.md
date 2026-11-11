# .git 있는 곳에서

> 무엇: 타깃에 남아 있는 .git 저장소에서 git log(커밋 목록)와 git show <해시>(커밋별 diff)로 소스 변경 이력을 조회하는 방법 정리다.
> 언제: 침투 중 서비스 소스 디렉터리에 .git이 남아 있을 때, 현재 파일에는 없는 이전 기능이나 자격 증명(예: 이후 삭제된 shell 엔드포인트)을 히스토리에서 찾을 때 쓴다.
> 조건: 대상 셸 접근과 .git 디렉터리 읽기 권한이 필요하다. `git checkout -- <파일>`로 이전 버전 파일을 복원해 내용을 볼 수 있다.

## git log -> 로그 조회

think@ip-10-10-247-143:/opt/dev$ git checkout -- pyrat.py.old
think@ip-10-10-247-143:/opt/dev$ git log
commit 0a3c36d66369fd4b07ddca72e5379461a63470bf (HEAD -> master)
Author: Jose Mario <josemlwdf@github.com>
Date: Wed Jun 21 09:32:14 2023 +0000

## git show 0a3c36d66369fd4b07ddca72e5379461a63470bf -> 변경 이력 상세 조회

commit 0a3c36d66369fd4b07ddca72e5379461a63470bf (HEAD -> master)
Author: Jose Mario <josemlwdf@github.com>
Date: Wed Jun 21 09:32:14 2023 +0000

    Added shell endpoint

diff --git a/pyrat.py.old b/pyrat.py.old
new file mode 100644
index 0000000..ce425cf
--- /dev/null
+++ b/pyrat.py.old
@@ -0,0 +1,27 @@
+...............................................

- +def switch_case(client_socket, data):
- if data == 'some_endpoint':
-        get_this_enpoint(client_socket)
- else:
-        # Check socket is admin and downgrade if is not aprooved
-        uid = os.getuid()
-        if (uid == 0):
-            change_uid()
-
-        if data == 'shell':
-            shell(client_socket)
-        else:
-            exec_python(client_socket, data)
- +def shell(client_socket):
- try:
-        import pty
-        os.dup2(client_socket.fileno(), 0)
-        os.dup2(client_socket.fileno(), 1)
-        os.dup2(client_socket.fileno(), 2)
-        pty.spawn("/bin/sh")
- except Exception as e:
-        send_data(client_socket, e
- +...............................................
