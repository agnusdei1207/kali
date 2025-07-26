# 쿠키 원본

Cookie: wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_45a7e4c82b517c5af328feabce4d0187=wpuser%7C1753668949%7CcPTwzE1cbFpF18C6ZZZnuwRE0D2eRXISGnrDPvbQcBv%7Cccf2b309c5881393194d94ea8fc1ff5c9b3a8324cfc1282e423f89ccc74ee070

# 디코딩

echo "wpuser%7C1753668949%7CcPTwzE1cbFpF18C6ZZZnuwRE0D2eRXISGnrDPvbQcBv%7Cccf2b309c5881393194d94ea8fc1ff5c9b3a8324cfc1282e423f89ccc74ee070" | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read()))"

# 결과

wpuser|1753668949|cPTwzE1cbFpF18C6ZZZnuwRE0D2eRXISGnrDPvbQcBv|ccf2b309c5881393194d94ea8fc1ff5c9b3a8324cfc1282e423f89ccc74ee070
