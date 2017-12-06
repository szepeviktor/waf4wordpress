# Miniban

Ban hosts. Works on webservers and reverse proxies.

## Installation of htaccess method

Copy this to your `wp-config.php`.

```php
require_once __DIR__ . '/wp-miniban-htaccess.inc.php';
Miniban::init(
    __DIR__ . '/.htaccess',
    // These IP addresses and IP ranges will get whitelisted.
    array( '127.0.0.0/8', 'SERVER-IP', '66.249.64.0/19' ),
    array( 'autounban' => true )
);
```

`wp-miniban-htaccess.inc.php` is a concatenation of `miniban-base.php` and `miniban-htaccess.php`.

Set up daily cron job to unban old bans.

```
php -r 'require "/PATH/TO/wp-miniban-htaccess.inc.php";Miniban::init("/DOC-ROOT/.htaccess");Miniban::unban();'
```

The best place to run Miniban is the PHP directive `auto_prepend_file`.
Put the above PHP code in a file, let's name it `miniban-load.php`.

If you use Apache's `mod_php` module add this line to your `.htaccess` file:

```apache
php_value auto_prepend_file "/PATH/TO/miniban-load.php"
```

If you use `mod_fastcgi` or `mod_proxy_fcgi` module add this line to your `.user.ini` file.

```ini
auto_prepend_file = "/PATH/TO/miniban-load.php"
```

Scanning for `.user.ini` must be enabled server-wide in the `user_ini.filename` directive.


### .htaccess method for Apache - miniban-htaccess.php

Hosts should be banned based on these HTTP headers:

| Webserver / Proxy            | HTTP header            |
| ---------------------------- | ---------------------- |
| Apache without reverse proxy | `Remote_Addr`          |
| CloudFlare                   | `X-FORWARDED-FOR`      |
| Incapsula                    | `HTTP_INCAP_CLIENT_IP` |
| Rackspace                    | `X-CLUSTER-CLIENT-IP`  |
| Varnish                      | `X-FORWARDED-FOR`      |
| HA proxy                     | `X-FORWARDED-FOR`      |

Sample `.htaccess` file that is generated on first ban:

```apache
# Apache < 2.3
<IfModule !mod_authz_core.c>
    Order allow,deny
    Deny from env=mini_ban
    Allow from all
    Satisfy All
</IfModule>

# Apache ≥ 2.3
<IfModule mod_authz_core.c>
    <RequireAll>
        Require all granted
        Require not env mini_ban
    </RequireAll>
</IfModule>

# Mini Ban for Apache directory configuration
SetEnvIf Remote_Addr "^192\.168\.1\.100$" mini_ban

# CloudFlare header
#SetEnvIf X-FORWARDED-FOR "^192\.168\.1\.100$" mini_ban

# Incapsula
#SetEnvIf INCAP_CLIENT_IP "^192\.168\.1\.100$" mini_ban

# Rackspace header
#SetEnvIf X-CLUSTER-CLIENT-IP "^192\.168\.1\.100$" mini_ban

# Varnish
#SetEnvIf X-FORWARDED-FOR "^192\.168\.1\.100$" mini_ban

# HA proxy
#SetEnvIf X-FORWARDED-FOR "^192\.168\.1\.100$" mini_ban
```


### WordPress plugin method - miniban-wordpress.php

A small MU plugin (miniban-firewall.php) bans the IP address stored in a WordPress option.

Does not work with HTML-cached pages.


### Tarpit method - miniban-tarpit.php

Wait for specified time and send random bytes continously.


### CloudFlare method - miniban-cloudflare.php

Communicate with CloudFlare API and ban/unban hosts.
@TODO


### Forbidden method - miniban-forbidden.php

Only respond with HTTP 403 forbidden.


### RewriteMap method for Apache - miniban-rewritemap.php

```apache
# Virtual host configuration
RewriteEngine On
RewriteMap ipblocklist "txt:/path/to/ipblocklist.txt"
RewriteCond "${ipblocklist:%{REMOTE_ADDR}|NOT-FOUND}" !=NOT-FOUND
RewriteRule ^ - [F]
```


### Nginx user configuration - miniban-nginx.php

```nginx
@TODO incron -> reload nginx config
```
