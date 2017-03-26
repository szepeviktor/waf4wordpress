# WordPress Block Bad Requests

Bans commonly used user names (hardcoded in a property), blocks non-static requests from CDN,
prevents author sniffing and examines every HTTP header in a login request.
Then triggers fail2ban accordingly.

To install copy `wp-fail2ban-bad-request-instant.inc.php` beside your `wp-config.php` and put this line in top of `wp-config.php`:

```php
require_once dirname( __FILE__ ) . '/wp-fail2ban-bad-request-instant.inc.php';
new \O1\Bad_Request();
```

Or – in a worse case – install it as an mu-plugin.
It [executes very early](https://wordpress.org/plugins/whats-running/) when `require`-d from `wp-config.php`.
As an mu-plugin WordPress loads before it executes.
You can find out plugin execution order by this simple wp-cli command:

```
wp option get "active_plugins"
```

### List of HTTP request parts checked

- custom CDN headers `*`
- URI length
- User Agent length
- HTTP methods
- Slash in URI, URI encoding, blacklist for the URI
- HTTP Protocol
- Request for robots.txt in a subdirectory
- `author` query field
- Request method to identify POST requests
- PHP file upload
- HTTP/POST without User Agent
- Accept header
- Content-Length header
- Content-Type header
- HTTP methods for WordPress login
- `log` POST variable blacklist (the WordPress username) `*`
- Request size for WordPress login `*`
- Accept-Language header
- Referer header `*`
- `action` query field to allow requests for password protected posts
- HTTP Protocol for WordPress login `*`
- Connection header `*`
- Accept-Encoding header
- Cookie named `wordpress_test_cookie` `*`
- User-Agent header `*`

The list is in order of appearance, `*` means it can be disabled by an option below.

```bash
grep -o "return '.*';" wp-fail2ban-bad-request-instant.inc.php
```

### Options

You can set these options by defining constants in your `wp-config.php`.
E.g. to allow Connection header other than `keep-alive` use this:

```php
define( 'O1_BAD_REQUEST_ALLOW_CONNECTION_CLOSE', true );
```

To blocks non-static requests from Amazon CloudFront copy this to your wp-config.php:

```php
define( 'O1_BAD_REQUEST_CDN_HEADERS', 'HTTP_X_FORWARDED_FOR:HTTP_X_AMZ_CF_ID:HTTP_VIA' );
```

Restrict access to CloudFlare only: `mod_remoteip`

- HTTP_CF_CONNECTING_IP
- HTTP_X_FORWARDED_FOR
- HTTP_CF_RAY

Constant list

- (boolean) `O1_BAD_REQUEST_POST_LOGGING` enable logging of all POST requests, even normal ones
- (integer) `O1_BAD_REQUEST_COUNT` fail2ban trigger limit, `maxretry`
- (integer) `O1_BAD_REQUEST_MAX_LOGIN_REQUEST_SIZE` maxumim size of the login request
- (string) `O1_BAD_REQUEST_CDN_HEADERS` a colon separated list of HTTP headers your CDN is recognized by
- (boolean) `O1_BAD_REQUEST_ALLOW_REG` allow WP registration, disabled referer and test cookie checks
- (boolean) `O1_BAD_REQUEST_ALLOW_IE8` allow login with IE8 too (IE8 is not a `Mozilla/5.0` browser)
- (boolean) `O1_BAD_REQUEST_ALLOW_OLD_PROXIES` allow `HTTP/1.0` login requests
- (boolean) `O1_BAD_REQUEST_ALLOW_CONNECTION_EMPTY` allow requests without HTTP Connection header
- (boolean) `O1_BAD_REQUEST_ALLOW_CONNECTION_CLOSE` allow other HTTP Connection headers than `keep-alive`
- (boolean) `O1_BAD_REQUEST_ALLOW_TWO_CAPS` allow user names like `JohnDoe`

### Experimental upload traffic analysis

Insert this code at the end of `__construct()`.

```php
        if ( ! empty( $_FILES ) ) {
            $this->enhanced_error_log( sprintf( 'bad_request_upload: %s, %s',
                $this->esc_log( $_FILES ),
                $this->esc_log( $_REQUEST )
            ), 'notice' );
        }
```

To learn attack internals insert the code in the MU plugin's README just before `ob_get_level()` in `trigger()`.

### XMLRPC request and response

```xml
<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
   <param><value>username</value></param>
   <param><value>password</value></param>
  </params>
</methodCall>
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value>
      <array><data>
  <value><struct>
  <member><name>isAdmin</name><value><boolean>1</boolean></value></member>
  <member><name>url</name><value><string>http://domain.wp/</string></value></member>
  <member><name>blogid</name><value><string>1</string></value></member>
  <member><name>blogName</name><value><string>Blog name</string></value></member>
  <member><name>xmlrpc</name><value><string>http://domain.wp/xmlrpc.php</string></value></member>
</struct></value>
</data></array>
      </value>
    </param>
  </params>
</methodResponse>
```

### SPDY note

All connections with SPDY are persistent connections.

```php
define( 'O1_BAD_REQUEST_ALLOW_CONNECTION_EMPTY', true );
```

### Other notes

You can customize the fail2ban trigger string in the `$prefix` property.

Tests are included as a shell script: `bad-request-test.sh`

[GitHub repository](https://github.com/szepeviktor/wordpress-fail2ban)
