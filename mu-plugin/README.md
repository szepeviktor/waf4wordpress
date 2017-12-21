# WordPress Fail2ban MU plugin

This is the Must Use (mu-plugin) version of *WordPress Fail2ban* plugin.
The code is commented, so you may understand it by looking at the code only.

### Advantages

- Early execution: Must Use plugins run before normal plugins thus banning sooner, causing less server load on DoS
- Security: cannot be deactivated, fiddled with by WordPress administrators
- Speed: because it is much simplier then the normal plugin with options

## Parts

- prevent anyone logging in (disabled by default)
- prevent redirections to admin (log in only at `/wp-admin` or `/wp-login.php`)
- stop brute force attacks (multiple login probes and password reminder attacks from one IP address)
- stop robots scanning non-existent URLs (404s, redirects, simple URL hacks, misinterpreted relative protocols)
- reply with HTTP/403 Forbidden to robots on non-frontend requests
- stop showing 404 pages to robots but send HTTP/404
- ban sequential 404 requests (from the same IP address)
- ban on any XMLRPC-based authentication (even on successful ones)
- ban on invalid AJAX, XMLRPC and other `wp_die()`-handled requests
- ban on unknown admin-ajax and admin-post actions
- stop spammers in cooperation with [Contact Form 7 Robot Trap](https://github.com/szepeviktor/wordpress-plugin-construction/tree/master/contact-form-7-robot-trap) plugin
- log WordPress logins and logouts

### Preventing login on unmaintained sites

To deny user login totally copy this into your `wp-config.php`

```php
define( 'O1_WP_FAIL2BAN_DISABLE_LOGIN', true );
```

### Allow unlimited redirections for sites with non-canonical links

To allow unlimited canonical redirections copy this into your `wp-config.php`:

```php
define( 'O1_WP_FAIL2BAN_ALLOW_REDIRECT', true );
```

### Disabling parts

By default all parts (Fail2ban triggers) are enabled. If you would like to disable any of them
you have to `remove_action()` or `remove_filter()` it in your own code at `init`.
Or comment out actions/filters in the constructor.

### Warning regarding updates!

An mu-plugin will not appear in the update notifications nor show its update status on the Plugins page.
A nice solution is a symlink in `wp-content/mu-plugins` which keeps it activated and also up-to-date.
In that case don't activate the normal plugin.

### Learning attack internals

Helps learning attack internals. Insert this code after `wp_logout();` in `trigger_instant()`.

```php
        $request_data = $_REQUEST;
        if ( empty( $request_data ) ) {
            $request_data = file_get_contents( 'php://input' );
        }
        $this->enhanced_error_log( sprintf( 'HTTP REQUEST: %s:%s',
            $this->esc_log( $_SERVER['REQUEST_METHOD'] ),
            $this->esc_log( $request_data )
        ) );
```

### Set up the Fail2ban filters

See: https://github.com/szepeviktor/debian-server-tools/tree/master/security/fail2ban-conf

Please examine the latest filter `failregexp`-s in
[Fail2ban GitHub repository](https://github.com/fail2ban/fail2ban/blob/master/config/filter.d).
It worth to combine every webserver related regexp-s in one custom filter.
You can customize the Fail2ban trigger string in the `$prefix` property of `WP_Fail2ban_MU` class.

**All the best wishes to you!**
