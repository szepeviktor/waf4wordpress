# Core events specific part of WAF for WordPress

This is the Must Use (mu-plugin) part of *WAF for WordPress*.
The code is commented, so you may understand it by looking at the code only.

### Advantages of MU

- Early execution: Must Use plugins run before normal plugins thus banning sooner, causing less server load on DoS
- Security: cannot be deactivated, fiddled with by WordPress administrators
- Speed: because it is much simplier then the normal plugin with options

## Security checks

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
define( 'W4WP_DISABLE_LOGIN', true );
```

### Allow unlimited redirections for sites with non-canonical links

To allow unlimited canonical redirections copy this into your `wp-config.php`:

```php
define( 'W4WP_ALLOW_REDIRECT', true );
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

To log requests set `W4WP_POST_LOGGING` to true in `Http_Analyzer` and custumize its conditions.

### Set up the Fail2ban filters

See: https://github.com/szepeviktor/debian-server-tools/tree/master/security/fail2ban-conf

Please examine the latest filter `failregexp`-s in
[Fail2ban GitHub repository](https://github.com/fail2ban/fail2ban/blob/master/config/filter.d).
It worth to combine every webserver related regexp-s in one custom filter.
You can customize the Fail2ban trigger string in the `$prefix` property of `Core_Events` class.

**All the best wishes to you!**
