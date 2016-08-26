# WordPress Fail2ban

Trigger banning on malicious requests by the Fail2ban daemon running on a server.  
Shared hosting has no server-wide banning (because of security reasons)
but you can install it without Fail2ban to stop attacks by using one of the Miniban methods.

Your WordPress (really HTTP) security consists of:

1. Use HTTPS
1. Have daily backup
1. Blocking known *shadow nets*
1. Have Fail2ban installed which controlls the firewall
1. Maintain your website + use strict Fail2ban filters which ban at the first attack instantly
1. Deny access to core WordPress files, themes and plugins
1. WordPress Fail2ban (this project)
1. Leanmail which filters notification emails

See the security and webserver folder in my `debian-server-tools` repo.

### O1_Bad_Request class

Examines every HTTP header in a login requests and triggers Fail2ban accordingly.

To install copy `wp-fail2ban-bad-request-instant.inc.php`
beside your `wp-config.php` and copy this line in top of `wp-config.php`:

```php
require_once __DIR__ . '/wp-fail2ban-bad-request-instant.inc.php';
```

Or – in a worse case – install it as an MU plugin.

### O1_WP_Fail2ban_MU class

It is an MU plugin that triggers Fail2ban on various attack types. Login is only logged, use
O1_Bad_Request class for handling that.

To install copy `wp-fail2ban-mu.php` into your `wp-content/mu-plugins/` directory.
You may have to create the `mu-plugins` directory. It activates automatically.

### non-wp-projects folder

Triggers Fail2ban on WordPress login probes.

To install copy the fake `wp-login.php`and `xmlrpc.php` to your **non-WordPress** project's root directory.

### The normal plugin - wp-fail2ban.php

Please **DO NOT use it** because it is outdated. Use the MU plugin version from the `mu-plugin` folder.

Examines every HTTP header in a login requests and triggers Fail2ban accordingly.
This is the normal version of the plugin with a setting page on WordPress admin.

**It is not yet syncronized to the mu-plugin.**

### WordPress Fail2ban is not in WordPress.org's plugin directory

After is it published on WordPress.org you can install the plugin and skip file copying.  
That way it'll be done automatically.

### Support Newsletter plugin, ALO EasyMail Newsletter plugin and PayPal IPN

Copy this into your in `wp-config.php`.

```php
// Enable email opens in Newsletter plugin
if ( isset( $_SERVER['REQUEST_URI'] ) ) {
    $o1_newsletter_path = parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH );
    if ( '/wp-content/plugins/newsletter/statistics/open.php' === $o1_newsletter_path
        || '/wp-content/plugins/newsletter/statistics/link.php' === $o1_newsletter_path
    ) {
        // UA hack for old email clients
        $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 ' . $_SERVER['HTTP_USER_AGENT'];
    }
}

// Enable email open tracking in ALO EasyMail Newsletter plugin
if ( isset( $_SERVER['REQUEST_URI'] ) ) {
    $o1_alo_path = parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH );
    if ( '/wp-content/plugins/alo-easymail/tr.php' === $o1_alo_path ) {
        // UA hack for old email clients
        $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 ' . $_SERVER['HTTP_USER_AGENT'];
    }
}

// Enable PayPal IPN in WooCommerce
if ( isset( $_SERVER['REQUEST_URI'] ) ) {
    $o1_wc_api_path = parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH );
    if ( '/wc-api/WC_Gateway_Paypal/' === $o1_wc_api_path ) {
        // PayPal IPN does not send Accept: and User-Agent: headers
        $_SERVER['HTTP_ACCEPT'] = '*/*';
        $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 PayPal/IPN';
    }
}
```

### Support and feature requests

[Open a new issue](https://github.com/szepeviktor/wordpress-fail2ban/issues/new)
