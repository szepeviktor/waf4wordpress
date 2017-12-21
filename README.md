# WordPress Fail2ban

Stop WordPress related attacks and trigger Fail2ban running on your server.  
Shared hosting has no server-wide banning (because of trust issues)
but you can still install this software without Fail2ban to stop attacks by using one of the Miniban methods.

Your WordPress (really HTTP) security consists of:

1. Use HTTPS
1. Have daily backup
1. Block known hostile networks
1. Have Fail2ban installed (controls the firewall)
1. Maintain your website + use strict Fail2ban filters which ban on the first attack instantly
1. Deny direct access to core WordPress files, themes and plugins
1. Install WordPress Fail2ban (this project)
1. Use Leanmail (filters Fail2ban notification emails)

See the security and webserver folders in my [`debian-server-tools` repo](https://github.com/szepeviktor/debian-server-tools).

### Bad_Request class

Examines headers in the HTTP requests and triggers Fail2ban accordingly.

To install it copy `block-bad-requests/wp-fail2ban-bad-request-instant.inc.php`
beside your `wp-config.php` and copy these two lines in top of `wp-config.php`:

```php
require_once __DIR__ . '/wp-fail2ban-bad-request-instant.inc.php';
new \O1\Bad_Request();
```

Or – in a worse case – install it as an MU plugin.

### WP_Fail2ban_MU class

It is an MU plugin that triggers Fail2ban on various attack types. Login is only logged, use
Bad_Request class for handling that.

To install copy `mu-plugin/wp-fail2ban-mu-instant.php` into your `wp-content/mu-plugins/` directory.
You may have to create the `mu-plugins` directory. It activates automatically.

### Non-wp-projects folder

Triggers Fail2ban on WordPress login probes.

To install copy the fake `non-wp-projects/wp-login.php`and `non-wp-projects/xmlrpc.php`
to your **non-WordPress** project's document root.

### The normal plugin

Please **DO NOT use it** because it is being designed. Use the MU plugin version from the `mu-plugin` folder.

Examines every HTTP header in a login requests and triggers Fail2ban accordingly.
This is the normal version of the plugin with a setting page on WordPress admin.

### WordPress Fail2ban is not in WordPress.org's plugin directory

After is it published on WordPress.org you can install the plugin and skip file copying.  
That way it'll be installed automatically.

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
