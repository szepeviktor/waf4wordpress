# WAF for WordPress

Stop real-life attacks on your WordPress website and trigger Fail2ban.

This WAF does not give proper HTTP responses to unusual requets.
It blocks the attacking IP address instantly, the purpose of this are the following.

1. Prevent website compromise in further requests
1. Prevent D/DoS attacks

Shared hosting has no server-wide banning (because of trust issues)
but you can still install this software without Fail2ban to stop attacks by using one of the Miniban methods.

Your WordPress - really general HTTP - security consists of:

1. Use HTTPS
1. Have daily backup
1. Block known hostile networks
1. Have Fail2ban installed (controls the firewall)
1. Maintain your website and use strict Fail2ban filters
   which ban on the first suspicious request instantly
1. Deny direct access to core WordPress files, themes and plugins
1. Install WAF for WordPress (this project)
1. Use Leanmail (filters Fail2ban notification emails)

See the [Block WordPress attack vectors](https://github.com/szepeviktor/debian-server-tools/blob/master/webserver/WordPress-security.md)
note in my other repository for an overview of the topic.

### `Http_Analyzer` class

Examines headers in the HTTP requests and triggers Fail2ban accordingly.

To install it copy `http-analyzer/waf4wordpress-http-analyzer.php`
beside your `wp-config.php` and copy these lines in top of `wp-config.php`:

```php
/** Security */
require_once __DIR__ . '/waf4wordpress-http-analyzer.php';
new \Waf4WordPress\Http_Analyzer();
```

A better solution is to load it from the `auto_prepend_file` PHP directive.
This time you have to copy the above code in the class file.

### `Core_Events` class

It is an MU plugin that triggers Fail2ban on various WordPress specific attack types.
Login is only logged, use `Http_Analyzer` class for handling that.

To install copy `core-events/waf4wordpress-core-events.php` into your `wp-content/mu-plugins/` directory.
You may have to create the `mu-plugins` directory. It activates automatically.

### The `non-wp-projects` folder

Triggers Fail2ban on WordPress login probes in any project.

To install copy the fake `non-wp-projects/wp-login.php`and `non-wp-projects/xmlrpc.php`
to your **non-WordPress** project's document root.

### WAF for WordPress is not in WordPress.org's plugin directory

After is it published on WordPress.org you can install the plugin and skip file copying.  
That way it'll be installed automatically.

### Support PayPal IPN, Brantree and custom entry points in poorly written plugins

Copy this into your in `wp-config.php`.

```php
// Enable PayPal IPN in WooCommerce
if ( isset( $_SERVER['REQUEST_URI'] ) ) {
    if ( '/wc-api/WC_Gateway_Paypal/' === parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH ) ) {
        // PayPal IPN does not send Accept: and User-Agent: headers
        $_SERVER['HTTP_ACCEPT'] = '*/*';
        $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 PayPal/IPN';
    }
}

// Enable Braintree Webhooks
new \Waf4WordPress\Braintree_Fix( '/braintree/webhook' );

// Enable email opens in Newsletter plugin
if ( isset( $_SERVER['REQUEST_URI'] ) ) {
    $newsletter_path = parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH );
    if ( '/wp-content/plugins/newsletter/statistics/open.php' === $newsletter_path
        || '/wp-content/plugins/newsletter/statistics/link.php' === $newsletter_path
    ) {
        // UA hack for old email clients
        $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 ' . $_SERVER['HTTP_USER_AGENT'];
    }
    unset( $newsletter_path );
}

// Enable email open tracking in ALO EasyMail Newsletter plugin
if ( isset( $_SERVER['REQUEST_URI'] ) ) {
    $alo_path = parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH );
    if ( '/wp-content/plugins/alo-easymail/tr.php' === $alo_path ) {
        // UA hack for old email clients
        $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 ' . $_SERVER['HTTP_USER_AGENT'];
    }
    unset( $alo_path );
}
```

### Support and feature requests

[Open a new issue](https://github.com/szepeviktor/wordpress-fail2ban/issues/new)
