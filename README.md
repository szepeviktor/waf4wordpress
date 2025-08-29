# WAF for WordPress

[![License][src-packagist-license]][href-license-file]
[![PHP Version][src-php-version]][href-composer-file]
[![Packagist stats][src-packagist-downloads]][href-packagist-stats]
[![Latest version][src-latest-version]][href-packagist]
[![PHPStan enabled][src-phpstan-enabled]][href-phpstan-org]

Stop real-life attacks on your WordPress website and
trigger [Fail2Ban](https://github.com/fail2ban/fail2ban).

:bulb: Before using this WAF you have to clean your website, get rid of even tiny errors.
See your access and error logs daily and run this WAF without Fail2ban for a week.

This WAF does not give proper HTTP responses to unusual requests.
It blocks the attacking IP address instantly, the purpose of this are the following.

1. Prevent website compromise in further requests
1. Prevent DoS attacks

Shared hosting has no server-wide banning (because of trust issues)
but you can still install this software without Fail2Ban to stop attacks by using one of the Miniban methods.

## Support my work

Please consider sponsoring me monthly if you use my packages in an agency.

[![Sponsor](https://github.com/szepeviktor/.github/raw/master/.github/assets/github-like-sponsor-button.svg)](https://github.com/sponsors/szepeviktor)

## Theory

Your WordPress - really general HTTP - security consists of the followings.

1. Use HTTPS
1. Have daily backups
1. Block [known hostile networks](https://github.com/szepeviktor/debian-server-tools/tree/master/security/myattackers-ipsets)
1. Have Fail2Ban installed (controls the firewall)
1. Maintain your website and use
    [strict Fail2Ban filters](https://github.com/szepeviktor/debian-server-tools/tree/master/security/fail2ban-conf)
    which ban on the first suspicious request instantly
1. Deny direct access to core WordPress files, themes and plugins
1. Install WAF for WordPress (this project)
1. Use [Leanmail](https://github.com/szepeviktor/debian-server-tools/tree/master/security/fail2ban-leanmail)
    for filtering Fail2Ban notification emails

See the [Block WordPress attack vectors](https://github.com/szepeviktor/wordpress-website-lifecycle/blob/master/WordPress-security.md)
note in my other repository for an overview of the topic.

## Composer installation

Technically this is not a WordPress plugin nor an MU plugin.
WAF for WordPress is distributed and autoloaded as a Composer package.

1. Issue `composer require szepeviktor/waf4wordpress` command
1. Load `vendor/autoload.php` from your `wp-config`
1. Instantiate `SzepeViktor\WordPress\Waf\HttpAnalyzer` class early in `wp-config`
    ```php
    require dirname(__DIR__) . '/vendor/autoload.php';
    new SzepeViktor\WordPress\Waf\HttpAnalyzer();
    ```
1. Create an MU plugin in `wp-content/mu-plugins/waf4wordpress.php`
    ```php
    <?php
    /*
     * Plugin Name: WAF for WordPress (MU)
     */
    if (! function_exists('add_filter')) {
        exit;
    }
    new SzepeViktor\WordPress\Waf\CoreEvents();
    ```

## Manual installation

:bulb: Please see [Composer-managed WordPress](https://github.com/szepeviktor/composer-managed-wordpress)
for managing WordPress with Composer.

Technically this is not a WordPress plugin nor an MU plugin.

1. First download
    [WAF for WordPress](https://github.com/szepeviktor/waf4wordpress/archive/refs/heads/master.zip)
    then extract files to a directory, e.g. `waf/`
1. Instantiate `SzepeViktor\WordPress\Waf\HttpAnalyzer` class early in `wp-config`
    ```php
    require_once __DIR__ . '/waf/src/HttpAnalyzer.php';
    require_once __DIR__ . '/waf/src/CoreEvents.php';
    new SzepeViktor\WordPress\Waf\HttpAnalyzer();
    ```
1. Create an MU plugin in `wp-content/mu-plugins/waf4wordpress.php`
    ```php
    <?php
    /*
     * Plugin Name: WAF for WordPress (MU)
     */
    if (! function_exists('add_filter')) {
        exit;
    }
    new SzepeViktor\WordPress\Waf\CoreEvents();
    ```

## Configuration

WAF for WordPress is configured in source code
before class instantiation. in `wp-config`.

Create custom filters for Fail2Ban catching these PHP messages.

- Likely malicious requests: `Malicious traffic detected:` may be banned after 6 attempts per 10 minutes
- Surely break-in attempts: `Break-in attempt detected:` may be banned instantly

### How to support PayPal IPN, Braintree and custom entry points in poorly written plugins

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

## Bug reports and feature requests

[Open a new issue](https://github.com/szepeviktor/waf4wordpress/issues/new)

## Where script kiddies look for WordPress

- `/backup/`
- `/blog/`
- `/cms/`
- `/demo/`
- `/dev/`
- `/home/`
- `/main/`
- `/new/`
- `/old/`
- `/portal/`
- `/site/`
- `/test/`
- `/tmp/`
- `/web/`
- `/wordpress/`
- `/wp/`

Best not to create these directories to avoid lengthy log excerpts.

[href-composer-file]: https://github.com/szepeviktor/waf4wordpress/blob/master/composer.json
[href-license-file]: https://github.com/szepeviktor/waf4wordpress/blob/master/LICENSE
[href-packagist]: https://packagist.org/packages/szepeviktor/waf4wordpress
[href-packagist-stats]: https://packagist.org/packages/szepeviktor/waf4wordpress/stats
[href-phpstan-org]: https://phpstan.org/
[src-latest-version]: https://img.shields.io/packagist/v/szepeviktor/waf4wordpress.svg
[src-packagist-downloads]: https://img.shields.io/packagist/dt/szepeviktor/waf4wordpress.svg
[src-packagist-license]: https://img.shields.io/packagist/l/szepeviktor/waf4wordpress
[src-phpstan-enabled]: https://img.shields.io/badge/PHPStan-enabled-44CC11
[src-php-version]: https://img.shields.io/packagist/dependency-v/szepeviktor/waf4wordpress/php
