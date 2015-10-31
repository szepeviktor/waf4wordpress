# WordPress fail2ban

Trigger banning on malicious requests by the fail2ban daemon running on a server.
Shared hosting has no server-wide banning (because of security reasons)
but you can use it without fail2ban to stop attacks temporarily by setting trigger count to 1.

### block-bad-requests

Examines every HTTP header in a login requests and triggers fail2ban accordingly.

To install copy `wp-fail2ban-bad-request-instant.inc.php`
beside your `wp-config.php` and copy this line in top of `wp-config.php`:

```php
require_once dirname( __FILE__ ) . '/wp-fail2ban-bad-request-instant.inc.php';
```

Or – in a worse case – install it as an mu-plugin.

### mu-plugin

Triggers fail2ban on common attack types. Login is only logged, use
[block-bad-requests](https://github.com/szepeviktor/wordpress-fail2ban/blob/master/README.md#block-bad-requests)
for that.

To install copy `wp-fail2ban-mu.php` into your `wp-content/mu-plugins/` directory.
You may have to create the `mu-plugins` directory. It activates automatically.

### non-wp-projects

Triggers fail2ban on WordPress login probes.

To install copy the fake `wp-login.php`and `xmlrpc.php` to your **non-WordPress** project's root directory.

### The normal plugin - wp-fail2ban.php

Please **DO NOT use it** because it is outdated. Use the *must use* plugin (mu-plugin) version.

Examines every HTTP header in a login requests and triggers fail2ban accordingly.
This is the normal version of the plugin with a setting page on WordPress admin.

It is not yet syncronized to the mu-plugin.

### WordPress fail2ban is not in WordPress.org's plugin directory

After is it published on WordPress.org you can install the plugin and skip normal activation
but create a symlink to the must use (mu-plugins) version. That way it activates automatically.

```bash
cd wp-content/
ln -s plugins/wordpress-fail2ban/mu-plugin/wp-fail2ban-mu.php mu-plugins/
```

### Support and feature requests

[Open a new issue](https://github.com/szepeviktor/wordpress-fail2ban/issues/new)
