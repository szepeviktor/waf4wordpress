# WordPress fail2ban

Trigger banning on malicious requests by the fail2ban daemon running on a server.
Shared hosting has no server-wide banning (because of security reasons)
but you can use it without fail2ban to stop attacks temporarily by setting trigger count to 1.

### block-bad-requests

Examines every HTTP header in a login requests and triggers fail2ban accordingly.

To install copy `wp-login-bad-request.inc.php` beside your `wp-config.php` and copy this line in top of `wp-config.php`:

```php
require_once( dirname( __FILE__ ) . '/wp-login-bad-request.inc.php' );
```

Or – in a worse case – install it as an mu-plugin, or in the **worst case** as a normal plugin.

### mu-plugin

Triggers fail2ban on common attack types. Login is only logged, use
[block-bad-requests](https://github.com/szepeviktor/wordpress-plugin-construction/tree/master/wordpress-fail2ban#block-bad-requests) for that.

To install copy `wp-fail2ban-mu.php` into your `wp-content/mu-plugins/` directory.
You may have to create the `mu-plugins` directory. It activates automatically.

### non-wp-projects

Triggers fail2ban on WordPress login probes.

To install copy this fake `wp-login.php` to your **non-WordPress** project's webroot.

### wp-fail2ban.php - the normal plugin

Examines every HTTP header in a login requests and triggers fail2ban accordingly.
This is the normal version of the plugin with configuration options aka. UI.

It is not yet syncronized to the mu-plugin.
Please **DO NOT** use it because it is outdated. Use the *must use* plugin (mu-plugin) version.

### WordPress fail2ban is not in wordpress.org's plugin directory

After is it published on WordPress.org you can install the plugin and skip normal activation
but symlink the must use (mu-plugin) version. That way it activates automatically.

```bash
cd wp-content/
ln -s plugins/wordpress-fail2ban/mu-plugin/wp-fail2ban-mu.php mu-plugins/
```

### Support and feature requests

[Open a new issue](https://github.com/szepeviktor/wordpress-plugin-construction/issues/new)
