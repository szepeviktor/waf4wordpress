<?php

declare(strict_types=1);

/**
 * Core events specific part of WAF for WordPress.
 *
 * @author Viktor Szépe <viktor@szepe.net>
 * @license https://opensource.org/licenses/MIT MIT
 * @link https://github.com/szepeviktor/waf4wordpress
 *
 * Constants:   W4WP_DISABLE_LOGIN
 * Constants:   W4WP_ALLOW_REDIRECT
 * Constants:   W4WP_DISABLE_REST_API
 * Constants:   W4WP_ONLY_OEMBED
 * Constants:   W4WP_MSNBOT
 * Constants:   W4WP_GOOGLEBOT
 * Constants:   W4WP_YANDEXBOT
 * Constants:   W4WP_GOOGLEPROXY
 * Constants:   W4WP_SEZNAMBOT
 * Constants:   W4WP_CONTENTKING
 * Constants:   W4WP_FACEBOOKCRAWLER
 */

namespace SzepeViktor\WordPress\Waf;

/**
 * WAF for WordPress Must-Use plugin part.
 *
 * To disable login completely copy this into your wp-config.php:
 *
 *     define('W4WP_DISABLE_LOGIN', true);
 *
 * To allow unlimited canonical redirections copy this into your wp-config.php:
 *
 *     define('W4WP_ALLOW_REDIRECT', true);
 *
 * @see README.md
 */
final class CoreEvents
{
    private $prefix = 'Malicious traffic detected: ';

    private $prefix_instant = 'Break-in attempt detected: ';

    private $wp_die_ajax_handler;

    private $wp_die_xmlrpc_handler;

    private $wp_die_handler;

    private $is_redirect = false;

    /**
     * Ban instead of displaying error message with `illegal_user_logins` filter.
     *
     * @link https://github.com/divine/reserved-usernames/blob/master/src/ReservedUsernames.php#L7
     */
    private $names2ban = [
        'access',
        'admin',
        'administrator',
        'backup',
        'blog',
        'business',
        'contact',
        'data',
        'demo',
        'doctor',
        'guest',
        'info',
        'information',
        'internet',
        'login',
        'manager',
        'marketing',
        'master',
        'number',
        'office',
        'pass',
        'password',
        'postmaster',
        'public',
        'root',
        'sales',
        'server',
        'service',
        'support',
        'test',
        'tester',
        'user',
        'user2',
        'username',
        'webmaster',
    ];

    private $min_username_length = 3;

    /** @see https://github.com/WordPress/WordPress/blob/5.2.2/wp-includes/pluggable.php#L2364 */
    private $secure_min_password_length = 12;

    /** @see https://keepass.info/help/kb/pw_quality_est.html */
    private $min_password_length = 8;

    public function __construct()
    {
        // Exit on local access
        // Don't run on install and upgrade
        if (
            php_sapi_name() === 'cli'
            || $_SERVER['REMOTE_ADDR'] === $_SERVER['SERVER_ADDR']
            || (defined('WP_INSTALLING') && WP_INSTALLING)
        ) {
            return;
        }

        // Prevent usage as a normal plugin in wp-content/plugins
        if (did_action('muplugins_loaded') !== 0) {
            $this->exit_with_instructions();
        }

        // REST API
        if (defined('W4WP_DISABLE_REST_API') && W4WP_DISABLE_REST_API) {
            // Remove core actions
            // Source: https://plugins.trac.wordpress.org/browser/disable-json-api/trunk/disable-json-api.php
            remove_action('xmlrpc_rsd_apis', 'rest_output_rsd');
            remove_action('wp_head', 'rest_output_link_wp_head', 10);
            remove_action('template_redirect', 'rest_output_link_header', 11);
            if (defined('W4WP_ONLY_OEMBED') && W4WP_ONLY_OEMBED) {
                add_filter('rest_pre_dispatch', [$this, 'rest_api_only_oembed'], 0, 3);
            } else {
                // Remove oembed core action
                remove_action('wp_head', 'wp_oembed_add_discovery_links');
                add_filter('rest_authentication_errors', [$this, 'rest_api_disabled'], 99999);
            }
        } else {
            add_filter('oembed_response_data', [$this, 'oembed_filter'], 0);
            add_filter('rest_post_dispatch', [$this, 'rest_filter'], 0, 3);
        }

        // Don't redirect to admin
        remove_action('template_redirect', 'wp_redirect_admin_locations', 1000);

        // Login related
        add_action('login_init', [$this, 'login']);
        if (! is_admin()) {
            add_action('admin_bar_menu', [$this, 'admin_bar'], 99999);
            // For login links in nav menus:
            // Appearance / Menus / (menu) / (item) / XFN = nofollow
        }
        add_action('wp_logout', [$this, 'logout'], 0, 1);
        add_action('retrieve_password', [$this, 'lostpass']);
        if (defined('W4WP_DISABLE_LOGIN') && W4WP_DISABLE_LOGIN) {
            // Disable login
            add_action('login_head', [$this, 'disable_user_login_js']);
            add_filter('authenticate', [$this, 'authentication_disabled'], 0, 2);
        } else {
            // Prevent registering with banned username
            add_filter('validate_username', [$this, 'banned_username'], 99999, 2);
            // wp-login, XMLRPC login (any authentication)
            add_action('wp_login_failed', [$this, 'login_failed']);
            add_filter('authenticate', [$this, 'before_login'], 0, 2);
            add_filter('wp_authenticate_user', [$this, 'authentication_strength'], 99999, 2);
            add_action('register_new_user', [$this, 'after_register'], 99999, 1);
            add_action('wp_login', [$this, 'after_login'], 0, 2);
        }

        // Don't use shortlinks which are redirected to canonical URL-s
        add_filter('pre_get_shortlink', '__return_empty_string');

        // Non-existent URLs
        add_action('init', [$this, 'url_hack']);
        if (!(defined('W4WP_ALLOW_REDIRECT') && W4WP_ALLOW_REDIRECT)) {
            add_filter('redirect_canonical', [$this, 'redirect'], 1, 2);
        }

        // Robot and human 404
        add_action('plugins_loaded', [$this, 'robot_403'], 0);
        // BuddyPress fiddles with is_404 at priority 10
        add_action('template_redirect', [$this, 'wp_404'], 11);

        // Non-empty wp_die messages
        add_filter('wp_die_ajax_handler', [$this, 'wp_die_ajax'], 1);
        add_filter('wp_die_xmlrpc_handler', [$this, 'wp_die_xmlrpc'], 1);
        add_filter('wp_die_handler', [$this, 'wp_die'], 1);

        // Unknown admin-ajax and admin-post action
        // admin_init is done just before AJAX actions
        add_action('admin_init', [$this, 'hook_all_action']);

        // Ban spammers (Contact Form 7 Robot Trap)
        add_action('robottrap_hiddenfield', [$this, 'spam_hiddenfield']);
        add_action('robottrap_mx', [$this, 'spam_mx']);

        // Ban bad robots (Nofollow Robot Trap)
        add_action('nofollow_robot_trap', [$this, 'nfrt_robot_trap']);
    }

    private function trigger_instant($slug, $message, $level = 'crit')
    {
        // Trigger Miniban at first
        if (class_exists('\Miniban')) {
            if (\Miniban::ban() !== true) {
                $this->enhanced_error_log('Miniban operation failed.');
            }
        }

        $this->trigger($slug, $message, $level, $this->prefix_instant);

        // Remove session
        remove_action('wp_logout', [$this, 'logout'], 0);
        wp_logout();

        // Respond
        if (ob_get_level() !== 0) {
            ob_end_clean();
        }
        if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
            $this->fake_xmlrpc();
        } elseif (! headers_sent()) {
            if ($GLOBALS['pagenow'] === 'wp-login.php' && isset($_POST['log'])) {
                $this->fake_wplogin();
            } else {
                $this->ban();
            }
        }

        exit;
    }

    private function trigger($slug, $message, $level = 'error', $prefix = '')
    {
        if ($prefix === '') {
            $prefix = $this->prefix;
        }

        // Trigger Fail2ban
        $error_msg = sprintf(
            '%s%s %s',
            $prefix,
            $slug,
            $this->esc_log($message)
        );
        $this->enhanced_error_log($error_msg, $level);

        // Report to Sucuri Scan
        if (class_exists('\SucuriScanEvent')) {
            if (\SucuriScanEvent::report_critical_event($error_msg) !== true) {
                // phpcs:set WordPress.PHP.DevelopmentFunctions exclude[] error_log
                error_log('Sucuri Scan report event failure.');
            }
        }

        // Report to Simple History
        if (!function_exists('SimpleLogger')) {
            return;
        }

        $simple_level = $this->translate_apache_level($level);
        $context = [
            '_security' => 'WAF4WordPress',
            '_server_request_method' => $this->esc_log($_SERVER['REQUEST_METHOD']),
        ];
        if (array_key_exists('HTTP_USER_AGENT', $_SERVER)) {
            $context['_server_http_user_agent'] = $this->esc_log($_SERVER['HTTP_USER_AGENT']);
        }
        if (! class_exists('\SimpleLogger')) {
            /** @phpstan-ignore class.notFound */
            \SimpleHistory::get_instance()->load_loggers();
        }
        \SimpleLogger()->log($simple_level, $error_msg, $context);
    }

    private function ban()
    {
        header('Status: 403 Forbidden');
        header('HTTP/1.1 403 Forbidden', true, 403);
        header('Connection: close');
        header('Cache-Control: max-age=0, private, no-store, no-cache, must-revalidate');
        header('X-Robots-Tag: noindex, nofollow');
        header('Content-Type: text/html');
        header('Content-Length: 0');
    }

    private function fake_wplogin()
    {
        $username = trim($_POST['log']);
        $expire = time() + 3600;
        $token = substr(hash_hmac('sha256', (string)rand(), 'token'), 0, 43);
        $hash = hash_hmac('sha256', (string)rand(), 'hash');
        $auth_cookie = $username . '|' . $expire . '|' . $token . '|' . $hash;
        $authcookie_name = 'wordpress_' . md5('authcookie');
        $loggedincookie_name = 'wordpress_logged_in_' . md5('cookiehash');

        header('Cache-Control: max-age=0, private, no-store, no-cache, must-revalidate');
        header('X-Robots-Tag: noindex, nofollow');
        setcookie($authcookie_name, $auth_cookie, $expire, '/brake/wp_content/plugins', '', false, true);
        setcookie($authcookie_name, $auth_cookie, $expire, '/brake/wp-admin', '', false, true);
        setcookie($loggedincookie_name, $auth_cookie, $expire, '/', '', false, true);
        header('Location: ' . home_url('/brake/wp-admin/'));
    }

    private function fake_xmlrpc()
    {
        header('Connection: close');
        header('Cache-Control: max-age=0, private, no-store, no-cache, must-revalidate');
        header('X-Robots-Tag: noindex, nofollow');
        header('Content-Type: text/xml; charset=UTF-8');

        printf(
            '<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value>
        <array><data><value><struct>
          <member><name>isAdmin</name><value><boolean>1</boolean></value></member>
          <member><name>url</name><value><string>%s</string></value></member>
          <member><name>blogid</name><value><string>1</string></value></member>
          <member><name>blogName</name><value><string>brake</string></value></member>
          <member><name>xmlrpc</name><value><string>%s</string></value></member>
        </struct></value></data></array>
      </value>
    </param>
  </params>
</methodResponse>
',
            esc_url(home_url('/')),
            esc_url(home_url('/brake/xmlrpc.php'))
        );
    }

    private function enhanced_error_log($message = '', $level = 'error')
    {
        // phpcs:ignore Squiz.PHP.CommentedOutCode
        /*
        // log_errors PHP directive does not actually disable logging
        $log_enabled = ('1' === ini_get('log_errors'));
        if (!$log_enabled || '' !== $log_destination) {
        */

        // Add entry point, correct when auto_prepend_file is empty
        $included_files = get_included_files();
        $first_included_file = reset($included_files);
        $error_msg = sprintf(
            '%s <%s',
            $message,
            $this->esc_log(sprintf('%s:%s', $_SERVER['REQUEST_METHOD'], $first_included_file))
        );

        /**
         * Add client data to log message if SAPI does not add it.
         *
         * level, IP address, port, referer
         */
        $log_destination = function_exists('ini_get') ? ini_get('error_log') : '';
        if ($log_destination !== '') {
            $referer = array_key_exists('HTTP_REFERER', $_SERVER) ? sprintf(', referer: %s', $this->esc_log($_SERVER['HTTP_REFERER'])) : '';

            $error_msg = sprintf(
                '[%s] [client %s:%s] %s%s',
                $level,
                $_SERVER['REMOTE_ADDR'],
                $_SERVER['REMOTE_PORT'],
                $error_msg,
                $referer
            );
        }

        // phpcs:set WordPress.PHP.DevelopmentFunctions exclude[] error_log
        error_log($error_msg);
    }

    public function wp_404()
    {
        if (!is_404()) {
            return;
        }

        $ua = array_key_exists('HTTP_USER_AGENT', $_SERVER) ? $_SERVER['HTTP_USER_AGENT'] : '';

        // HEAD probing resulting in a 404
        if (stripos($_SERVER['REQUEST_METHOD'], 'HEAD') !== false) {
            $this->trigger_instant('w4wp_404_head', $_SERVER['REQUEST_URI']);
        }

        $is_crawler = $this->is_crawler($ua);

        // Don't run 404 template for robots
        if ($this->is_robot($ua) && $is_crawler === false) {
            $this->trigger('w4wp_404_robot', $_SERVER['REQUEST_URI'], 'info');

            if (ob_get_level() !== 0) {
                ob_end_clean();
            }
            if (! headers_sent()) {
                header('Status: 404 Not Found');
                status_header(404);
                header('X-Robots-Tag: noindex, nofollow');
                header('Connection: close');
                header('Content-Length: 0');
                nocache_headers();
            }

            exit;
        }

        // Humans and web crawling bots
        if (is_string($is_crawler)) {
            $this->trigger($is_crawler, $_SERVER['REQUEST_URI'], 'info', 'Crawler 404: ');
        } else {
            $this->trigger('w4wp_404', $_SERVER['REQUEST_URI'], 'info');
        }
    }

    /**
     * Filter oEmbed requests.
     *
     * @param array<string, mixed> $data
     * @return array<string, mixed> $data
     */
    public function oembed_filter($data)
    {
        if (isset($data['author_url'])) {
            unset($data['author_url']);
        }

        return $data;
    }

    /**
     * Filter REST requests.
     *
     * @param \WP_HTTP_Response|\WP_Error $response
     * @param \WP_REST_Server $server
     * @param \WP_REST_Request<array<array-key,mixed>> $request
     * @return \WP_HTTP_Response|\WP_Error
     */
    public function rest_filter($response, $server, $request)
    {
        // Detect internal REST API requests
        if (! wp_is_json_request()) {
            return $response;
        }

        if ($response instanceof \WP_HTTP_Response) {
            $status = $response->get_status();
            $method = $request->get_method();
            $route = $request->get_route();
            /** @var array{code:string, message:string} $data */
            $data = $response->get_data();
            $is_user_listing = ($server::READABLE === $method && strtolower(substr($route, 0, 12)) === '/wp/v2/users');
            // Disable any kind of unauthorized user listing
            // Authenticated REST requests must have a nonce
            if (! current_user_can('list_users') && $is_user_listing) {
                $message = sprintf('<%s:%s', $method, $route);
                $this->trigger_instant('w4wp_rest_user_listing', $message);
            }
            // Detect HTTP/404 and 403
            switch ($status) {
                case 403:
                case 404:
                    $message = sprintf('%s <%s:%s', $data['code'], $method, $route);
                    $this->trigger('w4wp_rest_client_error', $message);
                    break;
            }
        } else {
            // @TODO Handle non-WP_HTTP_Response errors
            $this->trigger('w4wp_rest_error', 'Not a REST response but a ' . get_class($response));
        }

        return $response;
    }

    public function url_hack()
    {
        if (substr($_SERVER['REQUEST_URI'], 0, 2) !== '//') {
            return;
        }

        // Remember this to prevent double-logging in redirect()
        $this->is_redirect = true;
        $this->trigger('w4wp_url_hack', $_SERVER['REQUEST_URI']);
    }

    // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis
    public function rest_api_disabled($enabled)
    {
        $this->trigger('w4wp_rest_api_disabled', $_SERVER['REQUEST_URI'], 'notice');

        return new \WP_Error(
            'rest_no_route',
            __('No route was found matching the URL and request method'),
            ['status' => 404]
        );
    }

    public function rest_api_only_oembed($null, $that, $request)
    {
        // https://oembed.com/#section2.2
        if ($request->get_route() === '/oembed/1.0/embed') {
            return $null;
        }

        $this->trigger('w4wp_rest_api_not_oembed', $_SERVER['REQUEST_URI'], 'notice');

        $response_data = [
            'code' => 'rest_no_route',
            'message' => __('No route was found matching the URL and request method'),
            'data' => ['status' => 404],
        ];

        return new \WP_REST_Response($response_data, 404);
    }

    public function redirect($redirect_url, $requested_url)
    {
        if ($this->is_redirect === false) {
            $this->trigger('w4wp_redirect', $requested_url, 'notice');
        }

        return $redirect_url;
    }

    /**
     * Do not allow banned or short usernames.
     *
     * @param bool $valid
     * @param string $username
     * @return bool
     */
    public function banned_username($valid, $username)
    {
        if (
            in_array(strtolower($username), $this->names2ban, true)
            || mb_strlen($username) < $this->min_username_length
        ) {
            $this->trigger('w4wp_register_banned_username', $username, 'notice');
            $valid = false;
        }

        return $valid;
    }

    public function authentication_disabled($user, $username)
    {
        if (in_array(strtolower($username), $this->names2ban, true)) {
            $this->trigger_instant('w4wp_login_disabled_banned_username', $username);
        }

        $user = new \WP_Error('invalidcombo', __('<strong>NOTICE</strong>: Login is disabled for now.'));
        $this->trigger('w4wp_login_disabled', $username);

        return $user;
    }

    public function disable_user_login_js()
    {
        print '<script type="text/javascript">setTimeout(function(){
            try{document.getElementById("wp-submit").setAttribute("disabled", "disabled");}
            catch(e){}}, 0);</script>';
    }

    public function login_failed($username)
    {
        $this->trigger('w4wp_auth_failed', $username);
    }

    /**
     * Ban blacklisted usernames and authenticated XML-RPC.
     *
     * @param \WP_User|\WP_Error|null $user
     * @param string $username
     * @return \WP_User|\WP_Error|null
     */
    public function before_login($user, $username)
    {
        // Only act on login.
        if ($user instanceof \WP_User) {
            return $user;
        }

        if (in_array(strtolower($username), $this->names2ban, true)) {
            $this->trigger_instant('w4wp_banned_username', $username);
        }

        if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
            $this->trigger_instant('w4wp_xmlrpc_login', $username);
        }

        return $user;
    }

    /**
     * Make login with short details fail.
     *
     * @param \WP_User|\WP_Error $user
     * @param string $password
     * @return \WP_User|\WP_Error
     */
    public function authentication_strength($user, $password)
    {
        // Do not touch previous errors.
        if (! $user instanceof \WP_User) {
            return $user;
        }

        $min_password_length = user_can($user, 'list_users') ? $this->secure_min_password_length : $this->min_password_length;

        if (mb_strlen($user->user_login) < $this->min_username_length) {
            $user = new \WP_Error('invalid_username', __('<strong>ERROR</strong>: Sorry, that username is not allowed.'));
        }

        if (mb_strlen($password) < $min_password_length) {
            $user = new \WP_Error('incorrect_password', __('<strong>ERROR</strong>: The password you entered is too short.'));
        }

        return $user;
    }

    /**
     * Masquerade login page as missing.
     */
    public function login()
    {
        status_header(404);
    }

    /**
     * Add rel="nofollow" to login/register links.
     *
     * @param \WP_Admin_Bar $admin_bar
     */
    public function admin_bar($admin_bar)
    {
        $admin_bar_nodes = $admin_bar->get_nodes();
        if (!is_array($admin_bar_nodes)) {
            return;
        }

        foreach ($admin_bar_nodes as $id => $node) {
            if (!is_string($node->href) || strpos($node->href, '/wp-login.php') === false) {
                continue;
            }

            $admin_bar->remove_menu($id);
            $node->meta['rel'] = 'nofollow';
            $admin_bar->add_menu($node);
        }
    }

    /**
     * @param int $user_id
     */
    public function after_register($user_id)
    {
        $user = get_user_by('id', $user_id);
        \assert($user instanceof \WP_User);

        $this->trigger('registered', $user->user_login, 'info', 'WordPress auth: ');
    }

    /**
     * @param string $username
     * @param \WP_User $user
     */
    public function after_login($username, $user)
    {
        if (!is_a($user, 'WP_User')) {
            return;
        }

        $this->trigger('authenticated', $username, 'info', 'WordPress auth: ');
    }

    public function logout($user_id)
    {
        $user = get_user_by('id', $user_id);
        \assert($user instanceof \WP_User);

        // @TODO $user->user_login on profile deletion
        $this->trigger('logged_out', $user->user_login, 'info', 'WordPress auth: ');
    }

    /**
     * Catch lost password action.
     *
     * @param string $username
     */
    public function lostpass($username)
    {
        if (trim($username) === '') {
            $this->trigger('lost_pass_empty', $username, 'warn');
        }

        $this->trigger('lost_pass', $username, 'warn', 'WordPress auth: ');
    }

    /**
     * WordPress directory requests from robots.
     */
    public function robot_403()
    {
        $ua = array_key_exists('HTTP_USER_AGENT', $_SERVER) ? $_SERVER['HTTP_USER_AGENT'] : '';
        $request_path = (string)parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        $wp_dirs = sprintf('wp-admin|wp-includes|wp-content|%s', basename(WP_CONTENT_DIR));
        $uploads = wp_upload_dir();
        $uploads_base = basename($uploads['baseurl']);
        $cache = sprintf('%s/cache', basename(WP_CONTENT_DIR));

        // Don't have to handle wp-includes/ms-files.php:12
        // It does SHORTINIT, no mu-plugins get loaded
        if (
            !$this->is_robot($ua)
            // Not a whitelisted crawler
            || $this->is_crawler($ua) !== false
            // Request to a WordPress directory
            || preg_match('/\/(' . $wp_dirs . ')\//i', $request_path) !== 1
            // Exclude missing media files
            //      and stale cache items
            //      but not `*.pHp*`
            || (
                (
                    strstr($request_path, $uploads_base) !== false
                    || strstr($request_path, $cache) !== false
                )
                && stristr($request_path, '.php') === false
            )
            // Somehow logged in?
            || is_user_logged_in()
        ) {
            return;
        }

        $this->trigger_instant('w4wp_robot_403', $request_path);
    }

    /**
     * Set our callback in wp_die_ajax.
     *
     * @param callable $function
     * @return callable
     */
    public function wp_die_ajax($function)
    {
        // Remember the previous handler
        $this->wp_die_ajax_handler = $function;

        return [$this, 'wp_die_ajax_handler'];
    }

    /**
     * Catch wp_die_ajax errors.
     *
     * @param string|int|\WP_Error $message
     * @param string|int $title
     * @param string|int|array<mixed> $args
     */
    public function wp_die_ajax_handler($message, $title, $args)
    {
        // wp-admin/includes/ajax-actions.php returns -1 on security breach
        if (
            !(is_scalar($message) || $this->is_whitelisted_error($message))
            || (is_int($message) && $message < 0)
        ) {
            $this->trigger(
                'w4wp_wpdie_ajax',
                $message instanceof \WP_Error ? $message->get_error_message() : $message
            );
        }

        // Call previous handler
        // phpcs:ignore NeutronStandard.Functions.DisallowCallUserFunc.CallUserFunc
        call_user_func($this->wp_die_ajax_handler, $message, $title, $args);
    }

    /**
     * Set our callback in wp_die_xmlrpc.
     *
     * @param callable $function
     * @return callable
     */
    public function wp_die_xmlrpc($function)
    {
        // Remember the previous handler
        $this->wp_die_xmlrpc_handler = $function;

        return [$this, 'wp_die_xmlrpc_handler'];
    }

    /**
     * Catch wp_die_xmlrpc errors.
     *
     * @param string|\WP_Error $message
     * @param string|int $title
     * @param string|int|array<mixed> $args
     */
    public function wp_die_xmlrpc_handler($message, $title, $args)
    {
        if (!empty($message)) {
            $this->trigger(
                'w4wp_wpdie_xmlrpc',
                $message instanceof \WP_Error ? $message->get_error_message() : $message
            );
        }

        // Call previous handler
        // phpcs:ignore NeutronStandard.Functions.DisallowCallUserFunc.CallUserFunc
        call_user_func($this->wp_die_xmlrpc_handler, $message, $title, $args);
    }

    /**
     * Set our callback in wp_die.
     *
     * @param callable $function
     * @return callable
     */
    public function wp_die($function)  // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
    {
        // Remember the previous handler
        $this->wp_die_handler = $function;

        return [$this, 'wp_die_handler'];
    }

    /**
     * Catch wp_die errors.
     *
     * @param string|\WP_Error $message
     * @param string|int $title
     * @param string|int|array<mixed> $args
     */
    public function wp_die_handler($message, $title, $args)
    {
        if (!empty($message)) {
            $this->trigger(
                'w4wp_wpdie',
                $message instanceof \WP_Error ? $message->get_error_message() : $message
            );
        }

        // Call previous handler
        // phpcs:ignore NeutronStandard.Functions.DisallowCallUserFunc.CallUserFunc
        call_user_func($this->wp_die_handler, $message, $title, $args);
    }

    private function is_whitelisted_error($error)
    {

        if (! is_wp_error($error)) {
            return false;
        }

        $whitelist = [
            'themes_api_failed',
            'plugins_api_failed',
            'translations_api_failed',
        ];

        return in_array($error->get_error_code(), $whitelist, true);
    }

    public function hook_all_action()
    {
        // Don't slow down everything
        if (!isset($_REQUEST['action'])) {
            return;
        }

        add_action('all', [$this, 'unknown_action'], 0);
    }

    public function unknown_action($tag)
    {
        global $wp_actions;
        global $wp_filter;

        // Check tag first to speed things up
        if (
            substr($tag, 0, 8) !== 'wp_ajax_'
            && substr($tag, 0, 11) !== 'admin_post_'
        ) {
            return;
        }

        $whitelisted_actions = [
            'wp_ajax_nopriv_wp-remove-post-lock',
            'wp_ajax_nopriv_SimpleHistoryNewRowsNotifier',
            'wp_ajax_crop_image_pre_save',
        ];

        // Actions only, not filters, not registered ones, except whitelisted ones
        // Actions are basically filters
        if (
            !is_array($wp_actions)
            || !array_key_exists($tag, $wp_actions)
            || !is_array($wp_filter)
            || array_key_exists($tag, $wp_filter)
            || in_array($tag, $whitelisted_actions, true)
        ) {
            return;
        }

        $this->trigger_instant('w4wp_admin_action_unknown', $tag);
    }

    public function spam_hiddenfield($text)
    {
        $this->trigger_instant('w4wp_spam_hiddenfield', $text);
    }

    public function spam_mx($domain)
    {
        $this->trigger('w4wp_spam_mx', $domain, 'warn');
    }

    public function nfrt_robot_trap($message)
    {
        $this->trigger_instant('w4wp_nfrt_robot_trap', $message);
    }

    /**
     * Test user agent string for robots.
     *
     * Robots are everyone except modern browsers.
     *
     * @see http://www.useragentstring.com/pages/useragentstring.php?typ=Browser
     * @param string $ua
     * @return bool
     */
    private function is_robot($ua)
    {
        return (substr($ua, 0, 11) !== 'Mozilla/5.0')
            && (substr($ua, 0, 34) !== 'Mozilla/4.0 (compatible; MSIE 8.0;')
            && (substr($ua, 0, 34) !== 'Mozilla/4.0 (compatible; MSIE 7.0;')
            && (substr($ua, 0, 10) !== 'Opera/9.80');
            // phpcs:ignore Squiz.PHP.CommentedOutCode.Found
            // && 1 !== preg_match('#^\S+ Linux/\S+ Android/\S+ Release/\S+ Browser/AppleWebKit\S+ Chrome/\S+ Mobile Safari/\S+ System/Android \S+$#', $ua)
    }

    /**
     * Verify Bingbot.
     *
     * @see https://www.bing.com/webmaster/help/how-to-verify-bingbot-3905dc26
     * @param string $ua
     * @param string $ip
     * @return bool
     */
    private function is_msnbot($ua, $ip)
    {
        if (strpos($ua, 'bingbot') === false && strpos($ua, 'BingPreview') === false) {
            return false;
        }

        // No dot at end of host name!
        $host = gethostbyaddr($ip);
        if ($host === false || substr($host, -15) !== '.search.msn.com') {
            return false;
        }

        $rev_ip = gethostbyname($host);

        return $rev_ip === $ip;
    }

    /**
     * Verify Googlebot.
     *
     * @see https://support.google.com/webmasters/answer/80553
     * @see https://support.google.com/webmasters/answer/1061943
     * @param string $ua
     * @param string $ip
     * @return bool
     */
    private function is_googlebot($ua, $ip)
    {
        if (strpos($ua, 'Googlebot') === false && strpos($ua, 'AdsBot-Google') === false) {
            return false;
        }

        // No dot at end of host name!
        $host = gethostbyaddr($ip);
        if (
            $host === false
            || (substr($host, -14) !== '.googlebot.com' && substr($host, -11) !== '.google.com')
        ) {
            return false;
        }

        $rev_ip = gethostbyname($host);

        return $rev_ip === $ip;
    }

    /**
     * Verify YandexBot.
     *
     * @see https://yandex.com/support/webmaster/robot-workings/check-yandex-robots.html
     * @param string $ua
     * @param string $ip
     * @return bool
     */
    private function is_yandexbot($ua, $ip)
    {
        if (strpos($ua, 'Yandex') === false) {
            return false;
        }

        // No dot at end of host name!
        $host = gethostbyaddr($ip);
        if (
            $host === false
            || (
                substr($host, -10) !== '.yandex.ru'
                && substr($host, -11) !== '.yandex.net'
                && substr($host, -11) !== '.yandex.com'
            )
        ) {
            return false;
        }

        $rev_ip = gethostbyname($host);

        return $rev_ip === $ip;
    }

    /**
     * Verify Google image proxy.
     *
     * @see https://gmail.googleblog.com/2013/12/images-now-showing.html
     * @param string $ua
     * @param string $ip
     * @return bool
     */
    private function is_google_proxy($ua, $ip)
    {
        if (strpos($ua, 'via ggpht.com GoogleImageProxy') === false) {
            return false;
        }

        // No dot at end of host name!
        $host = gethostbyaddr($ip);
        if ($host === false || preg_match('/^google-proxy-[0-9-]+\.google\.com$/', $host) !== 1) {
            return false;
        }

        $rev_ip = gethostbyname($host);

        return $rev_ip === $ip;
    }

    /**
     * Verify SeznamBot.
     *
     * @see https://napoveda.seznam.cz/en/full-text-search/seznambot-crawler/
     * @param string $ua
     * @param string $ip
     * @return bool
     */
    private function is_seznambot($ua, $ip)
    {
        if (strpos($ua, 'SeznamBot') === false) {
            return false;
        }

        // No dot at end of host name!
        $host = gethostbyaddr($ip);
        if ($host === false || preg_match('/^seznam\.cz$/', $host) !== 1) {
            return false;
        }

        $rev_ip = gethostbyname($host);

        return $rev_ip === $ip;
    }

    /**
     * Verify ContentKing crawler.
     *
     * [...document.querySelector('#h_01J9VKQ42W7X3ZV4TQD82X3TDE').parentElement.nextElementSibling.querySelectorAll('li')].map(li => li.textContent.trim()).join("\n")
     *
     * @see https://support.conductor.com/hc/en-us/articles/34171452372115-Monitoring-FAQs
     * @param string $ua
     * @param string $ip
     * @return bool
     */
    private function is_contentking($ua, $ip)
    {
        $ranges = [
            '89.149.192.96/27',
            '81.17.55.192/27',
            '23.105.12.64/27',
            '173.234.16.0/28',
        ];

        if (strpos($ua, 'whatis.contentkingapp.com') === false) {
            return false;
        }

        foreach ($ranges as $range) {
            if ($this->ip_in_range($ip, $range)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Verify Facebook crawler checking links sent by users.
     *
     * Install facebook-crawler-ip-update.sh
     *
     * @see https://developers.facebook.com/docs/sharing/webmasters/crawler/
     * @param string $ua
     * @return bool
     */
    private function is_facebookcrawler($ua)
    {
        // facebook-crawler-ip-update.sh blocks fake Facebook crawlers.
        return strpos($ua, 'facebookexternalhit/') === 0;
    }

    /**
     * TODO Verify Baiduspider
     *     *.baidu.com or *.baidu.jp
     *
     * @see https://help.baidu.com/question?prod_id=99&class=0&id=3001
     */

    /**
     * TODO Verify Linguee Bot (search engine for translations)
     *     "Linguee Bot"
     *     wget -qO- "https://www.linguee.com/bot"|sed -n -e '/^<pre/,/^<\/pre/s#^[0-9.]\+$#&#p'
     *
     * @see https://www.linguee.com/bot
     */

    /**
     * Whether the user agent is a web crawler.
     *
     * @param string $ua
     * @return string|bool
     */
    private function is_crawler($ua)
    {
        // Humans and web crawling bots.
        if (
            defined('W4WP_MSNBOT') && W4WP_MSNBOT
            && $this->is_msnbot($ua, $_SERVER['REMOTE_ADDR'])
        ) {
            // Identified Bingbot.
            return 'w4wp_msnbot_404';
        }

        if (
            defined('W4WP_GOOGLEBOT') && W4WP_GOOGLEBOT
            && $this->is_googlebot($ua, $_SERVER['REMOTE_ADDR'])
        ) {
            // Identified Googlebot.
            return 'w4wp_googlebot_404';
        }

        if (
            defined('W4WP_YANDEXBOT') && W4WP_YANDEXBOT
            && $this->is_yandexbot($ua, $_SERVER['REMOTE_ADDR'])
        ) {
            // Identified Yandexbot.
            return 'w4wp_yandexbot_404';
        }

        if (
            defined('W4WP_GOOGLEPROXY') && W4WP_GOOGLEPROXY
            && $this->is_google_proxy($ua, $_SERVER['REMOTE_ADDR'])
        ) {
            // Identified GoogleProxy.
            return 'w4wp_googleproxy_404';
        }

        if (
            defined('W4WP_SEZNAMBOT') && W4WP_SEZNAMBOT
            && $this->is_seznambot($ua, $_SERVER['REMOTE_ADDR'])
        ) {
            // Identified SeznamBot.
            return 'w4wp_seznambot_404';
        }

        if (
            defined('W4WP_CONTENTKING') && W4WP_CONTENTKING
            && $this->is_contentking($ua, $_SERVER['REMOTE_ADDR'])
        ) {
            // Identified ContentKing crawler.
            return 'w4wp_contentking_404';
        }

        if (
            defined('W4WP_FACEBOOKCRAWLER') && W4WP_FACEBOOKCRAWLER
            && $this->is_facebookcrawler($ua)
        ) {
            // Identified Facebook crawler.
            return 'w4wp_facebookcrawler_404';
        }

        // Unidentified.
        return false;
    }

    /**
     * Whether the IPv4 address is in the given range.
     *
     * @param string $ip
     * @param string $range
     * @return bool
     */
    private function ip_in_range($ip, $range)
    {
        if (strpos($range, '/') === false) {
            $range .= '/32';
        }

        $ip_decimal = ip2long($ip);

        // Range is in CIDR format
        list($range_ip, $netmask) = explode('/', $range, 2);
        $range_decimal = ip2long($range_ip);
        $wildcard_decimal = pow(2, (32 - (int)$netmask)) - 1;
        $netmask_decimal = ~ $wildcard_decimal;

        return ($ip_decimal & $netmask_decimal) === ($range_decimal & $netmask_decimal);
    }

    /**
     * Encode and sanitize log data.
     *
     * @param mixed $data
     *
     * @return string
     */
    private function esc_log($data)
    {
        $escaped = json_encode($data, JSON_UNESCAPED_SLASHES);
        if ($escaped === false) {
            return ' ';
        }

        // Limit length
        $escaped = mb_substr($escaped, 0, 500, 'utf-8');
        // New lines to "|"
        $escaped = str_replace(["\n", "\r"], '|', $escaped);
        // Replace non-printables with "¿"
        $escaped = preg_replace('/[^\P{C}]+/u', "\xC2\xBF", $escaped);

        return sprintf('(%s)', $escaped);
    }

    /**
     * Translate Apache log levels for Simple History plugin.
     *
     * @param string $apache_level
     *
     * @return string
     */
    private function translate_apache_level($apache_level)
    {
        $levels = [
            'emerg' => 'emergency',
            'alert' => 'alert',
            'crit' => 'critical',
            'error' => 'error',
            'warn' => 'warning',
            'notice' => 'notice',
            'info' => 'info',
            'debug' => 'debug',
        ];

        return $levels[$apache_level] ?? 'info';
    }

    private function exit_with_instructions()
    {
        $doc_root = array_key_exists('DOCUMENT_ROOT', $_SERVER) ? $_SERVER['DOCUMENT_ROOT'] : ABSPATH;

        $iframe_msg = sprintf(
            '<p style="font:14px \'Open Sans\',sans-serif">
            <strong style="color:#DD3D36">ERROR:</strong> This is <em>not</em> a normal plugin,
            and it should not be activated as one.<br />
            Instead, <code style="font-family:Consolas,Monaco,monospace;background:rgba(0,0,0,0.07)">%s</code>
            must be copied to <code style="font-family:Consolas,Monaco,monospace;background:rgba(0,0,0,0.07)">%s</code></p>',
            esc_html(str_replace($doc_root, '', __FILE__)),
            esc_html(str_replace($doc_root, '', trailingslashit(WPMU_PLUGIN_DIR)) . basename(__FILE__))
        );

        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        exit($iframe_msg);
    }
}
