<?php declare( strict_types = 1 );
/**
 * Core events specific part of WAF for WordPress.
 *
 * @package Waf4wordpress
 *
 * @wordpress-plugin
 * Plugin Name: WAF for WordPress (MU)
 * Version:     5.0.4
 * Description: Stop WordPress related attacks and trigger Fail2ban.
 * Plugin URI:  https://github.com/szepeviktor/wordpress-fail2ban
 * License:     The MIT License (MIT)
 * Author:      Viktor Szépe
 * GitHub Plugin URI: https://github.com/szepeviktor/wordpress-fail2ban
 * Constants: W4WP_DISABLE_LOGIN
 * Constants: W4WP_ALLOW_REDIRECT
 * Constants: W4WP_DISABLE_REST_API
 * Constants: W4WP_ONLY_OEMBED
 * Constants: W4WP_MSNBOT
 * Constants: W4WP_GOOGLEBOT
 * Constants: W4WP_YANDEXBOT
 * Constants: W4WP_GOOGLEPROXY
 * Constants: W4WP_SEZNAMBOT
 */

namespace Waf4WordPress;

if ( ! function_exists( 'add_filter' ) ) {
    // phpcs:set WordPress.PHP.DevelopmentFunctions exclude[] error_log
    error_log(
        'Break-in attempt detected: w4wp_direct_access '
        . addslashes( isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '' )
    );
    if ( 0 !== ob_get_level() ) {
        ob_end_clean();
    }
    if ( ! headers_sent() ) {
        header( 'Status: 403 Forbidden' );
        header( 'HTTP/1.1 403 Forbidden', true, 403 );
        header( 'Connection: Close' );
    }
    exit;
}

/**
 * WAF for WordPress Must-Use part.
 *
 * To disable login completely copy this into your wp-config.php:
 *
 *     define( 'W4WP_DISABLE_LOGIN', true );
 *
 * To allow unlimited canonical redirections copy this into your wp-config.php:
 *
 *     define( 'W4WP_ALLOW_REDIRECT', true );
 *
 * @see README.md
 */
final class Core_Events {

    private $prefix = 'Malicious traffic detected: ';
    private $prefix_instant = 'Break-in attempt detected: ';
    private $wp_die_ajax_handler;
    private $wp_die_xmlrpc_handler;
    private $wp_die_handler;
    private $is_redirect = false;
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
    private $min_password_length = 12;

    public function __construct() {

        // Exit on local access
        // Don't run on install and upgrade
        if ( php_sapi_name() === 'cli'
            || $_SERVER['REMOTE_ADDR'] === $_SERVER['SERVER_ADDR']
            || ( defined( 'WP_INSTALLING' ) && WP_INSTALLING )
        ) {
            return;
        }

        // Prevent usage as a normal plugin in wp-content/plugins
        if ( 0 !== did_action( 'muplugins_loaded' ) ) {
            $this->exit_with_instructions();
        }

        // REST API
        if ( defined( 'W4WP_DISABLE_REST_API' ) && W4WP_DISABLE_REST_API ) {
            // Remove core actions
            // Source: https://plugins.trac.wordpress.org/browser/disable-json-api/trunk/disable-json-api.php
            remove_action( 'xmlrpc_rsd_apis', 'rest_output_rsd' );
            remove_action( 'wp_head', 'rest_output_link_wp_head', 10 );
            remove_action( 'template_redirect', 'rest_output_link_header', 11 );
            if ( defined( 'W4WP_ONLY_OEMBED' ) && W4WP_ONLY_OEMBED ) {
                add_filter( 'rest_pre_dispatch', [ $this, 'rest_api_only_oembed' ], 0, 3 );
            } else {
                // Remove oembed core action
                remove_action( 'wp_head', 'wp_oembed_add_discovery_links' );
                add_filter( 'rest_authentication_errors', [ $this, 'rest_api_disabled' ], 99999 );
            }
        } else {
            add_filter( 'oembed_response_data', [ $this, 'oembed_filter' ], 0 );
            add_filter( 'rest_post_dispatch', [ $this, 'rest_filter' ], 0, 3 );
        }

        // Don't redirect to admin
        remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );

        // Login related
        add_action( 'login_init', [ $this, 'login' ] );
        add_action( 'wp_logout', [ $this, 'logout' ] );
        add_action( 'retrieve_password', [ $this, 'lostpass' ] );
        if ( defined( 'W4WP_DISABLE_LOGIN' ) && W4WP_DISABLE_LOGIN ) {
            // Disable login
            add_action( 'login_head', [ $this, 'disable_user_login_js' ] );
            add_filter( 'authenticate', [ $this, 'authentication_disabled' ], 0, 2 );
        } else {
            // Prevent registering with banned username
            add_filter( 'validate_username', [ $this, 'banned_username' ], 99999, 2 );
            // wp-login, XMLRPC login (any authentication)
            add_action( 'wp_login_failed', [ $this, 'login_failed' ] );
            add_filter( 'authenticate', [ $this, 'before_login' ], 0, 2 );
            add_filter( 'wp_authenticate_user', [ $this, 'authentication_strength' ], 99999, 2 );
            add_action( 'wp_login', [ $this, 'after_login' ], 0, 2 );
        }

        // Don't use shortlinks which are redirected to canonical URL-s
        add_filter( 'pre_get_shortlink', '__return_empty_string' );

        // Non-existent URLs
        add_action( 'init', [ $this, 'url_hack' ] );
        if ( ! ( defined( 'W4WP_ALLOW_REDIRECT' ) && W4WP_ALLOW_REDIRECT ) ) {
            add_filter( 'redirect_canonical', [ $this, 'redirect' ], 1, 2 );
        }

        // Robot and human 404
        add_action( 'plugins_loaded', [ $this, 'robot_403' ], 0 );
        // BuddyPress fiddles with is_404 at priority 10
        add_action( 'template_redirect', [ $this, 'wp_404' ], 11 );

        // Non-empty wp_die messages
        add_filter( 'wp_die_ajax_handler', [ $this, 'wp_die_ajax' ], 1 );
        add_filter( 'wp_die_xmlrpc_handler', [ $this, 'wp_die_xmlrpc' ], 1 );
        add_filter( 'wp_die_handler', [ $this, 'wp_die' ], 1 );

        // Unknown admin-ajax and admin-post action
        // admin_init is done just before AJAX actions
        add_action( 'admin_init', [ $this, 'hook_all_action' ] );

        // Ban spammers (Contact Form 7 Robot Trap)
        add_action( 'robottrap_hiddenfield', [ $this, 'spam_hiddenfield' ] );
        add_action( 'robottrap_mx', [ $this, 'spam_mx' ] );

        // Ban bad robots (Nofollow Robot Trap)
        add_action( 'nofollow_robot_trap', [ $this, 'nfrt_robot_trap' ] );
    }

    private function trigger_instant( $slug, $message, $level = 'crit' ) {

        // Trigger Miniban at first
        if ( class_exists( '\Miniban' ) ) {
            if ( true !== \Miniban::ban() ) {
                $this->enhanced_error_log( 'Miniban operation failed.' );
            }
        }

        $this->trigger( $slug, $message, $level, $this->prefix_instant );

        // Remove session
        remove_action( 'wp_logout', [ $this, 'logout' ] );
        wp_logout();

        // Respond
        if ( 0 !== ob_get_level() ) {
            ob_end_clean();
        }
        if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
            $this->fake_xmlrpc();
        } elseif ( ! headers_sent() ) {
            if ( 'wp-login.php' === $GLOBALS['pagenow'] && isset( $_POST['log'] ) ) {
                $this->fake_wplogin();
            } else {
                $this->ban();
            }
        }

        exit;
    }

    private function trigger( $slug, $message, $level = 'error', $prefix = '' ) {

        if ( '' === $prefix ) {
            $prefix = $this->prefix;
        }

        // Trigger Fail2ban
        $error_msg = sprintf(
            '%s%s %s',
            $prefix,
            $slug,
            $this->esc_log( $message )
        );
        $this->enhanced_error_log( $error_msg, $level );

        // Report to Sucuri Scan
        if ( class_exists( '\SucuriScanEvent' ) ) {
            if ( true !== \SucuriScanEvent::report_critical_event( $error_msg ) ) {
                // phpcs:set WordPress.PHP.DevelopmentFunctions exclude[] error_log
                error_log( 'Sucuri Scan report event failure.' );
            }
        }

        // Report to Simple History
        if ( function_exists( 'SimpleLogger' ) ) {
            $simple_level = $this->translate_apache_level( $level );
            $context = [
                '_security' => 'WAF4WordPress',
                '_server_request_method' => $this->esc_log( $_SERVER['REQUEST_METHOD'] ),
            ];
            if ( array_key_exists( 'HTTP_USER_AGENT', $_SERVER ) ) {
                $context['_server_http_user_agent'] = $this->esc_log( $_SERVER['HTTP_USER_AGENT'] );
            }
            if ( ! class_exists( '\SimpleLogger' ) ) {
                \SimpleHistory::get_instance()->load_loggers();
            }
            \SimpleLogger()->log( $simple_level, $error_msg, $context );
        }

    }

    private function ban() {

        header( 'Status: 403 Forbidden' );
        header( 'HTTP/1.1 403 Forbidden', true, 403 );
        header( 'Connection: Close' );
        header( 'Cache-Control: max-age=0, private, no-store, no-cache, must-revalidate' );
        header( 'X-Robots-Tag: noindex, nofollow' );
        header( 'Content-Type: text/html' );
        header( 'Content-Length: 0' );
    }

    private function fake_wplogin() {

        $server_name = isset( $_SERVER['SERVER_NAME'] )
            ? $_SERVER['SERVER_NAME']
            : $_SERVER['HTTP_HOST'];
        $username = trim( $_POST['log'] );
        $expire = time() + 3600;
        $token = substr( hash_hmac( 'sha256', (string) rand(), 'token' ), 0, 43 );
        $hash = hash_hmac( 'sha256', (string) rand(), 'hash' );
        $auth_cookie = $username . '|' . $expire . '|' . $token . '|' . $hash;
        $authcookie_name = 'wordpress_' . md5( 'authcookie' );
        $loggedincookie_name = 'wordpress_logged_in_' . md5( 'cookiehash' );

        header( 'Cache-Control: max-age=0, private, no-store, no-cache, must-revalidate' );
        header( 'X-Robots-Tag: noindex, nofollow' );
        setcookie( $authcookie_name, $auth_cookie, $expire, '/brake/wp_content/plugins', '', false, true );
        setcookie( $authcookie_name, $auth_cookie, $expire, '/brake/wp-admin', '', false, true );
        setcookie( $loggedincookie_name, $auth_cookie, $expire, '/', '', false, true );
        header( 'Location: ' . home_url( '/brake/wp-admin/' ) );
    }

    private function fake_xmlrpc() {

        header( 'Connection: Close' );
        header( 'Cache-Control: max-age=0, private, no-store, no-cache, must-revalidate' );
        header( 'X-Robots-Tag: noindex, nofollow' );
        header( 'Content-Type: text/xml; charset=UTF-8' );

        printf(
            '<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value>
      <array><data>
  <value><struct>
  <member><name>isAdmin</name><value><boolean>1</boolean></value></member>
  <member><name>url</name><value><string>%s</string></value></member>
  <member><name>blogid</name><value><string>1</string></value></member>
  <member><name>blogName</name><value><string>brake</string></value></member>
  <member><name>xmlrpc</name><value><string>%s</string></value></member>
</struct></value>
</data></array>
      </value>
    </param>
  </params>
</methodResponse>
',
            esc_url( home_url( '/' ) ),
            esc_url( home_url( '/brake/xmlrpc.php' ) )
        );
    }

    private function enhanced_error_log( $message = '', $level = 'error' ) {

        // phpcs:ignore Squiz.PHP.CommentedOutCode
        /*
        // log_errors PHP directive does not actually disable logging
        $log_enabled = ( '1' === ini_get( 'log_errors' ) );
        if ( ! $log_enabled || '' !== $log_destination ) {
        */

        // Add entry point, correct when auto_prepend_file is empty
        $included_files = get_included_files();
        $first_included_file = reset( $included_files );
        $error_msg = sprintf(
            '%s <%s',
            $message,
            $this->esc_log( sprintf( '%s:%s', $_SERVER['REQUEST_METHOD'], $first_included_file ) )
        );

        /**
         * Add client data to log message if SAPI does not add it.
         *
         * level, IP address, port, referer
         */
        $log_destination = function_exists( 'ini_get' ) ? ini_get( 'error_log' ) : '';
        if ( '' !== $log_destination ) {
            if ( array_key_exists( 'HTTP_REFERER', $_SERVER ) ) {
                $referer = sprintf( ', referer: %s', $this->esc_log( $_SERVER['HTTP_REFERER'] ) );
            } else {
                $referer = '';
            }

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
        error_log( $error_msg );
    }

    public function wp_404() {

        if ( ! is_404() ) {
            return;
        }

        $ua = array_key_exists( 'HTTP_USER_AGENT', $_SERVER ) ? $_SERVER['HTTP_USER_AGENT'] : '';

        // HEAD probing resulting in a 404
        if ( false !== stripos( $_SERVER['REQUEST_METHOD'], 'HEAD' ) ) {
            $this->trigger_instant( 'w4wp_404_head', $_SERVER['REQUEST_URI'] );
        }

        $is_crawler = $this->is_crawler( $ua );

        // Don't run 404 template for robots
        if ( $this->is_robot( $ua ) && false === $is_crawler ) {

            $this->trigger( 'w4wp_404_robot', $_SERVER['REQUEST_URI'], 'info' );

            if ( 0 !== ob_get_level() ) {
                ob_end_clean();
            }
            if ( ! headers_sent() ) {
                header( 'Status: 404 Not Found' );
                status_header( 404 );
                header( 'X-Robots-Tag: noindex, nofollow' );
                header( 'Connection: Close' );
                header( 'Content-Length: 0' );
                nocache_headers();
            }

            exit;
        }

        // Humans and web crawling bots
        if ( is_string( $is_crawler ) ) {
            $this->trigger( $is_crawler, $_SERVER['REQUEST_URI'], 'info', 'Crawler 404: ' );
        } else {
            $this->trigger( 'w4wp_404', $_SERVER['REQUEST_URI'], 'info' );
        }
    }

    /**
     * Filter oEmbed requests.
     *
     * @param array $data
     * @return array $data
     */
    public function oembed_filter( $data ) {

        if ( isset( $data['author_url'] ) ) {
            unset( $data['author_url'] );
        }

        return $data;
    }

    /**
     * Filter REST requests.
     *
     * @param \WP_HTTP_Response|\WP_Error $response
     * @param \WP_REST_Server $server
     * @param \WP_REST_Request $request
     * @return \WP_HTTP_Response|\WP_Error
     */
    public function rest_filter( $response, $server, $request ) {

        if ( $response instanceof \WP_HTTP_Response ) {
            $status = $response->get_status();
            $method = $request->get_method();
            $route = $request->get_route();
            $data = $response->get_data();
            $is_user_listing = ( $server::READABLE === $method && '/wp/v2/users' === substr( $route, 0, 12 ) );
            // Disable any kind of unauthorized user listing
            // Authenticated REST requests must have a nonce
            if ( ! current_user_can( 'list_users' ) && $is_user_listing ) {
                $message = sprintf( '<%s:%s', $method, $route );
                $this->trigger_instant( 'w4wp_rest_user_listing', $message );
            }
            // Detect HTTP/404 and 403
            switch ( $status ) {
                case 403:
                case 404:
                    $message = sprintf( '%s <%s:%s', $data['code'], $method, $route );
                    $this->trigger( 'w4wp_rest_client_error', $message );
                    break;
            }
        } else {
            // @TODO Handle non-WP_HTTP_Response errors
            $this->trigger( 'w4wp_rest_error', 'Not a REST response but a ' . get_class( $response ) );
        }

        return $response;
    }

    public function url_hack() {

        if ( '//' === substr( $_SERVER['REQUEST_URI'], 0, 2 ) ) {
            // Remember this to prevent double-logging in redirect()
            $this->is_redirect = true;
            $this->trigger( 'w4wp_url_hack', $_SERVER['REQUEST_URI'] );
        }
    }

    public function rest_api_disabled( $enabled ) {

        $this->trigger( 'w4wp_rest_api_disabled', $_SERVER['REQUEST_URI'], 'notice' );

        return new \WP_Error(
            'rest_no_route',
            __( 'No route was found matching the URL and request method' ),
            [ 'status' => 404 ]
        );
    }

    public function rest_api_only_oembed( $null, $that, $request ) {

        // Spec: https://oembed.com/#section2.2
        if ( '/oembed/1.0/embed' === $request->get_route() ) {
            return $null;
        }

        $this->trigger( 'w4wp_rest_api_not_oembed', $_SERVER['REQUEST_URI'], 'notice' );

        $response_data = [
            'code' => 'rest_no_route',
            'message' => __( 'No route was found matching the URL and request method' ),
            'data' => [ 'status' => 404 ],
        ];

        return new \WP_REST_Response( $response_data, 404 );
    }

    public function redirect( $redirect_url, $requested_url ) {

        if ( false === $this->is_redirect ) {
            $this->trigger( 'w4wp_redirect', $requested_url, 'notice' );
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
    public function banned_username( $valid, $username ) {

        if ( in_array( strtolower( $username ), $this->names2ban, true )
            || mb_strlen( $username ) < $this->min_username_length
        ) {
            $this->trigger( 'w4wp_register_banned_username', $username, 'notice' );
            $valid = false;
        }

        return $valid;
    }

    public function authentication_disabled( $user, $username ) {

        if ( in_array( strtolower( $username ), $this->names2ban, true ) ) {
            $this->trigger_instant( 'w4wp_login_disabled_banned_username', $username );
        }

        $user = new \WP_Error( 'invalidcombo', __( '<strong>NOTICE</strong>: Login is disabled for now.' ) );
        $this->trigger( 'w4wp_login_disabled', $username );

        return $user;
    }

    public function disable_user_login_js() {

        print '<script type="text/javascript">setTimeout(function(){
            try{document.getElementById("wp-submit").setAttribute("disabled", "disabled");}
            catch(e){}}, 0);</script>';
    }

    public function login_failed( $username ) {

        $this->trigger( 'w4wp_auth_failed', $username );
    }

    /**
     * Ban blacklisted usernames and authenticated XML-RPC.
     *
     * @param null|\WP_User|\WP_Error $user
     * @param string $username
     * @return null|\WP_User|\WP_Error
     */
    public function before_login( $user, $username ) {

        // Only act on login.
        if ( $user instanceof \WP_User ) {
            return $user;
        }

        if ( in_array( strtolower( $username ), $this->names2ban, true ) ) {
            $this->trigger_instant( 'w4wp_banned_username', $username );
        }

        if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
            $this->trigger_instant( 'w4wp_xmlrpc_login', $username );
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
    public function authentication_strength( $user, $password ) {

        // Do not touch previous errors.
        if ( ! $user instanceof \WP_User ) {
            return $user;
        }

        if ( mb_strlen( $user->user_login ) < $this->min_username_length ) {
            $user = new \WP_Error( 'invalid_username', __( '<strong>ERROR</strong>: Sorry, that username is not allowed.' ) );
        }
        if ( mb_strlen( $password ) < $this->min_password_length ) {
            $user = new \WP_Error( 'incorrect_password', __( '<strong>ERROR</strong>: The password you entered is too short.' ) );
        }

        return $user;
    }

    /**
     * Masquerade login page as missing.
     */
    public function login() {

        status_header( 404 );
    }

    public function after_login( $username, $user ) {

        if ( is_a( $user, 'WP_User' ) ) {
            $this->trigger( 'authenticated', $username, 'info', 'WordPress auth: ' );
        }
    }

    public function logout() {

        if ( is_user_logged_in() ) {
            $current_user = wp_get_current_user();
            $user = $current_user->user_login;
        } else {
            $user = '';
        }

        $this->trigger( 'logged_out', $user, 'info', 'WordPress auth: ' );
    }

    /**
     * Catch lost password action.
     *
     * @param string $username
     */
    public function lostpass( $username ) {

        if ( '' === trim( $username ) ) {
            $this->trigger( 'lost_pass_empty', $username, 'warn' );
        }

        $this->trigger( 'lost_pass', $username, 'warn', 'WordPress auth: ' );
    }

    /**
     * WordPress directory requests from robots.
     */
    public function robot_403() {

        $ua = array_key_exists( 'HTTP_USER_AGENT', $_SERVER ) ? $_SERVER['HTTP_USER_AGENT'] : '';
        $request_path = (string) parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH );
        $admin_path = parse_url( admin_url(), PHP_URL_PATH );
        $wp_dirs = sprintf( 'wp-admin|wp-includes|wp-content|%s', basename( WP_CONTENT_DIR ) );
        $uploads = wp_upload_dir();
        $uploads_base = basename( $uploads['baseurl'] );
        $cache = sprintf( '%s/cache', basename( WP_CONTENT_DIR ) );

        // Don't have to handle wp-includes/ms-files.php:12
        // It does SHORTINIT, no mu-plugins get loaded
        if ( $this->is_robot( $ua )

            // Not a whitelisted crawler
            && false === $this->is_crawler( $ua )

            // Request to a WordPress directory
            && 1 === preg_match( '/\/(' . $wp_dirs . ')\//i', $request_path )

            // Exclude missing media files
            //      and stale cache items
            //  but not `*.pHp*`
            && ( ( false === strstr( $request_path, $uploads_base )
                    && false === strstr( $request_path, $cache )
                )
                || false !== stristr( $request_path, '.php' )
            )

            // Somehow logged in?
            && ! is_user_logged_in()
        ) {
            $this->trigger_instant( 'w4wp_robot_403', $request_path );
        }
    }

    /**
     * Set our callback in wp_die_ajax.
     *
     * @param callable $function
     * @return callable
     */
    public function wp_die_ajax( $function ) {

        // Remember the previous handler
        $this->wp_die_ajax_handler = $function;

        return [ $this, 'wp_die_ajax_handler' ];
    }

    /**
     * Catch wp_die_ajax errors.
     *
     * @param string|\WP_Error $message
     * @param string|int $title
     * @param string|array|int $args
     */
    public function wp_die_ajax_handler( $message, $title, $args ) {

        // wp-admin/includes/ajax-actions.php returns -1 on security breach
        if ( ! ( is_scalar( $message ) || $this->is_whitelisted_error( $message ) )
            || ( is_int( $message ) && $message < 0 )
        ) {
            $this->trigger( 'w4wp_wpdie_ajax', $message );
        }

        // Call previous handler
        // phpcs:ignore NeutronStandard.Functions.DisallowCallUserFunc.CallUserFunc
        call_user_func( $this->wp_die_ajax_handler, $message, $title, $args );
    }

    /**
     * Set our callback in wp_die_xmlrpc.
     *
     * @param callable $function
     * @return callable
     */
    public function wp_die_xmlrpc( $function ) {

        // Remember the previous handler
        $this->wp_die_xmlrpc_handler = $function;

        return [ $this, 'wp_die_xmlrpc_handler' ];
    }

    /**
     * Catch wp_die_xmlrpc errors.
     *
     * @param string|\WP_Error $message
     * @param string|int $title
     * @param string|array|int $args
     */
    public function wp_die_xmlrpc_handler( $message, $title, $args ) {

        if ( ! empty( $message ) ) {
            $this->trigger( 'w4wp_wpdie_xmlrpc', $message );
        }

        // Call previous handler
        // phpcs:ignore NeutronStandard.Functions.DisallowCallUserFunc.CallUserFunc
        call_user_func( $this->wp_die_xmlrpc_handler, $message, $title, $args );
    }

    /**
     * Set our callback in wp_die.
     *
     * @param callable $function
     * @return callable
     */
    public function wp_die( $function ) { // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

        // Remember the previous handler
        $this->wp_die_handler = $function;

        return [ $this, 'wp_die_handler' ];
    }

    /**
     * Catch wp_die errors.
     *
     * @param string|\WP_Error $message
     * @param string|int $title
     * @param string|array|int $args
     */
    public function wp_die_handler( $message, $title, $args ) {

        if ( ! empty( $message ) ) {
            $this->trigger( 'w4wp_wpdie', $message );
        }

        // Call previous handler
        // phpcs:ignore NeutronStandard.Functions.DisallowCallUserFunc.CallUserFunc
        call_user_func( $this->wp_die_handler, $message, $title, $args );
    }

    private function is_whitelisted_error( $error ) {

        if ( ! is_wp_error( $error ) ) {
            return false;
        }

        $whitelist = [
            'themes_api_failed',
            'plugins_api_failed',
            'translations_api_failed',
        ];
        $code = $error->get_error_code();

        if ( in_array( $code, $whitelist, true ) ) {
            return true;
        }

        return false;
    }

    public function hook_all_action() {

        // Don't slow down everything
        if ( isset( $_REQUEST['action'] ) ) {
            add_action( 'all', [ $this, 'unknown_action' ], 0 );
        }
    }

    public function unknown_action( $tag ) {

        // Check tag first to speed things up
        if ( 'wp_ajax_' === substr( $tag, 0, 8 )
            || 'admin_post_' === substr( $tag, 0, 11 )
        ) {
            global $wp_actions;
            global $wp_filter;

            $whitelisted_actions = [
                'wp_ajax_nopriv_wp-remove-post-lock',
                'wp_ajax_nopriv_SimpleHistoryNewRowsNotifier',
            ];

            // Actions only, not filters, not registered ones, except whitelisted ones
            // Actions are basically filters
            if ( is_array( $wp_actions )
                && array_key_exists( $tag, $wp_actions )
                && is_array( $wp_filter )
                && ! array_key_exists( $tag, $wp_filter )
                && ! in_array( $tag, $whitelisted_actions, true )
            ) {
                $this->trigger_instant( 'w4wp_admin_action_unknown', $tag );
            }
        }
    }

    public function spam_hiddenfield( $text ) {

        $this->trigger_instant( 'w4wp_spam_hiddenfield', $text );
    }

    public function spam_mx( $domain ) {

        $this->trigger( 'w4wp_spam_mx', $domain, 'warn' );
    }

    public function nfrt_robot_trap( $message ) {

        $this->trigger_instant( 'w4wp_nfrt_robot_trap', $message );
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
    private function is_robot( $ua ) {

        return ( ( 'Mozilla/5.0' !== substr( $ua, 0, 11 ) )
            && ( 'Mozilla/4.0 (compatible; MSIE 8.0;' !== substr( $ua, 0, 34 ) )
            && ( 'Mozilla/4.0 (compatible; MSIE 7.0;' !== substr( $ua, 0, 34 ) )
            && ( 'Opera/9.80' !== substr( $ua, 0, 10 ) )
        );
    }

    /**
     * Verify Bingbot.
     *
     * @see https://www.bing.com/webmaster/help/how-to-verify-bingbot-3905dc26
     * @param string $ua
     * @param string $ip
     * @return bool
     */
    private function is_msnbot( $ua, $ip ) {

        if ( false === strpos( $ua, 'bingbot' ) ) {
            return false;
        }

        // No dot at end of host name!
        $host = gethostbyaddr( $ip );
        if ( false === $host || '.search.msn.com' !== substr( $host, -15 ) ) {
            return false;
        }
        $rev_ip = gethostbyname( $host );
        $verified = ( $rev_ip === $ip );

        return $verified;
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
    private function is_googlebot( $ua, $ip ) {

        if ( false === strpos( $ua, 'Googlebot' ) && false === strpos( $ua, 'AdsBot-Google' ) ) {
            return false;
        }

        // No dot at end of host name!
        $host = gethostbyaddr( $ip );
        if ( false === $host
            || ( '.googlebot.com' !== substr( $host, -14 ) && '.google.com' !== substr( $host, -11 ) )
        ) {
            return false;
        }
        $rev_ip = gethostbyname( $host );
        $verified = ( $rev_ip === $ip );

        return $verified;
    }

    /**
     * Verify YandexBot.
     *
     * @see https://yandex.com/support/webmaster/robot-workings/check-yandex-robots.html
     * @param string $ua
     * @param string $ip
     * @return bool
     */
    private function is_yandexbot( $ua, $ip ) {

        if ( false === strpos( $ua, 'Yandex' ) ) {
            return false;
        }

        // No dot at end of host name!
        $host = gethostbyaddr( $ip );
        if ( false === $host
            || ( '.yandex.ru' !== substr( $host, -10 )
                && '.yandex.net' !== substr( $host, -11 )
                && '.yandex.com' !== substr( $host, -11 )
            )
        ) {
            return false;
        }
        $rev_ip = gethostbyname( $host );
        $verified = ( $rev_ip === $ip );

        return $verified;
    }

    /**
     * Verify Google image proxy.
     *
     * @see https://gmail.googleblog.com/2013/12/images-now-showing.html
     * @param string $ua
     * @param string $ip
     * @return bool
     */
    private function is_google_proxy( $ua, $ip ) {

        if ( false === strpos( $ua, 'via ggpht.com GoogleImageProxy' ) ) {
            return false;
        }

        // No dot at end of host name!
        $host = gethostbyaddr( $ip );
        if ( false === $host || 1 !== preg_match( '/^google-proxy-[0-9-]+\.google\.com$/', $host ) ) {
            return false;
        }
        $rev_ip = gethostbyname( $host );
        $verified = ( $rev_ip === $ip );

        return $verified;
    }

    /**
     * Verify SeznamBot.
     *
     * @see https://napoveda.seznam.cz/en/full-text-search/seznambot-crawler/
     * @param string $ua
     * @param string $ip
     * @return bool
     */
    private function is_seznambot( $ua, $ip ) {

        if ( false === strpos( $ua, 'SeznamBot' ) ) {
            return false;
        }

        // No dot at end of host name!
        $host = gethostbyaddr( $ip );
        if ( false === $host || 1 !== preg_match( '/^seznam\.cz$/', $host ) ) {
            return false;
        }
        $rev_ip = gethostbyname( $host );
        $verified = ( $rev_ip === $ip );

        return $verified;
    }

    /**
     * TODO Verify Facebook crawler (links sent by users)
     *     "facebookexternalhit/1.1"
     *     grepcidr -x -f <(whois -h whois.radb.net -- '-i origin AS32934'|sed -ne 's/^route6\?:\s\+\(\S\+\)$/\1/p')
     *
     * @see https://developers.facebook.com/docs/sharing/webmasters/crawler/
     */

    /**
     * Whether the user agent is a web crawler.
     *
     * @param string $ua
     * @return string|bool
     */
    private function is_crawler( $ua ) {

        // Humans and web crawling bots.
        if ( defined( 'W4WP_MSNBOT' ) && W4WP_MSNBOT
            && $this->is_msnbot( $ua, $_SERVER['REMOTE_ADDR'] )
        ) {
            // Identified Bingbot.
            return 'w4wp_msnbot_404';
        }

        if ( defined( 'W4WP_GOOGLEBOT' ) && W4WP_GOOGLEBOT
            && $this->is_googlebot( $ua, $_SERVER['REMOTE_ADDR'] )
        ) {
            // Identified Googlebot.
            return 'w4wp_googlebot_404';
        }

        if ( defined( 'W4WP_YANDEXBOT' ) && W4WP_YANDEXBOT
            && $this->is_yandexbot( $ua, $_SERVER['REMOTE_ADDR'] )
        ) {
            // Identified Yandexbot.
            return 'w4wp_yandexbot_404';
        }

        if ( defined( 'W4WP_GOOGLEPROXY' ) && W4WP_GOOGLEPROXY
            && $this->is_google_proxy( $ua, $_SERVER['REMOTE_ADDR'] )
        ) {
            // Identified GoogleProxy.
            return 'w4wp_googleproxy_404';
        }

        if ( defined( 'W4WP_SEZNAMBOT' ) && W4WP_SEZNAMBOT
            && $this->is_seznambot( $ua, $_SERVER['REMOTE_ADDR'] )
        ) {
            // Identified SeznamBot.
            return 'w4wp_seznambot_404';
        }

        // Unidentified.
        return false;
    }

    /**
     * Encode and sanitize log data.
     *
     * @param mixed $data
     *
     * @return string
     */
    private function esc_log( $data ) {

        $escaped = json_encode( $data, JSON_UNESCAPED_SLASHES );
        if ( false === $escaped ) {
            return ' ';
        }

        // Limit length
        $escaped = mb_substr( $escaped, 0, 500, 'utf-8' );
        // New lines to "|"
        $escaped = str_replace( [ "\n", "\r" ], '|', $escaped );
        // Replace non-printables with "¿"
        $escaped = preg_replace( '/[^\P{C}]+/u', "\xC2\xBF", $escaped );

        return sprintf( '(%s)', $escaped );
    }

    /**
     * Translate Apache log levels for Simple History plugin.
     *
     * @param string $apache_level
     *
     * @return string
     */
    private function translate_apache_level( $apache_level ) {

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

        if ( isset( $levels[ $apache_level ] ) ) {
            $level = $levels[ $apache_level ];
        } else {
            $level = 'info';
        }

        return $level;
    }

    private function exit_with_instructions() {

        $doc_root = array_key_exists( 'DOCUMENT_ROOT', $_SERVER ) ? $_SERVER['DOCUMENT_ROOT'] : ABSPATH;

        $iframe_msg = sprintf(
            '<p style="font:14px \'Open Sans\',sans-serif">
            <strong style="color:#DD3D36">ERROR:</strong> This is <em>not</em> a normal plugin,
            and it should not be activated as one.<br />
            Instead, <code style="font-family:Consolas,Monaco,monospace;background:rgba(0,0,0,0.07)">%s</code>
            must be copied to <code style="font-family:Consolas,Monaco,monospace;background:rgba(0,0,0,0.07)">%s</code></p>',
            esc_html( str_replace( $doc_root, '', __FILE__ ) ),
            esc_html( str_replace( $doc_root, '', trailingslashit( WPMU_PLUGIN_DIR ) ) . basename( __FILE__ ) )
        );

        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        exit( $iframe_msg );
    }
}

new Core_Events();
