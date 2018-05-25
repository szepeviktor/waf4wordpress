<?php
/*
Plugin Name: WordPress Fail2ban (MU)
Version: 4.14.0
Description: Stop WordPress related attacks and trigger Fail2ban.
Plugin URI: https://github.com/szepeviktor/wordpress-fail2ban
License: The MIT License (MIT)
Author: Viktor Szépe
GitHub Plugin URI: https://github.com/szepeviktor/wordpress-fail2ban
Constants: O1_WP_FAIL2BAN_DISABLE_LOGIN
Constants: O1_WP_FAIL2BAN_ALLOW_REDIRECT
Constants: O1_WP_FAIL2BAN_DISABLE_REST_API
Constants: O1_WP_FAIL2BAN_ONLY_OEMBED
*/

namespace O1;

if ( ! function_exists( 'add_filter' ) ) {
    // @codingStandardsChangeSetting WordPress.PHP.DevelopmentFunctions exclude error_log
    error_log( 'Break-in attempt detected: wpf2b_mu_direct_access '
        . addslashes( isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '' )
    );
    ob_get_level() && ob_end_clean();
    if ( ! headers_sent() ) {
        header( 'Status: 403 Forbidden' );
        header( 'HTTP/1.1 403 Forbidden', true, 403 );
        header( 'Connection: Close' );
    }
    exit;
}

/**
 * WordPress fail2ban Must-Use part.
 *
 * To disable login completely copy this into your wp-config.php:
 *
 *     define( 'O1_WP_FAIL2BAN_DISABLE_LOGIN', true );
 *
 * To allow unlimited canonical redirections copy this into your wp-config.php:
 *
 *     define( 'O1_WP_FAIL2BAN_ALLOW_REDIRECT', true );
 *
 * @package wordpress-fail2ban
 * @see     README.md
 */
final class WP_Fail2ban_MU {

    private $prefix         = 'Malicious traffic detected: ';
    private $prefix_instant = 'Break-in attempt detected: ';
    private $wp_die_ajax_handler;
    private $wp_die_xmlrpc_handler;
    private $wp_die_handler;
    private $is_redirect = false;
    private $names2ban   = array(
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
    );

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
        if ( did_action( 'muplugins_loaded' ) ) {
            $this->exit_with_instructions();
        }

        // Disable REST API
        if ( defined( 'O1_WP_FAIL2BAN_DISABLE_REST_API' ) && O1_WP_FAIL2BAN_DISABLE_REST_API ) {
            // Remove core actions
            // Source: https://plugins.trac.wordpress.org/browser/disable-json-api/trunk/disable-json-api.php
            remove_action( 'xmlrpc_rsd_apis', 'rest_output_rsd' );
            remove_action( 'wp_head', 'rest_output_link_wp_head', 10 );
            remove_action( 'template_redirect', 'rest_output_link_header', 11 );
            if ( defined( 'O1_WP_FAIL2BAN_ONLY_OEMBED' ) && O1_WP_FAIL2BAN_ONLY_OEMBED ) {
                add_filter( 'rest_pre_dispatch', array( $this, 'rest_api_only_oembed' ), 0, 3 );
            } else {
                // Remove oembed core action
                remove_action( 'wp_head', 'wp_oembed_add_discovery_links' );
                add_filter( 'rest_authentication_errors', array( $this, 'rest_api_disabled' ), 99999 );
            }
        } else {
            // @TODO Empty out "author_url:" in every REST response
            add_filter( 'rest_post_dispatch', array( $this, 'rest_40x' ), 0, 3 );
        }

        // Don't redirect to admin
        remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );

        // Don't use shortlinks which are redirected to canonical URL-s
        add_filter( 'pre_get_shortlink', '__return_empty_string' );

        // Login related
        add_action( 'login_init', array( $this, 'login' ) );
        add_action( 'wp_logout', array( $this, 'logout' ) );
        add_action( 'retrieve_password', array( $this, 'lostpass' ) );
        if ( defined( 'O1_WP_FAIL2BAN_DISABLE_LOGIN' ) && O1_WP_FAIL2BAN_DISABLE_LOGIN ) {
            // Disable login
            add_action( 'login_head', array( $this, 'disable_user_login_js' ) );
            add_filter( 'authenticate', array( $this, 'authentication_disabled' ), 0, 2 );
        } else {
            // Prevent registering with banned username
            add_filter( 'validate_username', array( $this, 'banned_username' ), 99999, 2 );
            // wp-login or XMLRPC login (any authentication)
            add_action( 'wp_login_failed', array( $this, 'login_failed' ) );
            add_filter( 'authenticate', array( $this, 'before_login' ), 0, 2 );
            add_action( 'wp_login', array( $this, 'after_login' ), 99999, 2 );
        }

        // Non-existent URLs
        add_action( 'init', array( $this, 'url_hack' ) );
        if ( ! ( defined( 'O1_WP_FAIL2BAN_ALLOW_REDIRECT' ) && O1_WP_FAIL2BAN_ALLOW_REDIRECT ) ) {
            add_filter( 'redirect_canonical', array( $this, 'redirect' ), 1, 2 );
        }

        // Robot and human 404
        add_action( 'plugins_loaded', array( $this, 'robot_403' ), 0 );
        add_action( 'template_redirect', array( $this, 'wp_404' ) );

        // Non-empty wp_die messages
        add_filter( 'wp_die_ajax_handler', array( $this, 'wp_die_ajax' ), 1 );
        add_filter( 'wp_die_xmlrpc_handler', array( $this, 'wp_die_xmlrpc' ), 1 );
        add_filter( 'wp_die_handler', array( $this, 'wp_die' ), 1 );

        // Unknown admin-ajax and admin-post action
        // admin_init is done just before AJAX actions
        add_action( 'admin_init', array( $this, 'hook_all_action' ) );

        // Ban spammers (Contact Form 7 Robot Trap)
        add_action( 'robottrap_hiddenfield', array( $this, 'wpcf7_spam_hiddenfield' ) );
        add_action( 'robottrap_mx', array( $this, 'wpcf7_spam_mx' ) );

        // Ban bad robots (Nofollow Robot Trap)
        add_action( 'nofollow_robot_trap', array( $this, 'nfrt_robot_trap' ) );
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
        remove_action( 'wp_logout', array( $this, 'logout' ) );
        wp_logout();

        // Respond
        ob_get_level() && ob_end_clean();
        if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
            $this->fake_xmlrpc();
        } elseif ( ! headers_sent() ) {
            if ( 'wp-login.php' === $GLOBALS['pagenow'] && ! empty( $_POST['log'] ) ) {
                $this->fake_wplogin();
            } else {
                $this->ban();
            }
        }

        exit;
    }

    private function trigger( $slug, $message, $level = 'error', $prefix = '' ) {

        if ( empty( $prefix ) ) {
            $prefix = $this->prefix;
        }

        // Trigger fail2ban
        $error_msg = sprintf( '%s%s %s',
            $prefix,
            $slug,
            $this->esc_log( $message )
        );
        $this->enhanced_error_log( $error_msg, $level );

        // Report to Sucuri Scan
        if ( class_exists( '\SucuriScanEvent' ) ) {
            if ( true !== \SucuriScanEvent::report_critical_event( $error_msg ) ) {
                // @codingStandardsChangeSetting WordPress.PHP.DevelopmentFunctions exclude error_log
                error_log( 'Sucuri Scan report event failure.' );
            }
        }

        // Report to Simple History
        if ( function_exists( 'SimpleLogger' ) ) {
            $simple_level = $this->translate_apache_level( $level );
            $context      = array(
                '_security'              => 'WordPress fail2ban',
                '_server_request_method' => $this->esc_log( $_SERVER['REQUEST_METHOD'] ),
            );
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

        $server_name         = isset( $_SERVER['SERVER_NAME'] )
            ? $_SERVER['SERVER_NAME']
            : $_SERVER['HTTP_HOST'];
        $username            = trim( $_POST['log'] );
        $expire              = time() + 3600;
        $token               = substr( hash_hmac( 'sha256', rand(), 'token' ), 0, 43 );
        $hash                = hash_hmac( 'sha256', rand(), 'hash' );
        $auth_cookie         = $username . '|' . $expire . '|' . $token . '|' . $hash;
        $authcookie_name     = 'wordpress_' . md5( 'authcookie' );
        $loggedincookie_name = 'wordpress_logged_in_' . md5( 'cookiehash' );

        header( 'Cache-Control: max-age=0, private, no-store, no-cache, must-revalidate' );
        header( 'X-Robots-Tag: noindex, nofollow' );
        setcookie( $authcookie_name, $auth_cookie, $expire, '/brake/wp_content/plugins', false, false, true );
        setcookie( $authcookie_name, $auth_cookie, $expire, '/brake/wp-admin', false, false, true );
        setcookie( $loggedincookie_name, $auth_cookie, $expire, '/', false, false, true );
        header( 'Location: ' . home_url( '/brake/wp-admin/' ) );
    }

    private function fake_xmlrpc() {

        header( 'Connection: Close' );
        header( 'Cache-Control: max-age=0, private, no-store, no-cache, must-revalidate' );
        header( 'X-Robots-Tag: noindex, nofollow' );
        header( 'Content-Type: text/xml; charset=UTF-8' );

        printf( '<?xml version="1.0" encoding="UTF-8"?>
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

        /*
        // log_errors PHP directive does not actually disable logging
        $log_enabled = ( '1' === ini_get( 'log_errors' ) );
        if ( ! $log_enabled || empty( $log_destination ) ) {
        */

        // Add entry point, correct when auto_prepend_file is empty
        $included_files      = get_included_files();
        $first_included_file = reset( $included_files );
        $error_msg           = sprintf( '%s <%s',
            $message,
            $this->esc_log( sprintf( '%s:%s', $_SERVER['REQUEST_METHOD'], $first_included_file ) )
        );

        /**
         * Add client data to log message if SAPI does not add it.
         *
         * level, IP address, port, referer
         */
        $log_destination = function_exists( 'ini_get' ) ? ini_get( 'error_log' ) : '';
        if ( ! empty( $log_destination ) ) {
            if ( array_key_exists( 'HTTP_REFERER', $_SERVER ) ) {
                $referer = sprintf( ', referer: %s', $this->esc_log( $_SERVER['HTTP_REFERER'] ) );
            } else {
                $referer = '';
            }

            $error_msg = sprintf( '[%s] [client %s:%s] %s%s',
                $level,
                $_SERVER['REMOTE_ADDR'],
                $_SERVER['REMOTE_PORT'],
                $error_msg,
                $referer
            );
        }

        // @codingStandardsChangeSetting WordPress.PHP.DevelopmentFunctions exclude error_log
        error_log( $error_msg );
    }

    public function wp_404() {

        if ( ! is_404() ) {
            return;
        }

        $ua = array_key_exists( 'HTTP_USER_AGENT', $_SERVER ) ? $_SERVER['HTTP_USER_AGENT'] : '';

        // HEAD probing resulting in a 404
        if ( false !== stripos( $_SERVER['REQUEST_METHOD'], 'HEAD' ) ) {
            $this->trigger_instant( 'wpf2b_404_head', $_SERVER['REQUEST_URI'] );
        }

        // Don't run 404 template for robots
        if ( $this->is_robot( $ua ) && ! is_user_logged_in() ) {

            $this->trigger( 'wpf2b_robot_404', $_SERVER['REQUEST_URI'], 'info' );

            ob_get_level() && ob_end_clean();
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

        // Humans
        $this->trigger( 'wpf2b_404', $_SERVER['REQUEST_URI'], 'info' );
    }

    public function rest_40x( $response, $instance, $request ) {

        if ( $response instanceof \WP_HTTP_Response ) {
            $status = $response->get_status();
            switch ( $status ) {
                case '403':
                case '404':
                    $data    = $response->get_data();
                    $method  = $request->get_method();
                    $route   = $request->get_route();
                    $message = sprintf( '%s <%s:%s', $data['code'], $method, $route );
                    $this->trigger( 'wpf2b_rest_error', $message );
                    break;
            }
        } else {
            // @TODO Handle non-WP_HTTP_Response errors
            $this->trigger( 'wpf2b_rest_error', 'Not a REST response but a ' . get_class( $response ) );
        }

        return $response;
    }

    public function url_hack() {

        if ( '//' === substr( $_SERVER['REQUEST_URI'], 0, 2 ) ) {
            // Remember this to prevent double-logging in redirect()
            $this->is_redirect = true;
            $this->trigger( 'wpf2b_url_hack', $_SERVER['REQUEST_URI'] );
        }
    }

    public function rest_api_disabled( $enabled ) {

        $this->trigger( 'wpf2b_rest_api_disabled', $_SERVER['REQUEST_URI'], 'notice' );

        return new \WP_Error( 'rest_no_route', __( 'No route was found matching the URL and request method' ), array( 'status' => 404 ) );
    }

    public function rest_api_only_oembed( $null, $that, $request ) {

        // Spec: https://oembed.com/#section2.2
        if ( '/oembed/1.0/embed' === $request->get_route() ) {
            return $null;
        }

        $this->trigger( 'wpf2b_rest_api_not_oembed', $_SERVER['REQUEST_URI'], 'notice' );

        $response_data = array(
            'code'    => 'rest_no_route',
            'message' => __( 'No route was found matching the URL and request method' ),
            'data'    => array( 'status' => 404 ),
        );

        return new \WP_REST_Response( $response_data, 404 );
    }

    public function redirect( $redirect_url, $requested_url ) {

        if ( false === $this->is_redirect ) {
            $this->trigger( 'wpf2b_redirect', $requested_url, 'notice' );
        }

        return $redirect_url;
    }

    public function banned_username( $valid, $username ) {

        if ( in_array( strtolower( $username ), $this->names2ban, true ) ) {
            $this->trigger( 'wpf2b_register_banned_username', $username, 'notice' );
            $valid = false;
        }

        return $valid;
    }

    public function authentication_disabled( $user, $username ) {

        if ( in_array( strtolower( $username ), $this->names2ban, true ) ) {
            $this->trigger_instant( 'wpf2b_login_disabled_banned_username', $username );
        }

        $user = new \WP_Error( 'invalidcombo', __( '<strong>NOTICE</strong>: Login is disabled for now.' ) );
        $this->trigger( 'wpf2b_login_disabled', $username );

        return $user;
    }

    public function disable_user_login_js() {

        print '<script type="text/javascript">setTimeout(function(){
            try{document.getElementById("wp-submit").setAttribute("disabled", "disabled");}
            catch(e){}}, 0);</script>';
    }

    public function login_failed( $username ) {

        $this->trigger( 'wpf2b_auth_failed', $username );
    }

    /**
     * Ban blacklisted usernames and authentication through XML-RPC.
     */
    public function before_login( $user, $username ) {

        if ( in_array( strtolower( $username ), $this->names2ban, true ) ) {
            $this->trigger_instant( 'wpf2b_banned_username', $username );
        }

        if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
            $this->trigger_instant( 'wpf2b_xmlrpc_login', $username );
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
            $user         = $current_user->user_login;
        } else {
            $user = '';
        }

        $this->trigger( 'logged_out', $user, 'info', 'WordPress auth: ' );
    }

    public function lostpass( $username ) {

        if ( empty( $username ) ) {
            $this->trigger( 'lost_pass_empty', $username, 'warn' );
        }

        $this->trigger( 'lost_pass', $username, 'warn', 'WordPress auth: ' );
    }

    /**
     * WordPress directory requests from robots.
     */
    public function robot_403() {

        $ua           = array_key_exists( 'HTTP_USER_AGENT', $_SERVER ) ? $_SERVER['HTTP_USER_AGENT'] : '';
        $request_path = parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH );
        $admin_path   = parse_url( admin_url(), PHP_URL_PATH );
        $wp_dirs      = sprintf( 'wp-admin|wp-includes|wp-content|%s', basename( WP_CONTENT_DIR ) );
        $uploads      = wp_upload_dir();
        $uploads_base = basename( $uploads['baseurl'] );
        $cache        = sprintf( '%s/cache', basename( WP_CONTENT_DIR ) );

        // Don't have to handle wp-includes/ms-files.php:12
        // It does SHORTINIT, no mu-plugins get loaded
        if ( $this->is_robot( $ua )

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
            $this->trigger_instant( 'wpf2b_robot_403', $request_path );
        }
    }

    public function wp_die_ajax( $arg ) {

        // Remember the previous handler
        $this->wp_die_ajax_handler = $arg;

        return array( $this, 'wp_die_ajax_handler' );
    }

    public function wp_die_ajax_handler( $message, $title, $args ) {

        // wp-admin/includes/ajax-actions.php returns -1 on security breach
        if ( ! ( is_scalar( $message ) || $this->is_whitelisted_error( $message ) )
            || (int) $message < 0
        ) {
            $this->trigger( 'wpf2b_wpdie_ajax', $message );
        }

        // Call previous handler
        call_user_func( $this->wp_die_ajax_handler, $message, $title, $args );
    }

    public function wp_die_xmlrpc( $arg ) {

        // Remember the previous handler
        $this->wp_die_xmlrpc_handler = $arg;

        return array( $this, 'wp_die_xmlrpc_handler' );
    }

    public function wp_die_xmlrpc_handler( $message, $title, $args ) {

        if ( ! empty( $message ) ) {
            $this->trigger( 'wpf2b_wpdie_xmlrpc', $message );
        }

        // Call previous handler
        call_user_func( $this->wp_die_xmlrpc_handler, $message, $title, $args );
    }

    public function wp_die( $arg ) {

        // Remember the previous handler
        $this->wp_die_handler = $arg; // WPCS: XSS ok.

        return array( $this, 'wp_die_handler' );
    }

    public function wp_die_handler( $message, $title, $args ) {

        if ( ! empty( $message ) ) {
            $this->trigger( 'wpf2b_wpdie', $message );
        }

        // Call previous handler
        call_user_func( $this->wp_die_handler, $message, $title, $args );
    }

    private function is_whitelisted_error( $error ) {

        if ( ! is_wp_error( $error ) ) {
            return false;
        }

        $whitelist = array(
            'themes_api_failed',
            'plugins_api_failed',
            'translations_api_failed',
        );
        $code      = $error->get_error_code();

        if ( in_array( $code, $whitelist, true ) ) {
            return true;
        }

        return false;
    }

    public function hook_all_action() {

        // Don't slow down everything
        if ( ! empty( $_REQUEST['action'] ) ) {
            add_action( 'all', array( $this, 'unknown_action' ), 0 );
        }
    }

    public function unknown_action( $tag ) {

        // Check tag first to speed things up
        if ( 'wp_ajax_' === substr( $tag, 0, 8 )
            || 'admin_post_' === substr( $tag, 0, 11 )
        ) {
            global $wp_actions;
            global $wp_filter;

            $whitelisted_actions = array(
                'wp_ajax_nopriv_wp-remove-post-lock',
                'wp_ajax_nopriv_SimpleHistoryNewRowsNotifier',
            );

            // Actions only, not filters, not registered ones, except whitelisted ones
            // Actions are basically filters
            if ( is_array( $wp_actions )
                && array_key_exists( $tag, $wp_actions )
                && is_array( $wp_filter )
                && ! array_key_exists( $tag, $wp_filter )
                && ! in_array( $tag, $whitelisted_actions, true )
            ) {
                $this->trigger_instant( 'wpf2b_admin_action_unknown', $tag );
            }
        }
    }

    public function wpcf7_spam_hiddenfield( $text ) {

        $this->trigger_instant( 'wpf2b_wpcf7_spam_hiddenfield', $text );
    }

    public function wpcf7_spam_mx( $domain ) {

        $this->trigger( 'wpf2b_wpcf7_spam_mx', $domain, 'warn' );
    }

    public function nfrt_robot_trap( $message ) {

        $this->trigger_instant( 'wpf2b_nfrt_robot_trap', $message );
    }

    /**
     * Test user agent string for robots.
     *
     * Robots are everyone except modern browsers.
     *
     * @see: http://www.useragentstring.com/pages/Browserlist/
     */
    private function is_robot( $ua ) {

        return ( ( 'Mozilla/5.0' !== substr( $ua, 0, 11 ) )
            && ( 'Mozilla/4.0 (compatible; MSIE 8.0;' !== substr( $ua, 0, 34 ) )
            && ( 'Mozilla/4.0 (compatible; MSIE 7.0;' !== substr( $ua, 0, 34 ) )
            && ( 'Opera/9.80' !== substr( $ua, 0, 10 ) )
        );
    }

    private function esc_log( $string ) {

        $escaped = json_encode( $string );
        // Limit length
        $escaped = mb_substr( $escaped, 0, 500, 'utf-8' );
        // New lines to "|"
        $escaped = str_replace( array( "\n", "\r" ), '|', $escaped );
        // Replace non-printables with "¿"
        $escaped = preg_replace( '/[^\P{C}]+/u', "\xC2\xBF", $escaped );

        return sprintf( '(%s)', $escaped );
    }

    private function translate_apache_level( $apache_level ) {

        $levels = array(
            'emerg'  => 'emergency',
            'alert'  => 'alert',
            'crit'   => 'critical',
            'error'  => 'error',
            'warn'   => 'warning',
            'notice' => 'notice',
            'info'   => 'info',
            'debug'  => 'debug',
        );

        if ( isset( $levels[ $apache_level ] ) ) {
            $level = $levels[ $apache_level ];
        } else {
            $level = 'info';
        }

        return $level;
    }

    private function exit_with_instructions() {

        $doc_root = array_key_exists( 'DOCUMENT_ROOT', $_SERVER ) ? $_SERVER['DOCUMENT_ROOT'] : ABSPATH;

        $iframe_msg = sprintf( '<p style="font:14px \'Open Sans\',sans-serif">
            <strong style="color:#DD3D36">ERROR:</strong> This is <em>not</em> a normal plugin,
            and it should not be activated as one.<br />
            Instead, <code style="font-family:Consolas,Monaco,monospace;background:rgba(0,0,0,0.07)">%s</code>
            must be copied to <code style="font-family:Consolas,Monaco,monospace;background:rgba(0,0,0,0.07)">%s</code></p>',
            esc_html( str_replace( $doc_root, '', __FILE__ ) ),
            esc_html( str_replace( $doc_root, '', trailingslashit( WPMU_PLUGIN_DIR ) ) . basename( __FILE__ ) )
        );

        exit( $iframe_msg ); // WPCS: XSS ok.
    }
}

new WP_Fail2ban_MU();
