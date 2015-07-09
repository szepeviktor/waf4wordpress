<?php
/*
Plugin Name: WordPress fail2ban
Plugin URI: https://github.com/szepeviktor/wordpress-plugin-construction
Description: Reports 404s and various attacks in error.log for fail2ban
Version: 0.9.1
Upstream: based on WordPress fail2ban MU v2.5
License: The MIT License (MIT)
Author: Viktor Szépe
Author URI: http://www.online1.hu/webdesign/
GitHub Plugin URI: https://github.com/szepeviktor/wordpress-plugin-construction/tree/master/wordpress-fail2ban
*/

if ( ! function_exists( 'add_filter' ) ) {
    error_log( 'Malicious traffic detected: wpf2b_direct_access '
               . addslashes( $_SERVER['REQUEST_URI'] )
    );
    ob_end_clean();
    header( 'Status: 403 Forbidden' );
    header( 'HTTP/1.0 403 Forbidden' );
    exit();
}

class O1_ErrorLog404 {

    private $prefix = 'Malicious traffic detected by wpf2b: ';
    private $wp_die_ajax_handler;
    private $wp_die_xmlrpc_handler;
    private $wp_die_handler;
    private $is_redirect = false;

    private $hide_robot_404 = false;

    public function __construct() {

        // admin
        if ( is_admin() ) {
            require_once dirname( __FILE__ ) . '/inc/errorlog-404-admin.php';
            $errorlog_404_admin = new O1_Errorlog_404_admin();
        }

        // admin_init() does register_activation_hook
        register_deactivation_hook( __FILE__, array( $this, 'deactivate' ) );
        //TODO uninstall hook/file

        // exit on local access
        // don't run on install / upgrade
        if ( php_sapi_name() === 'cli'
            || $_SERVER['REMOTE_ADDR'] === $_SERVER['SERVER_ADDR']
            || defined( 'WP_INSTALLING' ) && WP_INSTALLING
        )
            return;

        $general_options = get_option( 'o1_errorlog_general' );
        $request_options = get_option( 'o1_errorlog_request' );
        $login_options = get_option( 'o1_errorlog_login' );

        if ( '0' === $general_options['enabled'] )
            return;

        $this->prefix = $general_options['prefix'] . ' ';

        // non-existent / malicious URLs
        if ( 1 == $request_options['fourohfour'] ) {
            add_action( 'template_redirect', array( $this, 'wp_404' ) );
        }
        if ( 1 == $request_options['urlhack'] ) {
            add_action( 'init', array( $this, 'url_hack' ) );
        }
        if ( 1 == $request_options['redirect'] ) {
            add_filter( 'redirect_canonical', array( $this, 'redirect' ), 1, 2 );
        }

        // don't show 404 for robots
        if ( 1 == $request_options['robot404'] ) {
            $this->hide_robot_404 = true;
        }
        /* on update from mu-plugin: insert this into wp_404()
        if ( true === $this->hide_robot_404
        */

        // forbid robots to peek into WP
        if ( 1 == $request_options['robot403'] ) {
            add_action( 'plugins_loaded', array( $this, 'robot_403' ), 0 );
        }

        // ban spammers (Contact Form 7 Robot Trap)
        if ( 1 == $request_options['spam'] ) {
            add_action( 'robottrap_hiddenfield', array( $this, 'wpcf7_spam' ) );
        }
        if ( 1 == $request_options['spammx'] ) {
            add_action( 'robottrap_mx', array( $this, 'wpcf7_spam_mx' ) );
        }

        // don't redirect to admin
        if ( 1 == $login_options['adminredirect'] ) {
            remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );
        }

        // login failures
        if ( 1 == $login_options['loginfail'] ) {
            add_action( 'wp_login_failed', array( $this, 'login_failed' ) );
        }

        // successful login
        if ( 1 == $login_options['login'] ) {
            add_action( 'wp_login', array( $this, 'login' ) );
        }

        // logout
        if ( 1 == $login_options['logout'] ) {
            add_action( 'wp_logout', array( $this, 'logout' ) );
        }

        // logout
        if ( 1 == $login_options['lostpass'] ) {
            add_action( 'retrieve_password', array( $this, 'lostpass' ) );
        }

        // report bailouts for security reasons
        if ( 1 == $login_options['wpdie'] ) {
            add_filter( 'wp_die_ajax_handler', array( $this, 'wp_die_ajax' ), 1 );
            add_filter( 'wp_die_xmlrpc_handler', array( $this, 'wp_die_xmlrpc' ), 1 );
            add_filter( 'wp_die_handler', array( $this, 'wp_die' ), 1 );
        }
    }

    private function esc_log( $string ) {

        $string = serialize( $string ) ;
        // trim long data
        $string = mb_substr( $string, 0, 200, 'utf-8' );
        // replace non-printables with "¿" - sprintf( '%c%c', 194, 191 )
        $string = preg_replace( '/[^\P{C}]+/u', "\xC2\xBF", $string );

        return ' (' . $string . ')';
    }

    private function is_robot( $ua ) {

        // test user agent string (robot = not modern browser)
        // based on: http://www.useragentstring.com/pages/Browserlist/
        return ( ( 'Mozilla/5.0' !== substr( $ua, 0, 11 ) )
            && ( 'Mozilla/4.0 (compatible; MSIE 8.0;' !== substr( $ua, 0, 34 ) )
            && ( 'Opera/9.80' !== substr( $ua, 0, 10 ) )
        );
    }

    private function trigger( $slug, $message = '' ) {
        error_log( $this->prefix
                   . $slug
                   . ( empty( $message ) ? '' : $this->esc_log( $message ) ) );
    }

    public function deactivate() {

        // clean up options
        delete_option( 'o1_errorlog_general' );
        delete_option( 'o1_errorlog_request' );
        delete_option( 'o1_errorlog_login' );
    }

    // below the copy of WP fail2ban MU's public functions

    public function wp_404() {

        if ( ! is_404() )
            return;

        $ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? $_SERVER['HTTP_USER_AGENT'] : '';
        $request_uri = $_SERVER['REQUEST_URI'];

        // don't show the 404 page for robots
        if ( true === $this->hide_robot_404
            && ! is_user_logged_in()
            && $this->is_robot( $ua )
        ) {

            ob_end_clean();
            $this->trigger( 'errorlog_robot404', $request_uri );
            header( 'Status: 404 Not Found' );
            header( 'HTTP/1.0 404 Not Found' );
            exit();
        }

        // humans
        $this->trigger( 'errorlog_404', $request_uri );
    }

    public function url_hack() {

        $request_uri = $_SERVER['REQUEST_URI'];

        if ( substr( $request_uri, 0, 2 ) === '//'
            || strstr( $request_uri, '../' ) !== false
            || strstr( $request_uri, '/..' ) !== false
        ) {

            // remember this to prevent double-logging in redirect()
            $this->is_redirect = true;
            $this->trigger( 'errorlog_url_hack', $request_uri );
        }
    }

    public function redirect( $redirect_url, $requested_url ) {

        if ( false === $this->is_redirect )
            $this->trigger( 'errorlog_redirect', $requested_url );

        return $redirect_url;
    }

    public function login_failed( $username ) {

        $this->trigger( 'errorlog_login_failed', $username );
    }

    public function login( $username ) {

        error_log( 'WordPress logged in: ' . $username );
    }

    public function logout() {

        $current_user = wp_get_current_user();

        error_log( 'WordPress logout: ' . $current_user->user_login );
    }

    public function lostpass( $username ) {

        if ( empty( $username ) ) {
            //FIXME higher score !!!
        }

        error_log( 'WordPress lost password:' . $this->esc_log( $username ) );
    }

    public function wp_die_ajax( $arg ) {

        // remember the previous handler
        $this->wp_die_ajax_handler = $arg;

        return array( $this, 'wp_die_ajax_handler' );
    }

    public function wp_die_ajax_handler( $message, $title, $args ) {

        // wp-admin/includes/ajax-actions.php returns -1 of security breach
        if ( ! is_scalar( $message ) || (int) $message < 0 )
            $this->trigger( 'errorlog_wpdie_ajax' );

        // call previous handler
        call_user_func( $this->wp_die_ajax_handler, $message, $title, $args );
    }

    public function wp_die_xmlrpc( $arg ) {

        // remember the previous handler
        $this->wp_die_xmlrpc_handler = $arg;

        return array( $this, 'wp_die_xmlrpc_handler' );
    }

    public function wp_die_xmlrpc_handler( $message, $title, $args ) {

        if ( ! empty( $message ) )
            $this->trigger( 'errorlog_wpdie_xmlrpc', $message );

        // call previous handler
        call_user_func( $this->wp_die_xmlrpc_handler, $message, $title, $args );
    }

    public function wp_die( $arg ) {

        // remember the previous handler
        $this->wp_die_handler = $arg;

        return array( $this, 'wp_die_handler' );
    }

    public function wp_die_handler( $message, $title, $args ) {

        if ( ! empty( $message ) )
            $this->trigger( 'errorlog_wpdie', $message );

        // call previous handler
        call_user_func( $this->wp_die_handler, $message, $title, $args );
    }

    public function robot_403() {

        $ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? $_SERVER['HTTP_USER_AGENT'] : '';
        $request_path = parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH );
        $admin_path = parse_url( admin_url(), PHP_URL_PATH );
        $wp_dirs = 'wp-admin|wp-includes|wp-content|' . basename( WP_CONTENT_DIR );
        $uploads = wp_upload_dir();

        if ( ! is_user_logged_in()
            // a robot or < IE8
            && $this->is_robot( $ua )

            // robots may only enter on the frontend (index.php)
            // $this->trigger only in WP dirs: wp-admin, wp-includes, wp-content
            && 1 === preg_match( '/\/(' . $wp_dirs . ')\//i', $request_path )

            // exclude missing media files but not '.php'
            && ( false === strstr( $request_path, basename( $uploads['baseurl'] ) )
                || false !== stristr( $request_path, '.php' )
            )

            // exclude XML RPC (xmlrpc.php)
            && ! ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST )

            // exclude trackback (wp-trackback.php)
            && 1 !== preg_match( '/\/wp-trackback\.php$/i', $request_path )
        ) {

            //FIXME wp-includes/ms-files.php:12 ???
            ob_end_clean();
            $this->trigger( 'errorlog_robot403', $request_path );
            header( 'Status: 403 Forbidden' );
            header( 'HTTP/1.0 403 Forbidden' );
            exit();
        }
    }

    public function wpcf7_spam( $text ) {

        $this->trigger( 'errorlog_wpcf7_spam', $text );
    }

    public function wpcf7_spam_mx( $domain ) {

        $this->trigger( 'errorlog_wpcf7_spam_mx', $domain );
    }

}

new O1_ErrorLog404();

