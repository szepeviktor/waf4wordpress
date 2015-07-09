<?php
/*
Plugin Name: WordPress Block Bad Requests (wp-config snippet or MU plugin)
Description: Require it from the top of your wp-config.php or make it a Must Use plugin
Plugin URI: https://github.com/szepeviktor/wordpress-plugin-construction
License: The MIT License (MIT)
Author: Viktor Szépe
Author URI: http://www.online1.hu/webdesign/
Version: 2.0.0
Options: O1_BAD_REQUEST_COUNT, O1_BAD_REQUEST_MAX_LOGIN_REQUEST_SIZE,
Options: O1_BAD_REQUEST_CDN_HEADERS, O1_BAD_REQUEST_ALLOW_REG, O1_BAD_REQUEST_ALLOW_IE8,
Options: O1_BAD_REQUEST_ALLOW_OLD_PROXIES, O1_BAD_REQUEST_ALLOW_CONNECTION_EMPTY,
Options: O1_BAD_REQUEST_ALLOW_CONNECTION_CLOSE, O1_BAD_REQUEST_ALLOW_TWO_CAPS,
Options: O1_BAD_REQUEST_POST_LOGGING
*/

/**
 * WordPress Block Bad Requests.
 *
 * Require it from the top of your wp-config.php.
 *
 *     require_once( dirname( __FILE__ ) . '/wp-login-bad-request.inc.php' );
 *
 * @package wordpress-fail2ban
 * @see: README.md
 */
class O1_Bad_Request {

    private $prefix = 'Malicious traffic detected: ';
    private $prefix_instant = 'Break-in attempt detected: ';
    private $trigger_count = 6;
    private $max_login_request_size = 2000;
    private $names2ban = array(
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
        'webmaster'
    );
    private $cdn_headers;
    private $allow_registration = false;
    private $allow_ie8_login = false;
    private $allow_old_proxies = false;
    private $allow_connection_empty = false;
    private $allow_connection_close = false;
    private $allow_two_capitals = false;
    private $result = false;

    public function __construct() {

        // Experimental traffic analysis
        if ( count( $_FILES ) )
            error_log( 'wpf2b/upload: ' . serialize( $_FILES ) );

        // Options
        if ( defined( 'O1_BAD_REQUEST_POST_LOGGING' ) && O1_BAD_REQUEST_POST_LOGGING ) {
            if ( ! empty( $_POST ) )
                error_log( 'HTTP/POST: ' . serialize( $_POST ) );
        }

        if ( defined( 'O1_BAD_REQUEST_COUNT' ) )
            $this->trigger_count = intval( O1_BAD_REQUEST_COUNT );

        if ( defined( 'O1_BAD_REQUEST_MAX_LOGIN_REQUEST_SIZE' ) )
            $this->max_login_request_size = intval( O1_BAD_REQUEST_MAX_LOGIN_REQUEST_SIZE );

        if ( defined( 'O1_BAD_REQUEST_CDN_HEADERS' ) )
            $this->cdn_headers = explode( ':', O1_BAD_REQUEST_CDN_HEADERS );

        if ( defined( 'O1_BAD_REQUEST_ALLOW_REG' ) && O1_BAD_REQUEST_ALLOW_REG )
            $this->allow_registration = true;

        if ( defined( 'O1_BAD_REQUEST_ALLOW_IE8' ) && O1_BAD_REQUEST_ALLOW_IE8 )
            $this->allow_ie8_login = true;

        if ( defined( 'O1_BAD_REQUEST_ALLOW_OLD_PROXIES' ) && O1_BAD_REQUEST_ALLOW_OLD_PROXIES )
            $this->allow_old_proxies = true;

        if ( defined( 'O1_BAD_REQUEST_ALLOW_CONNECTION_EMPTY' ) && O1_BAD_REQUEST_ALLOW_CONNECTION_EMPTY )
            $this->allow_connection_empty = true;

        if ( defined( 'O1_BAD_REQUEST_ALLOW_CONNECTION_CLOSE' ) && O1_BAD_REQUEST_ALLOW_CONNECTION_CLOSE )
            $this->allow_connection_close = true;

        if ( defined( 'O1_BAD_REQUEST_ALLOW_TWO_CAPS' ) && O1_BAD_REQUEST_ALLOW_TWO_CAPS )
            $this->allow_two_capitals = true;

        $this->result = $this->check();

        //DEBUG echo '<pre>blocked by O1_Bad_Request, reason: <strong>'.$this->result;error_log('Bad_Request:'.$this->result);return;

        // False means NO bad requests
        if ( false !== $this->result )
            $this->trigger();
    }

    private function check() {

        // Declare apache_request_headers()
        if ( ! function_exists( 'apache_request_headers' ) ) {
            function apache_request_headers() {
               $headers = '';
               foreach ( $_SERVER as $name => $value )
                   if ( 'HTTP_' === substr( $name, 0, 5 ) )
                       $headers[ substr( $name, 5 ) ] = $value;
               return $headers;
            }
        }

        // Exit on local access
        // Don't run on install / upgrade
        if ( php_sapi_name() === 'cli'
            || $_SERVER['REMOTE_ADDR'] === $_SERVER['SERVER_ADDR']
            || defined( 'WP_INSTALLING' ) && WP_INSTALLING
        )
            return false;

        $request_path = parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH );
        $server_name = isset( $_SERVER['SERVER_NAME'] ) ? $_SERVER['SERVER_NAME'] : $_SERVER['HTTP_HOST'];

        // Block non-static requests from CDN
        // But allow robots.txt
        if ( ! empty( $this->cdn_headers ) && '/robots.txt' !== $request_path ) {
            $commons = array_intersect( $this->cdn_headers, array_keys( $_SERVER ) );
            if ( $commons === $this->cdn_headers ) {
                // Log HTTP request headers
                error_log( 'HTTP headers: ' . $this->esc_log( apache_request_headers() ) );
                // Workaround to prevent edge server banning
                // @TODO block these by another method
                $this->trigger_count = 1;
                $this->prefix = 'Attack through CDN: ';
                return 'bad_request_cdn_attack';
            }
        }

        // Author sniffing
        // Don't ban on post listing by author
        if ( false === strpos( $request_path, '/wp-admin/' )
            && isset( $_REQUEST['author'] )
            && is_numeric( $_REQUEST['author'] )
        )
            return 'bad_request_author_sniffing';

        // Check only POST requests to wp-login
        if ( false === stripos( $_SERVER['REQUEST_METHOD'], 'POST' )
            || false === stripos( $request_path, '/wp-login.php' )
        )
            return false;

        // --------------------------- >8 ---------------------------

        if ( ! empty($_POST['log'] ) ) {
            $username = trim( $_POST['log'] );

            // Banned usernames
            if ( in_array( strtolower( $username ), $this->names2ban ) )
                return 'bad_request_banned_username';

            // Attackers try usernames with "TwoCapitals"
            if ( ! $this->allow_two_capitals ) {
                if ( 1 === preg_match( '/^[A-Z][a-z]+[A-Z][a-z]+$/', $username ) )
                    return 'bad_request_username_pattern';
            }
        }

        // Maximum request size
        $request_size = strlen( http_build_query( apache_request_headers() ) )
            + strlen( $_SERVER['REQUEST_URI'] )
            + strlen( http_build_query( $_POST ) );
        if ( $request_size > $this->max_login_request_size )
            return 'bad_request_http_request_too_big';


        // Accept header - IE9 sends only "*/*"
        //|| false === strpos( $_SERVER['HTTP_ACCEPT'], 'text/html' )
        if ( ! isset( $_SERVER['HTTP_ACCEPT'] )
            || false === strpos( $_SERVER['HTTP_ACCEPT'], '/' )
        )
            return 'bad_request_http_post_accept';

        // Accept-Language header
        if ( ! isset( $_SERVER['HTTP_ACCEPT_LANGUAGE'] )
            || strlen( $_SERVER['HTTP_ACCEPT_LANGUAGE'] ) < 2
        )
            return 'bad_request_http_post_accept_language';

        // Content-Type header
        if ( ! isset( $_SERVER['CONTENT_TYPE'] )
            || false === strpos( $_SERVER['CONTENT_TYPE'], 'application/x-www-form-urlencoded' )
        )
            return 'bad_request_http_post_content_type';

        // Content-Length header
        if ( ! isset( $_SERVER['CONTENT_LENGTH'] )
            || ! is_numeric( $_SERVER['CONTENT_LENGTH'] )
        )
            return 'bad_request_http_post_content_length';

        // Referer header (empty)
        if ( ! isset ( $_SERVER['HTTP_REFERER'] ) )
            return 'bad_request_http_post_referer_empty';

        $referer = $_SERVER['HTTP_REFERER'];

        // Referer header (host part only)
        if ( ! $this->allow_registration ) {
            if ( $server_name !== parse_url( $referer, PHP_URL_HOST ) )
                return 'bad_request_http_post_referer_host';
        }

        // Don't ban password protected posts by rules AFTER this one
        if ( isset( $_SERVER['QUERY_STRING'] ) ) {
            $queries = $this->parse_query( $_SERVER['QUERY_STRING'] );

            if ( isset( $queries['action'] )
                && 'postpass' === $queries['action']
            )
                return false;
        }

        // --------------------------- >8 ---------------------------

        // Referer header (path)
        if ( ! $this->allow_registration ) {
            if ( false === strpos( parse_url( $referer, PHP_URL_PATH ), '/wp-login.php' ) )
                return 'bad_request_http_post_referer_path';
        }

        // Protocol version
        if ( ! isset( $_SERVER['SERVER_PROTOCOL'] ) )
                return 'bad_request_http_post_protocol_empty';

        if ( ! $this->allow_old_proxies ) {
            if ( false === strpos( $_SERVER['SERVER_PROTOCOL'], 'HTTP/1.1' ) )
                return 'bad_request_http_post_1_1';
        }

        // Connection header (keep alive)
        if ( ! $this->allow_connection_empty ) {
            if ( ! isset( $_SERVER['HTTP_CONNECTION'] ) )
                return 'bad_request_http_post_connection_empty';

            if ( ! $this->allow_connection_close ) {
                if ( false === stripos( $_SERVER['HTTP_CONNECTION'], 'keep-alive' ) )
                    return 'bad_request_http_post_connection';
            }
        }

        // Accept-Encoding header
        if ( ! isset ( $_SERVER['HTTP_ACCEPT_ENCODING'] )
            || false === strpos( $_SERVER['HTTP_ACCEPT_ENCODING'], 'gzip' )
        )
            return 'bad_request_http_post_accept_encoding';

        // Cookie
        if ( ! $this->allow_registration ) {

            if ( ! isset( $_SERVER['HTTP_COOKIE'] )
                || false === strpos( $_SERVER['HTTP_COOKIE'], 'wordpress_test_cookie' )
            )
                return 'bad_request_http_post_test_cookie';
        }

        // Empty user agent
        if ( isset( $_SERVER['HTTP_USER_AGENT'] ) ) {
            $user_agent = $_SERVER['HTTP_USER_AGENT'];
        } else {
            return 'bad_request_http_post_user_agent';
        }

        // IE8 logins
        if ( $this->allow_ie8_login ) {
            if ( 1 === preg_match( '/^Mozilla\/4\.0 \(compatible; MSIE 8\.0;/', $user_agent ) )
                return false;
        }

        // Botnets
        if ( 1 === preg_match('/Firefox\/1|bot|spider|crawl|user-agent|random|"|\\\\/i', $user_agent ) )
            return 'bad_request_http_post_user_agent_botnet';

        // Modern browsers
        if ( 1 !== preg_match( '/^Mozilla\/5\.0/', $user_agent ) )
            return 'bad_request_http_post_user_agent_mozilla_5_0';

        // OK
        return false;
    }

    private function trigger() {

        // Trigger fail2ban
        if ( 1 === $this->trigger_count ) {
            $this->enhanced_error_log( $this->prefix . $this->result );
        } else {
            $this->enhanced_error_log( $this->prefix_instant . $this->result );
        {

        // Helps learning attack internals
        error_log( 'HTTP REQUEST: ' . $this->esc_log( $_REQUEST ) );

        ob_get_level() && ob_end_clean();
        header( 'Status: 403 Forbidden' );
        header( 'HTTP/1.0 403 Forbidden' );
        exit();
    }

    private function enhanced_error_log( $message = '', $level = 'error' ) {

        // NOTE: `log_errors` option does not disable logging
        //$log_enabled = ( '1' === ini_get( 'log_errors' ) );
        //if ( ! $log_enabled || empty( $log_destination ) ) {

        // Add entry point. Correct only when `auto_prepend_file` is empty.
        $error_msg = (string)$message
            . ' <' . reset( get_included_files() );

        /**
         * Add log data to log message if SAPI does not add client data.
         *
         * level, IP address, port, referer
         */
        $log_destination = function_exists( 'ini_get' ) ? ini_get( 'error_log' ) : '';
        if ( ! empty( $log_destination ) ) {
            if ( isset( $_SERVER['HTTP_REFERER'] ) ) {
                $referer = $this->esc_log( $_SERVER['HTTP_REFERER'] );
            } else {
                $referer = false;
            }

            $error_msg = '[' . $level . '] '
                . '[client ' . @$_SERVER['REMOTE_ADDR'] . ':' . @$_SERVER['REMOTE_PORT'] . '] '
                . $error_msg
                . ( $referer ? ', referer:' . $referer : '' );
        }

        error_log( $error_msg );
    }

    private function parse_query( $query_string ) {
        $field_strings = explode( '&', $query_string );
        $fields = array();

        foreach ( $field_strings as $field_string ) {
            $name_value = explode( '=', $field_string );

            // Check field name
            if ( empty( $name_value[0] ) )
                continue;

            // Set field value
            $fields[$name_value[0]] = isset( $name_value[1] ) ? $name_value[1] : '';
        }

        return $fields;
    }

    private function esc_log( $string ) {

        $string = serialize( $string ) ;
        // Trim long data
        $string = mb_substr( $string, 0, 200, 'utf-8' );
        // Replace non-printables with "¿" - sprintf( '%c%c', 194, 191 )
        $string = preg_replace( '/[^\P{C}]+/u', "\xC2\xBF", $string );

        return ' (' . $string . ')';
    }

}

new O1_Bad_Request();

/* @TODO

php-doc
check POST: no more, no less variables  a:5:{s:11:"redirect_to";s:28:"http://domain.com/wp-admin/";s:10:"testcookie";s:1:"1";s:3:"log";s:5:"admin";s:3:"pwd";s:6:"123456";s:9:"wp-submit";s:6:"Log In";}
POST: login, postpass, resetpass, lostpassword, register
GET: logout, rp, lostpassword
non-login POSTs
comment POST etc.

*/
