<?php
/*
Plugin Name: WordPress Block Bad Requests (wp-config snippet or MU plugin)
Description: Require it from the top of your wp-config.php or make it a Must Use plugin
Plugin URI: https://github.com/szepeviktor/wordpress-plugin-construction
License: The MIT License (MIT)
Author: Viktor Szépe
Author URI: http://www.online1.hu/webdesign/
Version: 2.2.0
Options: O1_BAD_REQUEST_COUNT, O1_BAD_REQUEST_MAX_LOGIN_REQUEST_SIZE,
Options: O1_BAD_REQUEST_CDN_HEADERS, O1_BAD_REQUEST_ALLOW_REG, O1_BAD_REQUEST_ALLOW_IE8,
Options: O1_BAD_REQUEST_ALLOW_OLD_PROXIES, O1_BAD_REQUEST_ALLOW_CONNECTION_EMPTY,
Options: O1_BAD_REQUEST_ALLOW_CONNECTION_CLOSE, O1_BAD_REQUEST_ALLOW_TWO_CAPS,
Options: O1_BAD_REQUEST_POST_LOGGING
*/

if ( ! function_exists( 'add_filter' ) ) {
    error_log( 'Break-in attempt detected: wpf2b_bad_request_direct_access '
        . addslashes( @$_SERVER['REQUEST_URI'] )
    );
    ob_get_level() && ob_end_clean();
    header( 'Status: 403 Forbidden' );
    header( 'HTTP/1.0 403 Forbidden' );
    exit();
}

/**
 * WordPress Block Bad Requests.
 *
 * Require it from the top of your wp-config.php:
 *
 *     require_once( dirname( __FILE__ ) . '/wp-login-bad-request.inc-instant.php' );
 *
 * @package wordpress-fail2ban
 * @see     README.md
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

    /**
     * Set up options, run check and trigger fail2ban on malicous HTTP request.
     *
     * @return null
     */
    public function __construct() {

        // Experimental upload traffic analysis
        if ( count( $_FILES ) )
            $this->enhanced_error_log( sprintf( 'bad_request_upload: %s, %s',
                $this->esc_log( $_FILES ),
                $this->esc_log( $_REQUEST )
            ), 'notice' );

        // Options
        if ( defined( 'O1_BAD_REQUEST_POST_LOGGING' ) && O1_BAD_REQUEST_POST_LOGGING ) {
            if ( ! empty( $_POST ) )
                $this->enhanced_error_log( 'HTTP/POST: ' . $this->esc_log( $_POST ), 'notice' );
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

        //DEBUG echo '<pre>blocked by bad-request, reason: <b>'.$this->result;error_log('Bad_Request:'.$this->result);return;

        // "false" means there were no bad requests
        if ( false !== $this->result )
            $this->trigger();
    }

    /**
     * Detect for malicious HTTP requests.
     *
     * @return string|boolean  Attack type or false.
     */
    private function check() {

        // Declare apache_request_headers()
        if ( ! function_exists( 'apache_request_headers' ) ) {
            /**
             * Fetch all HTTP request headers.
             *
             * @return array  HTTP request headers
             */
            function apache_request_headers() {

               $headers = array();
               foreach ( $_SERVER as $name => $value )
                   if ( 'HTTP_' === substr( $name, 0, 5 ) )
                       $headers[ substr( $name, 5 ) ] = $value;

               return $headers;
            }
        }

        // Don't ban on local access and on install or upgrade
        if ( php_sapi_name() === 'cli'
            || $_SERVER['REMOTE_ADDR'] === $_SERVER['SERVER_ADDR']
            || defined( 'WP_INSTALLING' ) && WP_INSTALLING
        )
            return false;

        $request_path = parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH );
        $server_name = isset( $_SERVER['SERVER_NAME'] ) ? $_SERVER['SERVER_NAME'] : $_SERVER['HTTP_HOST'];

        // Block non-static requests from CDN but allow robots.txt
        if ( ! empty( $this->cdn_headers ) && '/robots.txt' !== $request_path ) {
            $common_headers = array_intersect( $this->cdn_headers, array_keys( $_SERVER ) );
            if ( $common_headers === $this->cdn_headers ) {
                // Log HTTP request headers
                $this->enhanced_error_log( 'HTTP headers: ' . $this->esc_log( apache_request_headers() ) );
                // Work-around to prevent edge server banning
                // @TODO Block these by another method
                $this->prefix = 'Attack through CDN: ';
                $this->trigger_count = 1;
                return 'bad_request_cdn_attack';
            }
        }

        // Author sniffing
        // Except on post listing by author on wp-admin
        if ( false === strpos( $request_path, '/wp-admin/' )
            && isset( $_REQUEST['author'] )
            && is_numeric( $_REQUEST['author'] )
        )
            return 'bad_request_author_sniffing';

        // Check POST HTTP requests only
        // wget sends: User-Agent, Accept, Host, Connection, Content-Type, Content-Length
        // curl sends: User-Agent, Host, Accept, Content-Length, Content-Type
        if ( false === stripos( $_SERVER['REQUEST_METHOD'], 'POST' ) )
            return false;
        // --------------------------- >8 ---------------------------

        // User agent HTTP header
        if ( isset( $_SERVER['HTTP_USER_AGENT'] ) ) {
            $user_agent = $_SERVER['HTTP_USER_AGENT'];
        } else {
            return 'bad_request_http_post_user_agent';
        }

        // Accept HTTP header
        // IE9, wget and curl sends only "*/*"
        // || false === strpos( $_SERVER['HTTP_ACCEPT'], 'text/html' )
        if ( ! isset( $_SERVER['HTTP_ACCEPT'] )
            || false === strpos( $_SERVER['HTTP_ACCEPT'], '/' )
        )
            return 'bad_request_http_post_accept';

        $post_content_types = array( 'application/x-www-form-urlencoded', 'multipart/form-data' );
        // Content-Type HTTP header
        if ( ! isset( $_SERVER['CONTENT_TYPE'] )
            || ! in_array( $_SERVER['CONTENT_TYPE'], $post_content_types )
        )
            return 'bad_request_http_post_content_type';

        // Content-Length HTTP header
        if ( ! isset( $_SERVER['CONTENT_LENGTH'] )
            || ! is_numeric( $_SERVER['CONTENT_LENGTH'] )
        )
            return 'bad_request_http_post_content_length';

        // Check login requests only
        if ( false === stripos( $request_path, '/wp-login.php' ) )
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

        // Maximum HTTP request size
        $request_size = strlen( http_build_query( apache_request_headers() ) )
            + strlen( $_SERVER['REQUEST_URI'] )
            + strlen( http_build_query( $_POST ) );
        if ( $request_size > $this->max_login_request_size )
            return 'bad_request_http_request_too_big';

        // Content-Type HTTP header (application/x-www-form-urlencoded)
        if ( false === strpos( $_SERVER['CONTENT_TYPE'], 'application/x-www-form-urlencoded' ) )
            return 'bad_request_http_login_content_type';

        // Accept-Language HTTP header
        if ( ! isset( $_SERVER['HTTP_ACCEPT_LANGUAGE'] )
            || strlen( $_SERVER['HTTP_ACCEPT_LANGUAGE'] ) < 2
        )
            return 'bad_request_http_post_accept_language';

        // Referer HTTP header
        if ( ! isset ( $_SERVER['HTTP_REFERER'] ) )
            return 'bad_request_http_post_referer_empty';

        $referer = $_SERVER['HTTP_REFERER'];

        // Referer HTTP header
        if ( ! $this->allow_registration ) {
            if ( $server_name !== parse_url( $referer, PHP_URL_HOST ) )
                return 'bad_request_http_post_referer_host';
        }

        // Don't ban post password requests
        if ( isset( $_SERVER['QUERY_STRING'] ) ) {
            $queries = $this->parse_query( $_SERVER['QUERY_STRING'] );

            if ( isset( $queries['action'] )
                && 'postpass' === $queries['action']
            )
                return false;
        }
        // --------------------------- >8 ---------------------------

        // Referer HTTP header
        if ( ! $this->allow_registration ) {
            if ( false === strpos( parse_url( $referer, PHP_URL_PATH ), '/wp-login.php' ) )
                return 'bad_request_http_post_referer_path';
        }

        // HTTP protocol version
        if ( ! isset( $_SERVER['SERVER_PROTOCOL'] ) )
                return 'bad_request_http_post_protocol_empty';

        if ( ! $this->allow_old_proxies ) {
            if ( false === strpos( $_SERVER['SERVER_PROTOCOL'], 'HTTP/1.1' ) )
                return 'bad_request_http_post_1_1';
        }

        // Connection HTTP header (keep alive)
        if ( ! $this->allow_connection_empty ) {
            if ( ! isset( $_SERVER['HTTP_CONNECTION'] ) )
                return 'bad_request_http_post_connection_empty';

            if ( ! $this->allow_connection_close ) {
                if ( false === stripos( $_SERVER['HTTP_CONNECTION'], 'keep-alive' ) )
                    return 'bad_request_http_post_connection';
            }
        }

        // Accept-Encoding HTTP header
        if ( ! isset ( $_SERVER['HTTP_ACCEPT_ENCODING'] )
            || false === strpos( $_SERVER['HTTP_ACCEPT_ENCODING'], 'gzip' )
        )
            return 'bad_request_http_post_accept_encoding';

        // WordPress test cookie
        if ( ! $this->allow_registration ) {

            if ( ! isset( $_SERVER['HTTP_COOKIE'] )
                || false === strpos( $_SERVER['HTTP_COOKIE'], 'wordpress_test_cookie' )
            )
                return 'bad_request_http_post_test_cookie';
        }

        // IE8 logins
        if ( $this->allow_ie8_login ) {
            if ( 1 === preg_match( '/^Mozilla\/4\.0 \(compatible; MSIE 8\.0;/', $user_agent ) )
                return false;
        }

        // Botnet user agents
        if ( 1 === preg_match('/Firefox\/1|bot|spider|crawl|user-agent|random|"|\\\\/i', $user_agent ) )
            return 'bad_request_http_post_user_agent_botnet';

        // Modern browser user agents
        if ( 1 !== preg_match( '/^Mozilla\/5\.0/', $user_agent ) )
            return 'bad_request_http_post_user_agent_mozilla_5_0';

        // Allow
        return false;
    }

    /**
     * Trigger fail2ban and exit with HTTP/403.
     *
     * @return null
     */
    private function trigger() {

        // Trigger fail2ban
        if ( 1 === $this->trigger_count ) {
            $this->enhanced_error_log( $this->prefix . $this->result );
        } else {
            $this->enhanced_error_log( $this->prefix_instant . $this->result, 'crit' );
        }

        // Helps learning attack internals
        $this->enhanced_error_log( 'HTTP REQUEST: ' . $this->esc_log( $_REQUEST ) );

        ob_get_level() && ob_end_clean();
        header( 'Status: 403 Forbidden' );
        header( 'HTTP/1.0 403 Forbidden' );
        exit();
    }

    /**
     * Send a string to error log optionally completed with client data.
     *
     * @param string $message  The log message
     * @param string $level    Log level (default: 'error')
     *
     * @return null
     *
     * @see http://httpd.apache.org/docs/trunk/mod/core.html#loglevel
     */
    private function enhanced_error_log( $message = '', $level = 'error' ) {

        /*
        // log_errors option does not actually disable logging
        $log_enabled = ( '1' === ini_get( 'log_errors' ) );
        if ( ! $log_enabled || empty( $log_destination ) ) {
        */

        // Add entry point. Only correct when auto_prepend_file option is empty.
        $error_msg = (string)$message
            . ' <' . reset( get_included_files() );

        /**
         * Add log level and client data to log message if SAPI does not add it.
         *
         * Client data: IP address, port, referer
         */
        $log_destination = function_exists( 'ini_get' ) ? ini_get( 'error_log' ) : '';
        if ( ! empty( $log_destination ) ) {
            if ( isset( $_SERVER['HTTP_REFERER'] ) ) {
                $referer = ', referer:' . $this->esc_log( $_SERVER['HTTP_REFERER'] );
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

        error_log( $error_msg );
    }

    /**
     * Parse URL query string to an array.
     *
     * @param string $query_string  The query string
     *
     * @return array                The query as an array
     */
    private function parse_query( $query_string ) {
        $query = array();
        $names_values_array = explode( '&', $query_string );

        foreach ( $names_values_array as $name_value ) {
            $name_value_array = explode( '=', $name_value );

            // Check field name
            if ( empty( $name_value_array[0] ) )
                continue;

            // Set field value
            $query[ $name_value_array[0] ] = isset( $name_value_array[1] ) ? $name_value_array[1] : '';
        }

        return $query;
    }

    /**
     * Prepare a string to safe logging.
     *
     * @param string $string  String to escape
     *
     * @return string         Escaped string in parentheses
     */
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
check POST: no more, no less variables  a:5:{s:11:"redirect_to";s:28:"http://domain.com/wp-admin/";s:10:"testcookie";s:1:"1";s:3:"log";s:5:"admin";s:3:"pwd";s:6:"123456";s:9:"wp-submit";s:6:"Log In";}
POST: login, postpass, resetpass, lostpassword, register
GET:  logout, rp, lostpassword
non-login POSTs: comments etc.
*/
