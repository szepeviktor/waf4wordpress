<?php
/*
Plugin Name: Block Bad Requests (required from wp-config or MU plugin)
Version: 2.15.1
Description: Stop various HTTP attacks and trigger Fail2ban.
Plugin URI: https://github.com/szepeviktor/wordpress-fail2ban
License: The MIT License (MIT)
Author: Viktor Szépe
GitHub Plugin URI: https://github.com/szepeviktor/wordpress-fail2ban
Options: O1_BAD_REQUEST_INSTANT
Options: O1_BAD_REQUEST_MAX_LOGIN_REQUEST_SIZE
Options: O1_BAD_REQUEST_CDN_HEADERS
Options: O1_BAD_REQUEST_ALLOW_REG
Options: O1_BAD_REQUEST_ALLOW_IE8
Options: O1_BAD_REQUEST_ALLOW_OLD_PROXIES
Options: O1_BAD_REQUEST_ALLOW_CONNECTION_EMPTY
Options: O1_BAD_REQUEST_ALLOW_CONNECTION_CLOSE
Options: O1_BAD_REQUEST_ALLOW_TWO_CAPS
Options: O1_BAD_REQUEST_POST_LOGGING
*/

namespace O1;

/**
 * WordPress Block Bad Requests.
 *
 * Require it from the top of your wp-config.php:
 *
 *     require_once __DIR__ . '/wp-fail2ban-bad-request-instant.inc.php';
 *     new O1\Bad_Request();
 *
 * @package wordpress-fail2ban
 * @see     README.md
 */
final class Bad_Request {

    private $prefix = 'Malicious traffic detected: ';
    private $prefix_instant = 'Break-in attempt detected: ';
    private $instant_trigger = true;
    private $max_login_request_size = 4000;
    private $is_wplogin = false;
    private $is_xmlrpc = false;
    private $is_options_method = false;
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
        'webmaster',
    );
    private $blacklist = array(
        '../', // path traversal
        '/..', // path traversal
        'wp-config', // WP core
        '/brake/wp-admin/', // from fake_wplogin()
        'allow_url_include', // PHP directive
        'auto_prepend_file', // PHP directive
        'testproxy.php', // scan for open proxies
        'httptest.php', // scan for open proxies
        'bigdump.php', // Staggered MySQL Dump Importer
        'wso.php', // Web Shell
        'w00tw00t', // DFind Scanner
        '/administrator', // Joomla Administrator
        'connector.asp', // Joomla FCKeditor 2.x File Manager Connector for ASP
        '/HNAP1', // D-Link routers
        '() { ', // Shell shock () { :;};
        '/cgi-bin/', // CGI folder
        'error_log', // default PHP error log
        'error-log', // PHP error log
        'htaccess', // Apache httpd configuration
        'web.config', // IIS configuration
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

        // Options
        if ( defined( 'O1_BAD_REQUEST_INSTANT' ) && false === O1_BAD_REQUEST_INSTANT ) {
            $this->instant_trigger = false;
        }

        if ( defined( 'O1_BAD_REQUEST_MAX_LOGIN_REQUEST_SIZE' ) ) {
            $this->max_login_request_size = intval( O1_BAD_REQUEST_MAX_LOGIN_REQUEST_SIZE );
        }

        if ( defined( 'O1_BAD_REQUEST_CDN_HEADERS' ) ) {
            $this->cdn_headers = explode( ':', O1_BAD_REQUEST_CDN_HEADERS );
        }

        if ( defined( 'O1_BAD_REQUEST_ALLOW_REG' ) && O1_BAD_REQUEST_ALLOW_REG ) {
            $this->allow_registration = true;
        }

        if ( defined( 'O1_BAD_REQUEST_ALLOW_IE8' ) && O1_BAD_REQUEST_ALLOW_IE8 ) {
            $this->allow_ie8_login = true;
        }

        if ( defined( 'O1_BAD_REQUEST_ALLOW_OLD_PROXIES' ) && O1_BAD_REQUEST_ALLOW_OLD_PROXIES ) {
            $this->allow_old_proxies = true;
        }

        if ( defined( 'O1_BAD_REQUEST_ALLOW_CONNECTION_EMPTY' ) && O1_BAD_REQUEST_ALLOW_CONNECTION_EMPTY ) {
            $this->allow_connection_empty = true;
        }

        if ( defined( 'O1_BAD_REQUEST_ALLOW_CONNECTION_CLOSE' ) && O1_BAD_REQUEST_ALLOW_CONNECTION_CLOSE ) {
            $this->allow_connection_close = true;
        }

        if ( defined( 'O1_BAD_REQUEST_ALLOW_TWO_CAPS' ) && O1_BAD_REQUEST_ALLOW_TWO_CAPS ) {
            $this->allow_two_capitals = true;
        }

        $this->result = $this->check();

        // "false" means there were no bad requests
        if ( false !== $this->result ) {
            $this->trigger();
            exit;
        }

        // @FIXME This blocks the mu-plugin's trigger!!!
        // Don't log POST requests before trigger - multi-line logging problem on mod_proxy_fcgi
        if ( defined( 'O1_BAD_REQUEST_POST_LOGGING' ) && O1_BAD_REQUEST_POST_LOGGING ) {
            if ( 'POST' === $_SERVER['REQUEST_METHOD'] ) {
                $this->enhanced_error_log( 'HTTP POST: ' . $this->esc_log( $_POST ), 'notice' );
            }
        }
    }

    /**
     * Detect for malicious HTTP requests.
     *
     * @return string|boolean  Attack type or false.
     */
    private function check() {

        // Declare apache_request_headers function
        if ( ! function_exists( 'apache_request_headers' ) ) {
            /**
             * Fetch all HTTP request headers.
             *
             * @return array  HTTP request headers
             */
            function apache_request_headers() {

                $headers = array();
                foreach ( $_SERVER as $name => $value ) {
                    if ( 'HTTP_' === substr( $name, 0, 5 ) ) {
                        $headers[ substr( $name, 5 ) ] = $value;
                    }
                }

                return $headers;
            }
        }

        // Don't ban on local access and on install or upgrade
        // WP_INSTALLING is available even before wp-config.php
        if ( 'cli' === php_sapi_name()
            || $_SERVER['REMOTE_ADDR'] === $_SERVER['SERVER_ADDR']
            || ( defined( 'WP_INSTALLING' ) && WP_INSTALLING )
        ) {
            // Local access
            return false;
        }

        $request_method = strtoupper( $_SERVER['REQUEST_METHOD'] );
        $wp_methods = array( 'HEAD', 'GET', 'POST' );
        $wp_login_methods = array( 'GET', 'POST' );
        $request_path = parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH );
        $request_query = isset( $_SERVER['QUERY_STRING'] )
            ? $_SERVER['QUERY_STRING']
            : parse_url( $_SERVER['REQUEST_URI'], PHP_URL_QUERY );
        $server_name = isset( $_SERVER['SERVER_NAME'] )
            ? $_SERVER['SERVER_NAME']
            : $_SERVER['HTTP_HOST'];

        // Block non-static requests from CDN but allow robots.txt
        if ( ! empty( $this->cdn_headers ) && '/robots.txt' !== $request_path ) {
            $common_headers = array_intersect( $this->cdn_headers, array_keys( $_SERVER ) );
            if ( $common_headers === $this->cdn_headers ) {
                // Log HTTP request headers
                $cdn_combined_headers = array_merge(
                    array( 'REQUEST_URI' => $_SERVER['REQUEST_URI'] ),
                    apache_request_headers()
                );
                $this->enhanced_error_log( 'HTTP headers: ' . $this->esc_log( $cdn_combined_headers ) );
                // Work-around to prevent edge server banning
                $this->prefix = 'Attack through CDN: ';
                $this->instant_trigger = false;
                return 'bad_request_cdn_attack';
            }
        }

        // Too big HTTP request URI
        // Apache: LimitRequestLine directive
        if ( strlen( $_SERVER['REQUEST_URI'] ) > 2000 ) {
            return 'bad_request_uri_length';
        }

        // Too big user agent
        if ( isset( $_SERVER['HTTP_USER_AGENT'] )
            && strlen( $_SERVER['HTTP_USER_AGENT'] ) > 400
        ) {
            return 'bad_request_user_agent_length';
        }

        // HTTP request method
        // Google Translate makes OPTIONS requests
        // Microsoft Office Protocol Discovery does it also
        // Windows Explorer (Microsoft-WebDAV-MiniRedir) also
        // https://tools.ietf.org/html/rfc2616#section-9.2
        if ( 'OPTIONS' === $request_method ) {
            $this->is_options_method = true;
            $this->instant_trigger = false;
            return 'bad_request_http_options_method';
        }
        if ( false === in_array( $request_method, $wp_methods ) ) {
            return 'bad_request_http_method';
        }

        // Request URI does not begin with forward slash (may begin with URL scheme)
        if ( '/' !== substr( $_SERVER['REQUEST_URI'], 0, 1 ) ) {
            return 'bad_request_uri_slash';
        }

        // Request URI encoding
        // https://tools.ietf.org/html/rfc3986#section-2.2
        // reserved    = gen-delims / sub-delims
        // gen-delims  = ":" / "/" / "?" / "#" / "[" / "]" / "@"
        // sub-delims  = "!" / "$" / "&" / "'" / "(" / ")"
        //             / "*" / "+" / "," / ";" / "="
        // unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
        // "#" removed
        // "%" added
        if ( substr_count( $_SERVER['REQUEST_URI'], '?' ) > 1
            || false !== strpos( $_SERVER['REQUEST_URI'], '#' )
            || 1 === preg_match( "/[^%:\/?\[\]@!$&'()*+,;=A-Za-z0-9._~-]/", $_SERVER['REQUEST_URI'] )
        ) {
            $this->instant_trigger = false;
            return 'bad_request_uri_encoding';
        }

        // URL path and query string blacklist
        if ( true === $this->strifounda( $_SERVER['REQUEST_URI'], $this->blacklist ) ) {
            return 'bad_request_uri_blacklist';
        }

        // HTTP protocol name
        if ( empty( $_SERVER['SERVER_PROTOCOL'] ) ) {
            return 'bad_request_protocol_empty';
        }

        // robots.txt probing in a subdirectory
        if ( false !== stripos( $_SERVER['REQUEST_URI'], 'robots.txt' )
            && '/robots.txt' !== $_SERVER['REQUEST_URI']
        ) {
            return 'bad_request_robots_probe';
        }

        // WordPress author sniffing
        // Except on post listing by author on wp-admin
        if ( false === strpos( $request_path, '/wp-admin/' )
            && isset( $_REQUEST['author'] )
            && is_numeric( $_REQUEST['author'] )
        ) {
            return 'bad_request_wp_author_sniffing';
        }

        // Check HTTP POST requests only
        // wget sends: User-Agent, Accept, Host, Connection, Content-Type, Content-Length
        // curl sends: User-Agent, Host, Accept, Content-Length, Content-Type
        if ( 'POST' !== $request_method ) {
            // Not HTTP/POST
            return false;
        }

        // --------------------------- >8 ---------------------------
        // is_post

        if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
            $this->is_xmlrpc = true;
        } elseif ( false !== strpos( $request_path, '/wp-login.php' ) ) {
            $this->is_wplogin = true;
        }

        // PHP file upload
        if ( ! empty( $_FILES ) ) {
            foreach ( $_FILES as $files ) {
                // Make it look like an HTML array
                if ( ! is_array( $files['name'] ) ) {
                    // Only name and type are checked
                    $files['name'] = array( $files['name'] );
                    if ( isset( $files['type'] ) ) {
                        $files['type'] = array( $files['type'] );
                    }
                }
                foreach ( $files['name'] as $index => $notused ) {
                    if ( false !== stripos( $files['name'][ $index ], '.php' )
                        || (
                            isset( $files['type'] )
                            && isset( $files['type'][ $index ] )
                            && false !== stripos( $files['type'][ $index ], 'php' )
                        )
                    ) {
                        return 'bad_request_post_upload_php';
                    }
                }
            }
        }

        // User agent HTTP header
        if ( empty( $_SERVER['HTTP_USER_AGENT'] ) ) {
            return 'bad_request_post_user_agent_empty';
        }
        $user_agent = $_SERVER['HTTP_USER_AGENT'];

        // Accept HTTP header
        // IE9, wget and curl sends only "*/*"
        // Otherwise the minimum should be: 'text/html'
        if ( empty( $_SERVER['HTTP_ACCEPT'] )
            || false === strpos( $_SERVER['HTTP_ACCEPT'], '/' )
        ) {
            return 'bad_request_post_accept';
        }

        // Content-Length HTTP header
        if ( ! isset( $_SERVER['CONTENT_LENGTH'] )
            || ! is_numeric( $_SERVER['CONTENT_LENGTH'] )
        ) {
            return 'bad_request_post_content_length';
        }

        // Content-Type HTTP header (for login, XML-RPC and AJAX)
        if ( '0' !== $_SERVER['CONTENT_LENGTH']
            && ( empty( $_SERVER['CONTENT_TYPE'] )
                || ( $this->is_wplogin
                    && 0 !== stripos( $_SERVER['CONTENT_TYPE'], 'application/x-www-form-urlencoded' )
                )
                || ( $this->is_xmlrpc
                    && 0 !== stripos( $_SERVER['CONTENT_TYPE'], 'text/xml' )
                )
                || ( 0 !== stripos( $_SERVER['CONTENT_TYPE'], 'application/x-www-form-urlencoded' )
                    && 0 !== stripos( $_SERVER['CONTENT_TYPE'], 'multipart/form-data' )
                    && 0 !== stripos( $_SERVER['CONTENT_TYPE'], 'text/xml' )
                    && 0 !== stripos( $_SERVER['CONTENT_TYPE'], 'application/json' )
                    && 0 !== stripos( $_SERVER['CONTENT_TYPE'], 'application/octet-stream' )
                )
            )
        ) {
            return 'bad_request_post_content_type';
        }

        // Check requests only for wp-login.php
        if ( ! $this->is_wplogin ) {
            // Not wp-login
            return false;
        }

        // --------------------------- >8 ---------------------------
        // is_wplogin

        // wp-login methods
        if ( false === in_array( $request_method, $wp_login_methods ) ) {
            return 'bad_request_wplogin_http_method';
        }

        // Login request with non-empty username
        if ( ! empty( $_POST['log'] ) ) {
            $username = trim( $_POST['log'] );

            // Banned usernames
            if ( in_array( strtolower( $username ), $this->names2ban ) ) {
                return 'bad_request_wplogin_username_banned';
            }

            // Attackers try usernames with "TwoCapitals"
            if ( ! $this->allow_two_capitals ) {
                if ( 1 === preg_match( '/^[A-Z][a-z]+[A-Z][a-z]+$/', $username ) ) {
                    return 'bad_request_wplogin_username_twocapitals';
                }
            }
        }

        // Maximum HTTP request size for logins
        $request_size = strlen( http_build_query( apache_request_headers() ) )
            + strlen( $_SERVER['REQUEST_URI'] )
            + strlen( http_build_query( $_POST ) );
        if ( $request_size > $this->max_login_request_size ) {
            return 'bad_request_wplogin_request_size';
        }

        // Accept-Language HTTP header
        if ( empty( $_SERVER['HTTP_ACCEPT_LANGUAGE'] )
            || strlen( $_SERVER['HTTP_ACCEPT_LANGUAGE'] ) < 2
        ) {
            return 'bad_request_wplogin_accept_language';
        }

        // Referer HTTP header
        if ( empty( $_SERVER['HTTP_REFERER'] ) ) {
            return 'bad_request_wplogin_referer_empty';
        }

        $referer = $_SERVER['HTTP_REFERER'];

        // Referer HTTP header
        if ( ! $this->allow_registration ) {
            if ( parse_url( $referer, PHP_URL_HOST ) !== $server_name ) {
                return 'bad_request_wplogin_referer_host';
            }
        }

        // Skip following checks on post password
        if ( ! empty( $request_query ) ) {
            $queries = $this->parse_query( $request_query );

            if ( isset( $queries['action'] ) && 'postpass' === $queries['action'] ) {
                // wp-login/postpass
                return false;
            }
        }

        // --------------------------- >8 ---------------------------
        // NOT wp-login/postpass

        // Referer HTTP header
        if ( ! $this->allow_registration ) {
            if ( false === strpos( parse_url( $referer, PHP_URL_PATH ), '/wp-login.php' ) ) {
                return 'bad_request_wplogin_referer_path';
            }
        }

        // HTTP protocol version
        if ( ! $this->allow_old_proxies ) {
            if ( false === strpos( $_SERVER['SERVER_PROTOCOL'], 'HTTP/1.1' )
                && false === strpos( $_SERVER['SERVER_PROTOCOL'], 'HTTP/2' )
            ) {
                return 'bad_request_wplogin_http11_2';
            }
        }

        // Connection HTTP header (keep alive)
        if ( ! $this->allow_connection_empty ) {
            if ( empty( $_SERVER['HTTP_CONNECTION'] ) ) {
                return 'bad_request_wplogin_connection_empty';
            }

            if ( ! $this->allow_connection_close ) {
                if ( false === stripos( $_SERVER['HTTP_CONNECTION'], 'keep-alive' ) ) {
                    return 'bad_request_wplogin_connection';
                }
            }
        }

        // Accept-Encoding HTTP header
        if ( empty( $_SERVER['HTTP_ACCEPT_ENCODING'] )
            || false === strpos( $_SERVER['HTTP_ACCEPT_ENCODING'], 'gzip' )
        ) {
            return 'bad_request_wplogin_accept_encoding';
        }

        // WordPress test cookie
        if ( ! $this->allow_registration ) {
            if ( empty( $_SERVER['HTTP_COOKIE'] )
                || false === strpos( $_SERVER['HTTP_COOKIE'], 'wordpress_test_cookie' )
            ) {
                return 'bad_request_wplogin_test_cookie';
            }
        }

        // IE8 login
        if ( $this->allow_ie8_login ) {
            if ( 'Mozilla/4.0 (compatible; MSIE 8.0;' === substr( $user_agent, 0, 34 ) ) {
                // Allow IE8
                return false;
            }
        }

        // Botnet user agents
        if ( 1 === preg_match( '/Firefox\/1|bot|spider|crawl|user-agent|random|"|\\\\/i', $user_agent ) ) {
            return 'bad_request_wplogin_user_agent_botnet';
        }

        // Modern browser user agents
        if ( 'Mozilla/5.0' !== substr( $user_agent, 0, 11 ) ) {
            return 'bad_request_wplogin_user_agent_mozilla50';
        }

        // OK
        return false;
    }

    /**
     * Trigger fail2ban and respond HTTP/403.
     *
     * @return null
     */
    private function trigger() {

        // Trigger miniban
        if ( class_exists( 'Miniban' ) && $this->instant_trigger ) {
            if ( true !== \Miniban::ban() ) {
                error_log( 'Miniban operation failed.' );
            }
        }

        // Trigger fail2ban
        if ( $this->instant_trigger ) {
            $this->enhanced_error_log( $this->prefix_instant . $this->result, 'crit' );
        } else {
            $this->enhanced_error_log( $this->prefix . $this->result );
        }

        // Log POST requests after trigger - multi-line logging problem on mod_proxy_fcgi
        if ( defined( 'O1_BAD_REQUEST_POST_LOGGING' ) && O1_BAD_REQUEST_POST_LOGGING ) {
            if ( 'POST' === $_SERVER['REQUEST_METHOD'] ) {
                $this->enhanced_error_log( 'HTTP POST: ' . $this->esc_log( $_POST ), 'notice' );
            }
        }

        ob_get_level() && ob_end_clean();
        if ( $this->is_options_method ) {
            $this->disable_options_method();

        } elseif ( $this->is_xmlrpc ) {
            $this->fake_xmlrpc();

        } elseif ( ! headers_sent() ) {
            if ( $this->is_wplogin && ! empty( $_POST['log'] ) ) {
                $this->fake_wplogin();
            } else {
                $this->ban();
            }
        }
    }

    private function ban() {

        header( 'Status: 403 Forbidden' );
        header( 'HTTP/1.1 403 Forbidden', true, 403 );

        header( 'Connection: Close' );
        header( 'Cache-Control: max-age=0, private, no-store, no-cache, must-revalidate' );
        header( 'X-Robots-Tag: noindex, nofollow' );
        header( 'Content-Length: 0' );
    }

    private function disable_options_method() {

        header( 'Status: 405 Method Not Allowed' );
        header( 'HTTP/1.1 405 Method Not Allowed', true, 405 );

        header( 'Allow: GET, POST, HEAD' );
        header( 'Content-Length: 0' );
    }

    private function fake_wplogin() {

        $server_name = isset( $_SERVER['SERVER_NAME'] )
            ? $_SERVER['SERVER_NAME']
            : $_SERVER['HTTP_HOST'];
        $username = trim( $_POST['log'] );
        $expire = time() + 3600;
        $token = substr( hash_hmac( 'sha256', rand(), 'token' ), 0, 43 );
        $hash = hash_hmac( 'sha256', rand(), 'hash' );
        $auth_cookie = $username . '|' . $expire . '|' . $token . '|' . $hash;
        $authcookie_name = 'wordpress_' . md5( 'authcookie' );
        $loggedincookie_name = 'wordpress_logged_in_' . md5( 'cookiehash' );

        header( 'Cache-Control: max-age=0, private, no-store, no-cache, must-revalidate' );
        header( 'X-Robots-Tag: noindex, nofollow' );
        setcookie( $authcookie_name, $auth_cookie, $expire, '/brake/wp_content/plugins', false, false, true );
        setcookie( $authcookie_name, $auth_cookie, $expire, '/brake/wp-admin', false, false, true );
        setcookie( $loggedincookie_name, $auth_cookie, $expire, '/', false, false, true );

        header( 'Location: http://' . $server_name . '/brake/wp-admin/' );
    }

    private function fake_xmlrpc() {

        $server_name = isset( $_SERVER['SERVER_NAME'] )
            ? $_SERVER['SERVER_NAME']
            : $_SERVER['HTTP_HOST'];

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
  <member><name>url</name><value><string>http://%s/</string></value></member>
  <member><name>blogid</name><value><string>1</string></value></member>
  <member><name>blogName</name><value><string>brake</string></value></member>
  <member><name>xmlrpc</name><value><string>http://%s/brake/xmlrpc.php</string></value></member>
</struct></value>
</data></array>
      </value>
    </param>
  </params>
</methodResponse>
',
            $server_name,
            $server_name
        );
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
        // log_errors directive does not actually disable logging.
        $log_enabled = ( '1' === ini_get( 'log_errors' ) );
        if ( ! $log_enabled || empty( $log_destination ) ) {
        */

        // Add entry point, correct when `auto_prepend_file` is empty
        $included_files = get_included_files();
        $first_included_file = reset( $included_files );
        $error_msg = sprintf( '%s <%s',
            $message,
            $this->esc_log( sprintf( '%s:%s', $_SERVER['REQUEST_METHOD'], $first_included_file ) )
        );

        /**
         * Add log level and client data to log message if SAPI does not add it.
         *
         * Client data: IP address, port, referer
         */
        $log_destination = function_exists( 'ini_get' ) ? ini_get( 'error_log' ) : '';
        if ( ! empty( $log_destination ) ) {
            $referer = '';
            if ( isset( $_SERVER['HTTP_REFERER'] ) ) {
                $referer = sprintf( ', referer:%s', $this->esc_log( $_SERVER['HTTP_REFERER'] ) );
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
            if ( empty( $name_value_array[0] ) ) {
                continue;
            }

            // Set field value
            $query[ $name_value_array[0] ] = isset( $name_value_array[1] ) ? $name_value_array[1] : '';
        }

        return $query;
    }

    /**
     * Prepare a string to safe logging
     *
     * @param string $string  String to escape.
     *
     * @return string         Escaped string in parentheses.
     */
    private function esc_log( $string ) {

        $escaped = serialize( $string );
        // Limit length
        $escaped = mb_substr( $escaped, 0, 500, 'utf-8' );
        // New lines to "|"
        $escaped = str_replace( array( "\n", "\r" ), '|', $escaped );
        // Replace non-printables with "¿"
        $escaped = preg_replace( '/[^\P{C}]+/u', "\xC2\xBF", $escaped );

        return sprintf( ' (%s)', $escaped );
    }

    /**
     * Whether an array contains a case-insensitive substring
     *
     * @param string $haystack  The haystack.
     * @param array $needles    The needles.
     *
     * @return boolean          A needle is found.
     */
    private function strifounda( $haystack, $needles ) {

        foreach ( $needles as $substring ) {
            if ( false !== stripos( $haystack, $substring ) ) {
                return true;
            }
        }

        return false;
    }
}
