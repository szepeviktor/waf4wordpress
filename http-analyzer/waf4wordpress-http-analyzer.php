<?php declare( strict_types = 1 );
/**
 * HTTP request analyzer part of WAF for WordPress.
 *
 * @package Waf4wordpress
 *
 * @wordpress-plugin
 * Plugin Name: WAF for WordPress (required from wp-config or started in auto_prepend_file)
 * Version:     3.0.2
 * Description: Stop various HTTP attacks and trigger Fail2ban.
 * Plugin URI:  https://github.com/szepeviktor/wordpress-fail2ban
 * License:     The MIT License (MIT)
 * Author:      Viktor Szépe
 * GitHub Plugin URI: https://github.com/szepeviktor/wordpress-fail2ban
 * Constants: W4WP_INSTANT
 * Constants: W4WP_PROXY_HOME_URL
 * Constants: W4WP_MAX_LOGIN_REQUEST_SIZE
 * Constants: W4WP_CDN_HEADERS
 * Constants: W4WP_ALLOW_REG
 * Constants: W4WP_ALLOW_IE8
 * Constants: W4WP_ALLOW_OLD_PROXIES
 * Constants: W4WP_ALLOW_CONNECTION_EMPTY
 * Constants: W4WP_ALLOW_CONNECTION_CLOSE
 * Constants: W4WP_ALLOW_TWO_CAPS
 * Constants: W4WP_DISALLOW_TOR_LOGIN
 * Constants: W4WP_POST_LOGGING
 */

namespace Waf4WordPress;

/**
 * Block bad requests and trigger Fail2ban.
 *
 * Require it from the top of your wp-config.php:
 *
 *     define( 'W4WP_ALLOW_CONNECTION_EMPTY', true ); // HTTP2
 *     require_once __DIR__ . '/waf4wordpress-http-analyzer.php';
 *     new \Waf4WordPress\Http_Analyzer();
 */
final class Http_Analyzer {

    private $prefix = 'Malicious traffic detected: ';
    private $prefix_instant = 'Break-in attempt detected: ';
    private $instant_trigger = true;
    private $login_url = '/wp-login.php';
    private $admin_url = '/wp-admin/';
    /**
     * Default rest_url_prefix.
     *
     * @var string
     */
    private $rest_url_prefix = '/wp-json/';
    private $max_login_request_size = 4000;
    private $is_login = false;
    private $is_xmlrpc = false;
    private $is_rest = false;
    private $is_options_method = false;
    private $is_delete_method = false;
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
    private $blacklist = [
        '../', // Path traversal
        '/..', // Path traversal
        'wp-config', // WP configuration
        '/wordpress/', // WP subdir install
        'wlwmanifest.xml', // Scan for WP
        '/brake/wp-admin/', // From fake_wplogin()
        'allow_url_include', // PHP directive
        'auto_prepend_file', // PHP directive
        'file_put_contents', // PHP write to a file
        'testproxy.php', // Scan for open proxies
        'httptest.php', // Scan for open proxies
        'bigdump.php', // Staggered MySQL Dump Importer
        'wso.php', // Web Shell
        'w00tw00t', // DFind Scanner
        'configuration.php', // Joomla configuration
        '/administrator', // Joomla Administrator
        'connector.asp', // Joomla FCKeditor 2.x File Manager Connector for ASP
        '/HNAP1', // D-Link routers
        // phpcs:ignore Squiz.PHP.CommentedOutCode
        '() { ', // Shell shock, Bash script: () { :;};
        '/cgi-bin/', // CGI folder
        'error_log', // Default PHP error log
        'error-log', // PHP error log
        'htaccess', // Apache httpd configuration
        'web.config', // IIS configuration
        'etc/passwd', // Linux password file
        'id_rsa', // SSH key file
        'id_dsa', // SSH key file
        'muieblackcat', // Vulnerability scanner
        'etc/local.xml', // Magento configuration
        'eval(', // Evaluate a string as PHP code
        '=die(', // "z!ax" PHP vulnerability probe
        'order by', // SQL injection
        ' -- ', // SQL comment
        'and 1=', // SQL injection
        'bea_wls_deployment_internal', // Oracle WebLogic Server
    ];
    private $botnet_pattern = '#Firefox/1|bot|spider|crawl|user-agent|random|"|\\\\#i';
    private $relative_request_uri = '';
    private $cdn_headers = [];
    private $allow_registration = false;
    private $allow_ie8_login = false;
    private $allow_old_proxies = false;
    private $allow_connection_empty = false;
    private $allow_connection_close = false;
    private $allow_two_capitals = false;
    private $disallow_tor_login = false;
    private $result = false;
    private $debug = false;

    /**
     * Set up options, run check and trigger Fail2ban on malicous HTTP request.
     */
    public function __construct() {

        // Don't run on CLI.
        // Don't run on install or upgrade.
        // WP_INSTALLING is available even before wp-config.php.
        if ( 'cli' === php_sapi_name()
            || ( defined( 'WP_INSTALLING' ) && WP_INSTALLING )
        ) {
            return;
        }

        if ( empty( $_SERVER['SERVER_ADDR'] )
            || empty( $_SERVER['REMOTE_ADDR'] )
            || empty( $_SERVER['REMOTE_PORT'] )
            || empty( $_SERVER['REQUEST_METHOD'] )
            || empty( $_SERVER['REQUEST_URI'] )
        ) {
            $this->prefix = 'Server configuration error: ';
            $this->instant_trigger = false;
            $this->result = 'bad_request_superglobal';
            $this->trigger();
            exit;
        }

        // Don't run on local access.
        if ( $_SERVER['REMOTE_ADDR'] === $_SERVER['SERVER_ADDR'] ) { // WPCS: input var okay.
            return;
        }

        $this->read_constants();

        $this->result = $this->check();

        // "false" means there were no bad requests.
        if ( false !== $this->result ) {
            $this->trigger();
            exit;
        }
    }

    /**
     * Set properties based on defined constants.
     */
    private function read_constants() {

        if ( defined( 'W4WP_INSTANT' ) && false === W4WP_INSTANT ) {
            $this->instant_trigger = false;
        }

        $this->relative_request_uri = $_SERVER['REQUEST_URI'];
        // W4WP_PROXY_HOME_URL should not have a trailing slash
        if ( defined( 'W4WP_PROXY_HOME_URL' ) ) {
            $home_url_length = strlen( W4WP_PROXY_HOME_URL );
            if ( W4WP_PROXY_HOME_URL === substr( $_SERVER['REQUEST_URI'], 0, $home_url_length ) ) {
                $this->relative_request_uri = substr( $_SERVER['REQUEST_URI'], $home_url_length );
                /*
                 * Fix request URI
                 *
                 * @see https://core.trac.wordpress.org/ticket/39586
                 *
                 * $_SERVER['REQUEST_URI'] = $this->relative_request_uri;
                 */
            }
        }

        if ( defined( 'W4WP_MAX_LOGIN_REQUEST_SIZE' ) ) {
            $this->max_login_request_size = intval( W4WP_MAX_LOGIN_REQUEST_SIZE );
        }

        if ( defined( 'W4WP_CDN_HEADERS' ) ) {
            $this->cdn_headers = explode( ':', W4WP_CDN_HEADERS );
        }

        if ( defined( 'W4WP_ALLOW_REG' ) && W4WP_ALLOW_REG ) {
            $this->allow_registration = true;
        }

        if ( defined( 'W4WP_ALLOW_IE8' ) && W4WP_ALLOW_IE8 ) {
            $this->allow_ie8_login = true;
        }

        if ( defined( 'W4WP_ALLOW_OLD_PROXIES' ) && W4WP_ALLOW_OLD_PROXIES ) {
            $this->allow_old_proxies = true;
        }

        if ( defined( 'W4WP_ALLOW_CONNECTION_EMPTY' ) && W4WP_ALLOW_CONNECTION_EMPTY ) {
            $this->allow_connection_empty = true;
        }

        if ( defined( 'W4WP_ALLOW_CONNECTION_CLOSE' ) && W4WP_ALLOW_CONNECTION_CLOSE ) {
            $this->allow_connection_close = true;
        }

        if ( defined( 'W4WP_ALLOW_TWO_CAPS' ) && W4WP_ALLOW_TWO_CAPS ) {
            $this->allow_two_capitals = true;
        }

        if ( defined( 'W4WP_DISALLOW_TOR_LOGIN' ) && W4WP_DISALLOW_TOR_LOGIN ) {
            $this->disallow_tor_login = true;
        }

        if ( defined( 'W4WP_POST_LOGGING' ) && W4WP_POST_LOGGING ) {
            $this->debug = true;
        }
    }

    /**
     * Detect for malicious HTTP requests.
     *
     * @return string|boolean Attack type or false.
     */
    private function check() {

        // Request methods.
        $request_method = strtoupper( $_SERVER['REQUEST_METHOD'] );
        $wp_methods = [ 'HEAD', 'GET', 'POST' ];
        $login_methods = [ 'GET', 'POST' ];
        $rest_methods = [ 'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS' ];
        $write_methods = [ 'POST', 'PUT', 'DELETE' ];

        // Dissect request URI.
        $request_path = (string) parse_url( $this->relative_request_uri, PHP_URL_PATH );
        $request_query = isset( $_SERVER['QUERY_STRING'] )
            ? $_SERVER['QUERY_STRING']
            : parse_url( $this->relative_request_uri, PHP_URL_QUERY );

        // Server name.
        $server_name = isset( $_SERVER['SERVER_NAME'] )
            ? $_SERVER['SERVER_NAME']
            : $_SERVER['HTTP_HOST'];

        // Log requests to a file.
        if ( $this->debug
            // Sample conditions.
            && 'POST' === $request_method
            && false !== strpos( $request_path, '/customer/account/createpost' )
            && isset( $_SERVER['HTTP_CF_RAY'] ) // Cloudflare request.
        ) {
            if ( empty( $_POST ) ) {
                // phpcs:ignore WordPress.VIP.RestrictedFunctions
                $request_data = file_get_contents( 'php://input' );
            } else {
                $request_data = $_POST;
            }
            $dump_file = sprintf(
                '%s/request-at-%s-from-%s.json',
                sys_get_temp_dir(),
                time(),
                $_SERVER['REMOTE_ADDR']
            );
            $dump = json_encode(
                [
                    'headers' => $this->apache_request_headers(),
                    'request' => $request_data,
                    'files' => $_FILES,
                    'cookies' => $_COOKIE,
                ],
                JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
            );
            // phpcs:ignore WordPress.VIP.FileSystemWritesDisallow
            file_put_contents( $dump_file, $dump, FILE_APPEND | LOCK_EX );
        }

        // Request type.
        if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
            $this->is_xmlrpc = true;
        } elseif ( false !== strpos( $request_path, $this->login_url ) ) {
            $this->is_login = true;
        } elseif ( false !== strpos( $request_path, $this->rest_url_prefix ) ) {
            $this->is_rest = true;
        }

        // Block non-static requests from CDN but allow robots.txt.
        if ( [] !== $this->cdn_headers && '/robots.txt' !== $request_path ) {
            $common_headers = array_intersect( $this->cdn_headers, array_keys( $_SERVER ) );
            if ( $common_headers === $this->cdn_headers ) {
                // Log HTTP request headers.
                $cdn_combined_headers = array_merge(
                    [
                        'REQUEST_URI' => $_SERVER['REQUEST_URI'],
                    ],
                    $this->apache_request_headers()
                );
                $header_list = $this->esc_log( $cdn_combined_headers );
                $this->enhanced_error_log( 'HTTP headers: ' . $header_list );
                // Work-around to prevent edge server banning.
                $this->prefix = 'Attack through CDN: ';
                $this->instant_trigger = false;
                return 'bad_request_cdn_attack';
            }
        }

        // Too big HTTP request URI.
        // Apache: LimitRequestLine directive defaults to 8190
        // By standard: HTTP/414 Request-URI Too Long
        // https://tools.ietf.org/html/rfc2616#section-10.4.15
        // 2500 bytes ~ deletion of 50 spam comments (GET form)
        if ( strlen( $_SERVER['REQUEST_URI'] ) > 2500 ) {
            return 'bad_request_uri_length';
        }

        // Too big user agent.
        if ( isset( $_SERVER['HTTP_USER_AGENT'] )
            && strlen( $this->fix_opera_ua( $_SERVER['HTTP_USER_AGENT'] ) ) > 472
        ) {
            return 'bad_request_user_agent_length';
        }

        // HTTP request method.
        // Google Translate makes OPTIONS requests
        // Microsoft Office Protocol Discovery does it also
        // Windows Explorer (Microsoft-WebDAV-MiniRedir) also
        // https://tools.ietf.org/html/rfc2616#section-9.2
        if ( ! $this->is_rest && 'OPTIONS' === $request_method ) {
            $this->is_options_method = true;
            $this->instant_trigger = false;
            return 'bad_request_http_options_method';
        }
        if ( 'DELETE' === $request_method ) {
            $this->is_delete_method = true;
        }
        if ( ! $this->is_login && ! $this->is_rest
            && false === in_array( $request_method, $wp_methods, true )
        ) {
            return 'bad_request_http_method';
        }
        if ( $this->is_login && false === in_array( $request_method, $login_methods, true ) ) {
            return 'bad_request_login_http_method';
        }
        if ( $this->is_rest && false === in_array( $request_method, $rest_methods, true ) ) {
            return 'bad_request_rest_http_method';
        }

        // Request URI does not begin with forward slash (maybe with URL scheme).
        if ( '/' !== substr( $this->relative_request_uri, 0, 1 ) ) {
            return 'bad_request_uri_slash';
        }

        // IE{8,9,10,11} may send UTF-8 encoded query string.
        if ( '' !== $request_query
            && ! empty( $_SERVER['HTTP_USER_AGENT'] )
            && $this->is_ie( $_SERVER['HTTP_USER_AGENT'] )
        ) {
            $this->rebuild_query( $request_query );
        }

        // Request URI encoding.
        // https://tools.ietf.org/html/rfc3986#section-2.2
        // reserved    = gen-delims / sub-delims
        // gen-delims  = ":" / "/" / "?" / "#" / "[" / "]" / "@"
        // sub-delims  = "!" / "$" / "&" / "'" / "(" / ")"
        //             / "*" / "+" / "," / ";" / "="
        // unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
        // "#" removed
        // "%" added
        // Look for "http:" in request path
        if ( substr_count( $_SERVER['REQUEST_URI'], '?' ) > 1
            || false !== strpos( $_SERVER['REQUEST_URI'], '#' )
            || 1 === preg_match( "/[^%:\/?\[\]@!$&'()*+,;=A-Za-z0-9._~-]/", $_SERVER['REQUEST_URI'] )
            || 1 === preg_match( '/(http|https|data):/i', $request_path )
        ) {
            $this->instant_trigger = false;
            return 'bad_request_uri_encoding';
        }

        // URL path and query string blacklist.
        if ( true === $this->strifounda( urldecode( $_SERVER['REQUEST_URI'] ), $this->blacklist ) ) {
            return 'bad_request_uri_blacklist';
        }

        // Query string arrays with hash indices.
        // @see https://core.trac.wordpress.org/ticket/17737
        if ( false !== strpos( urldecode( $request_query ), '[#' ) ) {
            return 'bad_request_uri_array_hash';
        }

        // HTTP protocol name.
        if ( empty( $_SERVER['SERVER_PROTOCOL'] ) ) {
            return 'bad_request_protocol_empty';
        }

        // Non-existent PHP file.
        // http://httpd.apache.org/docs/current/custom-error.html#variables
        if ( isset( $_SERVER['REDIRECT_URL'] )
            && false !== stripos( $_SERVER['REDIRECT_URL'], '.php' )
            // phpcs:ignore Squiz.PHP.CommentedOutCode
            /*
             * For old mod_fastcgi setups.
             *
             * && $_SERVER['SCRIPT_NAME'] !== $_SERVER['REDIRECT_URL']
             */
        ) {
            return 'bad_request_nonexistent_php';
        }

        // robots.txt probing in a subdirectory and with query string.
        if ( false !== stripos( $this->relative_request_uri, 'robots.txt' )
            && '/robots.txt' !== $this->relative_request_uri
        ) {
            return 'bad_request_robots_probe';
        }

        // WordPress author sniffing.
        // Except on post listing by author on wp-admin.
        if ( false === strpos( $request_path, $this->admin_url )
            && isset( $_REQUEST['author'] )
            && is_numeric( $_REQUEST['author'] )
        ) {
            return 'bad_request_wp_author_sniffing';
        }

        // Check write-type requests only.
        if ( false === in_array( $request_method, $write_methods, true ) ) {
            // Not a write-type method.
            return false;
        }

        /*
         * --------------------------- %< ---------------------------
         * @is_write_method
         * wget POST: User-Agent, Accept, Host, Connection, Content-Type, Content-Length
         * curl POST: User-Agent, Host, Accept, Content-Length, Content-Type
         */

        // PHP file upload.
        // @see https://www.php.net/manual/en/features.file-upload.post-method.php#118858
        if ( ! empty( $_FILES ) ) {
            foreach ( $_FILES as $files ) {
                if ( ! isset( $files['name'] ) ) {
                    continue;
                }
                $types = [];
                if ( is_array( $files['name'] ) ) {
                    // Convert to a leaf-only array.
                    $names = $this->get_leafs( $files['name'] );
                    if ( isset( $files['type'] ) ) {
                        $types = $this->get_leafs( $files['type'] );
                    }
                } else {
                    // Make it look like an HTML array.
                    // 'name' and 'type' are enough.
                    $names = [ $files['name'] ];
                    if ( isset( $files['type'] ) ) {
                        $types = [ $files['type'] ];
                    }
                }
                foreach ( $names as $key => $value ) {
                    if ( false !== stripos( $value, '.php' )
                        || (
                            isset( $types[ $key ] )
                            && (
                                false !== stripos( $types[ $key ], 'php' )
                                || false !== stripos( $types[ $key ], 'application/x-shockwave-flash' )
                            )
                        )
                    ) {
                        return 'bad_request_post_upload_php';
                    }
                }
            }
        }

        // User agent HTTP header.
        if ( empty( $_SERVER['HTTP_USER_AGENT'] ) ) {
            return 'bad_request_post_user_agent_empty';
        }
        $user_agent = $_SERVER['HTTP_USER_AGENT'];

        // Accept HTTP header.
        // IE9, wget and curl sends only '*/*'
        // Otherwise the minimum should be: 'text/html'
        if ( empty( $_SERVER['HTTP_ACCEPT'] )
            || false === strpos( $_SERVER['HTTP_ACCEPT'], '/' )
        ) {
            return 'bad_request_post_accept';
        }

        // Content-Length HTTP header.
        if ( ! isset( $_SERVER['CONTENT_LENGTH'] )
            || ! is_numeric( $_SERVER['CONTENT_LENGTH'] )
        ) {
            // DELETE request may not have a Content-Length header.
            if ( ! $this->is_delete_method ) {
                return 'bad_request_post_content_length';
            }
        }

        // Content-Type HTTP header for login, XML-RPC, REST and AJAX.
        if ( isset( $_SERVER['CONTENT_LENGTH'] )
            && '0' !== $_SERVER['CONTENT_LENGTH']
            && ( empty( $_SERVER['CONTENT_TYPE'] )
                || ( $this->is_login
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

        // Check requests only for wp-login.php.
        if ( ! $this->is_login ) {
            // Not login.
            return false;
        }

        /*
         * --------------------------- %< ---------------------------
         * @is_login
         */

        // Accept-Language HTTP header.
        if ( empty( $_SERVER['HTTP_ACCEPT_LANGUAGE'] )
            || strlen( $_SERVER['HTTP_ACCEPT_LANGUAGE'] ) < 2
        ) {
            return 'bad_request_login_accept_language';
        }

        // Referer HTTP header.
        if ( empty( $_SERVER['HTTP_REFERER'] ) ) {
            return 'bad_request_login_referer_empty';
        }

        $referer = $_SERVER['HTTP_REFERER'];

        // Referer HTTP header.
        if ( ! $this->allow_registration ) {
            if ( parse_url( $referer, PHP_URL_HOST ) !== $server_name ) {
                return 'bad_request_login_referer_host';
            }
        }

        // Maximum HTTP request size for logins (request URI + headers + post parameters).
        $request_size = strlen( $_SERVER['REQUEST_URI'] )
            + strlen( http_build_query( $this->apache_request_headers() ) )
            + strlen( http_build_query( $_POST ) );
        if ( $request_size > $this->max_login_request_size ) {
            return 'bad_request_login_request_size';
        }

        // Login request with non-empty username.
        if ( ! empty( $_POST['log'] ) ) {
            $username = trim( $_POST['log'] );

            // Banned usernames.
            if ( in_array( strtolower( $username ), $this->names2ban, true ) ) {
                return 'bad_request_login_username_banned';
            }

            // Attackers try usernames with "TwoCapitals".
            if ( ! $this->allow_two_capitals ) {
                if ( 1 === preg_match( '/^[A-Z][a-z]+[A-Z][a-z]+$/', $username ) ) {
                    return 'bad_request_login_username_twocapitals';
                }
            }
        }

        // Skip following checks on post password.
        if ( '' !== $request_query ) {
            $queries = $this->parse_query( $request_query );

            if ( isset( $queries['action'] ) && 'postpass' === $queries['action'] ) {
                // wp-login/postpass.
                return false;
            }
        }

        /*
         * --------------------------- %< ---------------------------
         * @is_registered_user
         * Other than wp-login/postpass.
         */

        // HTTP protocol version.
        if ( ! $this->allow_old_proxies ) {
            if ( false === strpos( $_SERVER['SERVER_PROTOCOL'], 'HTTP/1.1' )
                // Also matches 'HTTP/2.0'.
                && false === strpos( $_SERVER['SERVER_PROTOCOL'], 'HTTP/2' )
            ) {
                return 'bad_request_login_http11_2';
            }
        }

        // Accept-Encoding HTTP header.
        if ( empty( $_SERVER['HTTP_ACCEPT_ENCODING'] )
            || false === strpos( $_SERVER['HTTP_ACCEPT_ENCODING'], 'gzip' )
        ) {
            return 'bad_request_login_accept_encoding';
        }

        // IE8 login.
        if ( $this->allow_ie8_login ) {
            if ( 'Mozilla/4.0 (compatible; MSIE 8.0;' === substr( $user_agent, 0, 34 ) ) {
                // Allow IE8.
                return false;
            }
        }

        // Botnet user agents.
        if ( 1 === preg_match( $this->botnet_pattern, $user_agent ) ) {
            return 'bad_request_login_user_agent_botnet';
        }

        // Modern browser user agents.
        if ( 'Mozilla/5.0' !== substr( $user_agent, 0, 11 ) ) {
            return 'bad_request_login_user_agent_mozilla50';
        }

        // WordPress test cookie.
        if ( ! $this->allow_registration ) {
            if ( empty( $_SERVER['HTTP_COOKIE'] )
                || false === strpos( $_SERVER['HTTP_COOKIE'], 'wordpress_test_cookie' )
            ) {
                return 'bad_request_login_test_cookie';
            }
        }

        // Connection HTTP header (keep alive).
        if ( ! $this->allow_connection_empty ) {
            if ( empty( $_SERVER['HTTP_CONNECTION'] ) ) {
                return 'bad_request_login_connection_empty';
            }

            if ( ! $this->allow_connection_close ) {
                if ( false === stripos( $_SERVER['HTTP_CONNECTION'], 'keep-alive' ) ) {
                    return 'bad_request_login_connection';
                }
            }
        }

        // Referer HTTP header.
        if ( ! $this->allow_registration ) {
            $referer_path = (string) parse_url( $referer, PHP_URL_PATH );
            if ( false === strpos( $referer_path, $this->login_url ) ) {
                return 'bad_request_login_referer_path';
            }
        }

        // Tor network exit node detection.
        if ( $this->disallow_tor_login ) {
            $exitlist_tpl = '%s.80.%s.ip-port.exitlist.torproject.org';
            $remote_rev = implode( '.', array_reverse( explode( '.', $_SERVER['REMOTE_ADDR'] ) ) );
            $server_rev = implode( '.', array_reverse( explode( '.', $_SERVER['SERVER_ADDR'] ) ) );
            $exitlist_response = gethostbyname( sprintf( $exitlist_tpl, $remote_rev, $server_rev ) );
            if ( false !== strpos( $exitlist_response, '127.0.0' ) ) {
                    return 'bad_request_login_tor';
            }
        }

        // OK.
        return false;
    }

    /**
     * Trigger Fail2ban and give adequate response.
     */
    private function trigger() {

        // Trigger Miniban.
        if ( class_exists( '\Miniban' ) && $this->instant_trigger ) {
            if ( true !== \Miniban::ban() ) {
                // phpcs:set WordPress.PHP.DevelopmentFunctions exclude[] error_log
                error_log( 'Miniban operation failed.' );
            }
        }

        // Trigger Fail2ban.
        if ( $this->instant_trigger ) {
            $this->enhanced_error_log( $this->prefix_instant . $this->result, 'crit' );
        } else {
            $this->enhanced_error_log( $this->prefix . $this->result );
        }

        if ( 0 !== ob_get_level() ) {
            ob_end_clean();
        }
        if ( $this->is_options_method ) {
            $this->disable_options_method();

        } elseif ( $this->is_xmlrpc ) {
            $this->fake_xmlrpc();

        } elseif ( ! headers_sent() ) {
            if ( $this->is_login && isset( $_POST['log'] ) ) {
                $this->fake_wplogin();
            } else {
                $this->ban();
            }
        }
    }

    /**
     * Send HTTP/403 with no-cache headers.
     */
    private function ban() {

        header( 'Status: 403 Forbidden' );
        header( 'HTTP/1.1 403 Forbidden', true, 403 );

        header( 'Connection: Close' );
        header( 'Cache-Control: max-age=0, private, no-store, no-cache, must-revalidate' );
        header( 'X-Robots-Tag: noindex, nofollow' );
        header( 'Content-Length: 0' );
    }

    /**
     * Send HTTP/405 with allowed methods.
     */
    private function disable_options_method() {

        header( 'Status: 405 Method Not Allowed' );
        header( 'HTTP/1.1 405 Method Not Allowed', true, 405 );

        header( 'Allow: GET, POST, HEAD' );
        header( 'Content-Length: 0' );
    }

    /**
     * Send fake wp-login.php response.
     */
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

        header( 'Location: http://' . $server_name . '/brake/wp-admin/' );
    }

    /**
     * Send fake XML-RPC response.
     */
    private function fake_xmlrpc() {

        $server_name = isset( $_SERVER['SERVER_NAME'] )
            ? $_SERVER['SERVER_NAME']
            : $_SERVER['HTTP_HOST'];

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
            // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            $server_name,
            // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            $server_name
        );
    }

    /**
     * Send a string to error log optionally completed with client data.
     *
     * @param string $message The log message.
     * @param string $level   Log level.
     *
     * @see http://httpd.apache.org/docs/trunk/mod/core.html#loglevel
     */
    private function enhanced_error_log( $message = '', $level = 'error' ) {

        // phpcs:ignore Squiz.PHP.CommentedOutCode
        /*
            log_errors directive does not actually disable logging.
            $log_enabled = ( '1' === ini_get( 'log_errors' ) );
            if ( ! $log_enabled || '' === $log_destination ) {
        */

        // Add entry point, correct when `auto_prepend_file` is empty.
        $included_files = get_included_files();
        $first_included_file = reset( $included_files );
        $error_msg = sprintf(
            '%s <%s',
            $message,
            $this->esc_log( sprintf( '%s:%s', $_SERVER['REQUEST_METHOD'], $first_included_file ) )
        );

        // Add log level and client data to log message if SAPI does not add it.
        $log_destination = function_exists( 'ini_get' ) ? ini_get( 'error_log' ) : '';
        if ( '' !== $log_destination ) {
            $referer = '';
            if ( isset( $_SERVER['HTTP_REFERER'] ) ) {
                $referer = sprintf( ', referer: %s', $this->esc_log( $_SERVER['HTTP_REFERER'] ) );
            }

            // Client data: IP address, port, referer.
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

    /**
     * Fetch all HTTP request headers.
     *
     * @return array HTTP request headers
     */
    private function apache_request_headers() {

        if ( function_exists( 'apache_request_headers' ) ) {

            return (array) apache_request_headers();
        }

        $headers = [];
        foreach ( $_SERVER as $name => $value ) {
            if ( 'HTTP_' === substr( $name, 0, 5 ) ) {
                $headers[ substr( $name, 5 ) ] = $value;
            }
        }

        return $headers;
    }

    /**
     * Parse URL query string to an array.
     *
     * Arrays are not supported.
     *
     * @param string $query_string Raw query string.
     *
     * @return array               Array of individual queries.
     */
    private function parse_query( $query_string ) {

        $query = [];
        $names_values_array = explode( '&', $query_string );

        foreach ( $names_values_array as $name_value ) {
            $name_value_array = explode( '=', $name_value );

            // Check field name
            if ( '' === $name_value_array[0] ) {
                continue;
            }

            // Set field value
            $query[ $name_value_array[0] ] = isset( $name_value_array[1] ) ? $name_value_array[1] : '';
        }

        return $query;
    }

    /**
     * Prepare log data for safe logging.
     *
     * @param mixed $log_data Log data to escape.
     *
     * @return string         Escaped string in parentheses.
     */
    private function esc_log( $log_data ) {

        $escaped = json_encode( $log_data, JSON_UNESCAPED_SLASHES );
        if ( false === $escaped ) {
            return 'JSON n/a';
        }

        // Limit length.
        $escaped = mb_substr( $escaped, 0, 500, 'utf-8' );
        // Change new lines and tabs to "|".
        $escaped = str_replace( [ "\n", "\r", "\t" ], '|', $escaped );
        // Replace non-printables with "?".
        $escaped = preg_replace( '/[^\P{C}]+/u', '?', $escaped );

        return sprintf( '(%s)', $escaped );
    }

    /**
     * Whether an array contains a case-insensitive substring.
     *
     * @param string $haystack The haystack.
     * @param array  $needles  The needles.
     *
     * @return boolean         A needle is found.
     */
    private function strifounda( $haystack, $needles ) {

        foreach ( $needles as $substring ) {
            if ( false !== stripos( $haystack, $substring ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Convert a PHP multi-dimensional array to a leaf-only array with full-depth array keys.
     *
     * @param array $array The multi-dimensional array.
     *
     * @return array       An array containing the leafs only.
     */
    private function get_leafs( $array ) {

        $leafs = [];

        $array_iterator = new \RecursiveArrayIterator( $array );
        $iterator_iterator = new \RecursiveIteratorIterator( $array_iterator, \RecursiveIteratorIterator::LEAVES_ONLY );
        foreach ( $iterator_iterator as $key => $value ) {
            $keys = [];
            $depth = $iterator_iterator->getDepth();
            for ( $i = 0; $i < $depth; $i++ ) {
                $keys[] = $iterator_iterator->getSubIterator( $i )->key();
            }
            $keys[] = $key;
            $leaf_key = implode( ' ', $keys );

            $leafs[ $leaf_key ] = $value;
        }

        return $leafs;
    }

    /**
     * Detect Internet Explorer browser.
     *
     * @param string $ua The user agent string.
     *
     * @return boolean   The client is IE 8, 9, 10 or 11.
     */
    private function is_ie( $ua ) {

        if ( 1 === preg_match( '/^Mozilla\/5\.0 \(Windows NT [0-9.]*;.* Trident\/7\.0; rv:11\.0\) like Gecko/', $ua )
            || 1 === preg_match( '/^Mozilla\/5\.0 \(compatible; MSIE 10\.0; Windows NT [0-9.]*;.* Trident\/6\.0/', $ua )
            || 1 === preg_match( '/^Mozilla\/5\.0 \(compatible; MSIE 9\.0; Windows NT [0-9.]*;.* Trident\/5\.0/', $ua )
            || 1 === preg_match( '/^Mozilla\/4\.0 \(compatible; MSIE 8\.0; Windows NT [0-9.]*;.* Trident\/4\.0/', $ua )
        ) {

            return true;
        }

        return false;
    }

    /**
     * Remove duplicated unique identifiers for the Opera widget.
     *
     * @link https://web.archive.org/web/20101219090859/http://www.opera.com/docs/changelogs/windows/1100/
     *
     * @param string $ua The user agent string.
     *
     * @return string    The reduced user agent string.
     */
    private function fix_opera_ua( $ua ) {

        // phpcs:ignore Squiz.PHP.CommentedOutCode
        // "A unique identifier for the widget."
        // http://operasoftware.github.io/scope-interface/WidgetManager.html
        $ua_reduced = (string) preg_replace( '#(WUID=[0-9a-f]{32}; WTB=[0-9]+; )\1+#', '', $ua );

        return $ua_reduced;
    }

    /**
     * Rebuild possibly not URL-encoded query string.
     *
     * @param string $request_query The query string.
     */
    private function rebuild_query( $request_query ) {

        $rebuilt_query = [];
        $query_length = strlen( $request_query );
        $queries = $this->parse_query( $request_query );

        foreach ( $queries as $key => $value ) {
            $rebuilt_query[] = sprintf(
                '%s=%s',
                rawurlencode( urldecode( $key ) ),
                rawurlencode( urldecode( $value ) )
            );
        }

        // Fix up REQUEST_URI.
        $_SERVER['REQUEST_URI'] = substr( $_SERVER['REQUEST_URI'], 0, -1 * $query_length )
            . implode( '&', $rebuilt_query );
    }
}
