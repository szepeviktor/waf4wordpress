<?php
/*
Snippet Name: Trigger Fail2ban in non-WordPress projects and subdirectory installs.
Version: 0.4.0
Snippet URI: https://github.com/szepeviktor/wordpress-fail2ban
License: The MIT License (MIT)
Author: Viktor Szépe
*/

error_log( 'Break-in attempt detected: no_wp_here_wplogin' );

ob_get_level() && ob_end_clean();
fake_wplogin();
exit;

function fake_wplogin() {

    $server_name = isset( $_SERVER['SERVER_NAME'] )
        ? $_SERVER['SERVER_NAME']
        : $_SERVER['HTTP_HOST'];
    $username = isset( $_POST['log'] ) ? trim( $_POST['log'] ) : 'admin';
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
    // Should return HTTP/400
    $server_name = $_SERVER['SERVER_ADDR'];
    header( 'Location: http://' . $server_name . '/brake/wp-admin/' );
}
