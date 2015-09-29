<?php
/*
Plugin Name: Miniban Firewall
Version: 1.0.0
Description: Ban IP address.
Plugin URI: https://github.com/szepeviktor/wordpress-fail2ban
Author: Viktor Szépe
*/

function miniban_firewall() {

    $miniban_lockouts = get_option( 'miniban_lockouts' );
    if ( false !== $miniban_lockouts
        && array_key_exists( $_SERVER['REMOTE_ADDR'], $miniban_lockouts )
    ) {
        ob_get_level() && ob_end_clean();
        if ( ! headers_sent() ) {
            header( 'Status: 403 Forbidden' );
            header( 'HTTP/1.1 403 Forbidden' );
            header( 'Connection: Close' );
            header( 'Cache-Control: max-age=0, private, no-store, no-cache, must-revalidate' );
            header( 'X-Robots-Tag: noindex, nofollow' );
            header( 'Content-Type: text/html' );
            header( 'Content-Length: 0' );
        }

        exit;
    }
}

miniban_firewall();
