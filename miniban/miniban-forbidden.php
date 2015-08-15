<?php

class Miniban extends Miniban_Base {

    public static function ban( $ban_ip = null, $ban_time = 0 ) {

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

    public static function unban( $unban_ip = null ) {
    }
}
