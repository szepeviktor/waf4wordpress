<?php

/**
 * Fix absolute REQUEST_URI
 *     GET http://www.example.com:80/url-path/
 */
function o1_fix_request_uri( $home_url ) {
    $home_url_length = strlen( $home_url );
    if ( $home_url === substr( $_SERVER['REQUEST_URI'], 0, $home_url_length ) ) {
        error_log( 'REQUEST_URI fixed: ' . $_SERVER['REQUEST_URI'] );
        $_SERVER['REQUEST_URI'] = substr( $_SERVER['REQUEST_URI'], $home_url_length );
    }
}
o1_fix_request_uri( 'http://www.example.com:80' );
