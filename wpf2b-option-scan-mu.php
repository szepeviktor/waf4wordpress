<?php
/*
Plugin Name: WordPress fail2ban option table scan MU
Plugin URI: https://github.com/szepeviktor/wordpress-plugin-construction
Description: Find <code>&lt;script&gt;</code> and <code>&lt;iframe&gt;</code> tags in wp_options table and alert.
Version: 0.1.3
License: The MIT License (MIT)
Author: Viktor Szépe
Author URI: http://www.online1.hu/webdesign/
GitHub Plugin URI: https://github.com/szepeviktor/wordpress-plugin-construction/tree/master/wordpress-fail2ban
*/

add_action( 'plugins_loaded', 'wpf2b_add_option_scan_schedule' );
add_action( 'wpf2b/daily', 'wpf2b_option_scan' );

function wpf2b_add_option_scan_schedule() {

    if ( false === wp_get_schedule( 'wpf2b/daily' ) ) {
        wp_schedule_event( time(), 'daily', 'wpf2b/daily' );
    }
}

function wpf2b_option_scan() {

    global $wpdb;
    define( 'MAIL_EOF', "\r\n" );

    $injection_sql = '<script|<iframe';
    $options = $wpdb->get_results(
        $wpdb->prepare( "SELECT option_name, option_value FROM $wpdb->options WHERE option_value REGEXP %s", $injection_sql )
    );

    $to = get_option( 'admin_email' );
    $subject = "[admin] Malicious code found in WordPress options";
    $headers = array( 'Content-Type: text/plain; charset=UTF-8' );
    $body = get_option( 'blogname' ) . " has injected code in `options` database table: " . MAIL_EOF;
    $option_names = array();
    foreach ( $options as $option ) {
        $body .= "Option name: " . $option->option_name . MAIL_EOF;
        error_log( "Malicious code in wp_options: " . $option->option_name );
        $option_names[] = $option->option_name;
    }

    $mail = wp_mail( $to, $subject, $body, $headers );
    if ( false === $mail ) {
        error_log( sprintf( "E-mail sending error: Malicious code in wp_options: %s", implode( ',', $option_names ) ) );
    }
}
