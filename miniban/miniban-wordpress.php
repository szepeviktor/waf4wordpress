<?php

class Miniban extends Miniban_Base {

    public static function ban( $ban_ip = null, $ban_time = 0 ) {

/*

MU plugin: block banned IP-s

----------------------------

if ( ! defined ) define( 'SHORTINIT', true );
core loaded? if ( function_exists( 'add_filter' ) ) {
    find wp; load wp

?? Load WP from function/class??

serialized associative array:
    ip => expiration time



require_once dirname(__FILE__) . '/wp-load.php';

$option = 'nincs';
$serialized_value = 'van1';
$autoload = 'yes';

$update_args = array(
    'option_value' => $serialized_value,
    'autoload' => 'yes'
);
global $wpdb;
// Get
// ? In cache?
$row = $wpdb->get_row( $wpdb->prepare( "SELECT option_value FROM $wpdb->options WHERE option_name = %s LIMIT 1", $option ) );
if ( is_object( $row ) ) {
    // Update
    if ( $update_args['option_value'] !== $value = $row->option_value ) {
        $result = $wpdb->update( $wpdb->options, $update_args, array( 'option_name' => $option ) );
    } else {
        $result = false;
    }
} else {
    // Add new
    $result = $wpdb->query( $wpdb->prepare( "INSERT INTO `$wpdb->options` (`option_name`, `option_value`, `autoload`) VALUES (%s, %s, %s) ON DUPLICATE KEY UPDATE `option_name` = VALUES(`option_name`), `option_value` = VALUES(`option_value`), `autoload` = VALUES(`autoload`)",
        $option, $serialized_value, $autoload ) );
}

if ( false !== $result ) {

}
*/

    }

    public static function unban( $unban_ip = null ) {



    }
}
