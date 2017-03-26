<?php
/*
Plugin Name: Proactive security
Version: 0.1.0
Description: Prevent and ban general web and WordPress specific attacks.
Plugin URI: https://github.com/szepeviktor/wordpress-fail2ban
Author: Viktor Szépe
*/

/*
@TODO
admin page: display code to include in wp-config.php
- Miniban
- block bad request
- any of the two is missing -> notice

options for:
- Miniban
- block bad request
- wpf2b-mu

*/
class O1_WP_Fail2ban {

    private static $muplugin_rel = '/mu/wp-fail2ban-mu-instant.php';
    private static $symlink_rel = '/ban.php';

    public function __construct() {

        // Emergency (late) run
        if ( ! class_exists( 'O1_WP_Fail2ban_MU', false ) ) {
            require_once dirname( WPF2B_PATH ) . self::$muplugin_rel;

            if ( is_admin() ) {
                add_action( 'admin_notices', array( $this, 'broken_symlink_notice' ) );
            }
        }

        if ( class_exists( 'Miniban', false ) ) {
            // Schedule Miniban unban
            add_action( 'plugins_loaded', array( $this, 'add_schedule' ) );
            add_action( 'ban/hourly', array( $this, 'unban' ) );
        }
    }

    public function add_schedule() {

        if ( false === wp_get_schedule( 'ban/hourly' ) ) {
            wp_schedule_event( time(), 'daily', 'ban/hourly' );
        }
    }

    public function unban() {

        // Missing or uninitialized Miniban
        if ( ! class_exists( 'Miniban', false ) || empty( Miniban::$config ) ) {
            return;
        }

        Miniban::unban();
    }

    public static function symlink() {

        /* WP FileSystem API does not support symlink creation
        global $wp_filesystem;
        */

        $muplugin = dirname( WPF2B_PATH ) . self::$muplugin_rel;
        $symlink = WPMU_PLUGIN_DIR . self::$symlink_rel;

        if ( ! file_exists( WPMU_PLUGIN_DIR ) ) {
            if ( ! mkdir( WPMU_PLUGIN_DIR, 0755, true ) ) {
                return false;
            }
        }

        if ( is_link( $symlink ) || file_exists( $symlink ) ) {
            // Correct symbolic link
            if ( is_link( $symlink ) && readlink( $symlink ) === $muplugin ) {
                return true;
            } else {
                /* is_writable() does not detect broken symlinks, unlink() must be @muted
                // Incorrect and unwritable
                if ( ! is_writable( $symlink ) ) {
                    return false;
                }
                */

                // Remove symbolic link
                if ( ! @unlink( $symlink ) ) {
                    return false;
                }
            }
        }

        $linking = symlink( $muplugin, $symlink );

        return $linking;
    }

    public static function unlink() {

        // Clear schedule before file operations
        wp_clear_scheduled_hook( 'ban/daily' );

        $symlink = WPMU_PLUGIN_DIR . self::$symlink_rel;

        if ( ! is_link( $symlink ) ) {
            return true;
        }

        $unlinking = unlink( $symlink );

        return $unlinking;
    }

    public function broken_symlink_notice() {

        printf( '<div id="wpf2b-broken-symlink" class="error"><p><strong>%s <code>%s</code></strong></p></div>',
            'Please fix the symbolic link manually for <em>Proactive security with Fail2ban</em> in',
            WPMU_PLUGIN_DIR
        );
    }
}

if ( ! defined( 'WPF2B_PATH' ) ) {
    define( 'WPF2B_PATH', __FILE__ );
}
new O1_WP_Fail2ban();

register_activation_hook( WPF2B_PATH, 'O1_WP_Fail2ban::symlink' );
register_deactivation_hook( WPF2B_PATH, 'O1_WP_Fail2ban::unlink' );
