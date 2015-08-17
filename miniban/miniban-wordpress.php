<?php

class Miniban extends Miniban_Base {

    private static $option = 'miniban_lockouts';

    public static function ban( $ban_ip = null, $ban_time = 86400 ) {

        if ( ! is_int( $ban_time ) ) {
            return false;
        }

        if ( empty( $ban_ip ) ) {
            $ban_ip = $_SERVER['REMOTE_ADDR'];
        }

        // Process whitelist
        foreach ( parent::$ignoreip as $range ) {
            if ( parent::ip_in_range( $ban_ip, $range ) ) {
                return false;
            }
        }

        $now = time();

        if ( false === static::may_load_wordpress() ) {
            return false;
        }

        $lockouts = get_option( static::$option );

        if ( false === $lockouts ) {
            $lockouts = array();
            add_option( static::$option, $lockouts, 'yes' );
        }

        $expires = $now + $ban_time;
        $lockouts[ $ban_ip ] = $expires;

        update_option( static::$option, $lockouts );

        return true;
    }

    public static function unban( $unban_ip = null ) {

        $now = time();

        if ( false === static::may_load_wordpress() ) {
            return false;
        }

        $lockouts = get_option( static::$option );

        if ( false === $lockouts ) {
            $lockouts = array();
            add_option( static::$option, $lockouts, 'yes' );
        }

        if ( $unban_ip ) {
            // One IP
            if ( array_key_exists( $unban_ip, $lockouts ) ) {
                unset( $lockouts[ $unban_ip ] );
            }
        } else {
            // Unban expired bans
            foreach ( $lockouts as $ip => $expires ) {
                if ( empty( $expires ) || (int)$expires < $now ) {
                    unset( $lockouts[ $ip ] );
                }
            }
        }

        update_option( static::$option, $lockouts );

        return true;
    }

    private static function find_wordpress_core() {

        $this_dir = dirname( __FILE__ );

        // This dir
        if ( file_exists( $this_dir . '/wp-load.php' ) ) {
            return $this_dir;
        }

        // Subdirs
        $subdirs = glob( $this_dir . '/*', GLOB_ONLYDIR );
        if ( ! empty( $subdirs ) ) {
            foreach ( $subdirs as $subdir ) {
                if ( file_exists( $subdir . '/wp-load.php' ) ) {
                    return $subdir;
                }
            }
        }

        // Parent dir
        $parent_dir = dirname( $this_dir );
        if ( file_exists( $parent_dir . '/wp-load.php' ) ) {
            return $parent_dir;
        }

        return false;
    }

    private static function may_load_wordpress() {

        // Already loaded
        if ( function_exists( 'add_filter' ) ) {
            return true;
        }

        // Skip as much as it is possible
        if ( ! defined( 'SHORTINIT' ) ) {
            define( 'SHORTINIT', true );
        }

        // Find core
        $core_path = static::find_wordpress_core();
        if ( false === $core_path ) {
            return false;
        }

        require_once $core_path . '/wp-load.php';
        // Sanitize functions
        require_once $core_path . '/wp-includes/formatting.php';

        return true;
    }
}
