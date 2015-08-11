<?php

/*
# Apache Virtual host configuration

RewriteEngine On
RewriteMap ipblocklist "txt:/path/to/ipblocklist.txt"

RewriteCond "${ipblocklist:%{REMOTE_ADDR}|NOT-FOUND}" !=NOT-FOUND
RewriteRule ^ - [F]
*/

Mini_Ban::init( './ipblocklist.txt', array( '127.0.0.0/8', '1.2.3.4', '66.249.0.0/16' ) );

// Returns false
var_export( Mini_Ban::ban( '66.249.8.1' ) );

Mini_Ban::ban( '12.23.45.67' );
Mini_Ban::unban( '12.23.45.67' );

// Cron job to unban expired bans
Mini_Ban::unban();

// @TODO classes: Mini_Ban (base), Mini_Ban_Rewritemap, Mini_Ban_Htaccess

class Mini_Ban {

    private static $config = '';
    private static $ignoreip = array();

    public static function init( $path, $whitelist = array() ) {

        self::$config = $path;

        $banlist_dir = dirname( self::$config );

        if ( ! file_exists( $banlist_dir ) ) {
            mkdir( dirname( self::$config ), 0700, true );
        }
        if ( ! file_exists( self::$config ) ) {
            touch( self::$config );
        }

        self::$ignoreip = $whitelist;

    }

    public static function ban( $ip, $ban_time = 86400 ) {

        if ( empty( self::$config ) ) {
            return false;
        }

        if ( empty( $ip ) ) {
            $ip = $SERVER['REMOTE_ADDR'];
        }

        // Process whitelist
        foreach ( self::$ignoreip as $range ) {
            if ( self::ip_in_range( $ip, $range ) ) {
                return false;
            }
        }

        // Client IP + UTC
        $expires = time() + $ban_time;
        $ban_line = sprintf( "%s %s\n", $ip, $expires );

        return self::file_append_contents( self::$config, $ban_line );
    }

    public static function unban( $unban_ip ) {

        if ( empty( self::$config ) ) {
            return false;
        }

        $size = filesize( self::$config );
        if ( empty( $size ) ) {
            return;
        }

        $handle = fopen( self::$config, 'c+' );
        if ( false === $handle ) {
            return false;
        }

        // Wait till the file is available
        $flock = flock( $handle, LOCK_EX );
        if ( false === $flock ) {
            fclose( $handle );
            return false;
        }

        $contents = fread( $handle, filesize( self::$config ) );
        if ( ! empty( $contents ) ) {
            $now = time();
            $ban_lines = explode( "\n", $contents );
            $new_bans = array();

            foreach ( $ban_lines as $ban_line ) {
                if ( empty( $ban_line ) ) {
                    continue;
                }

                list( $ip, $expires ) = explode( ' ', $ban_line );
                if ( ! empty( $unban_ip ) && $unban_ip === $ip ) {
                    continue;
                }
                if ( ! empty( $expires ) && (int)$expires > $now ) {
                    $new_bans[] = $ban_line;
                }
            }
            $new_ban_lines = implode( "\n", $new_bans ) . "\n";

            ftruncate( $handle, 0 );
            rewind( $handle );
            fwrite( $handle, $new_ban_lines );
        }

        flock( $handle, LOCK_UN );

        return fclose( $handle );
    }

    private static function file_append_contents( $file, $contents ) {

        $handle = fopen( $file, 'a' );
        if ( false === $handle ) {
            return false;
        }

        // Wait till the file is available
        $flock = flock( $handle, LOCK_EX );
        if ( false === $flock ) {
            fclose( $handle );
            return false;
        }

        $fwrite = fwrite( $handle, $contents );
        if ( false === $fwrite ) {
            return false;
        }

        flock( $handle, LOCK_UN );

        return fclose( $handle );
    }

    private static function ip_in_range( $ip, $range ) {

        if ( false === strpos( $range, '/' ) ) {
            $range .= '/32';
        }

        $ip_decimal = ip2long( $ip );

        // Range is in CIDR format
        list( $range_ip, $netmask ) = explode( '/', $range, 2 );
        $range_decimal = ip2long( $range_ip );
        $wildcard_decimal = pow( 2, ( 32 - $netmask ) ) - 1;
        $netmask_decimal = ~ $wildcard_decimal;

        return ( ( $ip_decimal & $netmask_decimal ) === ( $range_decimal & $netmask_decimal ) );
    }
}
