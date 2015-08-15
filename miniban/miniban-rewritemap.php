<?php

class Miniban extends Miniban_Base {

    public static function ban( $ban_ip, $ban_time = 86400 ) {

        if ( empty( parent::$config ) ) {
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

        // Client IP + UTC
        $expires = time() + $ban_time;
        $ban_line = sprintf( "%s %s\n", $ban_ip, $expires );

        return parent::alter_config( 'static::write_callback', array( 'contents' => $ban_line ), 'a' );
    }

    protected static function write_callback( $handle, $parameters ) {

        return fwrite( $handle, $parameters['contents'] );
    }

    public static function unban( $unban_ip = null ) {

        return parent::alter_config( 'static::unban_callback', array( 'ip' => $unban_ip ) );
    }

    protected static function unban_callback( $handle, $parameters ) {

        $size = $parameters['initial_file_size'];
        if ( 0 === $size ) {
            return true;
        }

        $contents = fread( $handle, $size );
        if ( empty( $contents ) ) {
            return;
        }

        $now = time();
        $ban_lines = explode( "\n", $contents );
        $new_bans = array();

        // Unban expired bans
        foreach ( $ban_lines as $ban_line ) {
            if ( empty( $ban_line ) ) {
                continue;
            }

            list( $ip, $expires ) = explode( ' ', $ban_line );

            if ( ! empty( $parameters['ip'] ) && $parameters['ip'] === $ip ) {
                continue;
            }
            if ( ! empty( $expires ) && (int)$expires > $now ) {
                $new_bans[] = $ban_line;
            }
        }

        $new_ban_lines = implode( "\n", $new_bans );
        if ( ! empty( $new_ban_lines ) ) {
            $new_ban_lines .= "\n";
        }

        // Replace .htaccess contents
        ftruncate( $handle, 0 );
        rewind( $handle );

        return fwrite( $handle, $new_ban_lines );
    }
}
