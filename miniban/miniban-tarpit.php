<?php

class Miniban extends Miniban_Base {

    public static function ban( $ban_ip = null, $tarpit_time = 600 ) {

        if ( ! is_int( $tarpit_time ) || $tarpit_time < 1 ) {
            return false;
        }

        $max_execution_time = ini_get( 'max_execution_time' );
        $now = time();
        if ( $max_execution_time ) {
            // Substract REQUEST_TIME
            if ( ! empty( $_SERVER['REQUEST_TIME'] ) ) {
                $max_execution_time -= ( $now - $_SERVER['REQUEST_TIME'] );
            } else {
                // Approximate application execution time
                $max_execution_time -= 3;
            }
        } else {
            // Sensible default
            $max_execution_time = 30;
        }

        if ( $tarpit_time > $max_execution_time ) {
            $tarpit_time = $max_execution_time;
        }

        if ( empty( $ban_ip ) ) {
            $ban_ip = $_SERVER['REMOTE_ADDR'];
        }
        $content = sprintf( "%s #%s\n", $ban_ip, $now );
        parent::alter_config( 'static::write_callback', array( 'content' => $content ), 'a' );

        if ( ! headers_sent() ) {
            // Prevent gzip encoding thus buffering output
            header( 'Content-Encoding: none' );
            header( 'Content-Length: 2457600' );
            for ( $i = 0; $i < $tarpit_time; $i++ ) {
                sleep( 1 );
                // Send random bytes
                echo str_pad( chr( rand( 0, 255 ) ), 4096, chr( 0 ) );
                flush();
                ob_flush();
            }
        } else {
            sleep( $tarpit_time );
        }

        return true;
    }

    protected static function write_callback( $handle, $parameters ) {

        return fwrite( $handle, $parameters['content'] );
    }

    public static function unban( $unban_ip = null ) {
    }
}
