<?php
/**
 * Scaffold for Miniban ban methods
 *
 * @version    0.1.2
 * @package    miniban
 * @link       https://github.com/szepeviktor/wordpress-fail2ban
 * @author     Viktor Szépe
 * @license    GNU General Public License (GPL) version 2
 */
abstract class Miniban_Base {

    /**
     * Full path of the config
     *
     * @var string
     */
    protected static $config = '';

    /**
     * IP addresses to be excluded from banning
     *
     * @var array
     */
    protected static $ignoreip = array();

    /**
     * Additional configuration data
     *
     * For example HTTP header name.
     *
     * @var array
     */
    protected static $extra_config = array();

    /**
     * Initialize miniban
     *
     * Set path of configuration file, ignored IP addresses
     * and extra configuration data.
     *
     * @param string $config      Full path of configuration file.
     * @param array $ignoreip     Ignored IP addresses.
     * @param array $extra_config Additional configuration data.
     * @return boolean            Success.
     */
    final public static function init( $config, $ignoreip = array(), $extra_config = array() ) {

        self::$ignoreip = $ignoreip;

        self::$extra_config = $extra_config;

        if ( ! empty( $config ) ) {
            self::$config = $config;
            return self::check_config();
        }

        return true;
    }

    /**
     * Check and create if necessary the configuration file.
     *
     * @return boolean Success.
     */
    final protected static function check_config() {

        $banlist_dir = dirname( self::$config );

        if ( ! file_exists( $banlist_dir ) ) {
            $mkdir = mkdir( dirname( self::$config ), 0700, true );
            if ( false === $mkdir ) {
                return false;
            }
        }
        if ( ! file_exists( self::$config ) ) {
            $touch = touch( self::$config );
            chmod( self::$config, 0600 );
            if ( false === $touch ) {
                return false;
            }
        }

        if ( ! is_writeable( self::$config ) ) {
            return false;
        }

        return true;
    }

    public static function ban( $ban_ip, $ban_time ) {
    }

    public static function unban( $unban_ip = null ) {
    }

    final protected static function alter_config( $function, $parameters = array(), $fmode = 'c+' ) {

        if ( empty( self::$config ) ) {
            return false;
        }

        if ( ! file_exists( self::$config ) || ! is_writeable( self::$config ) ) {
            return false;
        }

        clearstatcache( false, self::$config );
        $size = filesize( self::$config );

        $handle = fopen( self::$config, $fmode );
        if ( false === $handle ) {
            return false;
        }

        // Wait till the file is available (max. 10 seconds, ~200 attempts)
        $waited_msec = 0;
        while ( ! flock( $handle, LOCK_EX | LOCK_NB ) ) {
            // Lock not acquired, try again in 0-100 msec
            $sleep_msec = rand( 1, 100 );
            // Convert to microseconds
            usleep( $sleep_msec * 1000 );
            $waited_msec += $sleep_msec;

            if ( $waited_msec > 10000 ) {
                fclose( $handle );
                return false;
            }
        }

        // Execute callback function
        $parameters['initial_file_size'] = $size;
        $cb_return = call_user_func( $function, $handle, $parameters );

        // Can not be an error
        flock( $handle, LOCK_UN );

        $fclose = fclose( $handle );

        if ( false === $cb_return || false === $fclose ) {
            return false;
        }

        return true;
    }

    final protected static function ip_in_range( $ip, $range ) {

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
