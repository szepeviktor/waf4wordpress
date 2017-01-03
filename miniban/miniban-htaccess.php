<?php
/**
 * Htaccess Miniban method
 *
 * @version    0.1.3
 * @package    miniban
 * @link       https://github.com/szepeviktor/wordpress-fail2ban
 * @author     Viktor Szépe
 * @license    GNU General Public License (GPL) version 2
 */
class Miniban extends Miniban_Base {

    private static $ban_rules = '
# Apache < 2.3
<IfModule !mod_authz_core.c>
    Order allow,deny
    Deny from env=mini_ban
    Allow from all
    Satisfy All
</IfModule>
# Apache ≥ 2.3
<IfModule mod_authz_core.c>
    <RequireAll>
        Require all granted
        Require not env mini_ban
    </RequireAll>
</IfModule>';

    public static function ban( $ban_ip = null, $ban_time = 86400 ) {

        if ( empty( parent::$config ) ) {
            return false;
        }

        if ( ! is_int( $ban_time ) ) {
            return false;
        }

        if ( empty( parent::$extra_config['header'] ) ) {
            parent::$extra_config['header'] = 'Remote_Addr';
        }

        if ( empty( $ban_ip ) ) {
            if ( 'Remote_Addr' === parent::$extra_config['header'] ) {
                $header_name = 'REMOTE_ADDR';
            } else {
                $header_name = 'HTTP_' . strtoupper( parent::$extra_config['header'] );
            }

            if ( empty( $_SERVER[ $header_name ] ) ) {
                return false;
            }
            $ban_ip = $_SERVER[ $header_name ];
        }

        // Process whitelist
        foreach ( parent::$ignoreip as $range ) {
            if ( parent::ip_in_range( $ban_ip, $range ) ) {
                return false;
            }
        }

        // Prepare .htaccess rule
        $parameters = array( 'operation' => 'add' );
        $expires = time() + $ban_time;
        $ban_line = sprintf( 'SetEnvIf %s "^%s$" mini_ban #%s',
            parent::$extra_config['header'],
            preg_quote( $ban_ip ),
            $expires
        );

        $parameters['contents'] = $ban_line;

        return parent::alter_config( 'static::insert_with_markers', $parameters, 'r+' );
    }

    public static function unban( $unban_ip = null ) {

        if ( empty( parent::$config ) ) {
            return false;
        }

        if ( empty( parent::$extra_config['header'] ) ) {
            parent::$extra_config['header'] = 'Remote_Addr';
        }

        $parameters = array( 'operation' => 'del' );

        if ( $unban_ip ) {
            // Unban one IP
            $ban_line = sprintf( 'SetEnvIf %s "^%s$" mini_ban',
                parent::$extra_config['header'],
                preg_quote( $unban_ip )
            );
        } else {
            // Unban all expired
            $parameters['now'] = time();
            // Matches all ban lines in .htaccess
            $ban_line = sprintf( 'SetEnvIf %s "^', parent::$extra_config['header'] );
        }
        $parameters['contents'] = $ban_line;

        return parent::alter_config( 'static::insert_with_markers', $parameters, 'r+' );
    }

    protected static function insert_with_markers( $handle, $parameters ) {

        $operation = $parameters['operation'];

        $size = $parameters['initial_file_size'];
        if ( $size > 0 ) {
            $contents = explode( "\n", fread( $handle, $size ) );
        } else {
            $contents = array();
        }
        $output = array();
        $foundit = false;
        // For auto unban
        $now = time();
        $ban_line_start = sprintf( 'SetEnvIf %s "^', parent::$extra_config['header'] );

        if ( ! empty( $contents ) ) {
            $foreign = true;

            foreach ( $contents as $markerline ) {
                // # BEGIN
                if ( false !== strpos( $markerline, '# BEGIN MINIBAN' ) ) {
                    $foreign = false;
                }

                // # END
                if ( false === $foreign && false !== strpos( $markerline, '# END MINIBAN' ) ) {
                    $foundit = true;
                    $foreign = true;
                    if ( 'add' === $operation ) {
                        // Ban
                        $output[] = $parameters['contents'];
                    }
                }

                if ( 'add' === $operation ) {
                    if ( isset( parent::$extra_config['autounban'] ) ) {
                        // Automatically unban expired ones
                        if ( true === $foreign
                            || false === strpos( $markerline, '#' )
                            || ! ( list( $marker_rule, $marker_expires ) = explode( '#', $markerline ) )
                            || false === strpos( $marker_rule, $ban_line_start )
                            || ( is_numeric( $marker_expires )
                                && (int) $marker_expires > $now
                            )
                        ) {
                            $output[] = $markerline;
                        }
                    } else {
                        // Keep old lines
                        $output[] = $markerline;
                    }
                } elseif ( 'del' === $operation ) {
                    // Unban one IP or all expired
                    /* Inside our makers?
                     *     Contains "#"?
                     *     Parse line - not a condition
                     *     Rule matches?
                     *     Time provided? -> check expiration
                     *         Valid timestamp
                     *         Not yet expired
                     */
                    if ( true === $foreign
                        || false === strpos( $markerline, '#' )
                        || ! ( list( $marker_rule, $marker_expires ) = explode( '#', $markerline ) )
                        || false === strpos( $marker_rule, $parameters['contents'] )
                        || ( ! empty( $parameters['now'] )
                            && is_numeric( $marker_expires )
                            && (int) $marker_expires > $parameters['now']
                        )
                    ) {
                        $output[] = $markerline;
                    }
                } // End if().
            } // End foreach().
        } // End if().

        if ( ! $foundit ) {
            $output[] = '';
            $output[] = '# BEGIN MINIBAN';
            $output[] = static::$ban_rules;
            if ( 'add' === $operation ) {
                $output[] = $parameters['contents'];
            }
            $output[] = '# END MINIBAN';
            $output[] = '';
        }

        $output_lines = implode( "\n", $output );

        // Replace .htaccess contents
        ftruncate( $handle, 0 );
        rewind( $handle );

        return fwrite( $handle, $output_lines );
    }
}
