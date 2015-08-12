<?php

/*

# Mini Ban for Apache directory configuration
SetEnvIf Remote_Addr "^192\.168\.12\.138$" mini_ban

# CloudFlare header
#SetEnvIf X-FORWARDED-FOR "^192\.168\.12\.138$" mini_ban

# Rackspace header
#SetEnvIf X-CLUSTER-CLIENT-IP "^192\.168\.12\.138$" mini_ban

*/

class Miniban_Htaccess extends Miniban {

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
            $ban_ip = $SERVER['REMOTE_ADDR'];
        }

        // Process whitelist
        foreach ( parent::$ignoreip as $range ) {
            if ( parent::ip_in_range( $ban_ip, $range ) ) {
                return false;
            }
        }

        // Prepare .htaccess rule
        $expires = time() + $ban_time;
        $ban_line = sprintf( 'SetEnvIf %s "^%s$" mini_ban #%s',
           parent::$extra_config['header'],
           preg_quote( $ban_ip ),
           $expires
        );

        return self::alter_config( 'static::insert_with_markers',
            array( 'contents' => $ban_line, 'operation' => 'add' ), 'r+' );
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
            // One IP
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

        return self::alter_config( 'static::insert_with_markers', $parameters, 'r+' );
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

        if ( ! empty( $contents ) ) {
            $foreign = true;

            foreach ( $contents as $markerline ) {
                // # BEGIN
                if ( false !== strpos( $markerline, '# BEGIN MINIBAN') ) {
                    $foreign = false;
                }
                // # END
                if ( false === $foreign && false !== strpos( $markerline, '# END MINIBAN' ) ) {
                    $foundit = true;
                    $foreign = true;
                    if ( 'add' === $operation ) {
                        $output[] = $parameters['contents'];
                    }
                }

                // Ban
                if ( 'add' === $operation ) {
                    $output[] = $markerline;

                // Unban one IP or all expired
                } elseif ( 'del' === $operation ) {
                    // Inside our makers?
                    //     Contains "#"?
                    //     Parse line - not a condition
                    //     Rule matches?
                    //     Time provided? -> check expiration
                    //         Valid timestamp
                    //         Not yet expired
                    if ( true === $foreign
                        || false === strpos( $markerline, '#' )
                        || ! ( list( $marker_rule, $marker_expires ) = explode( '#', $markerline ) )
                        || false === strpos( $marker_rule, $parameters['contents'] )
                        || ( ! empty( $parameters['now'] )
                            && is_numeric( $marker_expires )
                            && (int)$marker_expires > $parameters['now']
                        )
                    ) {
                        $output[] = $markerline;
                    }
                }
            }
        }

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

        $output_lines = implode( "\n", $output);

        // Replace .htaccess contents
        ftruncate( $handle, 0 );
        rewind( $handle );

        return fwrite( $handle, $output_lines );
    }
}
