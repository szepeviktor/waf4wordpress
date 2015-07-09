<?php

/*
*Apache
*NGINX
*other environments
*/

function htaccess_rules() {

    -> better-wp-security/core/class-itsec-files.php

define() custom HTTP header to get IP default:'X-CLUSTER-CLIENT-IP'
preg_quote $host_ip
"SetEnvIF " . array( 'REMOTE_ADDR', 'X-FORWARDED-FOR' ) $deny_env;
# Apache < 2.3, # Apache ≥ 2.3
<IfModule !mod_authz_core.c>
    Order allow,deny
    Deny from env=$deny_env
#    Deny from $host_ip
    Allow from all
    Satisfy All
</IfModule>
<IfModule mod_authz_core.c>
    Require not env $deny_env
#    Require not ip $host_ip
</IfModule>

}

function singleton_put_contents( $path, $marker, $content, $timeout ) {

    // wp-admin/includes/misc.php
        save_mod_rewrite_rules()
        clone: insert_with_markers()
    - gethome(htaccess) normal/subdir install

    //1. exists, writeable ...
    ! fstat()/mod -> then @chmod( $htaccess, 0664 );

    //2. lock || wait and loop
    "If the file has been locked with LOCK_EX in another process, the CALL WILL BLOCK UNTIL ALL OTHER LOCKS have been released."
    // must use "@"
    $fp = @fopen( $path, 'w' )
    check $fp

    $give_up = time() + 30;
    while ( ! flock( $file_handle, LOCK_EX | LOCK_NB ) ) {
        //Lock not acquired, try again in:
        usleep( round( rand( 0, 100 ) * 1000 ) );
        if ( $give_up >= time() )
    }

    //3. read rules
    $file_stat = fstat( $handle );
    $contents = fread( $handle, $file_stat['size'] );
    // line ends
    $contents = preg_replace( '/\n|\r\n?/', PHP_EOL, $contents );
    //already contains?
    preg_match multiline "# BEGIN " . $marker . PHP_EOL -> "# END " . $marker . PHP_EOL;

    //4. ftruncate($fp, 0); write new rules in one go

    // 5. release lock
    fflush
    flock( $handle, LOCK_UN );
    fclose
}
