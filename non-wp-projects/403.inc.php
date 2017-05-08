<?php
/*
Snippet Name: Trigger Fail2ban on HTTP/403 responses in any CMS.
Version: 0.1.2
Snippet URI: https://github.com/szepeviktor/wordpress-fail2ban
License: The MIT License (MIT)
Author: Viktor Szépe
*/

$included_files = get_included_files();
error_log( sprintf( 'Malicious traffic detected: 403_forbidden %s:%s',
    addslashes( $_SERVER['REQUEST_URI'] ),
    reset( $included_files )
) );

/*
if ( ! headers_sent() ) {
    header( "HTTP/1.1 403 Forbidden" );
}
*/
