<?php
/*
Snippet Name: Trigger fail2ban on HTTP/403 responses in any CMS.
Version: 0.1.1
Snippet URI: https://github.com/szepeviktor/wordpress-fail2ban
License: The MIT License (MIT)
Author: Viktor Szépe
Author URI: http://www.online1.hu/webdesign/
*/

error_log( sprintf( 'Malicious traffic detected: 403_forbidden (%s) <%s',
    addslashes( $_SERVER['REQUEST_URI'] ),
    reset( get_included_files() )
) );
/*
if ( ! headers_sent() ) {
    header( "HTTP/1.1 403 Forbidden" );
}
*/
