<?php
/*
Snippet Name: Trigger fail2ban on HTTP/404 responses in any CMS.
Version: 0.1.0
Snippet URI: https://github.com/szepeviktor/wordpress-fail2ban
License: The MIT License (MIT)
Author: Viktor Szépe
Author URI: http://www.online1.hu/webdesign/
*/

error_log(
    'Malicious traffic detected: '
    . '404_not_found'
    . ' (' . addslashes( $_SERVER['REQUEST_URI'] ) . ')'
    . ' <' . reset( get_included_files() )
);
//header( "HTTP/1.1 404 Not Found" );
