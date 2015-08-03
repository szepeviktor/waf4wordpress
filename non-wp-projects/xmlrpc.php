<?php
/*
Snippet Name: Trigger fail2ban in non-WordPress projects and subdirectory installs.
Version: 0.4.1
Snippet URI: https://github.com/szepeviktor/wordpress-fail2ban
License: The MIT License (MIT)
Author: Viktor Szépe
Author URI: http://www.online1.hu/webdesign/
*/

error_log( 'Break-in attempt detected: ' . 'no_wp_here_xmlrpc' );

ob_get_level() && ob_end_clean();
header( 'Status: 403 Forbidden' );
header( 'HTTP/1.1 403 Forbidden', true, 403 );
header( 'Connection: Close' );
exit();
