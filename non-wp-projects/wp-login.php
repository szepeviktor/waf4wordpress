<?php
/*
Snippet Name: Trigger fail2ban in non-WordPress projects and subdirectory installs.
Version: 0.3.0
Snippet URI: https://github.com/szepeviktor/wordpress-fail2ban
Description: Set the iteration count in the loop and copy into the project's root
License: The MIT License (MIT)
Author: Viktor Szépe
Author URI: http://www.online1.hu/webdesign/
*/

error_log( 'Break-in attempt detected: ' . 'no_wp_here_wplogin' );

ob_get_level() && ob_end_clean();
header( 'Status: 403 Forbidden' );
header( 'HTTP/1.0 403 Forbidden' );
exit();
