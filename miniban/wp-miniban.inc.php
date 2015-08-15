<?php

/*

Copy this to wp-config.php:

Miniban_Htaccess::init(
    dirname( __FILE__ ) . '/.htaccess',
    array( '127.0.0.0/8', '79.172.214.123', '66.249.64.0/19' ),
    array( 'header' => 'Remote_Addr' )
);
require_once dirname( __FILE__ ) . '/wp-miniban.inc.php';

Set up daily cron job:

    php -r 'require "/PATH/TO/wp-miniban.php"; Miniban_Htaccess::unban();'

Concatenation of miniban-base.php and miniban-htaccess.php
    grep -Fxvh '<?php' miniban-base.php miniban-htaccess.php
*/
