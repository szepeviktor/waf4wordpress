<?php

Miniban_Htaccess::init(
    dirname( __FILE__ ) . '/.htaccess',
    array( '127.0.0.0/8', '79.172.214.123', '66.249.64.0/19' ),
    array( 'header' => 'Remote_Addr' )
);

// Cron job daily
//     php -r 'require "/PATH/TO/wp-miniban.php"; Miniban_Htaccess::unban();'

// Concatenation of miniban-base.php and miniban-htaccess.php
//     grep -Fvxh '<?php' miniban-base.php miniban-htaccess.php
