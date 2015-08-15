<?php

require './miniban-base.php';
require './miniban-htaccess.php';

Miniban::init( './.htaccess', array( '127.0.0.0/8', '1.2.3.4', '66.249.0.0/16' ) );

//Miniban::init( './.htaccess', array( '127.0.0.0/8', '1.2.3.4', '66.249.0.0/16' ),
//    array( 'header' => 'X-FORWARDED-FOR' ) );

// Returns false
var_export( ! Miniban::ban( '66.249.8.1' ) ); echo "\n";

var_export( Miniban::ban( '12.23.45.67' ) ); echo "\n";
var_export( Miniban::unban( '12.23.45.67' ) ); echo "\n";
var_export( Miniban::ban( '12.23.45.67' ) ); echo "\n";
var_export( Miniban::ban() ); echo "\n";

// Cron job to unban expired bans
var_export( Miniban::unban() ); echo "\n";
