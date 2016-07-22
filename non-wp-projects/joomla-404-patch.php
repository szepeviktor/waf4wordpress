<?php

// In /templates/system/error.php before "<!DOCTYPE"
// FIXME Fail2ban
if ( 404 == $this->error->getCode() ) {
    error_log( sprintf( 'Malicious traffic detected: 404_not_found %s',
        addslashes( $_SERVER['REQUEST_URI'] )
    ) );
}
