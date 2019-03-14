<?php
/**
 * Repel an HTTP/POST attack on Magento 1 registration.
 */

// In waf4wordpress-http-analyzer.php

//            return 'bad_request_post_content_type';
//        }

        // Extra Magento POST variables
        if ( false !== strpos( $request_path, '/customer/account/createpost' )
            && (
                ( empty( $_SERVER['HTTP_ACCEPT_ENCODING'] ) || false === strpos( $_SERVER['HTTP_ACCEPT_ENCODING'], 'gzip' ) )
                || isset( $_POST['birthyear'] ) || isset( $_POST['sYear'] ) || isset( $_POST['year'] )
                || ( isset( $_POST['is_subscribed'] ) && '1' !== $_POST['is_subscribed'] )
            )
        ) {
            return 'bad_request_post_magento_vars';
        }
