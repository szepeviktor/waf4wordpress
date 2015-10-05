<?php
// ? in trigger()
// if xmlrpc ->
// if login ->

        // XMLRPC attack
        $server_name = isset( $_SERVER['SERVER_NAME'] )
            ? $_SERVER['SERVER_NAME']
            : $_SERVER['HTTP_HOST'];

        if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
            header( 'Content-Type: text/xml; charset=UTF-8' );

            printf( '<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value>
      <array><data>
  <value><struct>
  <member><name>isAdmin</name><value><boolean>1</boolean></value></member>
  <member><name>url</name><value><string>%s</string></value></member>
  <member><name>blogid</name><value><string>1</string></value></member>
  <member><name>blogName</name><value><string>brake</string></value></member>
  <member><name>xmlrpc</name><value><string>%s/xmlrpc.php</string></value></member>
</struct></value>
</data></array>
      </value>
    </param>
  </params>
</methodResponse>
', $server_name, $server_name );

            exit;
        }

        // Login request + Banned usernames
        if ( false !== strpos( $request_path, '/wp-login.php' ) && ! empty($_POST['log'] ) ) {
            $username = trim( $_POST['log'] );

            if ( in_array( strtolower( $username ), $this->names2ban ) ) {
                $expire = time() + 3600;
                $token = substr( hash_hmac( 'sha256', rand(), 'token' ), 0, 43 );
                $hash = hash_hmac( 'sha256', rand(), 'hash' );
                $auth_cookie = $username . '|' . $expire . '|' . $token . '|' . $hash;
                $authcookie_name = 'wordpress_' . md5( 'authcookie' );

                setcookie( $authcookie_name, $auth_cookie, $expire, '/brake/wp_content/plugins', false, false, true );
                setcookie( $authcookie_name, $auth_cookie, $expire, '/brake/wp-admin', false, false, true );
                setcookie( 'wordpress_logged_in_' . md5( 'cookiehash' ), $auth_cookie, $expire, '/', false, false, true );
                header( 'Location: http://' . $_SERVER['HTTP_HOST'] . '/brake/wp-admin/' );

                exit;
            }
        }

