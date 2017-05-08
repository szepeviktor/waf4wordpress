<?php
/*
Snippet Name: Trigger Fail2ban in non-WordPress projects and subdirectory installs.
Version: 0.5.0
Snippet URI: https://github.com/szepeviktor/wordpress-fail2ban
License: The MIT License (MIT)
Author: Viktor Szépe
*/

error_log( 'Break-in attempt detected: no_wp_here_xmlrpc' );

ob_get_level() && ob_end_clean();
fake_xmlrpc();
exit;

function fake_xmlrpc() {

    $server_name = isset( $_SERVER['SERVER_NAME'] )
        ? $_SERVER['SERVER_NAME']
        : $_SERVER['HTTP_HOST'];

    header( 'Connection: Close' );
    header( 'Cache-Control: max-age=0, private, no-store, no-cache, must-revalidate' );
    header( 'X-Robots-Tag: noindex, nofollow' );
    header( 'Content-Type: text/xml; charset=UTF-8' );

    printf( '<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value>
      <array><data>
  <value><struct>
  <member><name>isAdmin</name><value><boolean>1</boolean></value></member>
  <member><name>url</name><value><string>http://%s/</string></value></member>
  <member><name>blogid</name><value><string>1</string></value></member>
  <member><name>blogName</name><value><string>brake</string></value></member>
  <member><name>xmlrpc</name><value><string>http://%s/brake/xmlrpc.php</string></value></member>
</struct></value>
</data></array>
      </value>
    </param>
  </params>
</methodResponse>
',
        $server_name,
        $server_name
    );
}
