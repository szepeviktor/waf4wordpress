<?php

//      @TODO

class Miniban extends Miniban_Base {

// CloudFlare client API
function errorlog_is_cf() {

    // Looking for cloudflare plugin
    if ( ! function_exists( 'load_cloudflare_keys' ) ) return false;

    global $cf_api_host, $cf_api_port, $cloudflare_api_key, $cloudflare_api_email;

    load_cloudflare_keys();

    return ($cloudflare_api_key && $cloudflare_api_email);
}

function errorlog_cf_send($action) {

    global $cf_api_host, $cf_api_port, $cloudflare_api_key, $cloudflare_api_email;

    if (!errorlog_is_cf()) return 'not-cf';

    $cf_url = str_replace('ssl', 'https', $cf_api_host) . ':' . $cf_api_port . '/api_json.html';
    $postdata = array('a'        => $action,  // 'w'hite'l'ist, 'ban', 'nul'
                      'tkn'      => $cloudflare_api_key,
                      'email'    => $cloudflare_api_email,
                      'key'      => $_SERVER['HTTP_CF_CONNECTING_IP']  // proxy?
                );
    $cf_res = wp_remote_post($cf_url, array(
        'method' => 'POST',
        'blocking' => true,
        'body' => $postdata,
        )
    );

    if ( is_wp_error($cf_res) ) return 'cf-http-error:'.serialize($cf_res);
    $cf_res_body = json_decode($cf_res['body']);
    if ( !$cf_res_body ) return 'cf-response-body-notfound:'.serialize($cf_res);

    if ($cf_res_body->result == 'success') {
        return true;
    } else {
        return 'cf-comm-failure:'.serialize($cf_res_body);
    }
}
}

//errorlog_cf_send('ban');
//errorlog_cf_send('nul');
