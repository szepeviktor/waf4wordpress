<?php
/*
Plugin Name: rewrite please :)
*/

define('ERRORLOG_TARPIT', 8);
define('ERRORLOG_DEEP_TARPIT', 89);


// ------------------------------- METHODS -----------------------------------


// tarpit
function errorlog_action_tarpit($action) {
    switch ($action) {
        case 'ban':
            sleep(ERRORLOG_DEEP_TARPIT);
            return true;
            break;
        case 'score':
            sleep(ERRORLOG_TARPIT);
            return true;
            break;
    }
}


// CloudFlare client API
function errorlog_is_cf() {

    global $cf_api_host, $cf_api_port, $cloudflare_api_key, $cloudflare_api_email;

    // Looking for cloudflare plugin
    if ( ! function_exists( 'load_cloudflare_keys' ) ) return false;
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

function errorlog_action_cf($action) {
    switch ($action) {
        case 'ban':
            return errorlog_cf_send('ban');
            break;
        case 'unban':
            return errorlog_cf_send('nul');
            break;
        case 'score':
            // FIXME report to CF!!
            return true;
            break;
    }
}


// WordPress - exit; early
function errorlog_action_wordpress($action) {
    //ban flush buffers; exit;
    //score sleep(ERRORLOG_TARPIT); ???
    return true;
}


