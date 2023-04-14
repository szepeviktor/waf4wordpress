<?php

/*
 * Plugin Name: WAF for WordPress (MU)
 * Plugin URI: https://github.com/szepeviktor/waf4wordpress
 */

if (!function_exists('add_filter')) {
    exit;
}

new SzepeViktor\WordPress\Waf\CoreEvents();
