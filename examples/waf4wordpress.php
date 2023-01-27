<?php

/*
 * Plugin Name: WAF for WordPress (MU)
 */

if (! function_exists('add_filter')) {
    exit;
}

new SzepeViktor\WordPress\Waf\CoreEvents();
