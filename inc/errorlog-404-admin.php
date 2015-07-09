<?php

if ( ! defined( 'ABSPATH' ) ) {
    error_log( 'Malicious traffic detected by wpf2b: wpf2badmin_direct_access ' . $_SERVER['REQUEST_URI'] );
    header( 'Status: 403 Forbidden' );
    header( 'HTTP/1.1 403 Forbidden' );
    exit();
}

if ( ! class_exists('O1_Errorlog_404' ) ):

class O1_Errorlog_404_admin {

    private $settings_api;

    function __construct() {
        require_once dirname( __FILE__ ) . '/class.settings-api.php';
        $this->settings_api = new WeDevs_Settings_API2;

        add_action( 'admin_init', array($this, 'admin_init') );
        add_action( 'admin_menu', array($this, 'admin_menu') );
    }

    function admin_init() {
        $this->settings_api->set_sections( $this->get_settings_sections() );
        $this->settings_api->set_fields( $this->get_settings_fields() );
        $this->settings_api->admin_init();
    }

    function admin_menu() {
        add_options_page( __( 'Attack logging for fail2ban', 'o1' ), __( 'fail2ban triggers', 'o1' ), 'manage_options', 'errorlog_404', array( $this, 'tools_page' ) );
    }

    function tools_page() {
        printf( '<div class="wrap"><h2 id="errorlog-title">%s</h2><div class="metabox-holder">',
            __( 'Attack logging for fail2ban: Settings' )
        );

        $this->settings_api->show_navigation();
        $this->settings_api->show_forms();

        print '</div></div>';
    }

    function get_settings_sections() {
        $sections = array(
            array(
                'id' => 'o1_errorlog_general',
                'title' => __( 'General', 'o1' ),
                'desc' => __( 'This plugin writes into the error log on malicious actions
                                like password failures, seeking for exploits thus triggers fail2ban IP banning.<br/>
                                Here you can completely turn if ON or OFF.', 'o1' )
            ),
            array(
                'id' => 'o1_errorlog_request',
                'title' => __( 'Bad requests', 'o1' ),
                'desc' => __( 'These are the most common seekings for exploits.' )
            ),
            array(
                'id' => 'o1_errorlog_login',
                'title' => __( 'Logins', 'o1' ),
                'desc' => __( 'Authentication related actions could be also reported to fail2ban.' )
            )
        );
        return $sections;
    }

    /**
     * Returns all the settings fields
     *
     * @return array settings fields
     */
    function get_settings_fields() {

        $settings_fields = array(
            'o1_errorlog_general' => array(
                array(
                    'id' => 'enabled',
                    'name' => __( 'Enable Attack logging for fail2ban', 'o1' ),
                    'label' => __( 'Turn on logging for fail2ban', 'o1' ),
                    'desc' => __( 'DO NOT turn this off on public internet', 'o1' ),
                    'type' => 'checkbox',
                    'default' => '1'
                ),
                array(
                    'id' => 'prefix',
                    'name' => __( 'Trigger string for fail2ban', 'o1' ),
                    'desc' => __( 'The constant part of <code>failregex</code> in the fail2ban filter. Error codes will be appended to this string.', 'o1' ),
                    'type' => 'text',
                    'size' => 30,
                    'default' => 'Malicious traffic detected by wpf2b:'
                ),
                array(
                    'id' => 'maxretry',
                    'name' => __( 'Maximum number of errors', 'o1' ),
                    'label' => __( '', 'o1' ),
                    'desc' => __( 'The number of log lines after fail2ban bans the attacker. <code>maxretry</code> in fail2ban jail config.', 'o1' ),
                    'type' => 'text',
                    'size' => 2,
                    'default' => '6',
                    'sanitize_callback' => 'intval'
                )
            ),
            'o1_errorlog_request' => array(
                array(
                    'id' => 'fourohfour',
                    'name' => __( '404 requests', 'o1' ),
                    'label' => __( 'Turn on 404 page detection', 'o1' ),
                    'desc' => __( 'Record an error on 404 requests', 'o1' ),
                    'type' => 'checkbox',
                    'default' => '1'
                ),
                array(
                    'id' => 'robot404',
                    'name' => __( 'No 404 for robots', 'o1' ),
                    'label' => __( 'Don\'t generate a 404 page for robots', 'o1' ),
                    'desc' => __( 'It saves processor time in case of a DoS/flood attack, depends on the above "404 requests".', 'o1' ),
                    'type' => 'checkbox',
                    'default' => '1'
                ),
                array(
                    'id' => 'robot403',
                    'name' => __( 'Forbid robot requests', 'o1' ),
                    'label' => __( 'Generate HTTP/403 when a robots tries to look inside your WordPress installation', 'o1' ),
                    'desc' => __( 'Robots are only allowed to visit public pages.', 'o1' ),
                    'type' => 'checkbox',
                    'default' => '0'
                ),
                array(
                    'id' => 'urlhack',
                    'name' => __( 'URL hacking', 'o1' ),
                    'label' => __( 'Record most common URL hacks', 'o1' ),
                    'desc' => __( 'Record an error on request URLs beginning with <code>//</code> or containing directory traversal <code>/..</code> or <code>../</code>', 'o1' ),
                    'type' => 'checkbox',
                    'default' => '1'
                ),
                array(
                    'id' => 'redirect',
                    'name' => __( 'Redirects', 'o1' ),
                    'label' => __( 'Record canonical redirects in WordPress', 'o1' ),
                    'desc' => __( 'GET parameters <code>' . site_url() . '/?cat=1</code> and double slashes and mistyped URLs', 'o1' ),
                    'type' => 'checkbox',
                    'default' => '1'
                ),
                array(
                    'id' => 'spam',
                    'name' => __( 'Spam robots', 'o1' ),
                    'label' => __( 'Trigger fail2ban when Contact Form 7 Robot Trap plugin catches a spammer', 'o1' ),
                    'desc' => __( 'This options needs the Contact Form 7 Robot Trap plugin', 'o1' ),
                    'type' => 'checkbox',
                    'default' => '1'
                ),
                array(
                    'id' => 'spammx',
                    'name' => __( 'Non-existent email domains', 'o1' ),
                    'label' => __( 'Trigger fail2ban when Contact Form 7 Robot Trap plugin detects a non-existent email domain', 'o1' ),
                    'desc' => __( 'Turning this on may cause false positives when your namerver is out of operation', 'o1' ),
                    'type' => 'checkbox',
                    'default' => '0'
                )
            ),
            'o1_errorlog_login' => array(
                array(
                    'id' => 'adminredirect',
                    'name' => __( 'Disable admin redirects', 'o1' ),
                    'label' => __( 'Do not redirect to WordPress dashboard', 'o1' ),
                    'desc' => __( 'URLs containing: wp-admin, dashboard, admin,  wp-login.php or login', 'o1' ),
                    'type' => 'checkbox',
                    'default' => '1'
                ),
                array(
                    'id' => 'loginfail',
                    'name' => __( 'Failed logins', 'o1' ),
                    'label' => __( 'Any failed authentication', 'o1' ),
                    'desc' => __( 'Failed authentication includes login, XMLRPC, password protected pages', 'o1' ),
                    'type' => 'checkbox',
                    'default' => '1'
                ),
                array(
                    'id' => 'login',
                    'name' => __( 'Successful logins', 'o1' ),
                    'label' => __( 'Log username on login', 'o1' ),
                    'desc' => __( 'Report usernames in the error.log upon successful logins', 'o1' ),
                    'type' => 'checkbox',
                    'default' => '1'
                ),
                array(
                    'id' => 'logout',
                    'name' => __( 'Logouts', 'o1' ),
                    'label' => __( 'Log username on logout', 'o1' ),
                    'desc' => __( 'Report usernames in the error.log upon logout', 'o1' ),
                    'type' => 'checkbox',
                    'default' => '1'
                ),
                array(
                    'id' => 'lostpass',
                    'name' => __( 'Lost password', 'o1' ),
                    'label' => __( 'Log username on password retrieval requests', 'o1' ),
                    'desc' => __( 'Report usernames in the error.log upon password retrieval requests', 'o1' ),
                    'type' => 'checkbox',
                    'default' => '1'
                ),
                array(
                    'id' => 'wpdie',
                    'name' => __( '<code>wp_die</code> execution', 'o1' ),
                    'label' => __( 'When plugins or WordPress core finds sufficient permissions', 'o1' ),
                    'desc' => __( 'This could generate false positives on poorly written plugins', 'o1' ),
                    'type' => 'checkbox',
                    'default' => '0'
                )
            )
        );

        return $settings_fields;
    }

    /**
     * Get all the pages
     *
     * @return array page names with key value pairs
     */
/*
    function get_pages() {
        $pages = get_pages();
        $pages_options = array();
        if ( $pages ) {
            foreach ($pages as $page) {
                $pages_options[$page->ID] = $page->post_title;
            }
        }

        return $pages_options;
    }
*/

}

endif;

