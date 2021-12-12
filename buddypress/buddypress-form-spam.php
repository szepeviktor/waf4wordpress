<?php

// Stop BuddyPress registration form spam.
function waf4wp_bp_registration_validation() {
    global $bp;

    if ( ! isset( $_POST['field_2'], $_POST['field_3'], $_POST['field_4'], $_POST['field_5'] ) ) {
        return;
    }
    if (
        $_POST['field_2'] === $_POST['field_3']
        && $_POST['field_2'] === $_POST['field_4']
        && $_POST['field_2'] === $_POST['field_5']
    ) {
        $bp->signup->errors['field_2'] = __( 'Spam', 'buddypress' );

        do_action( 'robottrap_hiddenfield', 'bp_reg_identical_fields' );
    }
}
add_action( 'bp_signup_validate', 'waf4wp_bp_registration_validation', 10, 0 );
