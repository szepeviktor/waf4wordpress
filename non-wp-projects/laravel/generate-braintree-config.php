<?php
/**
 * Generate config/braintree.php.
 *
 * @see https://developers.braintreepayments.com/reference/general/braintree-ip-addresses
 */

$ipsUrl = 'https://assets.braintreegateway.com/json/ips.json';

$ips = json_decode(file_get_contents($ipsUrl), true);

$configArray = [
    'production_ips' => array_merge($ips['production']['cidrs'], $ips['production']['ips']),
    'sandbox_ips' => [ '0.0.0.0/0' ],
];

printf("<?php\n\nreturn %s;\n", var_export($configArray, true));
