<?php // phpcs:ignore WordPress.Files.FileName.NotHyphenatedLowercase

namespace Waf4WordPress;

class Braintree_Fix {

    /**
     * Braintree IP ranges.
     *
     * @see https://developers.braintreepayments.com/reference/general/braintree-ip-addresses
     *
     * @var array
     */
    private $ranges = [
        '63.146.102.0/26',
        '184.105.251.192/26',
        '204.109.13.0/24',
        '205.219.64.0/26',
        '209.117.187.192/26',
    ];

    /**
     * Fix Braintree Webhook request.
     *
     * @param string  $path Braintree Webhook URL path
     */
    public function __construct( $path ) {

        if ( ! isset( $_SERVER['REQUEST_URI'] ) || ! isset( $_SERVER['REMOTE_ADDR'] ) ) {
            return;
        }

        $request_path = parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH );
        if ( $request_path !== $path ) {
            return;
        }

        if ( ! $this->ip_in_ranges( $_SERVER['REMOTE_ADDR'], $this->ranges ) ) {
            return;
        }

        // Braintree-Webhooks does not send Accept: header and "Mozilla/5.0" in User-Agent: header
        $_SERVER['HTTP_ACCEPT'] = '*/*';
        $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 Braintree/Webhooks';
    }

    /**
     * Match a standalone IP to CIDRs.
     *
     * @param string  $ip
     * @param array   $ranges
     * @return bool
     */
    private function ip_in_ranges( $ip, $ranges ) {

        foreach ( $ranges as $range ) {
            if ( $this->ip_in_range( $ip, $range ) ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Match a standalone IP to a CIDR.
     *
     * @param string  $ip
     * @param string  $range
     * @return bool
     */
    private function ip_in_range( $ip, $range ) {

        if ( false === strpos( $range, '/' ) ) {
            $range .= '/32';
        }

        $ip_decimal = ip2long( $ip );

        // Range is in CIDR format
        list( $range_ip, $netmask ) = explode( '/', $range, 2 );
        $range_decimal = ip2long( $range_ip );
        $wildcard_decimal = pow( 2, ( 32 - (int) $netmask ) ) - 1;
        $netmask_decimal = ~ $wildcard_decimal;

        return ( ( $ip_decimal & $netmask_decimal ) === ( $range_decimal & $netmask_decimal ) );
    }
}
