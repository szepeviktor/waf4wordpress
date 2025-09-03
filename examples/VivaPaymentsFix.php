<?php

namespace SzepeViktor\WordPress\Waf;

/**
 * Fix Viva Payments webhook request.
 */
class VivaPaymentsFix
{
    public function __construct()
    {
        if (! isset($_SERVER['REQUEST_URI'], $_SERVER['REMOTE_ADDR']) || ! empty($_SERVER['HTTP_USER_AGENT'])) {
            return;
        }

        if (strpos($_SERVER['REQUEST_URI'], '/wp-json/wc_vivacom_smart/') !== 0) {
            return;
        }

        if (! $this->is_vivapayment($_SERVER['REMOTE_ADDR'])) {
            return;
        }

        // Fix headers
        $_SERVER['HTTP_USER_AGENT'] = 'VivaPayments-Webhook/1.0';
        $_SERVER['HTTP_ACCEPT'] = '*/*';
    }

    /**
     * Verify Viva Payments server.
     *
     * @see https://developer.viva.com/webhooks-for-payments/#whitelist-the-viva-addresses
     * @param string $ip
     * @return bool
     */
    private function is_vivapayment($ip)
    {
        $ranges = [
            '51.138.37.238',
            '13.80.70.181',
            '13.80.71.223',
            '13.79.28.70',
            '40.127.253.112/28',
            '51.105.129.192/28',
            '20.54.89.16',
            '4.223.76.50',
            '51.12.157.0/28',
        ];

        foreach ($ranges as $range) {
            if ($this->ip_in_range($ip, $range)) {
                return true;
            }
        }

        return false;
    }

    private function ip_in_range($ip, $range)
    {
        if (strpos($range, '/') === false) {
            $range .= '/32';
        }

        $ip_decimal = ip2long($ip);

        // Range is in CIDR format
        list($range_ip, $netmask) = explode('/', $range, 2);
        $range_decimal = ip2long($range_ip);
        $wildcard_decimal = pow(2, (32 - (int)$netmask)) - 1;
        $netmask_decimal = ~ $wildcard_decimal;

        return ($ip_decimal & $netmask_decimal) === ($range_decimal & $netmask_decimal);
    }
}
