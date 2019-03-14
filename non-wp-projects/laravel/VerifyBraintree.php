<?php

namespace App\Http\Middleware;

use Closure;
use Symfony\Component\HttpFoundation\IpUtils;

/**
 * // https://developers.braintreepayments.com/reference/general/braintree-ip-addresses
 * 'waf' => [
 *     'braintree_ip_ranges' => env('BRAINTREE_IP_RANGES', '63.146.102.0/26,184.105.251.192/26,204.109.13.0/24,205.219.64.0/26,209.117.187.192/26'),
 * ],
 */
class VerifyBraintree
{
    /**
     * IP ranges.
     *
     * @var array
     */
    protected $ipRanges = [];

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $this->ipRanges = explode(',', config('waf.braintree_ip_ranges'));

        foreach ($request->getClientIps() as $ip) {
            if (! $this->isValidIpRange($ip)) {
                // Trigger WAF
                // phpcs:ignore Squiz.PHP.DiscouragedFunctions
                error_log('Break-in attempt detected: laravel_braintree_ip ' . $ip);
                abort(403, 'Unauthorized.');
                return;
            }
        }

        return $next($request);
    }

    protected function isValidIpRange($ip)
    {
        return IpUtils::checkIp($ip, $this->ipRanges);
    }
}
