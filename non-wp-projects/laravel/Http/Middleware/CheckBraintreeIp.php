<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Support\Facades\App;
use Symfony\Component\HttpFoundation\IpUtils;

class CheckBraintreeIp
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $ips = App::environment('production') ? config('braintree.production_ips') : config('braintree.sandbox_ips');

        foreach ($request->getClientIps() as $ip) {
            if (! IpUtils::checkIp($ip, $ips)) {
                // phpcs:ignore Squiz.PHP.DiscouragedFunctions
                error_log('Break-in attempt detected: laravel_braintree_ip '.$ip);

                return abort(403, 'Unauthorized.');
            }
        }

        return $next($request);
    }
}
