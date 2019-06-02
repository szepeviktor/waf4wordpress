<?php

namespace App\Listeners;

/**
 * Register this subscriber in App\Providers\EventServiceProvider::$subscribe[] = 'App\Listeners\AuthEventSubscriber'
 *
 * @see https://laravel.com/docs/5.8/events#defining-listeners
 */
class AuthEventSubscriber
{
    /**
     * Handle auth events.
     */
    public function handleAuth($event)
    {
        $inOrOut = property_exists($event, 'remember') ? 'in' : 'out';
        Log::info(sprintf('Laravel auth: laravel_logged_%s (#%d)', $inOrOut, $event->user->id));
    }

    /**
     * Register the listeners for the subscriber.
     *
     * @param \Illuminate\Events\Dispatcher $events
     */
    public function subscribe($events)
    {
        $events->listen(
            'Illuminate\Auth\Events\Login',
            'App\Listeners\AuthEventSubscriber@handleAuth'
        );
        $events->listen(
            'Illuminate\Auth\Events\Logout',
            'App\Listeners\AuthEventSubscriber@handleAuth'
        );
    }
}
