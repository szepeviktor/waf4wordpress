<?php

namespace App\Exceptions;

use Exception;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Log;
use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;

class Handler extends ExceptionHandler
{
    /**
     * A list of the exception types that are not reported.
     *
     * @var array
     */
    protected $dontReport = [
        //
    ];

    /**
     * A list of the exception types that are reported to the security log.
     *
     * @var array
     */
    protected $security = [
        \Illuminate\Session\TokenMismatchException::class,
        \Illuminate\Auth\Access\AuthorizationException::class,
        \Illuminate\Database\Eloquent\ModelNotFoundException::class,
        \Symfony\Component\HttpKernel\Exception\HttpException::class,
        \Symfony\Component\HttpKernel\Exception\NotFoundHttpException::class,
    ];

    /**
     * A list of the validation errors that are reported to the security log.
     *
     * @var array
     */
    protected $validation_errors = [
        'email', // login
        'g-recaptcha-response', // registration
    ];

    /**
     * A list of the inputs that are never flashed for validation exceptions.
     *
     * @var array
     */
    protected $dontFlash = [
        'password',
        'password_confirmation',
    ];

    /**
     * Report or log an exception.
     *
     * This is a great spot to send exceptions to Sentry, Bugsnag, etc.
     *
     * @param  \Exception  $exception
     * @return void
     */
    public function report(Exception $exception)
    {
        parent::report($exception);
        $log = '';
        $type = get_class($exception);

        // ValidationException errors
        if ($exception instanceof \Illuminate\Validation\ValidationException) {
            // Get the MessageBag
            $errors = $exception->validator->errors();
            if ($errors->hasAny($this->validation_errors)) {
                $first_error = $errors->keys()[0];
                $log = sprintf('Malicious traffic detected: laravel_%s %s', 'ValidationException::' . $first_error, addslashes(url()->full()));
            }
        }
        // Other listed security exceptions
        if (in_array($type, $this->security)) {
            $log = sprintf('Malicious traffic detected: laravel_%s %s', str_replace('\\', '_', $type), addslashes(url()->full()));
        }

        // First trigger WAF
        if ($log !== '') {
            Log::info($log);
            if (App::environment(['local', 'production'])) {
                // phpcs:ignore Squiz.PHP.DiscouragedFunctions
                error_log($log);
            }
        }

        /*
        // Report to Sentry
        if (app()->bound('sentry') && $this->shouldReport($exception)) {
            app('sentry')->captureException($exception);
        }
        */
    }

    /**
     * Render an exception into an HTTP response.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Exception  $exception
     * @return \Illuminate\Http\Response
     */
    public function render($request, Exception $exception)
    {
        return parent::render($request, $exception);
    }
}
