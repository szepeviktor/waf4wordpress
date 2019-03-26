<?php

namespace Drupal\fail2ban\Logger;

use Drupal\Core\Logger\RfcLoggerTrait;
use Psr\Log\LoggerInterface;

/**
 * Trigger Fail2ban who controls the firewall.
 */
class Firewall implements LoggerInterface {
  use RfcLoggerTrait;

  /**
   * {@inheritdoc}
   */
  public function log($level, $message, array $context = []) {
    $prefix = 'Malicious traffic detected: ';
    $event = '';

    switch ($context['channel']) {
      case 'page not found':
        $event = '404_not_found';
        break;

      case 'access denied':
        $event = '403_forbidden';
        break;

      case 'user':
        if (substr($message, 0, 25) === 'Login attempt failed from') {
          $event = 'login_failed';
        }
        break;
    }

    if (empty($event)) {
      return;
    }

    // When error messages are sent to a file (aka. PHP error log)
    // IP address and referer are not logged.
    $log_destination = ini_get('error_log');

    // SAPI should add client data.
    $included_files = get_included_files();
    $error_msg = sprintf(
        '%s%s (%s) <%s',
        $prefix,
        $event,
        addslashes($context['request_uri']),
        reset($included_files)
    );

    // Add client data to log message.
    if (!empty($log_destination)) {
      if (array_key_exists('HTTP_REFERER', $_SERVER)) {
        $referer = sprintf(', referer: %s', addslashes($_SERVER['HTTP_REFERER']));
      }
      else {
        $referer = '';
      }

      $error_msg = sprintf(
            '[error] [client %s:%s] %s%s',
            ip_address(),
            $_SERVER['REMOTE_PORT'],
            $error_msg,
            $referer
        );
    }

    error_log($error_msg);
  }

}
