#!/bin/bash

# Should be executed from repository root
cd -P "$(dirname "${BASH_SOURCE[0]}")/../"

diff \
    <(sed -e '/names2ban = array/,/);/!d' block-bad-requests/wp-fail2ban-bad-request-instant.inc.php) \
    <(sed -e '/names2ban = array/,/);/!d' mu-plugin/wp-fail2ban-mu-instant.php)
