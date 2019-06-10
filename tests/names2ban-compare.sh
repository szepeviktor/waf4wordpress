#!/bin/bash

# Should be executed from repository root
cd -P "$(dirname "${BASH_SOURCE[0]}")/../"

diff \
    <(sed -e '/names2ban[ ]\+= array/,/);/!d' http-analyzer/waf4wordpress-http-analyzer.php) \
    <(sed -e '/names2ban[ ]\+= array/,/);/!d' core-events/waf4wordpress-core-events.php)
