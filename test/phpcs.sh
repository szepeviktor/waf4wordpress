#!/bin/bash

# Should be executed from repository root
if [ "$(basename "$(pwd)")" == test ]; then
    cd ../
fi

vendor/bin/phpcs --config-set installed_paths vendor/wp-coding-standards/wpcs/
vendor/bin/phpcs ./block-bad-requests/
vendor/bin/phpcs ./mu-plugin/
