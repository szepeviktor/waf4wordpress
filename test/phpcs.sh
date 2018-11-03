#!/bin/bash

# Should be executed from repository root
cd -P "$(dirname "${BASH_SOURCE[0]}")/../"

vendor/bin/phpcs --config-set installed_paths vendor/wp-coding-standards/wpcs/
vendor/bin/phpcs ./block-bad-requests/
vendor/bin/phpcs ./mu-plugin/
