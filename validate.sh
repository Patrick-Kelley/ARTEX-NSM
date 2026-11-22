#!/usr/bin/env bash
set -euo pipefail
set -eu
root=$(dirname "$0")
bash "$root/tests/replay-local.sh"
ruby "$root/tests/hunt-http.rb"
ruby "$root/tests/hunt-shared.rb"
exec bash "$root/tests/replay-campaign.sh"