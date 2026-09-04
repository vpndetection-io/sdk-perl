#!/bin/bash

# The integration suite inside the official perl image, because the box needs no
# Perl toolchain. CI runs `perl scripts/run.pl` directly; this is the same entry
# point with an interpreter around it.
#
#   ./scripts/run.sh
#   PERL_IMAGE=perl:5.22 ./scripts/run.sh
#
# The four tier keys are passed through by NAME, so no key ever reaches a command
# line. Only the integration directory is mounted: the suite must see the
# published distribution and not the source sitting beside it.

set -euo pipefail

cd "$(dirname "$0")/.."

PERL_IMAGE="${PERL_IMAGE:-perl:5.40}"

docker run --rm \
    -v "$PWD:/app" -w /app \
    -e VPNDETECTION_STAGING_KEY_FREE \
    -e VPNDETECTION_STAGING_KEY_STARTER \
    -e VPNDETECTION_STAGING_KEY_SCALE \
    -e VPNDETECTION_STAGING_KEY_MAX \
    "$PERL_IMAGE" perl scripts/run.pl "$@"
