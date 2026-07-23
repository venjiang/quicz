#!/bin/bash

# quicz interop endpoint runner
# Usage: run_endpoint.sh [server|client]

ROLE=${1:-server}
TESTCASE=${TESTCASE:-handshake}

echo "quicz interop: role=$ROLE testcase=$TESTCASE"

if [ "$ROLE" == "server" ]; then
    exec /usr/local/bin/quicz-interop-server
else
    exec /usr/local/bin/quicz-interop-client
fi
