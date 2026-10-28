#!/bin/sh
/cg/agent.sh &
exec /docker-entrypoint.sh "$@"
