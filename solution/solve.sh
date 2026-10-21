#!/usr/bin/env bash
set -euo pipefail

mkdir -p /app/src
cp -r "$(dirname "$0")/src/." /app/src/

make -C /app/src

cp /app/src/rpt7_server /app/rpt7_server

if [ ! -f /app/data/rpt7.db ]; then
    sqlite3 /app/data/rpt7.db < /app/data/schema.sql
fi

nohup /app/rpt7_server > /app/rpt7_server.log 2>&1 &
disown

for _ in $(seq 1 60); do
    if curl -sf http://127.0.0.1:8080/health > /dev/null; then
        echo "rpt7 service is up"
        exit 0
    fi
    sleep 0.5
done

echo "rpt7 service never became healthy" >&2
cat /app/rpt7_server.log >&2 || true
exit 1
