#!/bin/sh

python3 /app/internal/app.py &
node /app/external/dist/server/entry.mjs &
wait