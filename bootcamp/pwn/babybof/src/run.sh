#!/usr/bin/env bash
exec > /tmp/run.log 2>&1
echo "run.sh started at $(date)"
cd /ctf
timeout 1800 ./chall
echo "run.sh exited with $?"

