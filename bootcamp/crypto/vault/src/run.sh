#!/bin/sh
socat tcp-l:8017,reuseaddr,fork exec:"python3 vault.py"