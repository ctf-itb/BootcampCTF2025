#!/bin/sh
socat tcp-l:8567,reuseaddr,fork exec:"python3 battle.py"