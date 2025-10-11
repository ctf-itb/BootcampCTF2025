#!/bin/sh
socat tcp-l:8570,reuseaddr,fork exec:"python3 chall.py"