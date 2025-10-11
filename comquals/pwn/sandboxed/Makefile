FLAG := $(shell cat src/flag.txt)
OUTPUT := dist/dist.zip

.PHONY: all
all: src/chall $(OUTPUT) challenge.yml

src/chall: src/chall.c
	@echo "[+] Compiling chall..."
	@cd src
	@gcc -o chall chall.c

src/sandbox: src/sandbox.c
	@echo "[+] Compiling sandbox..."
	@cd src
	@gcc -o sandbox sandbox.c -lseccomp

src/printflag: src/printflag.s
	@echo "[+] Compiling printflag..."
	@cd src
	@gcc -nostdlib -nostartfiles -nodefaultlibs -static -o printflag printflag.s

$(OUTPUT): src/run.sh src/printflag.s src/chall src/chall.c src/sandbox src/sandbox.c src/Dockerfile src/docker-compose.yml 
	@echo "[+] Packing..."
	@cd src
	@7z a dist.zip printflag.s run.sh chall chall.c sandbox sandbox.c docker-compose.yml Dockerfile
	@cd ..
	@mkdir -p dist
	@mv src/dist.zip $(OUTPUT)
    

define CHALLENGE
name: "sandboxed"
category: binary exploitation
description: |- 
    Run `./printflag` to get the flag.

    Author: **msfir**
value: 1000
type: dynamic
extra:
    initial: 1000
    decay: 30
    minimum: 100
connection_info: nc 163.47.10.146 8457
flags:
    - $(FLAG)
files:
    - $(OUTPUT)
state: hidden
version: "0.1"
endef

export CHALLENGE

.ONESHELL:
challenge.yml: Makefile src/flag.txt
	@echo "[+] Generating challenge.yml..."
	@echo "$$CHALLENGE" > challenge.yml

.PHONY: clean
clean:
	@rm -rf $(OUTPUT) src/chall challenge.yml
	@echo "[+] Cleaned build artifacts"

.PHONY: rebuild
rebuild: clean all

